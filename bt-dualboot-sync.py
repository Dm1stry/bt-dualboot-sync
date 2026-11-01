#!/usr/bin/env python3
#
# bt-dualboot-sync
#
# Copies Bluetooth pairing keys from Windows to Linux (BlueZ), so that
# headphones (and any other Bluetooth devices) work in both systems of a
# dual-boot machine without pairing again.
#
# WHY
# ---
# When a device is paired, it and the computer agree on a shared secret key,
# and the device stores it together with the MAC address of the Bluetooth
# adapter. Windows and Linux run on the same adapter, so to the device they
# are the same computer. Pair in Windows - the device forgets the key Linux
# knows and remembers a new one. Linux presents the old key, the device
# rejects it, you pair again - and now Windows is broken. And so on.
#
# FIX: pair the device once in Windows, then read the key from the Windows
# registry in Linux and write it to BlueZ. After that both systems know the
# same key, and the device connects in both.
#
# IMPORTANT: COPY BEFORE BLUETOOTH STARTS
# ---------------------------------------
# Verified with HUAWEI FreeLace Pro 2 (btmon): if the headphones connect to
# Linux with the old key even once, they DELETE their pairing with this
# computer - and a Windows key copied later no longer helps (the headphones
# answer "no key" and demand a new pairing). And they switch on and connect
# by themselves as soon as you take them out. That is why the copy is
# automatic: a service runs at boot BEFORE bluetooth.service and after
# resume from hibernation (Windows may have been booted in between).
#
# To avoid overwriting what was paired in Linux, the script remembers
# fingerprints of the Windows keys (/var/lib/bt-dualboot-sync/state.json,
# the keys themselves are not stored there) and on its own copies only
# devices whose Windows key changed since the last run, i.e. devices that
# were re-paired in Windows.
#
# Where Windows keeps the keys (hive C:\Windows\System32\config\SYSTEM):
#   ControlSet00X\Services\BTHPORT\Parameters\Keys\<adapter>
#     <device>       REG_BINARY - Bluetooth Classic (BR/EDR) link key
#     <device>\      subkey     - Bluetooth LE keys (LTK, IRK, ERand...)
# The hive parser is built in, no third-party packages (chntpw, hivex) are
# needed. The Windows partition is mounted read-only and unmounted right
# away. BitLocker is not supported directly - see the script's message.
#
# Workflow, options and limitations: README.md, or bt-dualboot-sync --help.
#
# Root is required (/var/lib/bluetooth and mounting) - the script re-runs
# itself through sudo. Before each info file is edited, a copy named
# info.bak-<timestamp> is put next to it.
#
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

__version__ = "1.0.0"

BT_DIR = "/var/lib/bluetooth"
HIVE_PATH = ("Windows", "System32", "config", "SYSTEM")
STATE_FILE = "/var/lib/bt-dualboot-sync/state.json"
INSTALL_PATH = "/usr/local/sbin/bt-dualboot-sync"
UNIT_DIR = "/etc/systemd/system"
SLEEP_TARGETS = "hibernate.target hybrid-sleep.target suspend-then-hibernate.target"

if sys.stdout.isatty():
    RED, GRN, YLW, BLD, DIM, RST = "\033[31m", "\033[32m", "\033[33m", "\033[1m", "\033[2m", "\033[0m"
else:
    RED = GRN = YLW = BLD = DIM = RST = ""


def ok(msg):   print(f"  {GRN}✓{RST} {msg}")
def info(msg): print(f"  {BLD}·{RST} {msg}")
def warn(msg): print(f"  {YLW}!{RST} {msg}")
def head(msg): print(f"\n{BLD}{msg}{RST}")


def die(msg):
    print(f"  {RED}✗{RST} {msg}", file=sys.stderr)
    sys.exit(1)


# --- Reading a Windows registry hive (regf format) --------------------------

REG_BINARY, REG_DWORD, REG_QWORD = 3, 4, 11
NO_CELL = 0xFFFFFFFF


class HiveError(Exception):
    pass


class Hive:
    """Minimal registry hive parser: keys, subkeys, values."""

    def __init__(self, data):
        if len(data) < 0x1000 or data[:4] != b"regf":
            raise HiveError("not a registry hive file (no regf signature)")
        self.data = data
        # Different sequence numbers mean that part of the changes is only in
        # the SYSTEM.LOG1/LOG2 logs and has not reached the main file yet.
        self.seq1, self.seq2 = struct.unpack_from("<II", data, 4)
        self.root = Key(self, struct.unpack_from("<I", data, 0x24)[0])

    @property
    def dirty(self):
        return self.seq1 != self.seq2

    def cell(self, off):
        """Start and length of a cell's data by its offset from the hive bins."""
        pos = 0x1000 + off
        if off == NO_CELL or pos + 4 > len(self.data):
            raise HiveError(f"reference outside the hive: {off:#x}")
        size = abs(struct.unpack_from("<i", self.data, pos)[0])
        return pos + 4, size - 4

    def u32(self, pos):
        return struct.unpack_from("<I", self.data, pos)[0]


class Key:
    def __init__(self, hive, off):
        self.hive = hive
        d = hive.data
        p, _ = hive.cell(off)
        if d[p:p + 2] != b"nk":
            raise HiveError(f"expected a key (nk) at offset {off:#x}")
        flags, self.mtime = struct.unpack_from("<HQ", d, p + 2)
        self._nsub = hive.u32(p + 0x14)
        self._sublist = hive.u32(p + 0x1C)
        self._nval, self._vallist = struct.unpack_from("<II", d, p + 0x24)
        nlen = struct.unpack_from("<H", d, p + 0x48)[0]
        raw = d[p + 0x4C:p + 0x4C + nlen]
        self.name = raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le")

    def _offsets(self, off):
        h, d = self.hive, self.hive.data
        p, _ = h.cell(off)
        sig, n = d[p:p + 2], struct.unpack_from("<H", d, p + 2)[0]
        if sig in (b"lf", b"lh"):            # pairs of (offset, name hash)
            return [h.u32(p + 4 + 8 * i) for i in range(n)]
        if sig == b"li":
            return [h.u32(p + 4 + 4 * i) for i in range(n)]
        if sig == b"ri":                     # list of lists
            return [o for i in range(n) for o in self._offsets(h.u32(p + 4 + 4 * i))]
        raise HiveError(f"unknown subkey list {sig!r}")

    def subkeys(self):
        if self._nsub == 0 or self._sublist == NO_CELL:
            return []
        return [Key(self.hive, o) for o in self._offsets(self._sublist)]

    def subkey(self, *path):
        """Subkey by path, case-insensitive (as in Windows itself)."""
        key = self
        for name in path:
            key = next((k for k in key.subkeys() if k.name.lower() == name.lower()), None)
            if key is None:
                return None
        return key

    def values(self):
        """{lowercase name: (type, bytes)}"""
        out = {}
        if self._nval == 0 or self._vallist == NO_CELL:
            return out
        h, d = self.hive, self.hive.data
        p, _ = h.cell(self._vallist)
        for i in range(self._nval):
            q, _ = h.cell(h.u32(p + 4 * i))
            if d[q:q + 2] != b"vk":
                raise HiveError("expected a value (vk)")
            nlen, dsize, doff, vtype, vflags = struct.unpack_from("<HIIIH", d, q + 2)
            raw = d[q + 20:q + 20 + nlen]
            name = raw.decode("latin-1") if vflags & 1 else raw.decode("utf-16-le")
            if dsize & 0x80000000:           # up to 4 bytes are stored in the offset field
                data = d[q + 8:q + 8 + (dsize & 0x7FFFFFFF)]
            elif dsize == 0:
                data = b""
            else:
                r, clen = h.cell(doff)
                if dsize > clen and d[r:r + 2] == b"db":   # big value in segments
                    nseg, seglist = struct.unpack_from("<HI", d, r + 2)
                    s, _ = h.cell(seglist)
                    parts = []
                    for j in range(nseg):
                        sp, sl = h.cell(h.u32(s + 4 * j))
                        parts.append(d[sp:sp + min(sl, 16344)])
                    data = b"".join(parts)[:dsize]
                else:
                    data = d[r:r + dsize]
            out[name.lower()] = (vtype, data)
        return out


def filetime(ft):
    t = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=ft // 10)
    return t.astimezone().strftime("%Y-%m-%d %H:%M")


def as_int(value):
    return int.from_bytes(value[1][:8], "little")


# --- Windows keys -----------------------------------------------------------

MAC_HEX = re.compile(r"^[0-9a-fA-F]{12}$")


def fmt_mac(hex12):
    return ":".join(hex12[i:i + 2] for i in range(0, 12, 2)).upper()


def norm_mac(s):
    h = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(h) != 12:
        raise ValueError(s)
    return fmt_mac(h)


class WinDevice:
    def __init__(self, mac):
        self.mac = mac
        self.name = ""
        self.link_key = None     # bytes(16) for BR/EDR
        self.le = None           # subkey values for LE
        self.le_addr = None      # address from the Address value, if different


def read_windows(hive):
    """{adapter MAC: (modification time, {device MAC: WinDevice})}"""
    root = hive.root
    select = root.subkey("Select")
    if select is None or "current" not in select.values():
        raise HiveError("no Select key in the hive - is this really the SYSTEM file?")
    current = as_int(select.values()["current"])
    params = root.subkey(f"ControlSet{current:03d}", "Services", "BTHPORT", "Parameters")
    if params is None:
        return {}

    names = {}
    devices_key = params.subkey("Devices")
    for k in devices_key.subkeys() if devices_key else []:
        v = k.values().get("name")
        if MAC_HEX.match(k.name) and v:
            names[fmt_mac(k.name)] = v[1].split(b"\0")[0].decode("utf-8", "replace").strip()

    adapters = {}
    keys = params.subkey("Keys")
    for ak in keys.subkeys() if keys else []:
        if not MAC_HEX.match(ak.name):
            continue
        devices = {}
        for vname, (vtype, data) in ak.values().items():
            # Service values such as MasterIRK sit next to the keys - the name filters them out
            if MAC_HEX.match(vname) and vtype == REG_BINARY and len(data) == 16:
                devices.setdefault(fmt_mac(vname), WinDevice(fmt_mac(vname))).link_key = data
        for dk in ak.subkeys():
            if not MAC_HEX.match(dk.name):
                continue
            dev = devices.setdefault(fmt_mac(dk.name), WinDevice(fmt_mac(dk.name)))
            dev.le = dk.values()
            if "address" in dev.le:
                addr = fmt_mac(f"{as_int(dev.le['address']) & 0xFFFFFFFFFFFF:012x}")
                if addr != dev.mac:
                    dev.le_addr = addr
        for dev in devices.values():
            dev.name = names.get(dev.mac, "")
        adapters[fmt_mac(ak.name)] = (ak.mtime, devices)
    return adapters


# --- Finding and reading the SYSTEM hive ------------------------------------

def find_ci(base, parts):
    """Case-insensitive path inside base (case doesn't matter to Windows on NTFS)."""
    cur = base
    for part in parts:
        try:
            entries = os.listdir(cur)
        except OSError:
            return None
        match = next((e for e in entries if e.lower() == part.lower()), None)
        if match is None:
            return None
        cur = os.path.join(cur, match)
    return cur if os.path.isfile(cur) else None


def read_hive_from_device(dev):
    """Mounts the partition read-only, reads the hive, unmounts."""
    mnt = tempfile.mkdtemp(prefix="bt-dualboot-")
    try:
        for cmd in (["mount", "-o", "ro", dev, mnt],
                    ["mount", "-t", "ntfs3", "-o", "ro", dev, mnt]):
            if subprocess.run(cmd, capture_output=True).returncode == 0:
                break
        else:
            return None
        try:
            path = find_ci(mnt, HIVE_PATH)
            if path is None:
                return None
            with open(path, "rb") as f:
                return f.read()
        finally:
            subprocess.run(["umount", mnt], capture_output=True)
    finally:
        try:
            os.rmdir(mnt)
        except OSError:
            pass


def block_devices():
    # The MOUNTPOINTS column appeared in util-linux 2.37, older lsblk has only MOUNTPOINT
    for cols in ("PATH,FSTYPE,MOUNTPOINTS", "PATH,FSTYPE,MOUNTPOINT"):
        r = subprocess.run(["lsblk", "-J", "-p", "-o", cols], capture_output=True, text=True)
        if r.returncode == 0:
            break
    else:
        die(f"lsblk failed: {r.stderr.strip()}")
    todo, flat = json.loads(r.stdout)["blockdevices"], []
    while todo:
        d = todo.pop(0)
        todo[0:0] = d.get("children") or []
        d["mountpoints"] = [m for m in (d.get("mountpoints") or [d.get("mountpoint")]) if m]
        flat.append(d)
    return flat


def load_hive(args):
    """(hive bytes, where it was taken from)"""
    if args.hive:
        with open(args.hive, "rb") as f:
            return f.read(), args.hive

    if args.windows:
        if os.path.isdir(args.windows):
            path = find_ci(args.windows, HIVE_PATH)
            if path is None:
                die(f"no Windows/System32/config/SYSTEM in {args.windows}")
            with open(path, "rb") as f:
                return f.read(), path
        data = read_hive_from_device(args.windows)
        if data is None:
            die(f"could not mount {args.windows}, or there is no Windows on it")
        return data, args.windows

    # NVMe device names can change between boots, so search every time
    bitlocker = []
    for d in block_devices():
        fstype = (d.get("fstype") or "").lower()
        if fstype == "bitlocker":
            bitlocker.append(d["path"])
        if fstype != "ntfs":
            continue
        for mp in d["mountpoints"]:
            path = find_ci(mp, HIVE_PATH)
            if path:
                with open(path, "rb") as f:
                    return f.read(), f"{d['path']} (already mounted at {mp})"
        if not d["mountpoints"]:
            data = read_hive_from_device(d["path"])
            if data is not None:
                return data, f"{d['path']} (mounted read-only and unmounted)"

    if bitlocker:
        die("the Windows partition is encrypted with BitLocker: " + ", ".join(bitlocker) + ".\n"
            "    Unlock it with the recovery key and pass it explicitly:\n"
            f"      sudo cryptsetup bitlkOpen {bitlocker[0]} win\n"
            "      bt-dualboot-sync --windows /dev/mapper/win")
    die("Windows partition not found. Specify it: --windows /dev/... or --hive /path/to/SYSTEM")


# --- BlueZ info files ---------------------------------------------------------

class KeyFile:
    """Targeted editing of a BlueZ info file (GKeyFile format): everything
    we don't touch stays byte for byte."""

    def __init__(self, text=""):
        self.lines = text.splitlines()
        self.changed = []

    def _section(self, name):
        start = None
        for i, line in enumerate(self.lines):
            s = line.strip()
            if s.startswith("[") and s.endswith("]"):
                if start is not None:
                    return start, i
                if s[1:-1] == name:
                    start = i
        return (start, len(self.lines)) if start is not None else (None, None)

    def has(self, section):
        return self._section(section)[0] is not None

    def get(self, section, key):
        a, b = self._section(section)
        for line in self.lines[a + 1:b] if a is not None else []:
            k, sep, v = line.partition("=")
            if sep and not line.lstrip().startswith("#") and k.strip() == key:
                return v.strip()
        return None

    def set(self, section, key, value):
        if self.get(section, key) == value:
            return
        self.changed.append(f"{section}.{key}")
        a, b = self._section(section)
        if a is None:
            while self.lines and not self.lines[-1].strip():
                self.lines.pop()
            if self.lines:
                self.lines.append("")
            self.lines += [f"[{section}]", f"{key}={value}"]
            return
        for i in range(a + 1, b):
            k, sep, _ = self.lines[i].partition("=")
            if sep and not self.lines[i].lstrip().startswith("#") and k.strip() == key:
                self.lines[i] = f"{key}={value}"
                return
        j = b                                # after the last non-empty line of the section
        while j > a + 1 and not self.lines[j - 1].strip():
            j -= 1
        self.lines.insert(j, f"{key}={value}")

    def text(self):
        return "\n".join(self.lines) + "\n"


def apply_link_key(kf, key):
    kf.set("LinkKey", "Key", key.hex().upper())
    # Windows doesn't store the key type. If BlueZ already wrote one, keep it:
    # for headphones any SSP key type gives the required security level.
    if kf.get("LinkKey", "Type") is None:
        kf.set("LinkKey", "Type", "4")
    if kf.get("LinkKey", "PINLength") is None:
        kf.set("LinkKey", "PINLength", "0")


def apply_le(kf, le):
    """Bluetooth LE keys. Conversion rules follow the Arch Wiki (Dual boot pairing)."""
    if "ltk" in le and len(le["ltk"][1]) == 16:
        key = le["ltk"][1].hex().upper()                 # LTK - as is
        rand = as_int(le["erand"]) if "erand" in le else 0   # QWORD -> decimal
        ediv = as_int(le["ediv"]) if "ediv" in le else 0
        encsize = as_int(le["keylength"]) if "keylength" in le else 16
        secure = rand == 0 and ediv == 0                 # LE Secure Connections
        if secure:
            # An SC key is shared by both roles, and BlueZ puts it either in
            # LongTermKey or in PeripheralLongTermKey - update those present.
            sections = [s for s in ("LongTermKey", "PeripheralLongTermKey", "SlaveLongTermKey")
                        if kf.has(s)] or ["LongTermKey"]
        else:
            sections = ["LongTermKey"]
        for sec in sections:
            kf.set(sec, "Key", key)
            kf.set(sec, "Rand", str(rand))
            kf.set(sec, "EDiv", str(ediv))
            kf.set(sec, "EncSize", str(encsize))
            if kf.get(sec, "Authenticated") is None:
                mitm = as_int(le["authreq"]) & 0x04 if "authreq" in le else 0
                kf.set(sec, "Authenticated", str((2 if secure else 0) + (1 if mitm else 0)))

    if "irk" in le and len(le["irk"][1]) == 16:
        # The IRK byte order in Windows differs between devices. The IRK is set
        # by the device itself and usually doesn't change: if Linux already has
        # the same key in either order, it is correct - leave it alone.
        irk = le["irk"][1]
        if kf.get("IdentityResolvingKey", "Key") not in (irk.hex().upper(), irk[::-1].hex().upper()):
            kf.set("IdentityResolvingKey", "Key", irk.hex().upper())

    for wname, sec in (("csrk", "LocalSignatureKey"), ("csrkinbound", "RemoteSignatureKey")):
        if wname in le and len(le[wname][1]) == 16 and kf.has(sec):
            kf.set(sec, "Key", le[wname][1].hex().upper())


class Plan:
    def __init__(self, adapter, dev, allow_create):
        self.dev = dev
        self.kind = "/".join(t for t, on in (("BR/EDR", dev.link_key is not None),
                                             ("LE", dev.le is not None)) if on)
        mac = dev.mac
        if dev.le_addr and not os.path.isdir(os.path.join(BT_DIR, adapter, mac)) \
                and os.path.isdir(os.path.join(BT_DIR, adapter, dev.le_addr)):
            mac = dev.le_addr
        self.path = os.path.join(BT_DIR, adapter, mac, "info")
        self.exists = os.path.isfile(self.path)
        self.skip = None

        if self.exists:
            with open(self.path) as f:
                self.kf = KeyFile(f.read())
            self.name = dev.name or self.kf.get("General", "Name") or "?"
            if dev.link_key is not None:
                apply_link_key(self.kf, dev.link_key)
            if dev.le is not None:
                apply_le(self.kf, dev.le)
        else:
            self.kf = KeyFile()
            self.name = dev.name or "?"
            if dev.link_key is None:
                self.skip = "LE only: pair it in Linux first, then in Windows"
            elif not allow_create:
                self.skip = f"not in Linux (to add: --device {dev.mac})"
            else:
                g = "General"
                if dev.name:
                    self.kf.set(g, "Name", dev.name)
                self.kf.set(g, "SupportedTechnologies", "BR/EDR;")
                self.kf.set(g, "Trusted", "true")
                self.kf.set(g, "Blocked", "false")
                apply_link_key(self.kf, dev.link_key)

    @property
    def changed(self):
        return not self.skip and bool(self.kf.changed)


def write_plan(plan, stamp):
    if plan.exists:
        shutil.copy2(plan.path, f"{plan.path}.bak-{stamp}")
    else:
        os.makedirs(os.path.dirname(plan.path), mode=0o700, exist_ok=True)
    with open(plan.path, "w") as f:
        f.write(plan.kf.text())
    os.chmod(plan.path, 0o600)
    if shutil.which("restorecon"):       # SELinux labels for new files
        subprocess.run(["restorecon", "-R", os.path.dirname(plan.path)], capture_output=True)


# --- History: fingerprints of the Windows keys from the last run -------------

def fingerprint(dev):
    """Fingerprint of the device's keys in Windows (the keys themselves are not saved)."""
    h = hashlib.sha256()
    if dev.link_key is not None:
        h.update(b"br" + dev.link_key)
    for name in ("ltk", "erand", "ediv", "irk"):
        if dev.le and name in dev.le:
            h.update(name.encode() + dev.le[name][1])
    return h.hexdigest()[:16]


def load_state():
    """{"adapter/device": fingerprint}, or None if there is no history yet."""
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        warn(f"could not read {STATE_FILE} ({e}) - assuming there is no history")
        return None


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), mode=0o700, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1, sort_keys=True)
    os.replace(tmp, STATE_FILE)


def bluetooth_active():
    return subprocess.run(["systemctl", "is-active", "--quiet", "bluetooth"]).returncode == 0


# --- Auto-copy service ------------------------------------------------------

UNITS = {
    # Once per boot, before bluetoothd: while it isn't running the adapter is
    # off, and devices can't connect with the old key.
    "bt-dualboot-sync.service": f"""\
[Unit]
Description=Copy Bluetooth keys from Windows (before Bluetooth starts)
After=local-fs.target
Before=bluetooth.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={INSTALL_PATH} --auto
TimeoutStartSec=90

[Install]
WantedBy=bluetooth.service
""",
    # After resume from hibernation: Windows may have been booted while Linux slept.
    "bt-dualboot-sync-resume.service": f"""\
[Unit]
Description=Copy Bluetooth keys from Windows after resume from hibernation
After={SLEEP_TARGETS}

[Service]
Type=oneshot
ExecStart={INSTALL_PATH} --auto
TimeoutStartSec=90

[Install]
WantedBy={SLEEP_TARGETS}
""",
}


def unit_quote(arg):
    """An argument for ExecStart=: systemd expands % specifiers and C escapes."""
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def install(args):
    if args.hive:
        die("--hive can't be used with --install; use --windows")
    extra = ""
    if args.windows:
        load_hive(args)                      # fail now rather than at every boot
        extra = " --windows " + unit_quote(args.windows)
    src = os.path.realpath(__file__)
    if src != INSTALL_PATH:
        shutil.copyfile(src, INSTALL_PATH)
    os.chmod(INSTALL_PATH, 0o755)
    for name, text in UNITS.items():
        with open(os.path.join(UNIT_DIR, name), "w") as f:
            f.write(text.replace(" --auto\n", f" --auto{extra}\n"))
    if shutil.which("restorecon"):
        subprocess.run(["restorecon", INSTALL_PATH, *(os.path.join(UNIT_DIR, n) for n in UNITS)],
                       capture_output=True)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--quiet", *UNITS], check=True)
    head("Auto-copy service")
    ok(f"script: {INSTALL_PATH}")
    if args.windows:
        ok(f"Windows partition: {args.windows}")
    ok("copying at boot before Bluetooth and after resume from hibernation is enabled")
    if load_state() is None:
        sync(args, set(), baseline=True)
    info("now pair the device in Windows and reboot into Linux -\n"
         "    the key will be copied automatically (log: journalctl -u bt-dualboot-sync)")


def uninstall():
    subprocess.run(["systemctl", "disable", "--quiet", *UNITS], check=False)
    for path in [os.path.join(UNIT_DIR, n) for n in UNITS] + [INSTALL_PATH]:
        if os.path.exists(path):
            os.remove(path)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    ok(f"service removed (key history kept in {STATE_FILE})")


# --- main -------------------------------------------------------------------

def sync(args, wanted, baseline=False):
    """baseline - only remember the current Windows keys, change nothing."""
    auto = args.auto
    head("Windows")
    data, source = load_hive(args)
    ok(f"registry hive: {source}")
    try:
        hive = Hive(data)
        windows = read_windows(hive)
    except (HiveError, struct.error, UnicodeDecodeError) as e:
        die(f"could not parse the Windows registry: {e}")
    if hive.dirty:
        warn("the Windows registry was not fully saved (Windows was not shut down cleanly).\n"
             "    Fresh keys may not be written yet. If the device doesn't connect after\n"
             "    the copy, boot Windows and leave it with Restart (not Shut down).")
    if not windows:
        die("no paired Bluetooth devices in the Windows registry")

    state = load_state()
    new_state = dict(state or {})
    # The service changes nothing without history: it can't know which system
    # paired the device last. It only remembers.
    baseline = baseline or (auto and state is None)

    linux_adapters = set(os.listdir(BT_DIR)) if os.path.isdir(BT_DIR) else set()
    plans, seen = [], set()
    for adapter, (mtime, devices) in sorted(windows.items()):
        head(f"Adapter {adapter}")
        if adapter not in linux_adapters:
            warn("this adapter is not present in Linux (a different Bluetooth module) - skipping")
            continue
        info(f"keys in Windows last changed {filetime(mtime)}")
        for dev in sorted(devices.values(), key=lambda d: (d.name or "~").lower()):
            if wanted and dev.mac not in wanted:
                continue
            seen.add(dev.mac)
            sid = f"{adapter}/{dev.mac}"
            fp = fingerprint(dev)
            new_state[sid] = fp
            # The Windows key changed since the last run = the device was
            # re-paired in Windows, and its key is newer than the one in Linux.
            fresh = state is None or state.get(sid) != fp
            p = Plan(adapter, dev, allow_create=dev.mac in wanted)
            label = f"{dev.mac}  {p.name[:28]:<28} {p.kind:<9}"
            if p.skip:
                print(f"  {DIM}·{RST} {DIM}{label} {p.skip}{RST}")
            elif not p.changed:
                print(f"  {GRN}✓{RST} {label} matches")
            elif baseline:
                print(f"  {DIM}·{RST} {label} differs - first run, only remembering")
            elif not fresh and dev.mac not in wanted:
                print(f"  {DIM}·{RST} {label} differs, but unchanged in Windows since the last run\n"
                      f"    {DIM}(probably paired in Linux) - skipping; to copy anyway: --device {dev.mac}{RST}")
            elif p.exists:
                print(f"  {YLW}→{RST} {label} {BLD}will be updated{RST} {DIM}({', '.join(p.kf.changed)}){RST}")
                plans.append(p)
            else:
                print(f"  {YLW}+{RST} {label} {BLD}will be added{RST}")
                plans.append(p)
    for mac in sorted(wanted - seen):
        warn(f"{mac}: not among the devices paired in Windows on this adapter")

    head("Summary")
    if args.list:
        info(f"to change: {len(plans)}. --list mode - changing nothing")
        return
    if not plans:
        save_state(new_state)
        ok("nothing to change")
        if baseline:
            info("current Windows keys remembered: from now on, keys that change there get copied")
        return
    if not (args.yes or auto):
        try:
            answer = input(f"  Write Windows keys for {len(plans)} device(s) and restart bluetooth? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            info("cancelled, nothing changed")
            return

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    # bluetoothd reads the keys only at startup, and a running one may
    # overwrite the info file - so edit with the service stopped.
    # The boot service runs before bluetoothd - nothing to restart there.
    restart = not auto or bluetooth_active()
    if restart:
        subprocess.run(["systemctl", "stop", "bluetooth"], check=False)
    try:
        for p in plans:
            write_plan(p, stamp)
            ok(f"{p.dev.mac} {p.name}: written" + (f" (backup: info.bak-{stamp})" if p.exists else ""))
        save_state(new_state)
    finally:
        if restart:
            subprocess.run(["systemctl", "start", "bluetooth"], check=False)
    if restart:
        ok("bluetooth service restarted")
    if not auto:
        info("switch the device on - it should connect by itself\n"
             "    (or: bluetoothctl connect " + plans[0].dev.mac + ")")


def main():
    ap = argparse.ArgumentParser(
        description="Copy Bluetooth pairing keys from Windows to Linux (BlueZ) on a dual-boot machine.",
        epilog="Typical use: run --install once, then pair devices only in Windows and reboot "
               "into Linux - keys are copied at boot before Bluetooth starts.")
    ap.add_argument("--list", action="store_true", help="only show what would change, change nothing")
    ap.add_argument("-y", "--yes", action="store_true", help="apply without asking")
    ap.add_argument("-d", "--device", action="append", default=[], metavar="MAC",
                    help="only this device (copy even if unchanged in Windows); "
                         "adds it to Linux if it is missing there; can be repeated")
    ap.add_argument("--windows", metavar="DEV|DIR",
                    help="Windows partition or directory (with --install: passed on to the service)")
    ap.add_argument("--hive", metavar="FILE", help="read the SYSTEM hive file directly")
    ap.add_argument("--auto", action="store_true",
                    help="service mode: no questions, only what changed in Windows")
    ap.add_argument("--install", action="store_true", help="install the auto-copy service")
    ap.add_argument("--uninstall", action="store_true", help="remove the auto-copy service")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    try:
        wanted = {norm_mac(m) for m in args.device}
    except ValueError as e:
        die(f"doesn't look like a MAC address: {e}")

    if os.geteuid() != 0:
        # Without a terminal sudo can't ask for a password - use a polkit window (pkexec) then
        try:
            os.close(os.open("/dev/tty", os.O_RDWR))
            elevate = "sudo"
        except OSError:
            elevate = "pkexec"
        os.execvp(elevate, [elevate, sys.executable, os.path.realpath(__file__), *sys.argv[1:]])

    if not args.list and not shutil.which("systemctl"):
        die("systemctl not found: without systemd only --list works")

    if args.install:
        install(args)
    elif args.uninstall:
        uninstall()
    else:
        sync(args, wanted)


if __name__ == "__main__":
    main()
