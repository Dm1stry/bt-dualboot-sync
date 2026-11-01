"""Tests for bt-dualboot-sync: a synthetic Windows registry hive and a fake
/var/lib/bluetooth in a temporary directory. No root, no real Bluetooth.

Run: python3 -m unittest discover -s tests
"""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "bt-dualboot-sync.py")
spec = importlib.util.spec_from_file_location("bt_dualboot_sync", SCRIPT)
bds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bds)

NO_CELL = 0xFFFFFFFF
ADAPTER = "AA:BB:CC:DD:EE:FF"
HEADPHONES = "11:22:33:44:55:66"   # Bluetooth Classic
MOUSE = "C0:FF:EE:00:00:01"        # Bluetooth LE

BR_KEY = bytes(range(16))
LTK = bytes(range(0x10, 0x20))
IRK = bytes(range(0x20, 0x30))
ERAND = 0x1122334455667788
EDIV = 0x1234


def hexname(mac):
    return mac.replace(":", "").lower()


class HiveBuilder:
    """Writes a minimal regf hive: just enough for the script's parser."""

    def __init__(self):
        self.bins = bytearray(b"hbin" + bytes(28))

    def cell(self, payload):
        size = (len(payload) + 4 + 7) & ~7
        off = len(self.bins)
        self.bins += struct.pack("<i", -size) + payload + bytes(size - 4 - len(payload))
        return off

    def value(self, name, vtype, data):
        nb = name.encode("latin-1")
        if len(data) <= 4:
            dsize, doff = len(data) | 0x80000000, int.from_bytes(data.ljust(4, b"\0"), "little")
        else:
            dsize, doff = len(data), self.cell(data)
        return self.cell(b"vk" + struct.pack("<HIIIHH", len(nb), dsize, doff, vtype, 1, 0) + nb)

    def key(self, name, values=None, children=(), mtime=0):
        subs = [self.key(*c) for c in children]
        vals = [self.value(n, t, d) for n, (t, d) in (values or {}).items()]
        sublist = self.cell(b"lh" + struct.pack("<H", len(subs))
                            + b"".join(struct.pack("<II", o, 0) for o in subs)) if subs else NO_CELL
        vallist = self.cell(b"".join(struct.pack("<I", o) for o in vals)) if vals else NO_CELL
        nb = name.encode("latin-1")
        nk = bytearray(0x4C)
        nk[0:2] = b"nk"
        struct.pack_into("<HQ", nk, 2, 0x20, mtime)
        struct.pack_into("<II", nk, 0x14, len(subs), 0)
        struct.pack_into("<I", nk, 0x1C, sublist)
        struct.pack_into("<II", nk, 0x24, len(vals), vallist)
        struct.pack_into("<H", nk, 0x48, len(nb))
        return self.cell(bytes(nk) + nb)

    def hive(self, root, seq=(1, 1)):
        base = bytearray(0x1000)
        base[0:4] = b"regf"
        struct.pack_into("<II", base, 4, *seq)
        struct.pack_into("<I", base, 0x24, root)
        return bytes(base) + bytes(self.bins)


def make_hive(br_key=BR_KEY, seq=(1, 1)):
    B, D, Q = bds.REG_BINARY, bds.REG_DWORD, bds.REG_QWORD
    mouse = (hexname(MOUSE), {
        "LTK": (B, LTK),
        "KeyLength": (D, struct.pack("<I", 16)),
        "ERand": (Q, struct.pack("<Q", ERAND)),
        "EDIV": (D, struct.pack("<I", EDIV)),
        "IRK": (B, IRK),
        "Address": (Q, struct.pack("<Q", int(hexname(MOUSE), 16))),
        "AuthReq": (D, struct.pack("<I", 0x2D)),
    })
    adapter = (hexname(ADAPTER), {
        hexname(HEADPHONES): (B, br_key),
        "MasterIRK": (B, bytes(16)),          # not a device - must be ignored
    }, [mouse], 132000000000000000)
    devices = ("Devices", None, [
        (hexname(HEADPHONES), {"Name": (B, b"Test Headphones\0")}),
        (hexname(MOUSE), {"Name": (B, b"Test Mouse\0")}),
    ])
    params = ("Parameters", None, [devices, ("Keys", None, [adapter])])
    tree = ("ROOT", None, [
        ("Select", {"Current": (D, struct.pack("<I", 1))}),
        ("ControlSet001", None, [("Services", None, [("BTHPORT", None, [params])])]),
    ])
    b = HiveBuilder()
    return b.hive(b.key(*tree), seq)


HEADPHONES_INFO = """\
[General]
Name=Test Headphones
Trusted=true
Blocked=false

[LinkKey]
Key=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
Type=5
PINLength=0
"""

MOUSE_INFO = """\
[General]
Name=Test Mouse
AddressType=static

[LongTermKey]
Key=00000000000000000000000000000000
Authenticated=1
EncSize=16
EDiv=0
Rand=0
"""


class HiveParserTest(unittest.TestCase):
    def test_reads_classic_and_le_keys(self):
        adapters = bds.read_windows(bds.Hive(make_hive()))
        self.assertEqual(list(adapters), [ADAPTER])
        _, devices = adapters[ADAPTER]
        self.assertEqual(sorted(devices), [HEADPHONES, MOUSE])   # MasterIRK skipped
        self.assertEqual(devices[HEADPHONES].link_key, BR_KEY)
        self.assertEqual(devices[HEADPHONES].name, "Test Headphones")
        self.assertIsNone(devices[HEADPHONES].le)
        self.assertEqual(devices[MOUSE].le["ltk"][1], LTK)
        self.assertIsNone(devices[MOUSE].le_addr)

    def test_dirty_hive(self):
        self.assertFalse(bds.Hive(make_hive()).dirty)
        self.assertTrue(bds.Hive(make_hive(seq=(5, 4))).dirty)

    def test_not_a_hive(self):
        with self.assertRaises(bds.HiveError):
            bds.Hive(bytes(0x2000))


class KeyFileTest(unittest.TestCase):
    def test_untouched_lines_stay(self):
        kf = bds.KeyFile(HEADPHONES_INFO)
        bds.apply_link_key(kf, BR_KEY)
        self.assertEqual(kf.changed, ["LinkKey.Key"])            # Type=5 is kept
        self.assertEqual(kf.text(), HEADPHONES_INFO.replace("F" * 32, BR_KEY.hex().upper()))

    def test_le_conversion(self):
        kf = bds.KeyFile(MOUSE_INFO)
        le = bds.read_windows(bds.Hive(make_hive()))[ADAPTER][1][MOUSE].le
        bds.apply_le(kf, le)
        self.assertEqual(kf.get("LongTermKey", "Key"), LTK.hex().upper())
        self.assertEqual(kf.get("LongTermKey", "Rand"), str(ERAND))
        self.assertEqual(kf.get("LongTermKey", "EDiv"), str(EDIV))
        self.assertEqual(kf.get("LongTermKey", "Authenticated"), "1")   # kept
        self.assertEqual(kf.get("IdentityResolvingKey", "Key"), IRK.hex().upper())

    def test_irk_in_reverse_order_is_kept(self):
        kf = bds.KeyFile(MOUSE_INFO + f"\n[IdentityResolvingKey]\nKey={IRK[::-1].hex().upper()}\n")
        bds.apply_le(kf, {"irk": (bds.REG_BINARY, IRK)})
        self.assertEqual(kf.changed, [])


class SyncTest(unittest.TestCase):
    """The whole run, with systemctl and the paths replaced."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.bt_dir = os.path.join(root, "bluetooth")
        self.hive = os.path.join(root, "SYSTEM")
        self.calls = []
        for dev, text in ((HEADPHONES, HEADPHONES_INFO), (MOUSE, MOUSE_INFO)):
            os.makedirs(os.path.join(self.bt_dir, ADAPTER, dev))
            with open(self.info(dev), "w") as f:
                f.write(text)

        def fake_run(cmd, *a, **kw):
            self.calls.append(cmd)
            inactive = cmd[:2] == ["systemctl", "is-active"]   # boot: bluetoothd not started yet
            return subprocess.CompletedProcess(cmd, 3 if inactive else 0, "", "")

        for patch in (mock.patch.object(bds, "BT_DIR", self.bt_dir),
                      mock.patch.object(bds, "STATE_FILE", os.path.join(root, "state", "state.json")),
                      mock.patch.object(bds.subprocess, "run", fake_run)):
            patch.start()
            self.addCleanup(patch.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def info(self, dev):
        return os.path.join(self.bt_dir, ADAPTER, dev, "info")

    def read(self, dev):
        with open(self.info(dev)) as f:
            return f.read()

    def run_sync(self, br_key=BR_KEY, auto=True, devices=(), **kw):
        with open(self.hive, "wb") as f:
            f.write(make_hive(br_key))
        opts = dict(hive=self.hive, windows=None, list=False, yes=False, auto=auto, device=list(devices))
        opts.update(kw)
        args = argparse.Namespace(**opts)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bds.sync(args, set(devices))
        return out.getvalue()

    def test_service_flow(self):
        # 1. First run without history: only remembers, changes nothing
        self.run_sync()
        self.assertEqual(self.read(HEADPHONES), HEADPHONES_INFO)
        self.assertEqual(self.read(MOUSE), MOUSE_INFO)
        with open(bds.STATE_FILE) as f:
            self.assertEqual(len(json.load(f)), 2)

        # 2. Windows unchanged, Linux differs (paired in Linux): left alone
        self.run_sync()
        self.assertEqual(self.read(HEADPHONES), HEADPHONES_INFO)

        # 3. Re-paired in Windows: the new key is copied, a backup is made
        new_key = bytes(range(100, 116))
        self.run_sync(br_key=new_key)
        self.assertIn(f"Key={new_key.hex().upper()}\n", self.read(HEADPHONES))
        self.assertEqual(self.read(MOUSE), MOUSE_INFO)           # mouse unchanged in Windows
        backups = [n for n in os.listdir(os.path.dirname(self.info(HEADPHONES))) if n.startswith("info.bak-")]
        self.assertEqual(len(backups), 1)
        # bluetoothd wasn't running - nothing to stop or start
        self.assertNotIn(["systemctl", "stop", "bluetooth"], self.calls)

    def test_device_forces_copy_and_restarts_bluetooth(self):
        self.run_sync()                                          # baseline
        self.run_sync(auto=False, devices=[HEADPHONES], yes=True)
        self.assertIn(f"Key={BR_KEY.hex().upper()}\n", self.read(HEADPHONES))
        self.assertEqual(self.read(MOUSE), MOUSE_INFO)
        self.assertIn(["systemctl", "stop", "bluetooth"], self.calls)
        self.assertIn(["systemctl", "start", "bluetooth"], self.calls)

    def test_device_adds_missing_classic_device(self):
        os.remove(self.info(HEADPHONES))
        self.run_sync(auto=False, yes=True)
        self.assertFalse(os.path.exists(self.info(HEADPHONES)))  # not without --device
        self.run_sync(auto=False, devices=[HEADPHONES], yes=True)
        text = self.read(HEADPHONES)
        self.assertIn("Name=Test Headphones\n", text)
        self.assertIn(f"Key={BR_KEY.hex().upper()}\n", text)

    def test_list_changes_nothing(self):
        self.run_sync(auto=False, devices=[HEADPHONES], list=True)
        self.assertEqual(self.read(HEADPHONES), HEADPHONES_INFO)
        self.assertFalse(os.path.exists(bds.STATE_FILE))


class UnitQuoteTest(unittest.TestCase):
    def test_escapes(self):
        self.assertEqual(bds.unit_quote("/dev/disk/by-label/My\\x20Disk%"),
                         '"/dev/disk/by-label/My\\\\x20Disk%%"')


if __name__ == "__main__":
    unittest.main()
