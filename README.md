# bt-dualboot-sync

Use the same Bluetooth headphones (keyboard, mouse, phone…) in Windows and Linux on a dual-boot machine without pairing them again every time you switch systems.

The script reads the pairing keys from the Windows registry and writes them into BlueZ. Installed as a systemd service, it does this at every boot, **before** Bluetooth starts, so you only ever pair in Windows.

## The problem

When a device is paired, it and the computer agree on a secret link key, and the device stores that key under the MAC address of the computer's Bluetooth adapter. Windows and Linux share the adapter, so to the device they are one computer that should have one key. Pair in Windows and the key Linux has becomes invalid. Pair in Linux and the Windows key becomes invalid.

The fix is to pair in Windows and give Linux the same key. The [Arch Wiki](https://wiki.archlinux.org/title/Bluetooth#Dual_boot_pairing) explains how to do that by hand. This script automates it.

## Why the copy happens before Bluetooth starts

Some devices punish a wrong key. HUAWEI FreeLace Pro 2 headphones make a single connection attempt with an outdated key and then delete their pairing with the computer. After that no key works and only a new pairing helps (confirmed with `btmon`). They also connect on their own as soon as they are switched on, so copying the key by hand after logging in is already too late.

That's why the service runs at boot before `bluetooth.service`, while the adapter is still off and nothing can connect. It runs again after resume from hibernation, in case Windows was booted in between.

## Features

- **Automatic.** A systemd service copies changed keys at boot, before Bluetooth starts, and after resume from hibernation.
- **Finds Windows by itself.** It mounts the partition read-only and unmounts it right away. You don't need to mount Windows or know the device name, which matters because NVMe names can change between boots.
- **Doesn't overwrite what you paired in Linux.** It remembers fingerprints of the Windows keys and copies a device automatically only after the device was re-paired in Windows.
- **Careful with BlueZ files.** It changes only the key lines of an `info` file and saves a backup next to it first.
- **Bluetooth Classic (BR/EDR) and Bluetooth LE.** LE keys are converted following the Arch Wiki.
- **No dependencies beyond Python and standard system tools.** The registry hive parser is built in, so `chntpw` and `hivex` aren't needed.
- **Shows before it changes.** `--list` shows what would change without touching anything.

## Requirements

- Linux with systemd and BlueZ
- Python 3.7+
- util-linux (`lsblk`, `mount`) and NTFS read support: the kernel `ntfs3` driver or `ntfs-3g`
- Windows 10 or 11 on an NTFS partition without BitLocker (see [Limitations](#limitations))
- The same Bluetooth adapter in both systems, which is the case for dual boot on one machine

## Installation

```sh
git clone https://github.com/Dm1stry/bt-dualboot-sync.git
cd bt-dualboot-sync
./bt-dualboot-sync.py --install
```

`--install` does the following:

1. Copies the script to `/usr/local/sbin/bt-dualboot-sync`.
2. Installs and enables two systemd units.
3. Records the current Windows keys as a baseline. Nothing is changed on this first run.

The script gets root by itself through `sudo`, or through `pkexec` when there is no terminal.

If there are several Windows installations, or you want a fixed partition, pass it to the service: `--install --windows /dev/disk/by-uuid/XXXX`. Use a stable path like this one, because names such as `/dev/nvme0n1p3` can change between boots. After updating the script, run `--install` again with the same options.

## Usage

### Bluetooth Classic devices (most headphones and speakers)

1. Boot Windows and pair the device. If it was paired before, remove it first, then pair again. Check that it works.
2. Reboot into Linux. The key is copied before Bluetooth starts. Switch the device on and it connects.

If the device was never paired in Linux, it is skipped with the note `not in Linux`. Add it once with `bt-dualboot-sync --device AA:BB:CC:DD:EE:FF`, and keep the device switched off while you do. Alternatively, pair it in Linux before step 1.

### Bluetooth LE devices (many mice and keyboards)

An LE device has to exist in Linux before its keys can be copied, because BlueZ needs details that Windows doesn't store, such as the address type.

1. Pair the device in Linux.
2. Boot Windows and pair it there.
3. Reboot into Linux.

### Afterwards

Re-pair only in Windows. Windows doesn't know about a pairing made in Linux and keeps connecting with its old key. Devices like the FreeLace then drop the pairing altogether, including the one with Linux.

### Example

```
$ bt-dualboot-sync

Windows
  ✓ registry hive: /dev/nvme0n1p3 (mounted read-only and unmounted)

Adapter AA:BB:CC:DD:EE:FF
  · keys in Windows last changed 2026-10-08 22:35
  · 11:22:33:44:55:66  AirPods Pro                  BR/EDR    not in Linux (to add: --device 11:22:33:44:55:66)
  · C0:FF:EE:00:00:01  BT5.0MOUSE2                  LE        LE only: pair it in Linux first, then in Windows
  → 33:44:55:66:77:88  HUAWEI FreeLace Pro 2        BR/EDR    will be updated (LinkKey.Key)
  ✓ 22:33:44:55:66:77  Phone                        BR/EDR    matches
  ✓ D2:33:44:55:66:77  Phone                        LE        matches

Summary
  Write Windows keys for 1 device(s) and restart bluetooth? [y/N] y
  ✓ 33:44:55:66:77:88 HUAWEI FreeLace Pro 2: written (backup: info.bak-20261009-161549)
  ✓ bluetooth service restarted
  · switch the device on - it should connect by itself
    (or: bluetoothctl connect 33:44:55:66:77:88)
```

### Options

| Command | What it does |
|---|---|
| `bt-dualboot-sync` | Show what would change, ask, then apply |
| `bt-dualboot-sync --list` | Only show, change nothing |
| `bt-dualboot-sync --yes` | Apply without asking |
| `bt-dualboot-sync --device MAC` | Only this device (repeatable). Copies even if the key didn't change in Windows. Adds a Classic device that is missing in Linux |
| `bt-dualboot-sync --windows DEV\|DIR` | Use this Windows partition, or an already mounted Windows directory, instead of searching |
| `bt-dualboot-sync --hive FILE` | Read this `SYSTEM` registry hive file directly |
| `bt-dualboot-sync --install [--windows DEV]` | Install the service. `--windows` is passed on to it |
| `bt-dualboot-sync --uninstall` | Remove the service. The key history stays |
| `bt-dualboot-sync --auto` | Service mode: no questions, only devices whose Windows key changed |

## How it works

- **Windows side.** The keys are in the `SYSTEM` hive under `ControlSet00X\Services\BTHPORT\Parameters\Keys\<adapter>`. A Classic device is a `REG_BINARY` value holding the link key. An LE device is a subkey with `LTK`, `ERand`, `EDIV`, `IRK` and other values. Device names come from `...\Parameters\Devices`.
- **Linux side.** Keys go into `/var/lib/bluetooth/<adapter>/<device>/info`, with `info.bak-<timestamp>` saved next to it first. bluetoothd reads keys only at startup and may overwrite these files while running, so a running bluetoothd is stopped for the edit and started again.
- **History.** `/var/lib/bt-dualboot-sync/state.json` keeps a short SHA-256 fingerprint of each device's Windows keys, not the keys themselves. The service copies a device only when its fingerprint changed, which means the device was re-paired in Windows. If the Windows key didn't change but Linux has a different one, the device was probably paired in Linux, so it is left alone. Without history (the first run) the service only records fingerprints.
- **Units.** `bt-dualboot-sync.service` runs once per boot before `bluetooth.service`. `bt-dualboot-sync-resume.service` runs after resume from hibernation.

## Limitations

- **BitLocker.** An encrypted partition isn't unlocked automatically. Windows 11 turns on device encryption by default on many new laptops, so check with `lsblk -f`. To unlock by hand:
  ```sh
  sudo cryptsetup bitlkOpen /dev/nvme0n1p3 win   # asks for the recovery key
  bt-dualboot-sync --windows /dev/mapper/win
  ```
  For the boot service the volume would have to be unlocked at boot already, for example through `/etc/crypttab` with the `bitlk` option and a key file. That is untested, and keeping the recovery key on the Linux disk weakens the encryption.
- **Fast Startup and registry logs.** Turn off Fast Startup in Windows (Control Panel → Power Options → Choose what the power buttons do). It's a common dual-boot recommendation anyway. The script reads only the main `SYSTEM` file and doesn't replay the registry transaction logs (`SYSTEM.LOG1`, `SYSTEM.LOG2`). If Windows hasn't merged a fresh key into the main file yet, the script reads the old key. It warns when the hive is marked as not fully saved. If a device doesn't connect after a copy, boot Windows and leave it with Restart: a restart is always a full shutdown.
- **Several Windows installations.** The first NTFS partition with a Windows registry is used. Pass `--windows`, also together with `--install`.
- **systemd only.** Without systemd only `--list` works.
- **Different adapter address.** Some adapters report a different MAC address in Windows and in Linux. Keys are tied to that address, so such an adapter is skipped with a warning.
- **Resume from hibernation.** bluetoothd is already running after resume, a couple of seconds before the resume service. A device that connects in that window with the old key may still drop its pairing. A fresh boot into Linux is the reliable path.
- **LE is lightly tested.** The LE conversion follows the Arch Wiki table but has seen little real-world use. Bluetooth Classic is tested.

## Troubleshooting

- **Log:** `journalctl -u bt-dualboot-sync -b`, and `-u bt-dualboot-sync-resume` for resume.
- **"differs, but unchanged in Windows since the last run":** the device was most likely paired in Linux. To copy the Windows key anyway, use `--device MAC`.
- **Undo a change:** as root, copy `info.bak-<timestamp>` back over `info` in `/var/lib/bluetooth/<adapter>/<device>/`, then `systemctl restart bluetooth`.
- **The device still rejects the key:** it may have dropped its pairing after an attempt with the old key. Remove it in Windows, pair again, and reboot straight into Linux. `sudo btmon` shows what the device answers: `Pairing Not Allowed` right after the link key reply means the device no longer has a key for this computer.

## Tested on

- Fedora 44, Lenovo ThinkBook 14 G6+ AHP with a MediaTek Bluetooth adapter (USB `0489:e0cd`), Windows 11, `ntfs-3g`
- HUAWEI FreeLace Pro 2 (Classic): the key was copied automatically at boot several times, and the headphones connected right away
- Registry parser: checked byte for byte against [regipy](https://github.com/mkorman90/regipy) on about 35,000 values from five real Windows hives

Reports from other hardware are welcome. Please open an issue with the output of `bt-dualboot-sync --list`; it contains no keys, and you can mask the MAC addresses.

## Development

The tests use a synthetic registry hive and a temporary `/var/lib/bluetooth`. They need neither root nor Bluetooth:

```sh
python3 -m unittest discover -s tests
```

## Similar projects

- [bt-dualboot](https://github.com/x2es/bt-dualboot) is a command-line tool based on `chntpw` that you run by hand, with the Windows partition mounted beforehand. bt-dualboot-sync differs mainly in running automatically before Bluetooth starts, finding and mounting Windows itself, and leaving devices paired in Linux alone.
- [Arch Wiki: Dual boot pairing](https://wiki.archlinux.org/title/Bluetooth#Dual_boot_pairing) describes the manual procedure and the LE key conversion.

## Uninstall

```sh
sudo bt-dualboot-sync --uninstall
sudo rm -r /var/lib/bt-dualboot-sync       # key history, optional
```

The `info.bak-*` backups stay in `/var/lib/bluetooth/` until you delete them.

## License

[MIT](LICENSE)
