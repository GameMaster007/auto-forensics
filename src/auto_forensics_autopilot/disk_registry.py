"""What the registry hives copied from a disk image say about devices, files, programs and accounts.

Each ``_read_*`` function reads one group of keys from one hive and
returns ``Record`` objects whose locator is the key or value they came
from. ``parse_hive`` picks the functions for a hive by its file name and
runs each one on its own, so a damaged key costs one group of records,
not the hive.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Callable, Iterator

from .disk_parsers import (
    MAX_RECORDS_PER_FILE,
    Hive,
    ParseBudget,
    ParseError,
    Record,
    RegKey,
    clean_text,
    filetime_iso,
    rot13,
    shell_path,
    unix_iso,
    utf16,
    walk_keys,
)
from .disk_parsers import _idlist_size as idlist_size
from .disk_parsers import _item_name as item_name

MAX_GROUP_RECORDS = 5_000
EXPLORER = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
_DEVICE_TIMES = "{83da6326-97a6-4088-9453-a1923f573b29}"
_USB_DEVICE = re.compile(r"USBSTOR#(?P<kind>[A-Za-z]+)&Ven_(?P<vendor>[^&#]*)&Prod_(?P<product>[^&#]*)(&Rev_(?P<rev>[^&#]*))?"
                         r"#(?P<serial>[^#]+)#", re.IGNORECASE)
_OFFICE_MRU = re.compile(r"^\[F[0-9A-Fa-f]{8}\]\[T(?P<time>[0-9A-Fa-f]{16})\](\[O[0-9A-Fa-f]{8}\])?\*(?P<path>.+)$")

# Registry keys that show a program was installed or configured. The path
# is below HKLM\SOFTWARE for the SOFTWARE hive and below HKCU\Software for
# NTUSER.DAT. The label is one of the program names in
# ``disk_artifacts.WATCHLIST``.
PROGRAM_KEYS: tuple[tuple[str, str], ...] = (
    ("Google Drive", "Google\\Drive"),
    ("Google Drive", "Google\\DriveFS"),
    ("Dropbox", "Dropbox"),
    ("Dropbox", "Dropbox\\ks"),
    ("OneDrive", "Microsoft\\OneDrive"),
    ("OneDrive", "Microsoft\\SkyDrive"),
    ("iCloud", "Apple Inc.\\Internet Services"),
    ("iCloud", "Apple Inc.\\iCloud"),
    ("Box", "Box\\Box"),
    ("MEGA", "MEGA Limited"),
    ("pCloud", "pCloud"),
    ("CCleaner", "Piriform\\CCleaner"),
    ("Eraser", "Eraser"),
    ("Eraser", "Eraser\\Eraser 6"),
    ("BleachBit", "BleachBit"),
    ("SDelete", "Sysinternals\\SDelete"),
    ("BCWipe", "Jetico\\BCWipe"),
    ("Privazer", "PrivaZer"),
    ("WinRAR", "WinRAR"),
    ("7-Zip", "7-Zip"),
    ("TrueCrypt", "TrueCrypt"),
    ("VeraCrypt", "VeraCrypt"),
    ("Thunderbird", "Mozilla\\Mozilla Thunderbird"),
    ("Thunderbird", "Mozilla\\Thunderbird"),
    ("TeamViewer", "TeamViewer"),
    ("FileZilla", "FileZilla Client"),
    ("WinSCP", "Martin Prikryl\\WinSCP 2"),
)


def _rec(kind: str, when: str | None, locator: str, **fields: object) -> Record:
    return Record(kind, when, {name: value for name, value in fields.items() if value not in (None, "")}, locator)


def _control_set(hive: Hive) -> RegKey | None:
    select = hive.open("Select")
    number = None
    if select is not None:
        current = select.value("Current")
        number = current.number if current is not None else None
    for name in ([f"ControlSet{number:03d}"] if number else []) + ["ControlSet001", "ControlSet002"]:
        key = hive.open(name)
        if key is not None:
            return key
    return None


def _usb_parts(text: str) -> dict[str, str]:
    """Vendor, product, revision and serial from a ``USBSTOR#Disk&Ven_...#serial#`` device string."""
    found = _USB_DEVICE.search(text.replace("\\", "#") + "#")
    if not found:
        return {}
    serial = found["serial"]
    return {"vendor": clean_text(found["vendor"], 64), "product": clean_text(found["product"], 64),
            "revision": clean_text(found["rev"] or "", 16), "serial": clean_text(serial.split("&")[0] if
                                                                                  len(serial) > 2 and serial[1] != "&"
                                                                                  else serial, 80),
            # Windows invents an identifier when the stick has no serial; its second character is "&".
            "serial_is_unique": len(serial) > 2 and serial[1] != "&"}


def _device_property_time(instance: RegKey, number: int) -> str | None:
    properties = instance.open(f"Properties\\{_DEVICE_TIMES}")
    if properties is None:
        return None
    for name in (f"{number:04X}", f"{number:08X}"):
        key = properties.subkey(name)
        if key is None:
            continue
        for holder in (key, key.subkey("00000000")):
            if holder is None:
                continue
            for value in holder.values():
                if len(value.data) == 8 and value.name in ("", "Data"):
                    return filetime_iso(struct.unpack("<Q", value.data)[0])
    return None


# --------------------------------------------------------------------------
# SYSTEM
# --------------------------------------------------------------------------


def _read_system_facts(hive: Hive) -> Iterator[Record]:
    control = _control_set(hive)
    if control is None:
        return
    zone = control.open("Control\\TimeZoneInformation")
    if zone is not None:
        name = zone.value("TimeZoneKeyName") or zone.value("StandardName")

        def minutes(value_name: str) -> int | None:
            value = zone.value(value_name)
            number = value.number if value is not None else None
            # Stored unsigned; zones east of Greenwich have a negative bias.
            return number - 0x100000000 if number is not None and number > 0x7FFFFFFF else number

        yield _rec("system_fact", zone.time, (name or zone).locator, fact="time_zone",
                   value=name.text if name is not None else "", bias_minutes=minutes("Bias"),
                   active_bias_minutes=minutes("ActiveTimeBias"))
    windows = control.open("Control\\Windows")
    shutdown = windows.value("ShutdownTime") if windows is not None else None
    if shutdown is not None and len(shutdown.data) == 8:
        yield _rec("system_fact", filetime_iso(struct.unpack("<Q", shutdown.data)[0]), shutdown.locator,
                   fact="last_shutdown")
    computer = control.open("Control\\ComputerName\\ComputerName")
    name = computer.value("ComputerName") if computer is not None else None
    if name is not None:
        yield _rec("system_fact", computer.time, name.locator, fact="computer_name", value=name.text)


def _read_usbstor(hive: Hive) -> Iterator[Record]:
    control = _control_set(hive)
    root = control.open("Enum\\USBSTOR") if control is not None else None
    if root is None:
        return
    for device in root.subkeys():
        for instance in device.subkeys():
            parts = _usb_parts(f"USBSTOR#{device.name}#{instance.name}#")
            yield _rec("usb_device", instance.time, instance.locator, source="USBSTOR", device_class=device.name,
                       friendly_name=instance.text("FriendlyName"), parent_id_prefix=instance.text("ParentIdPrefix"),
                       container_id=instance.text("ContainerID"),
                       first_install=_device_property_time(instance, 0x65) or _device_property_time(instance, 0x64),
                       last_arrival=_device_property_time(instance, 0x66),
                       last_removal=_device_property_time(instance, 0x67), **parts)


def _read_usb_enum(hive: Hive) -> Iterator[Record]:
    control = _control_set(hive)
    root = control.open("Enum\\USB") if control is not None else None
    if root is None:
        return
    for device in root.subkeys():
        ids = re.match(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", device.name)
        if not ids:
            continue
        for instance in device.subkeys():
            if instance.text("Service").upper() != "USBSTOR":
                continue
            yield _rec("usb_bus_device", instance.time, instance.locator, vendor_id=ids[1].upper(),
                       product_id=ids[2].upper(), serial=clean_text(instance.name, 80))


def _read_mounted_devices(hive: Hive) -> Iterator[Record]:
    key = hive.open("MountedDevices")
    if key is None:
        return
    for value in key.values():
        data = value.data
        mount = value.name.replace("\\DosDevices\\", "").replace("\\??\\", "")
        text = utf16(data, 400) if len(data) > 24 and data[1:2] == b"\0" else ""
        if text:
            yield _rec("mounted_device", key.time, value.locator, mount=clean_text(mount, 64), device=text,
                       is_usb="USBSTOR#" in text.upper(), is_optical="CDROM" in text.upper(), **_usb_parts(text))
        elif len(data) == 12:
            signature, offset = struct.unpack("<IQ", data)
            yield _rec("mounted_device", key.time, value.locator, mount=clean_text(mount, 64),
                       device=f"disk signature {signature:08X}, partition offset {offset}", is_usb=False)


def _read_usb_labels(hive: Hive) -> Iterator[Record]:
    control = _control_set(hive)
    root = control.open("Enum\\WpdBusEnumRoot\\UMB") if control is not None else None
    if root is not None:
        for device in root.subkeys():
            parts = _usb_parts(device.name)
            if parts:
                yield _rec("usb_volume_name", device.time, device.locator, source="WpdBusEnumRoot",
                           volume_name=device.text("FriendlyName"), **parts)
    classes = control.open("Control\\DeviceClasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}") if control else None
    if classes is not None:
        for device in classes.subkeys():
            parts = _usb_parts(device.name)
            if parts:
                yield _rec("usb_connection", device.time, device.locator, source="DeviceClasses", **parts)


def _read_optical_drives(hive: Hive) -> Iterator[Record]:
    control = _control_set(hive)
    for bus in ("IDE", "SCSI"):
        root = control.open(f"Enum\\{bus}") if control is not None else None
        if root is None:
            continue
        for device in root.subkeys():
            if not device.name.lower().startswith("cdrom"):
                continue
            for instance in device.subkeys():
                yield _rec("optical_drive", instance.time, instance.locator, bus=bus,
                           device_class=clean_text(device.name, 200), friendly_name=instance.text("FriendlyName"))


# --------------------------------------------------------------------------
# SOFTWARE
# --------------------------------------------------------------------------


def _read_os_facts(hive: Hive) -> Iterator[Record]:
    key = hive.open("Microsoft\\Windows NT\\CurrentVersion")
    if key is None:
        return
    install = key.value("InstallDate")
    if install is not None and install.number:
        yield _rec("system_fact", unix_iso(install.number), install.locator, fact="os_install_date")
    product = key.value("ProductName")
    if product is not None:
        yield _rec("system_fact", key.time, product.locator, fact="os_version", value=product.text,
                   build=key.text("CurrentBuildNumber") or key.text("CurrentBuild"),
                   service_pack=key.text("CSDVersion"))
    owner = key.value("RegisteredOwner")
    if owner is not None and owner.text:
        yield _rec("system_fact", key.time, owner.locator, fact="registered_owner", value=owner.text)


def _read_profiles(hive: Hive) -> Iterator[Record]:
    key = hive.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
    if key is None:
        return
    for profile in key.subkeys():
        path = profile.text("ProfileImagePath")
        if path:
            yield _rec("user_profile", profile.time, profile.locator, sid=clean_text(profile.name, 80), path=path)


def _read_uninstall(hive: Hive, base: str = "") -> Iterator[Record]:
    for prefix in ("Microsoft", "Wow6432Node\\Microsoft"):
        key = hive.open(f"{base}{prefix}\\Windows\\CurrentVersion\\Uninstall")
        if key is None:
            continue
        for program in key.subkeys():
            name = program.text("DisplayName")
            if not name:
                continue
            yield _rec("installed_program", program.time, program.locator, name=name,
                       version=program.text("DisplayVersion"), publisher=program.text("Publisher"),
                       install_date=program.text("InstallDate"), location=program.text("InstallLocation"),
                       key_name=clean_text(program.name, 120))


def _read_run_keys(hive: Hive, base: str = "") -> Iterator[Record]:
    for prefix in ("Microsoft", "Wow6432Node\\Microsoft"):
        for name in ("Run", "RunOnce"):
            key = hive.open(f"{base}{prefix}\\Windows\\CurrentVersion\\{name}")
            if key is None:
                continue
            for value in key.values():
                if value.text:
                    yield _rec("autorun", key.time, value.locator, name=clean_text(value.name, 120),
                               command=value.text, run_key=name)


def _read_portable_devices(hive: Hive) -> Iterator[Record]:
    key = hive.open("Microsoft\\Windows Portable Devices\\Devices")
    if key is not None:
        for device in key.subkeys():
            parts = _usb_parts(device.name)
            name = device.text("FriendlyName")
            if parts or name:
                yield _rec("usb_volume_name", device.time, device.locator, source="Windows Portable Devices",
                           volume_name=name, **parts)
    boost = hive.open("Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt")
    if boost is not None:
        for device in boost.subkeys():
            parts = _usb_parts(device.name)
            tail = device.name.rsplit("}", 1)[-1]  # "<label>_<volume serial as decimal>"
            label, _, number = tail.rpartition("_")
            serial = ""
            if number.isdigit() and int(number) <= 0xFFFFFFFF:
                serial = f"{int(number) >> 16:04X}-{int(number) & 0xFFFF:04X}"
            if parts:  # ReadyBoost also tests internal disks; only USB sticks are of interest here
                yield _rec("usb_volume_name", device.time, device.locator, source="EMDMgmt",
                           volume_name=clean_text(label, 64), volume_serial=serial, **parts)


def _read_program_keys(hive: Hive, base: str = "") -> Iterator[Record]:
    for label, path in PROGRAM_KEYS:
        for prefix in ("", "Wow6432Node\\"):
            key = hive.open(f"{base}{prefix}{path}")
            if key is not None:
                yield _rec("program_key", key.time, key.locator, program=label, key_path=f"{base}{prefix}{path}")


def _read_mail_clients(hive: Hive) -> Iterator[Record]:
    key = hive.open("Clients\\Mail")
    if key is None:
        return
    default = key.value("")
    if default is not None and default.text:
        yield _rec("mail_client", key.time, default.locator, name=default.text, role="default mail client")
    for client in key.subkeys():
        yield _rec("mail_client", client.time, client.locator, name=clean_text(client.name, 120), role="registered")


# --------------------------------------------------------------------------
# NTUSER.DAT
# --------------------------------------------------------------------------


def _read_mount_points(hive: Hive) -> Iterator[Record]:
    key = hive.open(f"{EXPLORER}\\MountPoints2")
    if key is None:
        return
    for point in key.subkeys():
        name = point.name
        if name.startswith("##"):
            yield _rec("mount_point", point.time, point.locator, mount_type="network",
                       share="\\\\" + clean_text(name[2:].replace("#", "\\"), 300))
        elif name.startswith("{"):
            yield _rec("mount_point", point.time, point.locator, mount_type="volume", volume=clean_text(name, 64))
        elif len(name) == 1:
            yield _rec("mount_point", point.time, point.locator, mount_type="drive", drive=name.upper() + ":")


def _mru_order(key: RegKey) -> list[str]:
    value = key.value("MRUListEx")
    if value is None:
        return []
    data = value.data
    order = []
    for index in range(0, len(data) - 3, 4):
        number = struct.unpack_from("<I", data, index)[0]
        if number == 0xFFFFFFFF:
            break
        order.append(str(number))
    return order


def _read_recent_docs(hive: Hive) -> Iterator[Record]:
    root = hive.open(f"{EXPLORER}\\RecentDocs")
    if root is None:
        return
    for key in [root, *root.subkeys()]:
        order = _mru_order(key)
        newest = order[0] if order else None
        for value in key.values():
            if not value.name.isdigit():
                continue
            name = utf16(value.data)
            if not name:
                continue
            # Only the newest entry of a list has a time: the key's last write.
            yield _rec("recent_doc", key.time if value.name == newest else None, value.locator, name=name,
                       group=clean_text(key.name, 32) if key is not root else "all",
                       position=order.index(value.name) + 1 if value.name in order else None)


def _read_common_dialogs(hive: Hive) -> Iterator[Record]:
    base = hive.open(f"{EXPLORER}\\ComDlg32")
    if base is None:
        return
    for name in ("OpenSavePidlMRU", "OpenSaveMRU"):
        root = base.subkey(name)
        if root is None:
            continue
        for key in [root, *root.subkeys()]:
            order = _mru_order(key)
            newest = order[0] if order else None
            for value in key.values():
                if value.name in ("MRUListEx", "MRUList"):
                    continue
                path = shell_path(value.data) if name == "OpenSavePidlMRU" else utf16(value.data, 1024)
                if path:
                    yield _rec("open_save", key.time if value.name == newest else None, value.locator, path=path,
                               group=clean_text(key.name, 32) if key is not root else "all")
    for name in ("LastVisitedPidlMRU", "LastVisitedMRU"):
        key = base.subkey(name)
        if key is None:
            continue
        order = _mru_order(key)
        newest = order[0] if order else None
        for value in key.values():
            if value.name in ("MRUListEx", "MRUList"):
                continue
            data = value.data
            program = utf16(data, 260)
            rest = data[(len(program) + 1) * 2:]
            folder = shell_path(rest) if name == "LastVisitedPidlMRU" else utf16(rest, 1024)
            if program:
                yield _rec("last_visited", key.time if value.name == newest else None, value.locator,
                           program=program, folder=folder)


def _read_user_assist(hive: Hive) -> Iterator[Record]:
    root = hive.open(f"{EXPLORER}\\UserAssist")
    if root is None:
        return
    for group in root.subkeys():
        count = group.subkey("Count")
        if count is None:
            continue
        for value in count.values():
            name = rot13(value.name)
            data = value.data
            if name.startswith("UEME_CTL") or not name:
                continue
            if len(data) >= 68:  # Windows 7 and later
                runs, focus_count, focus_ms = struct.unpack_from("<III", data, 4)
                stamp = filetime_iso(struct.unpack_from("<Q", data, 60)[0])
            elif len(data) == 16:  # XP and Vista: the counter starts at 5
                runs = max(0, struct.unpack_from("<I", data, 4)[0] - 5)
                focus_ms = 0
                stamp = filetime_iso(struct.unpack_from("<Q", data, 8)[0])
            else:
                continue
            if not runs and not stamp:
                continue
            yield _rec("user_assist", stamp, value.locator, program=clean_text(name, 400), run_count=runs,
                       focus_seconds=focus_ms // 1000)


def _read_network_drives(hive: Hive) -> Iterator[Record]:
    key = hive.open("Network")
    if key is not None:
        for drive in key.subkeys():
            remote = drive.text("RemotePath")
            if remote:
                yield _rec("mapped_drive", drive.time, drive.locator, drive=clean_text(drive.name, 4).upper() + ":",
                           share=remote, user=drive.text("UserName"))
    mru = hive.open(f"{EXPLORER}\\Map Network Drive MRU")
    if mru is not None:
        for value in mru.values():
            if value.name != "MRUList" and value.text:
                yield _rec("mapped_drive", None, value.locator, share=value.text, source="Map Network Drive MRU")


def _read_typed(hive: Hive) -> Iterator[Record]:
    paths = hive.open(f"{EXPLORER}\\TypedPaths")
    if paths is not None:
        for value in paths.values():
            if value.text:
                yield _rec("typed_path", paths.time if value.name == "url1" else None, value.locator, path=value.text)
    urls = hive.open("Software\\Microsoft\\Internet Explorer\\TypedURLs")
    times = hive.open("Software\\Microsoft\\Internet Explorer\\TypedURLsTime")
    stamps = {}
    if times is not None:
        stamps = {v.name: filetime_iso(struct.unpack("<Q", v.data)[0]) for v in times.values() if len(v.data) == 8}
    if urls is not None:
        for value in urls.values():
            if value.text:
                when = stamps.get(value.name) or (urls.time if value.name == "url1" else None)
                yield _rec("typed_url", when, value.locator, url=value.text)
    search = hive.open(f"{EXPLORER}\\WordWheelQuery")
    if search is not None:
        order = _mru_order(search)
        for value in search.values():
            if value.name.isdigit():
                term = utf16(value.data, 300)
                if term:
                    yield _rec("explorer_search", search.time if order[:1] == [value.name] else None, value.locator,
                               term=term)
    run = hive.open(f"{EXPLORER}\\RunMRU")
    if run is not None:
        for value in run.values():
            if value.name != "MRUList" and value.text:
                yield _rec("run_command", None, value.locator, command=value.text.removesuffix("\\1"))


def _read_cd_burning(hive: Hive) -> Iterator[Record]:
    root = hive.open(f"{EXPLORER}\\CD Burning")
    if root is None:
        return
    staging = root.subkey("StagingInfo")
    if staging is not None:
        for volume in staging.subkeys():
            yield _rec("cd_burning", volume.time, volume.locator, what="staging folder",
                       staging_path=volume.text("StagingPath"), volume=clean_text(volume.name, 64))
    drives = root.subkey("Drives")
    if drives is not None:
        for volume in drives.subkeys():
            media = volume.subkey("Current Media")
            if media is None:
                continue
            label = media.text("Disc Label")
            total = media.value("TotalBytes")
            free = media.value("FreeBytes")
            live = media.value("Live FS")
            # Windows keeps "Current Media" for each optical drive: the last disc Explorer's burning code looked at.
            # It is written for read-only discs too, so on its own it shows a disc was in the drive, not a burn.
            yield _rec("cd_burning", media.time, media.locator, what="disc seen in drive", disc_label=label,
                       volume=clean_text(volume.name, 64), total_bytes=total.number if total is not None else None,
                       free_bytes=free.number if free is not None else None,
                       live_file_system=bool(live.number) if live is not None and live.number is not None else None)


def _read_office_mru(hive: Hive) -> Iterator[Record]:
    office = hive.open("Software\\Microsoft\\Office")
    if office is None:
        return
    emitted = 0
    for key in walk_keys(office, max_depth=6, limit=4000):
        if key.name not in ("File MRU", "Place MRU") or emitted >= MAX_GROUP_RECORDS:
            continue
        parts = key.path.split("\\")
        app = parts[-2] if len(parts) >= 2 and parts[-2] not in ("User MRU",) else ""
        if "User MRU" in parts:
            app = parts[parts.index("User MRU") - 1]
        for value in key.values():
            found = _OFFICE_MRU.match(value.text)
            if found:
                emitted += 1
                yield _rec("office_mru", filetime_iso(int(found["time"], 16)), value.locator,
                           app=clean_text(app, 32), path=clean_text(found["path"], 1024),
                           is_folder=key.name == "Place MRU")
            elif value.name.lower().startswith(("item", "file")) and re.match(r"^[A-Za-z]:\\|^\\\\", value.text):
                emitted += 1
                yield _rec("office_mru", None, value.locator, app=clean_text(app, 32), path=value.text,
                           is_folder=False)


def _read_mail_profiles(hive: Hive) -> Iterator[Record]:
    seen = 0
    for path in ("Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles",
                 *(f"Software\\Microsoft\\Office\\{version}\\Outlook\\Profiles" for version in
                   ("15.0", "16.0", "14.0", "12.0"))):
        key = hive.open(path)
        if key is None:
            continue
        for profile in key.subkeys():
            seen += 1
            yield _rec("mail_profile", profile.time, profile.locator, client="Outlook",
                       profile=clean_text(profile.name, 120))
    for version in ("16.0", "15.0", "14.0", "12.0"):
        catalog = hive.open(f"Software\\Microsoft\\Office\\{version}\\Outlook\\Search\\Catalog")
        if catalog is None:
            catalog = hive.open(f"Software\\Microsoft\\Office\\{version}\\Outlook\\Catalog")
        if catalog is not None:
            for value in catalog.values():
                if re.search(r"\.(ost|pst)$", value.name, re.IGNORECASE):
                    yield _rec("mail_store", catalog.time, value.locator, client="Outlook",
                               path=clean_text(value.name, 1024))


def _read_archive_history(hive: Hive) -> Iterator[Record]:
    for tool, path in (("WinRAR", "Software\\WinRAR\\ArcHistory"), ("WinRAR", "Software\\WinRAR\\DialogEditHistory\\ArcName"),
                       ("7-Zip", "Software\\7-Zip\\Compression\\ArcHistory")):
        key = hive.open(path)
        if key is None:
            continue
        for value in key.values():
            text = value.text
            if not text and value.kind == 3:  # 7-Zip keeps one UTF-16 list
                text = clean_text(value.data.decode("utf-16-le", errors="replace").replace("\0", " | "), 1024)
            if text:
                yield _rec("archive_history", key.time if value.name in ("0", "ArcHistory") else None, value.locator,
                           tool=tool, path=text)


def _shellbags(hive: Hive, root_path: str) -> Iterator[Record]:
    root = hive.open(root_path)
    if root is None:
        return
    stack: list[tuple[RegKey, list[str]]] = [(root, [])]
    emitted = 0
    while stack and emitted < MAX_GROUP_RECORDS:
        key, trail = stack.pop()
        if len(trail) > 16:
            continue
        children = {child.name: child for child in key.subkeys()}
        for value in key.values():
            if not value.name.isdigit():
                continue
            data = value.data
            kind, name = item_name(data[:idlist_size(data)])
            if kind in ("volume", "network"):
                path = [name]
            elif kind == "root":
                path = [name] if name else []
            elif name:
                path = [*trail, name]
            else:
                path = [*trail, "?"]
            child = children.get(value.name)
            if name and path:
                emitted += 1
                yield _rec("shellbag", child.time if child is not None else None, value.locator,
                           path=clean_text("\\".join(path), 1024))
            if child is not None:
                stack.append((child, path))


def _read_shellbags_user(hive: Hive) -> Iterator[Record]:
    yield from _shellbags(hive, "Software\\Microsoft\\Windows\\Shell\\BagMRU")
    yield from _shellbags(hive, "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU")


def _read_shellbags_classes(hive: Hive) -> Iterator[Record]:
    yield from _shellbags(hive, "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU")
    yield from _shellbags(hive, "Local Settings\\Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU")


# --------------------------------------------------------------------------
# SAM
# --------------------------------------------------------------------------


def _read_accounts(hive: Hive) -> Iterator[Record]:
    users = hive.open("SAM\\Domains\\Account\\Users")
    names = users.subkey("Names") if users is not None else None
    if users is None or names is None:
        return
    by_rid: dict[int, RegKey] = {}
    for key in users.subkeys():
        if re.fullmatch(r"[0-9A-Fa-f]{8}", key.name):
            by_rid[int(key.name, 16)] = key
    for name in names.subkeys():
        default = name.value("")
        rid = default.kind if default is not None else 0  # the RID is stored as the value's type
        fields: dict[str, object] = {"name": clean_text(name.name, 120), "rid": rid, "created": name.time}
        detail = by_rid.get(rid)
        fixed = detail.value("F") if detail is not None else None
        if fixed is not None and len(fixed.data) >= 68:
            # The F value: last logon at 8, password set at 24, account flags at 56, logon count at 66.
            last_logon, _, password_set = struct.unpack_from("<QQQ", fixed.data, 8)
            flags = struct.unpack_from("<H", fixed.data, 56)[0]
            fields.update(last_logon=filetime_iso(last_logon), password_set=filetime_iso(password_set),
                          logon_count=struct.unpack_from("<H", fixed.data, 66)[0], disabled=bool(flags & 1))
        yield _rec("user_account", name.time, name.locator, **fields)


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

Reader = Callable[[Hive], Iterator[Record]]


def _user_software(reader: Callable[..., Iterator[Record]]) -> Reader:
    return lambda hive: reader(hive, "Software\\")


HIVE_READERS: dict[str, tuple[tuple[str, Reader], ...]] = {
    "system": (("system facts", _read_system_facts), ("USBSTOR", _read_usbstor), ("USB bus", _read_usb_enum),
               ("MountedDevices", _read_mounted_devices), ("USB volume names", _read_usb_labels),
               ("optical drives", _read_optical_drives)),
    "software": (("OS facts", _read_os_facts), ("user profiles", _read_profiles),
                 ("installed programs", _read_uninstall), ("Run keys", _read_run_keys),
                 ("portable devices", _read_portable_devices), ("program keys", _read_program_keys),
                 ("mail clients", _read_mail_clients)),
    "ntuser": (("MountPoints2", _read_mount_points), ("RecentDocs", _read_recent_docs),
               ("common dialogs", _read_common_dialogs), ("UserAssist", _read_user_assist),
               ("network drives", _read_network_drives), ("typed paths and searches", _read_typed),
               ("CD burning", _read_cd_burning), ("Office recent files", _read_office_mru),
               ("mail profiles", _read_mail_profiles), ("archive history", _read_archive_history),
               ("Run keys", _user_software(_read_run_keys)), ("installed programs", _user_software(_read_uninstall)),
               ("program keys", _user_software(_read_program_keys)), ("shellbags", _read_shellbags_user)),
    "usrclass": (("shellbags", _read_shellbags_classes),),
    "sam": (("user accounts", _read_accounts),),
}


def hive_kind(name: str) -> str | None:
    """Which reader set a hive file gets, from its file name."""
    lowered = name.lower()
    if lowered in ("system", "software", "sam"):
        return lowered
    if lowered == "ntuser.dat":
        return "ntuser"
    if lowered == "usrclass.dat":
        return "usrclass"
    return None


def parse_hive(path: Path, kind: str) -> tuple[list[Record], list[str]]:
    """(records, problems) for one hive. A problem names the group of keys that could not be read."""
    records: list[Record] = []
    problems: list[str] = []
    with Hive(path) as hive:
        if hive.dirty:
            problems.append("the hive was not cleanly saved; changes still in its transaction logs are not read")
        for label, reader in HIVE_READERS.get(kind, ()):
            group: list[Record] = []
            try:
                for record in reader(hive):
                    group.append(record)
                    if len(group) >= MAX_GROUP_RECORDS:
                        problems.append(f"{label}: stopped at {MAX_GROUP_RECORDS} records")
                        break
            except ParseBudget as exc:
                problems.append(f"{label}: {exc}")
            except (ParseError, struct.error, ValueError, IndexError, UnicodeError) as exc:
                problems.append(f"{label}: could not be read ({type(exc).__name__})")
            records.extend(group)
            if len(records) >= MAX_RECORDS_PER_FILE * 2:
                problems.append("stopped: record limit for one hive reached")
                break
    return records, problems
