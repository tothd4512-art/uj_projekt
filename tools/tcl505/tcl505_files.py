#!/usr/bin/env python3
"""Optional, explicitly requested read-only ADB file collector for TCL 505.

Copies only an allowlist of system configuration/build metadata to a new local
folder and ZIP. It never requests root, reads raw partitions or /data, changes
the phone, or uploads anything. Normal shell-user permissions are respected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from tcl505_probe import (Session, find_tool, parse_devices, select_device,
                          redact, run_command)

VERSION = "0.1.0"
MANIFEST_SCHEMA = 1
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 40
# Firmware/configuration files only. Never add /data, /sdcard, accounts,
# databases, raw block devices, wildcard paths, or a recursive pull.
FILE_ALLOWLIST = (
    "/system/build.prop",
    "/vendor/build.prop",
    "/product/build.prop",
    "/system_ext/build.prop",
    "/odm/build.prop",
    "/system/etc/prop.default",
    "/vendor/default.prop",
    "/system/system/build.prop",
    "/vendor/vendor/build.prop",
    "/product/product/build.prop",
    "/system_ext/system_ext/build.prop",
    "/odm/odm/etc/build.prop",
    "/vendor/odm/etc/build.prop",
    "/vendor/etc/fstab.mt6765",
    "/vendor/etc/fstab.mt6765p",
    "/vendor/etc/fstab.ant",
    "/odm/etc/fstab.mt6765",
    "/odm/etc/fstab.ant",
    "/first_stage_ramdisk/fstab.mt6765",
    "/first_stage_ramdisk/fstab.ant",
    "/system/etc/init/hw/init.ant.rc",
    "/vendor/etc/init/hw/init.ant.rc",
    "/vendor/etc/init/init.ant.rc",
    "/vendor/etc/init/hw/init.mt6765.rc",
    "/vendor/etc/init/init.mt6765.rc",
    "/vendor/etc/init/hw/init.mt6765.usb.rc",
    "/vendor/etc/init/init.mt6765.usb.rc",
    "/vendor/etc/init/hw/init.ant.usb.rc",
    "/vendor/etc/init/hw/init.tcl.rc",
    "/vendor/etc/init/init.tcl.rc",
    "/vendor/etc/init/hw/init.tct.rc",
    "/vendor/etc/init/init.tct.rc",
    "/system/etc/init/tct_token.rc",
    "/system_ext/etc/init/tct_token.rc",
    "/vendor/etc/init/tct_token.rc",
)
PROPERTY_LINE = re.compile(r"^([A-Za-z0-9_.-]+)\s*=\s*(.*)$")
SETPROP_LINE = re.compile(r"^(\s*(?:setprop|export)\s+)([A-Za-z0-9_.-]+)(\s+)(.*)$")
SECRET_KEY = re.compile(
    r"(?i)(serial|imei|meid|imsi|iccid|mac(?:addr|_addr)?|wifi|bluetooth|"
    r"password|passwd|secret|credential|authkey|android_id|ssid|bssid|"
    r"email|account|phone|msisdn|tksn|uuid|hardware_id)"
)
TOKEN_KEY = re.compile(
    r"(?i)(^|[._])token$|(^|[._])(oem|fastboot|adb|root|retail|perf|sml|uart|diag|smartlog|rollback)token$"
)
BOOL_VALUES = frozenset(("true", "false", "0", "1", "yes", "no"))


def safe_relative(source: str) -> str:
    if source not in FILE_ALLOWLIST:
        raise ValueError("A forrásfájl nincs a rögzített engedélylistán.")
    return source.lstrip("/")


def _redact_value(key: str, value: str) -> str:
    if TOKEN_KEY.search(key):
        return value if value.lower() in BOOL_VALUES else "<redacted-nonboolean>"
    if SECRET_KEY.search(key):
        return "<redacted>"
    return value


def sanitize_text(text: str, serials: tuple[str, ...] = ()) -> str:
    """Keep firmware metadata while removing recognizable personal/secret fields."""
    kept = []
    for line in text.splitlines():
        match = PROPERTY_LINE.match(line.strip())
        if match:
            key, value = match.groups()
            line = f"{key}={_redact_value(key, value)}"
        else:
            match = SETPROP_LINE.match(line)
            if match:
                prefix, key, space, value = match.groups()
                line = f"{prefix}{key}{space}{_redact_value(key, value)}"
        kept.append(line)
    # Source files have their own 2 MiB cap; do not apply the short command
    # output cap and silently lose the rest of a build/init/fstab file.
    return redact("\n".join(kept) + "\n", serials, max_chars=None)


def classify_pull_error(result: dict) -> str:
    if result["status"] in ("timeout", "unavailable"):
        return result["status"]
    text = (result.get("stdout", "") + "\n" + result.get("stderr", "")).lower()
    if "permission denied" in text or "access denied" in text:
        return "denied"
    if any(phrase in text for phrase in ("no such file", "does not exist", "not found", "cannot stat")):
        return "missing"
    return result["status"] if result["status"] != "ok" else "error"


def copy_file(session: Session, executable: str, serial: str, source: str,
              destination: Path) -> dict:
    relative = safe_relative(source)
    entry = {"source": source, "file": relative, "status": "pending",
             "bytes": None, "sha256": None, "detail": ""}
    if destination.exists() or destination.is_symlink():
        raise ValueError("A célkönyvtárban már létezik egy azonos nevű fájl.")
    # adb pull talks to adbd and enforces the existing shell-user permissions.
    # Never invoke su, dd, cat /dev/block, remount, or a recursive directory pull.
    result = session.run([executable, "-s", serial, "pull", source, str(destination)])
    if result["status"] != "ok":
        destination.unlink(missing_ok=True)
        entry.update(status=classify_pull_error(result),
                     detail=result["stderr"] or result["stdout"])
        return entry
    if not destination.is_file() or destination.is_symlink():
        destination.unlink(missing_ok=True)
        entry.update(status="error", detail="A másolat nem szabályos fájl; nem kerül a csomagba.")
        return entry
    size = destination.stat().st_size
    if size > MAX_FILE_BYTES or size == 0:
        destination.unlink()
        entry.update(status="too_large" if size else "empty", bytes=size,
                     detail="A fájl mérete kívül esik a gyűjtési kereten." if size else "Üres fájl.")
        return entry
    raw = destination.read_bytes()
    if b"\x00" in raw:
        destination.unlink()
        entry.update(status="not_text", bytes=size,
                     detail="Bináris tartalom; ez a gyűjtő csak szöveges konfigurációt másol.")
        return entry
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        destination.unlink()
        entry.update(status="not_text", bytes=size, detail="Nem UTF-8 szöveg; nem kerül a csomagba.")
        return entry
    payload = sanitize_text(text, tuple(session.serials)).encode("utf-8")
    destination.write_bytes(payload)
    entry.update(status="ok", bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest(),
                 detail="Szöveges másolat; az ismert személyes/titkos mezők redakciója megtörtént.")
    return entry


def write_bundle_zip(bundle: Path, output_root: Path) -> Path:
    zip_path = output_root / f"{bundle.name}.zip"
    with zipfile.ZipFile(zip_path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(bundle.rglob("*")):
            if path.is_file() and not path.is_symlink():
                archive.write(path, f"{bundle.name}/{path.relative_to(bundle).as_posix()}")
    return zip_path


def collect_files(folder: Optional[Path], serial: Optional[str], timeout: float,
                  output_root: Path, runner=run_command) -> tuple[Path, dict, Path]:
    executable = find_tool("adb", folder)
    session = Session(timeout, runner)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    bundle = output_root / f"tcl505-files-{stamp}"
    bundle.mkdir(parents=True, exist_ok=False)
    manifest = {"schema_version": MANIFEST_SCHEMA, "tool_version": VERSION,
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "read_only_on_phone": True, "uploaded_by_tool": False,
                "connected": False, "issue": None, "files": [], "commands": []}
    try:
        if executable is None:
            manifest["issue"] = "Az adb nem található. Add meg a Platform Tools mappáját."
        else:
            session.run([executable, "version"])
            listing = session.run([executable, "devices", "-l"])
            devices = parse_devices(listing, "adb")
            session.remember_serials([device["_serial"] for device in devices] + ([serial] if serial else []))
            selected, issue = select_device(devices, serial, "adb")
            manifest["issue"] = issue
            if selected is not None:
                manifest["connected"] = True
                for source in FILE_ALLOWLIST[:MAX_FILES]:
                    target = bundle / safe_relative(source)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    manifest["files"].append(copy_file(session, executable, selected, source, target))
    finally:
        manifest["commands"] = session.commands
        with (bundle / "manifest.json").open("x", encoding="utf-8") as handle:
            json.dump(manifest, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        (bundle / "README.txt").write_text(
            "TCL 505 / T509K célzott fájlmásolat\n"
            "A program nem kért rootot, nem írt a telefonra, nem olvasott nyers partíciót és nem töltött fel.\n"
            "A manifest.json a forrásutakat, állapotokat és a szerkesztett másolatok SHA-256 kivonatát tartalmazza.\n"
            "Feltöltés előtt nézd át a fájlokat. Lehetőleg privát Drive-mappába vagy privát tárolóba tedd.\n",
            encoding="utf-8")
    # Build the uploadable ZIP only after the manifest is closed. Returning from
    # inside try/finally would evaluate the old zip_path before finally ran.
    zip_path = write_bundle_zip(bundle, output_root)
    return bundle, manifest, zip_path


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="TCL 505: célzott, csak olvasó ADB fájlmásolás. Nem kér rootot és nem tölt fel.")
    parser.add_argument("--platform-tools", type=Path)
    parser.add_argument("--serial")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent / "reports")
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 120:
        parser.error("--timeout: 1 és 120 közötti érték szükséges.")
    if args.platform_tools and not args.platform_tools.is_dir():
        parser.error("A --platform-tools mappa nem létezik.")
    try:
        bundle, manifest, zip_path = collect_files(args.platform_tools, args.serial, args.timeout,
                                                   args.output_dir.expanduser().resolve())
    except (OSError, ValueError) as exc:
        print(f"Nem sikerült a fájlok másolása: {exc}", file=sys.stderr)
        return 2
    copied = sum(entry["status"] == "ok" for entry in manifest["files"])
    print(f"Másolt fájlok: {copied}/{len(FILE_ALLOWLIST[:MAX_FILES])}")
    print(f"Csomagmappa: {bundle}\nJegyzék: {bundle / 'manifest.json'}")
    if zip_path:
        print(f"Feltölthető ZIP: {zip_path}")
    if manifest["issue"]:
        print(manifest["issue"])
    print("A telefonon nem történt írás, rootkérés vagy újraindítás. Feltöltés előtt nézd át a fájlokat.")
    return 0 if manifest["connected"] else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
