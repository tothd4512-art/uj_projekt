#!/usr/bin/env python3
"""TCL 505 / T509K: read-only ADB/fastboot diagnostic collector.

Requires Python 3.9+ and Android SDK Platform Tools. No third-party Python
packages, network access, root, reboot, partition access or flashing are used.
This program DOES NOT unlock a bootloader. See README.hu.md for its limitations.
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

VERSION = "0.3.1"
REPORT_SCHEMA = 2
MAX_OUTPUT = 16000
TOKEN_PACKAGE = "com.tcl.token"
TOKEN_SERIAL_PROPERTY = "ro.boot.tksn"

# Deliberately narrow allowlists. Never collect the full property dump or
# `fastboot getvar all`: those can contain serial numbers, IMEIs or MAC addresses.
ANDROID_PROPERTIES = (
    "ro.product.manufacturer", "ro.product.model", "ro.product.name",
    "ro.product.device", "ro.product.first_api_level",
    "ro.build.id", "ro.build.display.id", "ro.build.fingerprint",
    "ro.build.version.release", "ro.build.version.sdk",
    "ro.build.version.incremental", "ro.build.version.security_patch",
    "ro.build.type", "ro.build.tags",
    "ro.vendor.build.fingerprint", "ro.vendor.build.version.security_patch",
    "ro.hardware", "ro.board.platform", "ro.boot.hardware",
    "ro.bootloader", "ro.boot.bootloader", "ro.boot.mode",
    "ro.boot.slot_suffix", "ro.boot.flash.locked",
    "ro.boot.verifiedbootstate", "ro.boot.veritymode",
    "ro.boot.vbmeta.device_state", "ro.boot.avb_version",
    "ro.oem_unlock_supported", "sys.oem_unlock_allowed",
    "ro.secure", "ro.debuggable", "ro.treble.enabled",
    "ro.boot.dynamic_partitions", "ro.virtual_ab.enabled",
)
FASTBOOT_VARIABLES = (
    "version", "version-bootloader", "product", "secure", "unlocked",
    "is-userspace", "current-slot", "slot-count", "has-slot:boot",
    "partition-type:boot", "partition-size:boot", "max-download-size",
)
# Community-documented TCL token flags. Reading a flag is not authorization,
# and a missing flag does not prove that the bootloader has no token check.
TOKEN_PROPERTIES = (
    "ro.boot.oemtoken", "ro.boot.fastboottoken", "ro.boot.adbtoken",
    "ro.boot.roottoken", "ro.boot.retailtoken", "ro.boot.perftoken",
    "ro.boot.smltoken", "ro.boot.uarttoken", "ro.boot.diagtoken",
    "ro.boot.smartlogtoken", "ro.boot.rollbacktoken",
)
ANDROID_PROPERTIES += TOKEN_PROPERTIES
TOKEN_BOOLEAN_VALUES = frozenset(("true", "false", "1", "0", "yes", "no"))
Runner = Callable[[list[str], float], dict]


def redact(text: str, serials: tuple[str, ...] = (), max_chars: Optional[int] = MAX_OUTPUT) -> str:
    """Remove selected/listed transport IDs and common identifying fields.

    max_chars=None keeps the full text for the separate, size-capped file
    collector; diagnostic command output remains capped by default.
    """
    for serial in sorted(set(serials), key=len, reverse=True):
        if serial:
            text = text.replace(serial, "<device-id-redacted>")
    text = re.sub(r"(?i)\b(imei[12]?|meid|serialno|serial)\s*[:=]\s*[^\s,;]+",
                  r"\1=<redacted>", text)
    text = re.sub(r"(?i)([a-z]:\\users\\)[^\\\r\n]+", r"\1<user>", text)
    text = re.sub(r"(/home/)[^/\r\n]+", r"\1<user>", text)
    return text if max_chars is None else text[:max_chars]


def run_command(argv: list[str], timeout: float) -> dict:
    """Run a fixed argument vector, never a shell command."""
    try:
        proc = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        return {"status": "ok" if proc.returncode == 0 else "error",
                "returncode": proc.returncode, "stdout": stdout, "stderr": stderr}
    except subprocess.TimeoutExpired as exc:
        def decoded(value: object) -> str:
            return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else (value or "")
        return {"status": "timeout", "returncode": None,
                "stdout": decoded(exc.stdout), "stderr": decoded(exc.stderr)}
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return {"status": "unavailable", "returncode": None,
                "stdout": "", "stderr": f"{type(exc).__name__}: {exc}"}


def display_argv(argv: list[str], serials: tuple[str, ...]) -> str:
    shown = [Path(argv[0]).name]
    skip = False
    for arg in argv[1:]:
        if skip:
            shown.append("<device-id-redacted>")
            skip = False
        elif arg == "-s":
            shown.append(arg)
            skip = True
        else:
            shown.append(redact(arg, serials))
    return " ".join(shown)


class Session:
    def __init__(self, timeout: float, runner: Runner = run_command):
        self.timeout = timeout
        self.runner = runner
        self.serials: list[str] = []
        self.commands: list[dict] = []

    def remember_serials(self, serials: list[str]) -> None:
        """Also scrub discovery output, which necessarily preceded discovery."""
        self.serials.extend(serials)
        known = tuple(self.serials)
        for entry in self.commands:
            for key in ("stdout", "stderr", "command"):
                entry[key] = redact(entry[key], known)

    def run(self, argv: list[str]) -> dict:
        result = self.runner(argv, self.timeout)
        result = {key: result.get(key, "") for key in ("status", "returncode", "stdout", "stderr")}
        result["stdout"] = redact(str(result["stdout"]), tuple(self.serials))
        result["stderr"] = redact(str(result["stderr"]), tuple(self.serials))
        result["command"] = display_argv(argv, tuple(self.serials))
        self.commands.append(result)
        return result


def find_tool(name: str, folder: Optional[Path]) -> Optional[str]:
    exe = name + ".exe" if platform.system() == "Windows" else name
    candidates = []
    if folder:
        candidates.append(folder / exe)
    candidates.append(Path(__file__).resolve().parent / "platform-tools" / exe)
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())
    return shutil.which(name) or shutil.which(exe)


def parse_devices(result: dict, mode: str) -> list[dict]:
    devices = []
    for line in result["stdout"].splitlines():
        line = line.strip()
        if not line or line.startswith(("*", "List of devices", "adb server", "daemon")):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        if mode == "fastboot" and fields[1] in ("fastboot", "fastbootd"):
            devices.append({"state": fields[1], "_serial": fields[0]})
        elif mode == "adb" and fields[1] in ("device", "unauthorized", "offline", "recovery", "sideload"):
            devices.append({"state": fields[1], "_serial": fields[0]})
    return devices


def select_device(devices: list[dict], requested: Optional[str], mode: str) -> tuple[Optional[str], Optional[str]]:
    if not devices:
        return None, f"Nem található {mode} eszköz. Ellenőrizd a kábelt, az USB-drivert és az eszköz módját."
    if requested:
        matched = [d for d in devices if d["_serial"] == requested]
        if not matched:
            return None, "A megadott --serial eszköz nem látható ebben a módban."
        selected = matched[0]
    elif len(devices) == 1:
        selected = devices[0]
    else:
        return None, "Több eszköz látható. Add meg a kívánt eszközt a --serial kapcsolóval; a program nem választ helyetted."
    if selected["state"] == "unauthorized":
        return None, "Az ADB nincs engedélyezve a telefonon. Hagy jóvá a saját gép USB-hibakeresési kulcsát, majd futtasd újra."
    if selected["state"] != "device" and mode == "adb":
        return None, f"Az eszköz állapota: {selected['state']}. Normál, engedélyezett ADB kapcsolat szükséges."
    return selected["_serial"], None


def parse_variable(result: dict, key: str) -> Optional[str]:
    pattern = re.compile(r"^(?:\([^)]*\)\s*)?" + re.escape(key) + r"\s*:\s*(.*?)\s*$", re.MULTILINE)
    combined = result["stdout"] + "\n" + result["stderr"]
    match = pattern.search(combined)
    return match.group(1) if match else None


def parse_unlock_ability(result: dict) -> Optional[str]:
    """Parse the standard query and the vendor ``unlock_ability = ...`` alias.

    The numeric text is preserved verbatim. A non-0/1 value is evidence of a
    vendor response, not permission to unlock; interpretation happens later.
    """
    combined = result["stdout"] + "\n" + result["stderr"]
    pattern = re.compile(
        r"^(?:\([^)]*\)\s*)?(?:get_unlock_ability|unlock_ability)\s*[:=]\s*(.*?)\s*$",
        re.MULTILINE,
    )
    match = pattern.search(combined)
    return match.group(1) if match else None


def query_result(result: dict, value: Optional[str]) -> dict:
    output = (result["stdout"] + "\n" + result["stderr"]).lower()
    if any(phrase in output for phrase in ("unknown command", "unknown variable", "variable not found",
                                           "not supported", "invalid command")):
        status = "unsupported"
    elif result["status"] != "ok":
        status = result["status"]
    elif "failed" in output:
        status = "error"
    elif value is None or value == "":
        status = "missing"
    else:
        status = "ok"
    return {"status": status, "value": value, "returncode": result["returncode"],
            "detail": result["stderr"] or result["stdout"] if status != "ok" else ""}


def collect_token_flag(session: Session, argv: list[str]) -> dict:
    """These community-documented fields are flags, not exported credentials."""
    result = session.run(argv)
    value = result["stdout"].strip() if result["status"] == "ok" else None
    item = query_result(result, value)
    safe_value = value if value and value.lower() in TOKEN_BOOLEAN_VALUES else None
    if value and safe_value is None:
        item.update(status="redacted", value=None,
                    detail="Nem logikai érték; a nyers érték nem kerül a jelentésbe.")
    # An unfamiliar implementation could echo a credential on an error path.
    # Keep only allowlisted boolean output, never arbitrary raw streams.
    session.commands[-1]["stdout"] = safe_value or "<token-output-not-exported>"
    session.commands[-1]["stderr"] = ""
    if item["status"] != "ok":
        item["detail"] = ("Nem logikai érték; a nyers érték nem kerül a jelentésbe."
                          if item["status"] == "redacted" else
                          "A tokenlekérdezés nem adott kiértékelhető választ; nyers kimenet nélkül.")
    return item


def collect_presence(session: Session, argv: list[str]) -> dict:
    """Report presence without exporting a device-bound token serial/ID."""
    result = session.run(argv)
    present = result["status"] == "ok" and bool(result["stdout"].strip())
    status = ("ok" if present else "missing") if result["status"] == "ok" else result["status"]
    # Never interpret or retain either raw stream: either could contain the
    # identifier on an unfamiliar implementation, including on an error path.
    session.commands[-1]["stdout"] = "<presence-only>"
    session.commands[-1]["stderr"] = ""
    return {"status": status, "value": "present" if present else None,
            "returncode": result["returncode"],
            "detail": "Csak a mező jelenlétét vizsgáljuk; az értékét nem gyűjtjük."}


def collect_adb(session: Session, executable: str, requested: Optional[str]) -> dict:
    version = session.run([executable, "version"])
    devices_result = session.run([executable, "devices", "-l"])
    devices = parse_devices(devices_result, "adb")
    session.remember_serials([d["_serial"] for d in devices] + ([requested] if requested else []))
    serial, issue = select_device(devices, requested, "adb")
    data = {"tool_version": version["stdout"].splitlines()[:3],
            "devices": [{"state": d["state"]} for d in devices],
            "connected": serial is not None, "issue": issue, "properties": {},
            "token_package": {"status": "unavailable", "value": None, "returncode": None,
                              "detail": "Nem futott lekérdezés használható ADB kapcsolat nélkül."},
            "token_serial": {"status": "unavailable", "value": None, "returncode": None,
                             "detail": "Nem futott lekérdezés használható ADB kapcsolat nélkül."}}
    if serial is None:
        return data
    for key in ANDROID_PROPERTIES:
        argv = [executable, "-s", serial, "shell", "getprop", key]
        if key in TOKEN_PROPERTIES:
            data["properties"][key] = collect_token_flag(session, argv)
        else:
            result = session.run(argv)
            value = result["stdout"].strip() if result["status"] == "ok" else None
            data["properties"][key] = query_result(result, value)
    # Read-only package query. Do not start the token app, contact its server,
    # read its data, or request/export a token.
    package_result = session.run([executable, "-s", serial, "shell", "pm", "list", "packages", TOKEN_PACKAGE])
    package_lines = {line.strip() for line in package_result["stdout"].splitlines()}
    package_value = TOKEN_PACKAGE if f"package:{TOKEN_PACKAGE}" in package_lines else None
    data["token_package"] = query_result(package_result, package_value)
    data["token_serial"] = collect_presence(
        session, [executable, "-s", serial, "shell", "getprop", TOKEN_SERIAL_PROPERTY])
    return data


def collect_fastboot(session: Session, executable: str, requested: Optional[str]) -> dict:
    version = session.run([executable, "--version"])
    devices_result = session.run([executable, "devices"])
    devices = parse_devices(devices_result, "fastboot")
    session.remember_serials([d["_serial"] for d in devices] + ([requested] if requested else []))
    serial, issue = select_device(devices, requested, "fastboot")
    data = {"tool_version": version["stdout"].splitlines()[:3],
            "devices": [{"state": d["state"]} for d in devices],
            "connected": serial is not None, "issue": issue, "variables": {}}
    if serial is None:
        return data
    for key in FASTBOOT_VARIABLES:
        result = session.run([executable, "-s", serial, "getvar", key])
        data["variables"][key] = query_result(result, parse_variable(result, key))
    # Despite its command group name, get_unlock_ability is a query, not unlock.
    result = session.run([executable, "-s", serial, "flashing", "get_unlock_ability"])
    data["variables"]["get_unlock_ability"] = query_result(result, parse_unlock_ability(result))
    return data


def value_of(values: dict, key: str) -> Optional[str]:
    item = values.get(key, {})
    return item.get("value") if item.get("status") == "ok" else None


def interpret(mode: str, data: dict) -> list[str]:
    notes = ["Ez állapotfelmérés, nem feloldás. A hiányzó válasz nem jelent nemleges választ.",
             "A jelentés nem bizonyítja a BROM/MTKClient hozzáférést vagy egy exploit működését."]
    if not data["connected"]:
        return notes + [data["issue"]]
    if mode == "adb":
        props = data["properties"]
        locked = value_of(props, "ro.boot.flash.locked")
        if locked == "1":
            notes.append("ro.boot.flash.locked=1: zárolt állapotot jelez.")
        elif locked == "0":
            notes.append("ro.boot.flash.locked=0: feloldottnak jelzett állapot. TCL-nél ez önmagában nem bizonyít teljes, szabványos feloldást.")
        allowed = value_of(props, "sys.oem_unlock_allowed")
        if allowed is not None:
            notes.append(f"sys.oem_unlock_allowed={allowed}: az OEM-feloldás beállítás állapota, nem a bootloader tényleges zároltsága.")
        if not value_of(props, "ro.build.fingerprint"):
            notes.append("Nincs olvasható build fingerprint; a teljes TCL firmware azonosítása még nem kész.")
        token_values = {key: value_of(props, key) for key in TOKEN_PROPERTIES}
        token_true = [key for key, value in token_values.items()
                      if value is not None and value.lower() in ("true", "1", "yes")]
        if token_true:
            notes.append("Ezek a közösségi TCL token-jelzők igaz/1 értékűek: " + ", ".join(token_true) +
                         ". Ez nyomozási kiindulópont, nem igazolt szerver-engedély vagy bootloader-feloldás.")
        elif any(value is not None for value in token_values.values()):
            notes.append("Van olvasható TCL token-jelző, de egyik sem igaz/1. A hamis vagy hiányzó érték nem cáfolja a bootloader oldali token/auth ellenőrzést.")
        else:
            notes.append("Nem olvasható a közösségi TCL token-jelzőkészlet. Ez nem cáfolja az authboot/token mechanizmust.")
        package = data.get("token_package", {})
        if package.get("status") == "ok":
            notes.append("A com.tcl.token csomag jelen van. Nem indítottuk el, nem kértünk tokent és nem léptünk hálózatra vele.")
        elif package.get("status") == "missing":
            notes.append("A com.tcl.token csomag nem található ezzel a lekérdezéssel. Ettől még lehet bootloader oldali token/auth ellenőrzés.")
        if data.get("token_serial", {}).get("status") == "ok":
            notes.append("A ro.boot.tksn mező jelen van; az értékét nem gyűjtöttük. Jelenléte nem bizonyít felhasználói tokenigénylési vagy feloldási lehetőséget.")
    else:
        variables = data["variables"]
        if value_of(variables, "is-userspace") == "yes":
            notes.append("is-userspace=yes: fastbootd látható, nem a bootloader-fastboot. Az itteni eredmény nem igazolja a bootloader feloldhatóságát.")
        unlocked = value_of(variables, "unlocked")
        if unlocked is not None:
            notes.append(f"A bootloader unlocked változója: {unlocked}.")
        ability = value_of(variables, "get_unlock_ability")
        if ability == "0":
            notes.append("get_unlock_ability=0: a bootloader nem engedélyezett feloldást jelez. Ez nem a telefon hardveres hibájára utal.")
        elif ability == "1":
            notes.append("get_unlock_ability=1: a bootloader feloldási engedélyt jelez. Ez még nem bizonyítja, hogy a TCL ezt a konkrét feloldási parancsot elfogadja.")
        elif ability is not None:
            notes.append(f"get_unlock_ability={ability}: nem szabványos 0/1 válasz. Gyártói érték; önmagában nem feloldási engedély és nem tiltás. Külön elemzés és jóváhagyás szükséges.")
        if variables.get("get_unlock_ability", {}).get("status") == "unsupported":
            notes.append("A get_unlock_ability lekérdezés nem támogatott; nem szabad ebből 0-ra vagy 1-re következtetni.")
    return notes


def render_text(report: dict) -> str:
    lines = ["TCL 505 / T509K – csak olvasó diagnosztika", "=" * 46,
             f"Program: {report['tool_version']} | Mód: {report['mode']}",
             f"Időpont (UTC): {report['created_utc']}",
             "Nem történt feloldás, flashelés, törlés vagy újraindítás.", ""]
    data = report["data"]
    lines.append(f"Kapcsolat: {'észlelve' if data['connected'] else 'nem használható'}")
    lines.extend(report["interpretation"])
    lines.append("")
    for section, title in (("properties", "Android tulajdonságok"), ("variables", "Fastboot változók")):
        if section in data:
            lines.extend([title, "-" * len(title)])
            for key, item in data[section].items():
                value = item["value"] if item["value"] not in (None, "") else "(nincs adat)"
                lines.append(f"{key} = {value} [{item['status']}]")
            lines.append("")
    if "token_package" in data:
        lines.extend(["TCL token nyomok", "-" * 16])
        for key, label in (("token_package", TOKEN_PACKAGE), ("token_serial", TOKEN_SERIAL_PROPERTY)):
            item = data.get(key, {})
            value = item.get("value") or "(nincs adat)"
            lines.append(f"{label} = {value} [{item.get('status', 'missing')}]")
        lines.append("")
    lines.extend(["Parancsnapló (eszközazonosítók eltávolítva)", "-" * 46])
    for command in report["commands"]:
        lines.append(f"[{command['status']}] {command['command']}")
        if command["status"] != "ok" and command["stderr"]:
            lines.append("  " + command["stderr"].replace("\n", "\n  ").strip())
    lines.extend(["", "A fájlok helyben készülnek; a program nem tölt fel adatot.",
                  "Megosztás előtt minden esetben nézd át a tartalmat."])
    return "\n".join(lines) + "\n"


def collect(mode: str, folder: Optional[Path], serial: Optional[str], timeout: float,
            runner: Runner = run_command) -> dict:
    executable = find_tool(mode, folder)
    session = Session(timeout, runner)
    if executable is None:
        data = {"connected": False, "issue": f"A(z) {mode} nem található. Add meg a Platform Tools mappáját a --platform-tools kapcsolóval.",
                "tool_version": [], "devices": [], "properties" if mode == "adb" else "variables": {}}
    elif mode == "adb":
        data = collect_adb(session, executable, serial)
    else:
        data = collect_fastboot(session, executable, serial)
    return {"schema_version": REPORT_SCHEMA, "tool_version": VERSION,
            "created_utc": datetime.now(timezone.utc).isoformat(), "mode": mode,
            "read_only": True, "data": data, "interpretation": interpret(mode, data),
            "commands": session.commands}


def write_reports(report: dict, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    base = output_dir / f"tcl505-{report['mode']}-{stamp}"
    # Append extensions: with_suffix() would remove the timestamp's fractional
    # seconds after its dot and let rapid consecutive reports overwrite one another.
    json_path, text_path = Path(str(base) + ".json"), Path(str(base) + ".txt")
    with json_path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    with text_path.open("x", encoding="utf-8") as handle:
        handle.write(render_text(report))
    return text_path, json_path


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="TCL 505/T509K read-only diagnostics; NEM old fel a bootloadert.")
    parser.add_argument("--mode", choices=("adb", "fastboot"), default="adb")
    parser.add_argument("--platform-tools", type=Path, help="A hivatalos adb/fastboot programokat tartalmazó mappa.")
    parser.add_argument("--serial", help="Eszközazonosító, ha több eszköz csatlakozik. Nem kerül a jelentésbe.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Parancsonkénti időkorlát, 1–120 másodperc (alap: 10).")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent / "reports")
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 120:
        parser.error("--timeout: 1 és 120 közötti értéket adj meg.")
    if args.platform_tools and not args.platform_tools.is_dir():
        parser.error("A --platform-tools mappa nem létezik.")
    try:
        report = collect(args.mode, args.platform_tools, args.serial, args.timeout)
        text_path, json_path = write_reports(report, args.output_dir.expanduser().resolve())
    except (OSError, ValueError) as exc:
        print(f"Nem sikerült elkészíteni a jelentést: {exc}", file=sys.stderr)
        return 2
    print(render_text(report))
    print(f"Szöveges jelentés: {text_path}\nJSON jelentés: {json_path}")
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
