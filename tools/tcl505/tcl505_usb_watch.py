#!/usr/bin/env python3
"""Passive Windows USB/PnP mode watcher for TCL 505 / T509K research.

This module only observes Windows Plug and Play metadata. It does not open a
USB/serial device handle, send USB transfers, run ADB/fastboot/MTK commands,
install drivers, load a DA, run an exploit, read/write partitions, or reboot.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import json
import math
import queue
import re
import secrets
import sys
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from tcl505_probe import redact

VERSION = "0.3.0"
REPORT_SCHEMA = 1
MANIFEST_SCHEMA = 1
MAX_EVENTS = 10000
MAX_METADATA = 256
DEFAULT_SECONDS = 120.0
MIN_SECONDS = 1.0
MAX_SECONDS = 600.0
SNAPSHOT_INTERVAL = 1.0
DRAIN_TIMEOUT = 0.2
_MARKER_THREAD_STARTED = False
MAX_MARKERS = 200
MARKER_MAX_CHARS = 120

# CM_NOTIFY_ACTION values for CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE.
CM_ACTIONS = {7: "enumerated", 8: "started", 9: "removed"}
CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE = 2
CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES = 2
CM_GETIDLIST_FILTER_ENUMERATOR = 0x00000001
CM_GETIDLIST_FILTER_PRESENT = 0x00000100
CR_SUCCESS = 0
CR_BUFFER_SMALL = 0x0000001A
DEVPROP_TYPE_STRING = 0x00000012
DEVICE_PROPERTY_GUID = "a45c254e-df1c-4efd-8020-67d146a850e0"
DEVICE_PROPERTIES = {"description": 2, "service": 6, "device_class": 9}

# Classification hints only. A VID/PID match is not proof of BROM, preloader,
# DA, auth bypass, or partition access.
MTK_BROM_PIDS = frozenset(("0003",))
MTK_PRELOADER_PIDS = frozenset(("2000", "201D", "20FF", "3000", "6000"))
MTK_PRELOADER_OR_DA_PIDS = frozenset(("2001",))
# 0E8D:201C is reported by several independent sources as MediaTek LK fastboot
# (bootloader fastboot, not fastbootd). The definitive check stays a read-only
# "getvar is-userspace", which this passive watcher never issues.
MTK_LK_FASTBOOT_PIDS = frozenset(("201C",))
TCL_ADB_PID = "0C01"  # this device's init.mt6765.usb.rc uses VID 0x1BBB / PID 0x0C01
VID_RE = re.compile(r"(?i)\bVID_([0-9A-F]{4})\b")
PID_RE = re.compile(r"(?i)\bPID_([0-9A-F]{4})\b")
MI_RE = re.compile(r"(?i)\bMI_([0-9A-F]{2})\b")


def parse_usb_instance(instance_id: str) -> Optional[dict]:
    """Extract USB identity fields; never return the instance serial suffix."""
    if not instance_id:
        return None
    parts = instance_id.strip().split("\\")
    if len(parts) < 2:
        return None
    bus = parts[0].upper()
    if bus not in ("USB", "USBSTOR"):
        return None
    hardware = parts[1].upper()
    vid_match = VID_RE.search(hardware)
    pid_match = PID_RE.search(hardware)
    if not vid_match or not pid_match:
        return None
    vid = vid_match.group(1).upper()
    pid = pid_match.group(1).upper()
    mi_match = MI_RE.search(hardware)
    mi = mi_match.group(1).upper() if mi_match else None
    hardware_id = f"{bus}\\VID_{vid}&PID_{pid}" + (f"&MI_{mi}" if mi else "")
    return {"bus": bus, "vid": vid, "pid": pid, "mi": mi, "hardware_id": hardware_id}


def classify_usb(vid: str, pid: str) -> str:
    vid = vid.upper()
    pid = pid.upper()
    if vid == "0E8D":
        if pid in MTK_BROM_PIDS:
            return "mediatek_brom_candidate"
        if pid in MTK_PRELOADER_PIDS:
            return "mediatek_preloader_candidate"
        if pid in MTK_PRELOADER_OR_DA_PIDS:
            return "mediatek_preloader_or_da_candidate"
        if pid in MTK_LK_FASTBOOT_PIDS:
            return "mediatek_lk_fastboot_candidate"
        return "mediatek_other_usb"
    if vid == "1BBB":
        return "tcl_adb_usb_candidate" if pid == TCL_ADB_PID else "tcl_other_usb"
    return "other_usb"


def instance_key(instance_id: str, salt: str) -> str:
    """Per-run salted pseudonym; the raw instance ID/serial is not exported."""
    return hashlib.sha256((salt + "\0" + instance_id).encode("utf-8")).hexdigest()[:16]


def sanitize_metadata(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    cleaned = redact(str(value), max_chars=None)
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", cleaned).strip()
    cleaned = cleaned[:MAX_METADATA]
    return cleaned or None


def decode_notification_instance(data: bytes) -> Optional[str]:
    """Decode a bounded CM_NOTIFY_EVENT_DATA buffer for DEVICEINSTANCE.

    Layout: DWORD FilterType, DWORD Reserved, then union. For DEVICEINSTANCE
    the union starts with WCHAR InstanceId[] at offset 8.
    """
    if len(data) < 10:
        return None
    filter_type = int.from_bytes(data[0:4], "little")
    if filter_type != CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE:
        return None
    payload = data[8:]
    if len(payload) % 2:
        payload = payload[:-1]
    text = payload.decode("utf-16-le", errors="replace")
    instance = text.split("\0", 1)[0].strip()
    return instance or None


class UsbTracker:
    """Track sanitized USB PnP events and visible durations."""

    def __init__(self, salt: Optional[str] = None, max_events: int = MAX_EVENTS):
        self.salt = salt or secrets.token_hex(16)
        self.max_events = max_events
        self.events: list[dict] = []
        self.sessions: list[dict] = []
        self.active: dict[str, dict] = {}
        self.dropped_events = 0
        self.ignored_non_usb = 0
        self.markers: list[dict] = []
        self.markers_dropped = 0

    def add_marker(self, label: Optional[str], elapsed: float, utc: datetime) -> bool:
        """Record an operator marker at an exact elapsed time.

        A marker is the user's own label for what they were doing at that
        moment (for example "Hangerő FEL + bedugás"). Only the label text and
        the two timestamps are kept.
        """
        text = sanitize_metadata(label)
        if text:
            text = text[:MARKER_MAX_CHARS]
        if not text:
            return False
        if len(self.markers) >= MAX_MARKERS:
            self.markers_dropped += 1
            return False
        self.markers.append({
            "sequence": len(self.markers) + 1,
            "utc": utc.isoformat(),
            "elapsed_seconds": round(max(0.0, elapsed), 6),
            "label": text,
        })
        return True

    def _info(self, info: Optional[dict]) -> dict:
        info = info or {}
        return {
            "description": sanitize_metadata(info.get("description")),
            "device_class": sanitize_metadata(info.get("device_class")),
            "service": sanitize_metadata(info.get("service")),
        }

    def observe(self, action: str, instance_id: str, elapsed: float, utc: datetime,
                info: Optional[dict] = None, source: str = "notification") -> bool:
        parsed = parse_usb_instance(instance_id)
        if parsed is None:
            self.ignored_non_usb += 1
            return False
        key = instance_key(instance_id, self.salt)
        classification = classify_usb(parsed["vid"], parsed["pid"])
        metadata = self._info(info)
        elapsed = round(max(0.0, elapsed), 6)
        event = {
            "sequence": len(self.events) + self.dropped_events + 1,
            "utc": utc.isoformat(),
            "elapsed_seconds": elapsed,
            "action": action,
            "source": source,
            "instance_key": key,
            **parsed,
            "classification": classification,
            **metadata,
        }
        if len(self.events) < self.max_events:
            self.events.append(event)
        else:
            self.dropped_events += 1
        if action in ("enumerated", "started", "present"):
            state = self.active.get(key)
            if state is None:
                self.active[key] = {
                    "_instance_id": instance_id,
                    "instance_key": key,
                    **parsed,
                    "classification": classification,
                    **metadata,
                    "first_utc": utc.isoformat(),
                    "first_elapsed_seconds": elapsed,
                    "last_utc": utc.isoformat(),
                    "last_elapsed_seconds": elapsed,
                    "actions": [action],
                    "sources": [source],
                }
            else:
                if elapsed < state["first_elapsed_seconds"]:
                    state["first_elapsed_seconds"] = elapsed
                    state["first_utc"] = utc.isoformat()
                if elapsed >= state["last_elapsed_seconds"]:
                    state["last_utc"] = utc.isoformat()
                    state["last_elapsed_seconds"] = elapsed
                if action not in state["actions"]:
                    state["actions"].append(action)
                if source not in state["sources"]:
                    state["sources"].append(source)
                for field in ("description", "device_class", "service"):
                    if metadata.get(field) and not state.get(field):
                        state[field] = metadata[field]
        elif action == "removed":
            state = self.active.pop(key, None)
            first_elapsed = state["first_elapsed_seconds"] if state else elapsed
            session = {
                "instance_key": key,
                **parsed,
                "classification": classification,
                **(metadata if state is None else {
                    field: state.get(field) for field in ("description", "device_class", "service")
                }),
                "first_utc": state["first_utc"] if state else utc.isoformat(),
                "first_elapsed_seconds": first_elapsed,
                "last_utc": utc.isoformat(),
                "last_elapsed_seconds": elapsed,
                "duration_seconds": round(max(0.0, elapsed - first_elapsed), 6) if state else None,
                "end_reason": "removed" if state else "removed_without_observed_arrival",
                "actions": (state["actions"] + [action]) if state else [action],
                "sources": (state["sources"] + [source]) if state else [source],
            }
            self.sessions.append(session)
        return True

    def reconcile_snapshot(self, instance_ids: list[str], elapsed: float, utc: datetime,
                           source: str, describe: Optional[Callable[[str], dict]] = None) -> None:
        current: dict[str, str] = {}
        for instance_id in instance_ids:
            if parse_usb_instance(instance_id) is not None:
                current[instance_key(instance_id, self.salt)] = instance_id
        for key in list(self.active):
            if key not in current:
                state = self.active[key]
                self.observe("removed", state["_instance_id"], elapsed, utc, None, source)
        for key, instance_id in current.items():
            if key in self.active:
                state = self.active[key]
                state["last_utc"] = utc.isoformat()
                state["last_elapsed_seconds"] = round(max(0.0, elapsed), 6)
                if source not in state["sources"]:
                    state["sources"].append(source)
            else:
                info = describe(instance_id) if describe else None
                self.observe("present", instance_id, elapsed, utc, info, source)

    def finalize(self, elapsed: float, utc: datetime) -> None:
        elapsed = round(max(0.0, elapsed), 6)
        for state in list(self.active.values()):
            self.sessions.append({
                "instance_key": state["instance_key"],
                **{field: state[field] for field in ("bus", "vid", "pid", "mi", "hardware_id", "classification",
                                                       "description", "device_class", "service")},
                "first_utc": state["first_utc"],
                "first_elapsed_seconds": state["first_elapsed_seconds"],
                "last_utc": utc.isoformat(),
                "last_elapsed_seconds": elapsed,
                "duration_seconds": round(max(0.0, elapsed - state["first_elapsed_seconds"]), 6),
                "end_reason": "still_present_at_end",
                "actions": state["actions"],
                "sources": state["sources"],
            })
        self.active.clear()


class WindowsPnpBackend:
    """Read-only Windows cfgmgr32 PnP notification/metadata backend.

    It never calls CreateFile on a device interface and never opens a COM port.
    """

    name = "windows-cfgmgr32-pnp"

    def __init__(self):
        self._queue: queue.Queue = queue.Queue(maxsize=MAX_EVENTS * 2)
        self._dll = None
        self._handle = None
        self._callback_ref = None
        self._ctypes = None
        self._devpropkey = None
        self.started = False
        self.errors: list[str] = []
        self.callback_errors = 0
        self.callback_dropped = 0

    def start(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError("A passzív USB-figyelő Windows PnP API-t igényel (Windows 10/11).")
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes

        class CM_NOTIFY_FILTER(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("Flags", wintypes.DWORD),
                ("FilterType", wintypes.DWORD),
                ("Reserved", wintypes.DWORD),
                ("InstanceId", ctypes.c_wchar * 200),
            ]

        class DEVPROPKEY(ctypes.Structure):
            _fields_ = [("fmtid", ctypes.c_byte * 16), ("pid", wintypes.DWORD)]

        self._devpropkey = DEVPROPKEY
        callback_type = ctypes.WINFUNCTYPE(
            wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
            wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        )
        backend = self

        def _callback(hnotify, context, action, event_data, event_data_size):
            try:
                if int(action) in CM_ACTIONS and event_data and event_data_size >= 10:
                    size = min(int(event_data_size), 4096)
                    data = ctypes.string_at(int(event_data), size)
                    instance = decode_notification_instance(data)
                    if instance:
                        try:
                            backend._queue.put_nowait((time.monotonic(), datetime.now(timezone.utc),
                                                       int(action), instance))
                        except queue.Full:
                            backend.callback_dropped += 1
            except Exception:
                backend.callback_errors += 1
            return 0

        self._callback_ref = callback_type(_callback)
        self._dll = ctypes.WinDLL("cfgmgr32")
        self._dll.CM_Register_Notification.argtypes = [
            ctypes.POINTER(CM_NOTIFY_FILTER), ctypes.c_void_p, callback_type,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._dll.CM_Register_Notification.restype = wintypes.DWORD
        self._dll.CM_Unregister_Notification.argtypes = [ctypes.c_void_p]
        self._dll.CM_Unregister_Notification.restype = wintypes.DWORD
        self._dll.CM_Get_Device_ID_List_SizeW.argtypes = [
            ctypes.POINTER(wintypes.DWORD), ctypes.c_wchar_p, wintypes.DWORD,
        ]
        self._dll.CM_Get_Device_ID_List_SizeW.restype = wintypes.DWORD
        self._dll.CM_Get_Device_ID_ListW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        ]
        self._dll.CM_Get_Device_ID_ListW.restype = wintypes.DWORD
        self._dll.CM_Locate_DevNodeW.argtypes = [
            ctypes.POINTER(wintypes.DWORD), ctypes.c_wchar_p, wintypes.DWORD,
        ]
        self._dll.CM_Locate_DevNodeW.restype = wintypes.DWORD
        self._dll.CM_Get_DevNode_PropertyW.argtypes = [
            wintypes.DWORD, ctypes.POINTER(DEVPROPKEY), ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
        ]
        self._dll.CM_Get_DevNode_PropertyW.restype = wintypes.DWORD

        notify_filter = CM_NOTIFY_FILTER()
        notify_filter.cbSize = ctypes.sizeof(CM_NOTIFY_FILTER)
        notify_filter.Flags = CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES
        notify_filter.FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE
        notify_filter.InstanceId = ""
        handle = ctypes.c_void_p()
        result = self._dll.CM_Register_Notification(
            ctypes.byref(notify_filter), None, self._callback_ref, ctypes.byref(handle)
        )
        if result != CR_SUCCESS:
            raise RuntimeError(f"CM_Register_Notification sikertelen (CONFIGRET={result}).")
        self._handle = handle
        self.started = True

    def stop(self) -> None:
        if self._handle is not None and self._dll is not None:
            try:
                result = self._dll.CM_Unregister_Notification(self._handle)
                if result != CR_SUCCESS:
                    self.errors.append(f"CM_Unregister_Notification CONFIGRET={result}")
            except Exception as exc:
                self.errors.append(f"CM_Unregister_Notification: {type(exc).__name__}: {exc}")
            self._handle = None
        self.started = False
        self._callback_ref = None

    def drain(self, timeout: float) -> list[tuple]:
        items = []
        try:
            items.append(self._queue.get(timeout=max(0.0, timeout)))
        except queue.Empty:
            return items
        while True:
            try:
                items.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return items

    def snapshot(self) -> Optional[list[str]]:
        """Return present USB enumerator instance IDs, or None on API failure."""
        if self._dll is None:
            return None
        ctypes = self._ctypes
        from ctypes import wintypes
        flags = CM_GETIDLIST_FILTER_ENUMERATOR | CM_GETIDLIST_FILTER_PRESENT
        for _ in range(3):
            size = wintypes.DWORD()
            result = self._dll.CM_Get_Device_ID_List_SizeW(ctypes.byref(size), "USB", flags)
            if result != CR_SUCCESS:
                self.errors.append(f"CM_Get_Device_ID_List_SizeW CONFIGRET={result}")
                return None
            length = int(size.value)
            if length <= 0:
                return []
            buffer = ctypes.create_unicode_buffer(length)
            result = self._dll.CM_Get_Device_ID_ListW("USB", ctypes.cast(buffer, ctypes.c_void_p), length, flags)
            if result == CR_SUCCESS:
                raw = ctypes.string_at(ctypes.addressof(buffer), length * 2).decode("utf-16-le", errors="replace")
                return [part for part in raw.split("\0") if part]
            if result != CR_BUFFER_SMALL:
                self.errors.append(f"CM_Get_Device_ID_ListW CONFIGRET={result}")
                return None
        self.errors.append("CM_Get_Device_ID_ListW CR_BUFFER_SMALL retry exhausted")
        return None

    def _property_key(self, pid: int):
        ctypes = self._ctypes
        key = self._devpropkey()
        guid = uuid.UUID(DEVICE_PROPERTY_GUID)
        key.fmtid = (ctypes.c_byte * 16)(*guid.bytes_le)
        key.pid = pid
        return key

    def describe(self, instance_id: str) -> dict:
        if self._dll is None:
            return {}
        ctypes = self._ctypes
        from ctypes import wintypes
        devinst = wintypes.DWORD()
        result = self._dll.CM_Locate_DevNodeW(ctypes.byref(devinst), instance_id, 0)
        if result != CR_SUCCESS:
            return {}
        info = {}
        for field, pid in DEVICE_PROPERTIES.items():
            key = self._property_key(pid)
            buffer = ctypes.create_unicode_buffer(256)
            required = wintypes.DWORD(ctypes.sizeof(buffer))
            prop_type = wintypes.DWORD()
            result = self._dll.CM_Get_DevNode_PropertyW(
                devinst, ctypes.byref(key), ctypes.byref(prop_type),
                ctypes.cast(buffer, ctypes.c_void_p), ctypes.byref(required), 0,
            )
            if result == CR_BUFFER_SMALL and 0 < int(required.value) <= 65536:
                buffer = ctypes.create_unicode_buffer(int(required.value) // 2 + 1)
                required = wintypes.DWORD(ctypes.sizeof(buffer))
                result = self._dll.CM_Get_DevNode_PropertyW(
                    devinst, ctypes.byref(key), ctypes.byref(prop_type),
                    ctypes.cast(buffer, ctypes.c_void_p), ctypes.byref(required), 0,
                )
            if result == CR_SUCCESS and int(prop_type.value) == DEVPROP_TYPE_STRING:
                info[field] = sanitize_metadata(buffer.value)
        return info


def annotate_sessions_with_markers(sessions: list[dict], markers: list[dict]) -> None:
    """Attach the operator marker that was active when a window opened.

    For every session this records the most recent marker at or before the
    session start, the seconds between that marker and the window opening,
    and any markers that fall inside the window. This is a timing aid only:
    it cannot prove that a button press caused the USB mode.
    """
    if not markers:
        return
    ordered = sorted(markers, key=lambda m: m["elapsed_seconds"])
    for session in sessions:
        first = session.get("first_elapsed_seconds")
        last = session.get("last_elapsed_seconds")
        if first is None:
            continue
        preceding = None
        inside = []
        for marker in ordered:
            if marker["elapsed_seconds"] <= first:
                preceding = marker
            elif last is not None and marker["elapsed_seconds"] <= last:
                inside.append(marker["label"])
        if preceding is None:
            continue
        session["preceding_marker_label"] = preceding["label"]
        session["preceding_marker_elapsed_seconds"] = preceding["elapsed_seconds"]
        session["seconds_after_marker"] = round(first - preceding["elapsed_seconds"], 6)
        if inside:
            session["markers_inside_window"] = inside


def interpret(report: dict) -> list[str]:
    notes = [
        "Passzív Windows PnP/USB megfigyelés: a program nem nyitott meg eszközt és nem küldött USB/ADB/fastboot/MTK parancsot.",
        "A VID/PID egyezés csak jelölt; nem bizonyít BROM-exploitot, DA betöltést, SLA/DAA megkerülést vagy írható seccfg hozzáférést.",
        "A láthatósági idő Windows PnP idő, nem pontos preloader handshake idő. A jelölt hiánya nem bizonyítja, hogy nincs preloader ablak.",
    ]
    incomplete = (report.get("issue") or report.get("backend_errors") or report.get("callback_errors")
                  or report.get("callback_dropped") or report.get("dropped_events")
                  or report.get("stop_reason") in ("error", "interrupted"))
    if incomplete:
        notes.append("A megfigyelés hiányos vagy hibás lehet; a negatív eredményt nem szabad bizonyítékként kezelni.")
    if report.get("marker_reader_error"):
        notes.append(
            "A marker-beolvasó hibát jelzett, ezért a gombpróba időpontja hiányos lehet: "
            f"{report['marker_reader_error']}"
        )
    if report.get("markers"):
        notes.append(
            f"Operátor-markerek rögzítve: {len(report['markers'])} db. A marker a pillanat, "
            "amikor Entert nyomtál; a gombállapotot a marker szövege írja le, "
            "a program azt nem látja."
        )
    candidates = report.get("candidate_sessions", [])
    if candidates:
        notes.append("Jelölt USB módok látszottak; a következő lépés csak a napló elemzése után, külön jóváhagyással dönthető el.")
        if any(s.get("classification") == "mediatek_lk_fastboot_candidate" for s in candidates):
            notes.append(
                "MediaTek LK fastboot jelölt (0E8D:201C) látszott: ez bootloader-fastboot lehet, "
                "nem preloader/BROM. A bootloader- vagy fastbootd-mivolt csak külön, csak olvasó "
                "getvar is-userspace lekérdezéssel dönthető el, amit ez a figyelő nem küld."
            )
    elif not incomplete:
        notes.append("Nem látszott ismert MTK BROM/preloader/DA, MTK LK fastboot vagy TCL ADB jelölt a rögzített ablakban.")
    return notes


def build_report(tracker: UsbTracker, *, backend_name: str, requested_seconds: float,
                 actual_seconds: float, started_utc: datetime, stopped_utc: datetime,
                 stop_reason: str, issue: Optional[str], initial_count: Optional[int],
                 final_count: Optional[int], snapshot_count: int, backend_errors: list[str],
                 callback_errors: int, callback_dropped: int,
                 marker_reader_error: Optional[str] = None) -> dict:
    candidate_sessions = [s for s in tracker.sessions if s["classification"] != "other_usb"]
    complete = (stop_reason == "completed" and not issue and not backend_errors
                and callback_errors == 0 and callback_dropped == 0 and tracker.dropped_events == 0)
    report = {
        "schema_version": REPORT_SCHEMA,
        "tool_version": VERSION,
        "created_utc": stopped_utc.isoformat(),
        "mode": "passive-usb-pnp",
        "backend": backend_name,
        "read_only_on_phone": True,
        "opened_device_handles": False,
        "usb_transfers": False,
        "driver_changes": False,
        "uploaded_by_tool": False,
        "requested_seconds": requested_seconds,
        "actual_seconds": round(max(0.0, actual_seconds), 6),
        "started_utc": started_utc.isoformat(),
        "stopped_utc": stopped_utc.isoformat(),
        "stop_reason": stop_reason,
        "complete": complete,
        "issue": issue,
        "initial_usb_devices": initial_count,
        "final_usb_devices": final_count,
        "snapshot_count": snapshot_count,
        "backend_errors": backend_errors[:50],
        "callback_errors": callback_errors,
        "callback_dropped": callback_dropped,
        "dropped_events": tracker.dropped_events,
        "ignored_non_usb_events": tracker.ignored_non_usb,
        "events_recorded": len(tracker.events),
        "sessions_recorded": len(tracker.sessions),
        "markers": list(tracker.markers),
        "markers_recorded": len(tracker.markers),
        "markers_dropped": tracker.markers_dropped,
        "marker_reader_error": marker_reader_error,
        "candidate_sessions": candidate_sessions,
        "events": tracker.events,
        "sessions": tracker.sessions,
    }
    annotate_sessions_with_markers(report["sessions"], report["markers"])
    report["candidate_sessions"] = [
        s for s in report["sessions"] if s["classification"] != "other_usb"
    ]
    report["interpretation"] = interpret(report)
    return report


def render_text(report: dict) -> str:
    lines = [
        "TCL 505 / T509K – passzív Windows USB/PnP figyelő",
        "=" * 52,
        f"Program: {report['tool_version']} | Backend: {report['backend']}",
        f"Kezdés (UTC): {report['started_utc']}",
        f"Befejezés (UTC): {report['stopped_utc']}",
        f"Kért idő: {report['requested_seconds']} s | Mért idő: {report['actual_seconds']} s",
        f"Leállás oka: {report['stop_reason']} | Teljes ablak: {'igen' if report.get('complete') else 'nem/hiányos'}",
        "A program nem nyitott meg eszközt, nem küldött USB transzfert, nem telepített drivert, nem futtatott exploit/DA műveletet, nem írt partíciót és nem indított újra.",
        "",
    ]
    if report.get("issue"):
        lines.append(f"Hiba: {report['issue']}")
        lines.append("")
    lines.extend(report["interpretation"])
    lines.extend([
        "",
        f"Kezdeti USB eszközök: {report['initial_usb_devices']}",
        f"Végső USB eszközök: {report['final_usb_devices']}",
        f"Pillanatképek: {report['snapshot_count']}",
        f"Rögzített események: {report['events_recorded']} | Munkamenetek: {report['sessions_recorded']}",
        f"Eldobott események: {report['dropped_events']} | Callback hiba/eldobott: {report['callback_errors']}/{report['callback_dropped']}",
        f"Nem USB események: {report['ignored_non_usb_events']}",
        f"Operátor-markerek: {report.get('markers_recorded', 0)} | eldobott marker: {report.get('markers_dropped', 0)}",
        "",
        "Operátor-markerek (az a pillanat, amikor Entert nyomtál)",
        "-" * 51,
    ])
    markers = report.get("markers") or []
    if not markers:
        lines.append("(nincs marker – a naplóban csak relatív idő van)")
    for marker in markers:
        lines.append(f"[{marker['elapsed_seconds']:9.3f}s] {marker['label']}")
    lines.extend([
        "",
        "Jelölt munkamenetek",
        "-" * 18,
    ])
    if not report["candidate_sessions"]:
        lines.append("(nincs)")
    for session in report["candidate_sessions"]:
        duration = session["duration_seconds"]
        duration_text = "ismeretlen" if duration is None else f"{duration:.6f} s"
        line = (
            f"{session['hardware_id']} | {session['classification']} | látható: {duration_text} | "
            f"ok: {session['end_reason']} | osztály: {session.get('device_class') or '-'} | "
            f"szolgáltatás: {session.get('service') or '-'}"
        )
        if session.get("preceding_marker_label") is not None:
            line += (f" | előző marker: \"{session['preceding_marker_label']}\""
                     f" (+{session['seconds_after_marker']:.3f} s)")
        if session.get("markers_inside_window"):
            line += " | ablakon belül: " + ", ".join(
                f"\"{label}\"" for label in session["markers_inside_window"])
        lines.append(line)
    lines.extend(["", "Utolsó események (max. 50; teljes lista a JSON-ban)", "-" * 49])
    for event in report["events"][-50:]:
        lines.append(
            f"[{event['elapsed_seconds']:.6f}s] {event['action']} {event['hardware_id']} "
            f"{event['classification']} ({event['source']})"
        )
    lines.extend(["", "A fájlok helyben készülnek; a program nem tölt fel adatot.",
                  "Megosztás előtt nézd át a tartalmat. Az eszköz instance-azonosítója/serialja nem kerül a jelentésbe."])
    return "\n".join(lines) + "\n"


def write_bundle(report: dict, output_dir: Path) -> tuple[Path, dict, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    bundle = output_dir / f"tcl505-usb-{stamp}"
    bundle.mkdir(parents=True, exist_ok=False)
    json_path = bundle / "report.json"
    text_path = bundle / "report.txt"
    with json_path.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    with text_path.open("x", encoding="utf-8") as handle:
        handle.write(render_text(report))
    (bundle / "README.txt").write_text(
        "TCL 505 / T509K passzív USB/PnP jelentés\n"
        "A program csak Windows PnP metaadatot figyelt; nem nyitott meg eszközt, nem írt a telefonra és nem töltött fel.\n"
        "A report.json teljes eseménynapló, a report.txt összefoglaló, a manifest.json fájlkivonatokat tartalmaz.\n"
        "Az instance-azonosító/serial csak futásonkénti sózott kivonatként szerepel. Megosztás előtt nézd át a fájlokat.\n",
        encoding="utf-8")
    files = []
    for path in sorted(bundle.iterdir()):
        if path.is_file() and path.name != "manifest.json":
            payload = path.read_bytes()
            files.append({"file": path.name, "bytes": len(payload),
                          "sha256": hashlib.sha256(payload).hexdigest()})
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "tool_version": VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "passive-usb-pnp",
        "read_only_on_phone": True,
        "uploaded_by_tool": False,
        "complete": report.get("complete", False),
        "stop_reason": report["stop_reason"],
        "issue": report.get("issue"),
        "files": files,
    }
    with (bundle / "manifest.json").open("x", encoding="utf-8") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    zip_path = output_dir / f"{bundle.name}.zip"
    with zipfile.ZipFile(zip_path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(bundle.rglob("*")):
            if path.is_file() and not path.is_symlink():
                archive.write(path, f"{bundle.name}/{path.relative_to(bundle).as_posix()}")
    return bundle, manifest, zip_path


def _append_issue(issue: Optional[str], message: str) -> str:
    return f"{issue}; {message}" if issue else message


class _ClosedStream:
    """Stand-in stream used after cancel(); readline() blocks forever."""

    def readline(self) -> bytes:
        threading.Event().wait()
        return b""


_CLOSED_STREAM = _ClosedStream()


class MarkerReader(threading.Thread):
    """Read operator markers from stdin while the observation runs.

    Every line the user enters becomes an immediate timestamped marker: the
    elapsed time and the UTC time are printed the moment Enter is pressed,
    so no timing has to be remembered. An empty line gets an automatic label.
    The reader never touches the USB or phone side.
    """

    def __init__(self, on_marker: Callable[[str], None], prompt: str = "marker> ",
                 stream=None):
        super().__init__(daemon=True, name="tcl505-marker-reader")
        self.on_marker = on_marker
        self.prompt = prompt
        self.stream = stream
        self._stop_event = threading.Event()
        self._cancelled = False
        self.error: Optional[str] = None

    def run(self) -> None:
        stream = self.stream if self.stream is not None else getattr(sys.stdin, "buffer", sys.stdin)
        try:
            while not self._stop_event.is_set() and not self._cancelled:
                print(self.prompt, end="", flush=True)
                line = stream.readline()
                if not line:
                    break
                if isinstance(line, bytes):
                    line = line.decode("utf-8", errors="replace")
                # A line already read is still recorded: the operator pressed
                # Enter before the observation window closed.
                text = line.strip()
                if not text:
                    text = "marker"
                self.on_marker(text)
        except Exception as exc:  # stdin closed, not a terminal, etc.
            self.error = f"{type(exc).__name__}: {exc}"

    def stop(self) -> None:
        self._stop_event.set()

    def cancel(self) -> None:
        """Abandon the reader without touching stdin again.

        Called at shutdown: the blocked daemon thread stays parked in
        readline(), but no further read is attempted, so Python's
        buffered-stdin lock cannot collide with interpreter finalisation
        (that collision is the _enter_buffered_busy fatal error).
        """
        self._cancelled = True
        self.stop()


def _echo_event(action: str, parsed: dict, elapsed: float, first_seen: dict,
                info: Optional[dict] = None) -> None:
    """Print interesting USB events while the observation is running.

    Only MTK/TCL candidates are echoed, so ordinary mouse/keyboard churn does
    not scroll the marker prompt away. Every printed line is timestamped, and
    on removal the visible duration is computed, which is exactly the piece of
    timing the user otherwise has to reconstruct afterwards. Nothing is opened
    or sent.
    """
    classification = classify_usb(parsed["vid"], parsed["pid"])
    if classification == "other_usb":
        return
    key = parsed["hardware_id"]
    if action == "removed":
        start = first_seen.pop(key, None)
        held = f"  ({elapsed - start:.3f} s)" if start is not None else ""
        print(f"[{elapsed:9.3f}s] ELTUNT   {key}  ({classification}){held}", flush=True)
        return
    if key in first_seen:
        return
    first_seen[key] = elapsed
    description = (info or {}).get("description") or ""
    tail = f'  "{description}"' if description else ""
    print(f"[{elapsed:9.3f}s] MEGJELENT {key}  ({classification}){tail}", flush=True)


def collect_watch(seconds: float, output_dir: Path, backend=None,
                  clock: Callable[[], float] = time.monotonic,
                  utc_now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                  markers: bool = False,
                  marker_reader: Optional[MarkerReader] = None,
                  marker_stream=None,
                  echo: bool = False) -> tuple[dict, Path, Path]:
    backend = backend if backend is not None else WindowsPnpBackend()
    tracker = UsbTracker()
    started_clock = clock()
    started_utc = utc_now()
    issue = None
    stop_reason = "completed"
    initial_count = None
    final_count = None
    snapshot_count = 0

    live_seen: dict[str, float] = {}

    def process_events(items: list[tuple]) -> None:
        for monotonic, event_utc, action, instance_id in items:
            action_name = CM_ACTIONS.get(int(action))
            if action_name is None:
                continue
            info = None
            parsed = parse_usb_instance(instance_id)
            if action_name in ("enumerated", "started") and parsed is not None:
                info = backend.describe(instance_id)
            elapsed = monotonic - started_clock
            if echo and parsed is not None:
                _echo_event(action_name, parsed, elapsed, live_seen, info)
            tracker.observe(action_name, instance_id, elapsed, event_utc, info, "notification")

    def record_marker(text: str) -> None:
        elapsed = clock() - started_clock
        stamp = utc_now()
        if tracker.add_marker(text, elapsed, stamp):
            print(f"[{elapsed:9.3f}s] marker: {text} ({stamp.isoformat(timespec='seconds')})", flush=True)
        else:
            print(f"[{elapsed:9.3f}s] marker eldobva: {text}", flush=True)

    if marker_reader is None and markers:
        marker_reader = MarkerReader(record_marker, stream=marker_stream)
    if marker_reader is not None:
        try:
            marker_reader.start()
            globals()["_MARKER_THREAD_STARTED"] = True
        except Exception as exc:
            issue = _append_issue(issue, f"marker_reader: {type(exc).__name__}: {exc}")
            marker_reader = None

    try:
        backend.start()
        initial = backend.snapshot()
        if initial is None:
            issue = _append_issue(issue, "initial_snapshot: nem sikerült lekérdezni a jelenlévő USB eszközöket.")
        else:
            initial_count = sum(parse_usb_instance(item) is not None for item in initial)
            tracker.reconcile_snapshot(initial, 0.0, started_utc, "initial_snapshot", backend.describe)
            snapshot_count += 1
        next_snapshot = SNAPSHOT_INTERVAL
        while True:
            elapsed = clock() - started_clock
            if elapsed >= seconds:
                break
            wait = min(DRAIN_TIMEOUT, seconds - elapsed, max(0.0, next_snapshot - elapsed))
            process_events(backend.drain(wait))
            elapsed = clock() - started_clock
            if elapsed >= next_snapshot:
                current = backend.snapshot()
                if current is not None:
                    tracker.reconcile_snapshot(current, elapsed, utc_now(), "periodic_snapshot", backend.describe)
                    snapshot_count += 1
                next_snapshot = max(next_snapshot + SNAPSHOT_INTERVAL, elapsed + SNAPSHOT_INTERVAL)
    except KeyboardInterrupt:
        stop_reason = "interrupted"
    except Exception as exc:
        stop_reason = "error"
        issue = _append_issue(issue, f"{type(exc).__name__}: {exc}")
    finally:
        if marker_reader is not None:
            try:
                # A piped/file stream reaches EOF and delivers its last lines;
                # an interactive terminal read times out and is cancelled.
                marker_reader.join(timeout=0.3)
                marker_reader.cancel()
            except Exception as exc:
                issue = _append_issue(issue, f"marker_reader_stop: {type(exc).__name__}: {exc}")
        try:
            backend.stop()
        except Exception as exc:
            issue = _append_issue(issue, f"backend_stop: {type(exc).__name__}: {exc}")
        try:
            process_events(backend.drain(0))
        except Exception as exc:
            issue = _append_issue(issue, f"final_drain: {type(exc).__name__}: {exc}")
        elapsed = clock() - started_clock
        stopped_utc = utc_now()
        try:
            final = backend.snapshot()
            if final is None:
                issue = _append_issue(issue, "final_snapshot: nem sikerült lekérdezni a jelenlévő USB eszközöket.")
            else:
                final_count = sum(parse_usb_instance(item) is not None for item in final)
                tracker.reconcile_snapshot(final, elapsed, stopped_utc, "final_snapshot", backend.describe)
                snapshot_count += 1
        except Exception as exc:
            issue = _append_issue(issue, f"final_snapshot: {type(exc).__name__}: {exc}")
        tracker.finalize(elapsed, stopped_utc)
        report = build_report(
            tracker, backend_name=getattr(backend, "name", type(backend).__name__),
            requested_seconds=seconds, actual_seconds=elapsed, started_utc=started_utc,
            stopped_utc=stopped_utc, stop_reason=stop_reason, issue=issue,
            initial_count=initial_count, final_count=final_count, snapshot_count=snapshot_count,
            backend_errors=list(getattr(backend, "errors", [])),
            callback_errors=int(getattr(backend, "callback_errors", 0)),
            callback_dropped=int(getattr(backend, "callback_dropped", 0)),
            marker_reader_error=(marker_reader.error if marker_reader is not None else None),
        )
        bundle, _manifest, zip_path = write_bundle(report, output_dir)
    return report, bundle, zip_path


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="TCL 505/T509K passzív Windows USB/PnP figyelő. Nem nyit meg eszközt és nem ír a telefonra."
    )
    parser.add_argument("--seconds", type=float, default=DEFAULT_SECONDS,
                        help=f"Megfigyelési idő másodpercben ({MIN_SECONDS:g}–{MAX_SECONDS:g}, alap: {DEFAULT_SECONDS:g}).")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent / "reports")
    parser.add_argument("--no-markers", action="store_true",
                        help="Ne olvasson markereket a billentyuzetrol (kimenet atiranyitasakor).")
    args = parser.parse_args(argv)
    if not math.isfinite(args.seconds) or not MIN_SECONDS <= args.seconds <= MAX_SECONDS:
        parser.error(f"--seconds: {MIN_SECONDS:g} és {MAX_SECONDS:g} közötti véges érték szükséges.")
    if sys.platform != "win32":
        print("Ez a figyelő Windows 10/11 PnP API-t használ; Linux alatt nem futtatható.", file=sys.stderr)
        return 2
    report = bundle = zip_path = None
    try:
        print(f"Passzív USB/PnP figyelés indul ({args.seconds:g} s). Ctrl+C: leállítás és részleges jelentés.")
        print("A program nem nyit meg eszközt, nem telepít drivert és nem indítja újra a telefont.")
        if not args.no_markers:
            print("MARKER: minden gombproba pillanataban nyomj Entert, es irj be egy rovid cimket,")
            print("        pl. 'Vol+ bedugas' vagy 'gomb nelkul'. A program azonnal kiirja az idopontot.")
            print("        A markerek a jelentésben az USB-ablakokhoz lesznek rendelve.")
        report, bundle, zip_path = collect_watch(
            args.seconds, args.output_dir.expanduser().resolve(),
            markers=not args.no_markers,
            echo=True,
        )
    except (OSError, ValueError) as exc:
        print(f"Nem sikerült a jelentés elkészítése: {exc}", file=sys.stderr)
        return 2
    print(render_text(report))
    print(f"Jelentésmappa: {bundle}\nSzöveges jelentés: {bundle / 'report.txt'}\nJSON jelentés: {bundle / 'report.json'}")
    print(f"Feltölthető ZIP: {zip_path}")
    sys.stdout.flush()
    code = 0 if report.get("complete") else 1
    if globals().get("_MARKER_THREAD_STARTED"):
        # The marker thread is parked in stdin.readline(). Do not let the
        # interpreter finalise its buffered stdin under that thread (that is
        # the _enter_buffered_busy crash); leave the process immediately.
        os._exit(code)
    return code


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
