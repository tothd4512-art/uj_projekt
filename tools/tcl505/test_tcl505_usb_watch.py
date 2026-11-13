"""Offline tests for the passive Windows USB/PnP watcher.

No phone, no Windows API calls, no network. The cfgmgr32 backend is replaced
by a scripted fake; only the pure logic and report packaging run here.
"""
import ast
import contextlib
import io
import json
import shutil
import struct
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import tcl505_usb_watch as watch

TCL = "USB\\VID_1BBB&PID_0C01\\SERIAL-TCL-123"
BROM = "USB\\VID_0E8D&PID_0003&MI_00\\SERIAL-BROM-456"
PRELOADER = "USB\\VID_0E8D&PID_2000\\SERIAL-PRE-789"
NOW = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)


def utc(seconds=0.0):
    return datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc).fromtimestamp(
        NOW.timestamp() + seconds, tz=timezone.utc)


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def advance(self, delta):
        self.value += delta


class FakeBackend:
    name = "fake-pnp"

    def __init__(self, snapshots=None, events=None, start_error=None,
                 snapshot_none=False, interrupt=False):
        self.snapshots = snapshots if snapshots is not None else [[]]
        self.events = list(events or [])
        self.start_error = start_error
        self.snapshot_none = snapshot_none
        self.interrupt = interrupt
        self.clock = None
        self.calls = []
        self.snapshot_index = 0
        self.started = False
        self.ready = False
        self.errors = []
        self.callback_errors = 0
        self.callback_dropped = 0

    def start(self):
        self.calls.append("start")
        if self.start_error:
            raise self.start_error
        self.started = True
        self.ready = True

    def stop(self):
        self.calls.append("stop")
        self.started = False

    def drain(self, timeout):
        self.calls.append(("drain", timeout))
        if self.interrupt:
            self.interrupt = False
            raise KeyboardInterrupt()
        if self.clock is not None:
            self.clock.advance(max(0.0, timeout))
        now = self.clock.value if self.clock else 0.0
        due = [event for event in self.events if event[0] <= now + 1e-9]
        self.events = [event for event in self.events if event[0] > now + 1e-9]
        return due

    def snapshot(self):
        self.calls.append("snapshot")
        if not self.ready or self.snapshot_none:
            return None
        index = min(self.snapshot_index, len(self.snapshots) - 1)
        self.snapshot_index += 1
        return list(self.snapshots[index])

    def describe(self, instance_id):
        self.calls.append(("describe", instance_id))
        return {"description": "MediaTek PreLoader USB VCOM (COM3)",
                "device_class": "Ports", "service": "usbser"}


def make_report(**overrides):
    tracker = watch.UsbTracker(salt="test-salt")
    kwargs = dict(backend_name="fake-pnp", requested_seconds=1.0, actual_seconds=1.0,
                  started_utc=NOW, stopped_utc=utc(1.0), stop_reason="completed",
                  issue=None, initial_count=0, final_count=0, snapshot_count=2,
                  backend_errors=[], callback_errors=0, callback_dropped=0)
    kwargs.update(overrides)
    return watch.build_report(tracker, **kwargs)


class ParsingTests(unittest.TestCase):
    def test_usb_instance_extracts_vid_pid_mi_without_serial(self):
        parsed = watch.parse_usb_instance(BROM)
        self.assertEqual(parsed["vid"], "0E8D")
        self.assertEqual(parsed["pid"], "0003")
        self.assertEqual(parsed["mi"], "00")
        self.assertEqual(parsed["hardware_id"], "USB\\VID_0E8D&PID_0003&MI_00")
        self.assertNotIn("SERIAL-BROM-456", json.dumps(parsed))

    def test_lowercase_and_no_mi(self):
        parsed = watch.parse_usb_instance("usb\\vid_0e8d&pid_2000\\abc")
        self.assertEqual(parsed["hardware_id"], "USB\\VID_0E8D&PID_2000")
        self.assertIsNone(parsed["mi"])

    def test_non_usb_or_incomplete_ids_are_ignored(self):
        for value in ("", None, "COM3", "PCI\\VEN_1234&DEV_5678",
                      "USB\\VID_0E8D", "USB\\ROOT_HUB30\\4&abc",
                      "USBSTOR\\Disk&Ven_Test&Prod_Test\\123"):
            self.assertIsNone(watch.parse_usb_instance(value))

    def test_classification_hints(self):
        self.assertEqual(watch.classify_usb("0E8D", "0003"), "mediatek_brom_candidate")
        self.assertEqual(watch.classify_usb("0e8d", "2000"), "mediatek_preloader_candidate")
        self.assertEqual(watch.classify_usb("0E8D", "2001"), "mediatek_preloader_or_da_candidate")
        self.assertEqual(watch.classify_usb("0E8D", "201C"), "mediatek_lk_fastboot_candidate")
        self.assertEqual(watch.classify_usb("0e8d", "201c"), "mediatek_lk_fastboot_candidate")
        self.assertEqual(watch.classify_usb("0E8D", "9999"), "mediatek_other_usb")
        self.assertEqual(watch.classify_usb("1BBB", "0C01"), "tcl_adb_usb_candidate")
        self.assertEqual(watch.classify_usb("1BBB", "0001"), "tcl_other_usb")
        self.assertEqual(watch.classify_usb("1234", "5678"), "other_usb")

    def test_notification_decode_deviceinstance(self):
        instance = PRELOADER
        payload = instance.encode("utf-16-le") + b"\x00\x00"
        data = struct.pack("<II", watch.CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE, 0) + payload
        self.assertEqual(watch.decode_notification_instance(data), instance)

    def test_notification_decode_rejects_other_filter_and_short_buffers(self):
        payload = PRELOADER.encode("utf-16-le") + b"\x00\x00"
        other = struct.pack("<II", 0, 0) + payload
        self.assertIsNone(watch.decode_notification_instance(other))
        self.assertIsNone(watch.decode_notification_instance(b"\x02\x00"))
        empty = struct.pack("<II", watch.CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE, 0) + b"\x00\x00"
        self.assertIsNone(watch.decode_notification_instance(empty))

    def test_instance_key_is_salted_and_does_not_leak_id(self):
        key1 = watch.instance_key(TCL, "salt-a")
        key2 = watch.instance_key(TCL, "salt-a")
        key3 = watch.instance_key(TCL, "salt-b")
        self.assertEqual(key1, key2)
        self.assertNotEqual(key1, key3)
        self.assertNotIn("SERIAL-TCL-123", key1)
        self.assertEqual(len(key1), 16)


class SanitizationTests(unittest.TestCase):
    def test_metadata_redacts_identifiers_and_control_chars(self):
        cleaned = watch.sanitize_metadata("Port serial=ABC123 IMEI: 123456789012345\x00\x07")
        self.assertNotIn("ABC123", cleaned)
        self.assertNotIn("123456789012345", cleaned)
        self.assertNotIn("\x00", cleaned)
        self.assertNotIn("\x07", cleaned)

    def test_metadata_cap_and_none(self):
        self.assertIsNone(watch.sanitize_metadata(None))
        self.assertIsNone(watch.sanitize_metadata("   "))
        self.assertEqual(len(watch.sanitize_metadata("x" * 1000)), watch.MAX_METADATA)


class TrackerTests(unittest.TestCase):
    def test_enumerated_started_removed_duration(self):
        tracker = watch.UsbTracker(salt="s")
        tracker.observe("enumerated", BROM, 0.25, utc(0.25), {"description": "MTK BROM"})
        tracker.observe("started", BROM, 0.30, utc(0.30))
        tracker.observe("removed", BROM, 0.75, utc(0.75))
        tracker.finalize(1.0, utc(1.0))
        self.assertEqual(len(tracker.sessions), 1)
        session = tracker.sessions[0]
        self.assertEqual(session["end_reason"], "removed")
        self.assertAlmostEqual(session["duration_seconds"], 0.5)
        self.assertEqual(session["classification"], "mediatek_brom_candidate")
        self.assertNotIn("SERIAL-BROM-456", json.dumps(tracker.events + tracker.sessions))

    def test_removed_without_arrival_has_unknown_duration(self):
        tracker = watch.UsbTracker(salt="s")
        tracker.observe("removed", BROM, 0.5, utc(0.5))
        self.assertIsNone(tracker.sessions[0]["duration_seconds"])
        self.assertEqual(tracker.sessions[0]["end_reason"], "removed_without_observed_arrival")

    def test_finalize_marks_still_present(self):
        tracker = watch.UsbTracker(salt="s")
        tracker.observe("present", TCL, 0.0, NOW)
        tracker.finalize(2.0, utc(2.0))
        self.assertEqual(tracker.sessions[0]["end_reason"], "still_present_at_end")
        self.assertAlmostEqual(tracker.sessions[0]["duration_seconds"], 2.0)
        self.assertEqual(tracker.active, {})

    def test_snapshot_reconcile_adds_and_removes(self):
        tracker = watch.UsbTracker(salt="s")
        tracker.reconcile_snapshot([TCL], 0.0, NOW, "initial_snapshot")
        self.assertIn(watch.instance_key(TCL, "s"), tracker.active)
        tracker.reconcile_snapshot([BROM], 1.0, utc(1.0), "periodic_snapshot")
        self.assertEqual(tracker.sessions[0]["end_reason"], "removed")
        self.assertIn(watch.instance_key(BROM, "s"), tracker.active)

    def test_non_usb_ignored_and_event_cap(self):
        tracker = watch.UsbTracker(salt="s", max_events=1)
        self.assertFalse(tracker.observe("started", "COM3", 0.0, NOW))
        self.assertEqual(tracker.ignored_non_usb, 1)
        tracker.observe("started", TCL, 0.0, NOW)
        tracker.observe("removed", TCL, 0.5, utc(0.5))
        self.assertEqual(len(tracker.events), 1)
        self.assertEqual(tracker.dropped_events, 1)
        self.assertEqual(len(tracker.sessions), 1)

    def test_out_of_order_notification_does_not_shrink_window(self):
        tracker = watch.UsbTracker(salt="s")
        tracker.observe("present", BROM, 0.5, utc(0.5))
        tracker.observe("enumerated", BROM, 0.2, utc(0.2))
        tracker.observe("removed", BROM, 0.9, utc(0.9))
        session = tracker.sessions[0]
        self.assertAlmostEqual(session["first_elapsed_seconds"], 0.2)
        self.assertAlmostEqual(session["duration_seconds"], 0.7)


class ReportTests(unittest.TestCase):
    def test_complete_report_interpretation(self):
        report = make_report()
        self.assertTrue(report["complete"])
        self.assertFalse(report["opened_device_handles"])
        self.assertFalse(report["usb_transfers"])
        self.assertFalse(report["driver_changes"])
        self.assertFalse(report["uploaded_by_tool"])
        self.assertTrue(any("Nem látszott" in note for note in report["interpretation"]))

    def test_incomplete_report_warns(self):
        report = make_report(stop_reason="error", issue="RuntimeError: teszt")
        self.assertFalse(report["complete"])
        self.assertTrue(any("hiányos" in note for note in report["interpretation"]))
        self.assertFalse(any("Nem látszott" in note for note in report["interpretation"]))

    def test_candidate_session_reported(self):
        tracker = watch.UsbTracker(salt="s")
        tracker.observe("present", BROM, 0.0, NOW)
        tracker.finalize(1.0, utc(1.0))
        report = watch.build_report(
            tracker, backend_name="fake", requested_seconds=1.0, actual_seconds=1.0,
            started_utc=NOW, stopped_utc=utc(1.0), stop_reason="completed", issue=None,
            initial_count=1, final_count=0, snapshot_count=2, backend_errors=[],
            callback_errors=0, callback_dropped=0)
        self.assertEqual(len(report["candidate_sessions"]), 1)
        text = watch.render_text(report)
        self.assertIn("USB\\VID_0E8D&PID_0003", text)
        self.assertNotIn("SERIAL-BROM-456", text)

    def test_lk_fastboot_candidate_gets_own_note(self):
        tracker = watch.UsbTracker(salt="s")
        tracker.observe("enumerated", "USB\\VID_0E8D&PID_201C\\SERIAL-LK-321", 0.0, NOW,
                        {"description": "Android Bootloader Interface"})
        tracker.observe("removed", "USB\\VID_0E8D&PID_201C\\SERIAL-LK-321", 4.0, utc(4.0))
        report = watch.build_report(
            tracker, backend_name="fake", requested_seconds=5.0, actual_seconds=5.0,
            started_utc=NOW, stopped_utc=utc(5.0), stop_reason="completed", issue=None,
            initial_count=0, final_count=0, snapshot_count=6, backend_errors=[],
            callback_errors=0, callback_dropped=0)
        self.assertEqual(report["candidate_sessions"][0]["classification"],
                         "mediatek_lk_fastboot_candidate")
        notes = " ".join(report["interpretation"])
        self.assertIn("LK fastboot", notes)
        self.assertIn("getvar is-userspace", notes)
        self.assertNotIn("SERIAL-LK-321", json.dumps(report))
        text = watch.render_text(report)
        self.assertIn("0E8D&PID_201C", text)
        self.assertNotIn("SERIAL-LK-321", text)

    def test_write_bundle_manifest_and_zip(self):
        report = make_report()
        with tempfile.TemporaryDirectory() as directory:
            bundle, manifest, zip_path = watch.write_bundle(report, Path(directory))
            self.assertTrue((bundle / "report.json").is_file())
            self.assertTrue((bundle / "report.txt").is_file())
            self.assertTrue((bundle / "manifest.json").is_file())
            self.assertTrue(zip_path.is_file())
            for entry in manifest["files"]:
                payload = (bundle / entry["file"]).read_bytes()
                self.assertEqual(entry["bytes"], len(payload))
                import hashlib
                self.assertEqual(entry["sha256"], hashlib.sha256(payload).hexdigest())
            with zipfile.ZipFile(zip_path) as archive:
                self.assertIsNone(archive.testzip())
                names = archive.namelist()
                self.assertIn(f"{bundle.name}/report.json", names)
                self.assertIn(f"{bundle.name}/manifest.json", names)
            saved = json.loads((bundle / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["schema_version"], watch.REPORT_SCHEMA)


class CollectionTests(unittest.TestCase):
    def collect(self, backend, seconds=1.0):
        clock = FakeClock()
        backend.clock = clock
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        return watch.collect_watch(
            seconds, directory, backend=backend, clock=clock, utc_now=lambda: NOW)

    def test_happy_path_registers_before_snapshot_and_packages(self):
        events = [(0.30, utc(0.30), 7, BROM), (0.35, utc(0.35), 8, BROM),
                  (0.80, utc(0.80), 9, BROM)]
        backend = FakeBackend(snapshots=[[TCL], [TCL], []], events=events)
        report, bundle, zip_path = self.collect(backend)
        self.assertTrue(report["complete"])
        self.assertEqual(report["stop_reason"], "completed")
        self.assertEqual(backend.calls[0], "start")
        self.assertEqual(backend.calls[1], "snapshot")
        self.assertIn("stop", backend.calls)
        classifications = {s["classification"] for s in report["candidate_sessions"]}
        self.assertIn("mediatek_brom_candidate", classifications)
        self.assertTrue(zip_path.is_file())
        self.assertNotIn("SERIAL-BROM-456", (bundle / "report.json").read_text(encoding="utf-8"))

    def test_start_failure_still_writes_report(self):
        backend = FakeBackend(start_error=RuntimeError("PnP nem erheto el"))
        report, bundle, zip_path = self.collect(backend)
        self.assertFalse(report["complete"])
        self.assertEqual(report["stop_reason"], "error")
        self.assertIn("PnP nem erheto el", report["issue"])
        self.assertTrue(zip_path.is_file())
        self.assertIn("stop", backend.calls)

    def test_keyboard_interrupt_writes_partial_report(self):
        backend = FakeBackend(snapshots=[[]], interrupt=True)
        report, _, zip_path = self.collect(backend)
        self.assertEqual(report["stop_reason"], "interrupted")
        self.assertFalse(report["complete"])
        self.assertTrue(zip_path.is_file())

    def test_snapshot_failure_marks_incomplete(self):
        backend = FakeBackend(snapshot_none=True)
        backend.started = True
        report, _, _ = self.collect(backend)
        self.assertFalse(report["complete"])
        self.assertIsNotNone(report["issue"])


class WindowsBackendOfflineTests(unittest.TestCase):
    def test_start_requires_windows(self):
        backend = watch.WindowsPnpBackend()
        with mock.patch.object(watch.sys, "platform", "linux"):
            with self.assertRaises(RuntimeError):
                backend.start()
        self.assertIsNone(backend.snapshot())
        self.assertEqual(backend.describe(TCL), {})
        backend.stop()

    def test_action_constants(self):
        self.assertEqual(watch.CM_ACTIONS, {7: "enumerated", 8: "started", 9: "removed"})
        self.assertEqual(watch.CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE, 2)
        self.assertEqual(watch.CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES, 2)


class CliTests(unittest.TestCase):
    def test_non_windows_returns_2(self):
        with mock.patch.object(watch.sys, "platform", "linux"), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(watch.main([]), 2)

    def test_invalid_seconds_rejected(self):
        for value in ("0", "601", "nan", "inf"):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                watch.main(["--seconds", value])
            self.assertEqual(caught.exception.code, 2)

    def test_windows_complete_returns_0(self):
        report = make_report()
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            bundle.mkdir()
            with mock.patch.object(watch.sys, "platform", "win32"), \
                    mock.patch.object(watch, "collect_watch", return_value=(report, bundle, Path(directory) / "b.zip")), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(watch.main(["--output-dir", directory]), 0)

    def test_windows_incomplete_returns_1(self):
        report = make_report(stop_reason="error", issue="hiba")
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            bundle.mkdir()
            with mock.patch.object(watch.sys, "platform", "win32"), \
                    mock.patch.object(watch, "collect_watch", return_value=(report, bundle, Path(directory) / "b.zip")), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(watch.main(["--output-dir", directory]), 1)

    def test_output_error_returns_2(self):
        with mock.patch.object(watch.sys, "platform", "win32"), \
                mock.patch.object(watch, "collect_watch", side_effect=OSError("nem irhato")), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(watch.main([]), 2)


class SafetyTests(unittest.TestCase):
    def test_module_does_not_import_active_or_network_libraries(self):
        source = Path(watch.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        forbidden = {"subprocess", "socket", "urllib", "http", "serial", "usb",
                     "pyusb", "requests", "ftplib", "smtplib", "telnetlib"}
        self.assertFalse(imported & forbidden)

    def test_launcher_is_ascii_crlf_and_calls_watcher(self):
        path = Path(watch.__file__).resolve().parent / "TCL505-USBfigyelo.cmd"
        payload = path.read_bytes()
        payload.decode("ascii")
        self.assertIn(b"\r\n", payload)
        self.assertNotIn(b"\n", payload.replace(b"\r\n", b""))
        self.assertIn(b"tcl505_usb_watch.py", payload)
        self.assertIn(b"sys.version_info >= (3,9)", payload)


if __name__ == "__main__":
    unittest.main()
