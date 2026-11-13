"""Offline tests for the optional ADB file collector; no phone or network."""
import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import tcl505_files as files
import tcl505_probe as probe


def result(stdout="", stderr="", status="ok", returncode=0):
    return {"stdout": stdout, "stderr": stderr, "status": status, "returncode": returncode}


class FakeAdb:
    def __init__(self, listing="SECRET123\tdevice\n", contents=None, errors=None):
        self.listing = listing
        self.contents = contents or {}
        self.errors = errors or {}
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        if "version" in argv:
            return result("Android Debug Bridge version 1.0.41\n")
        if "devices" in argv:
            return result(self.listing)
        if "pull" in argv:
            source, destination = argv[-2], Path(argv[-1])
            if source in self.errors:
                return self.errors[source]
            if source not in self.contents:
                return result(stderr=f"adb: error: failed to stat remote object '{source}': No such file or directory\n",
                              status="error", returncode=1)
            destination.parent.mkdir(parents=True, exist_ok=True)
            payload = self.contents[source]
            destination.write_bytes(payload.encode("utf-8") if isinstance(payload, str) else payload)
            return result("1 file pulled\n")
        raise AssertionError(f"Unexpected command: {argv}")


class AllowlistTests(unittest.TestCase):
    def test_only_fixed_system_files_are_allowed(self):
        for source in files.FILE_ALLOWLIST:
            self.assertTrue(source.startswith(("/system/", "/vendor/", "/product/", "/system_ext/", "/odm/", "/first_stage_ramdisk/")))
            self.assertNotIn("..", source)
            self.assertEqual(files.safe_relative(source), source.lstrip("/"))
        for source in ("/data/local/tmp/x", "/sdcard/DCIM/x", "/dev/block/by-name/lk_a", "/system/../data/x", "relative"):
            with self.assertRaises(ValueError):
                files.safe_relative(source)

    def test_allowlist_has_no_duplicates_and_respects_cap(self):
        self.assertEqual(len(files.FILE_ALLOWLIST), len(set(files.FILE_ALLOWLIST)))
        self.assertLessEqual(len(files.FILE_ALLOWLIST), files.MAX_FILES)


class SanitizationTests(unittest.TestCase):
    def test_personal_fields_are_redacted_but_build_metadata_kept(self):
        text = ("ro.build.fingerprint=TCL/T509K_EEA/T509K:14/UP1A.231005.007/TEST:user/release-keys\n"
                "ro.serialno=ABC123\npersist.vendor.wifi.mac=AA:BB:CC:DD:EE:FF\n"
                "setprop ro.boot.tksn PRIVATE-TKSN\n")
        cleaned = files.sanitize_text(text, ("ABC123",))
        self.assertIn("UP1A.231005.007", cleaned)
        self.assertNotIn("ABC123", cleaned)
        self.assertNotIn("AA:BB:CC:DD:EE:FF", cleaned)
        self.assertNotIn("PRIVATE-TKSN", cleaned)
        self.assertIn("setprop ro.boot.tksn <redacted>", cleaned)

    def test_token_flags_keep_boolean_but_not_credentials(self):
        text = "ro.boot.oemtoken=true\nro.boot.fastboottoken=SECRET-TOKEN\n"
        cleaned = files.sanitize_text(text)
        self.assertIn("ro.boot.oemtoken=true", cleaned)
        self.assertIn("ro.boot.fastboottoken=<redacted-nonboolean>", cleaned)
        self.assertNotIn("SECRET-TOKEN", cleaned)

    def test_long_file_is_not_cut_to_command_output_cap(self):
        text = "ro.build.fingerprint=TCL/T509K\n" + ("# comment\n" * 3000)
        cleaned = files.sanitize_text(text)
        self.assertGreater(len(cleaned), probe.MAX_OUTPUT)
        self.assertTrue(cleaned.endswith("# comment\n"))

    def test_probe_redaction_can_keep_full_text_when_requested(self):
        text = "x" * (probe.MAX_OUTPUT + 100)
        self.assertEqual(len(probe.redact(text, max_chars=None)), len(text))
        self.assertEqual(len(probe.redact(text)), probe.MAX_OUTPUT)


class CollectionTests(unittest.TestCase):
    def collect(self, fake, output_root):
        with mock.patch.object(files, "find_tool", return_value="adb"):
            return files.collect_files(None, None, 1, output_root, fake)

    def test_copies_only_allowlisted_files_and_writes_zip_manifest(self):
        fake = FakeAdb(contents={
            "/system/build.prop": "ro.product.model=T509K\nro.serialno=SECRET123\n",
            "/vendor/etc/fstab.mt6765": "/dev/block/by-name/userdata /data f2fs defaults\n",
        })
        with tempfile.TemporaryDirectory() as directory:
            bundle, manifest, zip_path = self.collect(fake, Path(directory))
            self.assertTrue(manifest["connected"])
            self.assertTrue(manifest["read_only_on_phone"])
            self.assertFalse(manifest["uploaded_by_tool"])
            ok = [entry for entry in manifest["files"] if entry["status"] == "ok"]
            self.assertEqual({entry["source"] for entry in ok}, {"/system/build.prop", "/vendor/etc/fstab.mt6765"})
            self.assertNotIn("SECRET123", json.dumps(manifest))
            self.assertNotIn("SECRET123", (bundle / "system/build.prop").read_text(encoding="utf-8"))
            self.assertTrue(zip_path.is_file())
            with zipfile.ZipFile(zip_path) as archive:
                self.assertIsNone(archive.testzip())
                names = archive.namelist()
                self.assertIn(f"{bundle.name}/manifest.json", names)
                self.assertIn(f"{bundle.name}/system/build.prop", names)
            for argv in fake.calls:
                self.assertFalse({"su", "root", "reboot", "push", "shell", "remount", "dd"} & set(argv))
                if "pull" in argv:
                    self.assertIn(argv[-2], files.FILE_ALLOWLIST)

    def test_missing_and_denied_files_are_reported_not_bypassed(self):
        fake = FakeAdb(contents={"/system/build.prop": "ro.product.model=T509K\n"},
                       errors={"/vendor/build.prop": result(stderr="adb: error: Permission denied\n", status="error", returncode=1)})
        with tempfile.TemporaryDirectory() as directory:
            bundle, manifest, _ = self.collect(fake, Path(directory))
            entries = {entry["source"]: entry for entry in manifest["files"]}
            self.assertEqual(entries["/vendor/build.prop"]["status"], "denied")
            self.assertEqual(entries["/product/build.prop"]["status"], "missing")
            self.assertFalse((bundle / "vendor/build.prop").exists())
            self.assertFalse(any("su" in argv for argv in fake.calls))

    def test_binary_empty_and_oversized_files_are_not_packaged(self):
        fake = FakeAdb(contents={
            "/system/build.prop": b"\x00ELF",
            "/vendor/build.prop": "",
            "/product/build.prop": "x" * (files.MAX_FILE_BYTES + 1),
        })
        with tempfile.TemporaryDirectory() as directory:
            bundle, manifest, _ = self.collect(fake, Path(directory))
            entries = {entry["source"]: entry for entry in manifest["files"]}
            self.assertEqual(entries["/system/build.prop"]["status"], "not_text")
            self.assertEqual(entries["/vendor/build.prop"]["status"], "empty")
            self.assertEqual(entries["/product/build.prop"]["status"], "too_large")
            self.assertFalse((bundle / "system/build.prop").exists())
            self.assertFalse((bundle / "product/build.prop").exists())

    def test_no_device_means_no_pull(self):
        fake = FakeAdb(listing="")
        with tempfile.TemporaryDirectory() as directory:
            _, manifest, zip_path = self.collect(fake, Path(directory))
            self.assertFalse(manifest["connected"])
            self.assertFalse(any("pull" in argv for argv in fake.calls))
            self.assertTrue(zip_path.is_file())

    def test_multiple_devices_require_selection(self):
        fake = FakeAdb(listing="A device\nB device\n")
        with tempfile.TemporaryDirectory() as directory:
            _, manifest, _ = self.collect(fake, Path(directory))
            self.assertFalse(manifest["connected"])
            self.assertFalse(any("pull" in argv for argv in fake.calls))

    def test_missing_adb_produces_manifest_without_commands(self):
        fake = FakeAdb()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(files, "find_tool", return_value=None):
                _, manifest, zip_path = files.collect_files(None, None, 1, Path(directory), fake)
            self.assertFalse(manifest["connected"])
            self.assertEqual(fake.calls, [])
            self.assertTrue(zip_path.is_file())

    def test_existing_destination_is_not_overwritten(self):
        session = probe.Session(1, lambda argv, timeout: result())
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "build.prop"
            target.write_text("keep", encoding="utf-8")
            with self.assertRaises(ValueError):
                files.copy_file(session, "adb", "SECRET", "/system/build.prop", target)
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")


class CliTests(unittest.TestCase):
    def test_cli_rejects_unsafe_timeout(self):
        for value in ("0", "121"):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                files.main(["--timeout", value])
            self.assertEqual(caught.exception.code, 2)

    def test_cli_creates_bundle_without_phone(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = FakeAdb(listing="")
            with mock.patch.object(files, "find_tool", return_value="adb"), \
                    mock.patch.object(files, "run_command", fake), contextlib.redirect_stdout(io.StringIO()):
                code = files.main(["--output-dir", directory])
            self.assertEqual(code, 1)
            self.assertEqual(len(list(Path(directory).glob("*.zip"))), 1)


if __name__ == "__main__":
    unittest.main()
