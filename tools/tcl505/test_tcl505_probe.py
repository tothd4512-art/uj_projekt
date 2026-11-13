"""Offline tests: no phone, USB access, downloads or third-party packages."""
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import tcl505_probe as probe


def result(stdout="", stderr="", status="ok", returncode=0):
    return {"stdout": stdout, "stderr": stderr, "status": status, "returncode": returncode}


class FakeDevice:
    def __init__(self, mode="adb", listing=None, responses=None):
        self.mode = mode
        self.listing = listing if listing is not None else (
            "SECRET123\tdevice\n" if mode == "adb" else "FBSECRET\tfastboot\n")
        self.responses = responses or {}
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        if "version" in argv or "--version" in argv:
            return result(f"{self.mode} test version 1.0\n")
        if "devices" in argv:
            return result(self.listing)
        if "getprop" in argv:
            key = argv[-1]
            return result(self.responses.get(key, ""))
        if "pm" in argv and "list" in argv and "packages" in argv:
            return result(self.responses.get("token_package_listing", ""))
        if "getvar" in argv:
            key = argv[-1]
            value = self.responses.get(key, "")
            return result(stderr=f"(bootloader) {key}: {value}\nOKAY\n") if value else result()
        if argv[-2:] == ["flashing", "get_unlock_ability"]:
            raw = self.responses.get("get_unlock_ability_raw")
            if raw is not None:
                return result(stderr=raw)
            value = self.responses.get("get_unlock_ability", "")
            return result(stderr=f"get_unlock_ability: {value}\nOKAY\n") if value else result()
        raise AssertionError(f"Unexpected command: {argv}")


class ParsingTests(unittest.TestCase):
    def test_adb_device_listing_ignores_daemon_messages(self):
        devices = probe.parse_devices(result(
            "* daemon started successfully *\nList of devices attached\n"
            "ABC123 device product:x model:y transport_id:2\n"), "adb")
        self.assertEqual(devices, [{"state": "device", "_serial": "ABC123"}])

    def test_unauthorized_and_offline_are_not_ready(self):
        for state in ("unauthorized", "offline", "recovery", "sideload"):
            devices = [{"state": state, "_serial": "X"}]
            self.assertIsNone(probe.select_device(devices, None, "adb")[0])

    def test_fastboot_listing(self):
        devices = probe.parse_devices(result("FB123\tfastboot\n"), "fastboot")
        self.assertEqual(probe.select_device(devices, None, "fastboot")[0], "FB123")

    def test_multiple_devices_require_explicit_selection(self):
        devices = [{"state": "device", "_serial": "A"}, {"state": "device", "_serial": "B"}]
        self.assertIsNone(probe.select_device(devices, None, "adb")[0])
        self.assertEqual(probe.select_device(devices, "B", "adb")[0], "B")
        self.assertIsNone(probe.select_device(devices, "C", "adb")[0])

    def test_no_device(self):
        self.assertIsNone(probe.select_device([], None, "adb")[0])

    def test_fastboot_response_on_stderr(self):
        value = probe.parse_variable(result(stderr="version-bootloader: ABC\nFinished. Total time: 0.001s"),
                                     "version-bootloader")
        self.assertEqual(value, "ABC")

    def test_unlock_ability_standard_colon_form(self):
        value = probe.parse_unlock_ability(result(stderr="get_unlock_ability: 1\nOKAY\n"))
        self.assertEqual(value, "1")

    def test_unlock_ability_vendor_equals_alias(self):
        raw = "(bootloader) unlock_ability = 16777216\r\nOKAY [  0.007s]\r\nFinished. Total time: 0.007s\r\n"
        self.assertEqual(probe.parse_unlock_ability(result(stderr=raw)), "16777216")

    def test_unlock_ability_vendor_hex_alias(self):
        raw = "(bootloader) unlock_ability = 0x1000000\r\nOKAY\r\n"
        self.assertEqual(probe.parse_unlock_ability(result(stderr=raw)), "0x1000000")

    def test_unlock_ability_missing_is_not_zero(self):
        self.assertIsNone(probe.parse_unlock_ability(result(stderr="OKAY\n")))

    def test_variable_not_found_is_unsupported(self):
        item = probe.query_result(result(stderr="getvar:partition-size:boot FAILED (remote: 'GetVar Variable Not found')\n"), None)
        self.assertEqual(item["status"], "unsupported")

    def test_missing_property_is_not_zero_or_false(self):
        item = probe.query_result(result(), "")
        self.assertEqual(item["status"], "missing")
        self.assertIsNone(probe.value_of({"x": item}, "x"))

    def test_unsupported_query_is_not_permission_denied(self):
        item = probe.query_result(result(stderr="FAILED (remote: unknown command)", returncode=1), None)
        self.assertEqual(item["status"], "unsupported")

    def test_failed_with_zero_exit_is_not_success(self):
        item = probe.query_result(result(stderr="FAILED (remote: error)"), None)
        self.assertEqual(item["status"], "error")

    def test_timeout_preserved(self):
        item = probe.query_result(result(status="timeout", returncode=None), None)
        self.assertEqual(item["status"], "timeout")

    def test_redaction(self):
        text = "ID=ABC123 IMEI1: 123456789012345 serial=XYZ C:\\Users\\Alice\\tools /home/alice/tools"
        cleaned = probe.redact(text, ("ABC123",))
        for secret in ("ABC123", "123456789012345", "XYZ", "Alice", "alice"):
            self.assertNotIn(secret, cleaned)

    def test_discovery_output_is_scrubbed_after_learning_serial(self):
        session = probe.Session(1, lambda argv, timeout: result("SECRET123 device\n"))
        session.run(["adb", "devices"])
        session.remember_serials(["SECRET123"])
        self.assertNotIn("SECRET123", json.dumps(session.commands))


class CollectionTests(unittest.TestCase):
    def collect(self, mode, fake):
        with mock.patch.object(probe, "find_tool", return_value=mode):
            return probe.collect(mode, None, None, 1, fake)

    def test_adb_happy_path_uses_only_fixed_queries(self):
        fake = FakeDevice(responses={
            "ro.product.model": "T509K", "ro.boot.flash.locked": "1",
            "sys.oem_unlock_allowed": "1",
            "ro.build.fingerprint": "TCL/T509K_EEA/T509K:14/UP1A.231005.007/TEST:user/release-keys",
        })
        report = self.collect("adb", fake)
        self.assertTrue(report["read_only"])
        self.assertTrue(report["data"]["connected"])
        self.assertEqual(probe.value_of(report["data"]["properties"], "ro.product.model"), "T509K")
        self.assertNotIn("SECRET123", json.dumps(report))
        for argv in fake.calls:
            self.assertFalse({"reboot", "unlock", "flash", "erase", "format", "push", "pull"} & set(argv))
            if "getprop" in argv:
                self.assertIn(argv[-1], probe.ANDROID_PROPERTIES + (probe.TOKEN_SERIAL_PROPERTY,))
            if "pm" in argv:
                self.assertEqual(argv[-4:], ["pm", "list", "packages", probe.TOKEN_PACKAGE])
        self.assertNotIn("getprop", [" ".join(c) for c in fake.calls])
        self.assertEqual(report["schema_version"], 2)

    def test_fastboot_queries_ability_but_never_unlocks(self):
        fake = FakeDevice("fastboot", "FBSECRET\tfastboot\n", {
            "unlocked": "no", "is-userspace": "no", "get_unlock_ability": "0",
        })
        report = self.collect("fastboot", fake)
        variables = report["data"]["variables"]
        self.assertEqual(probe.value_of(variables, "get_unlock_ability"), "0")
        self.assertNotIn("FBSECRET", json.dumps(report))
        self.assertIn(["fastboot", "-s", "FBSECRET", "flashing", "get_unlock_ability"], fake.calls)
        for argv in fake.calls:
            self.assertFalse({"unlock", "unlock_critical", "lock", "flash", "erase", "format", "reboot", "oem"} & set(argv))
            if "getvar" in argv:
                self.assertIn(argv[-1], probe.FASTBOOT_VARIABLES)
                self.assertNotEqual(argv[-1], "all")

    def test_fastboot_vendor_unlock_ability_is_recorded_but_not_permission(self):
        fake = FakeDevice("fastboot", "FBSECRET\tfastboot\n", {
            "unlocked": "no", "is-userspace": "no", "secure": "yes",
            "get_unlock_ability_raw": "(bootloader) unlock_ability = 16777216\r\nOKAY [  0.007s]\r\n",
        })
        report = self.collect("fastboot", fake)
        item = report["data"]["variables"]["get_unlock_ability"]
        self.assertEqual(item["status"], "ok")
        self.assertEqual(item["value"], "16777216")
        self.assertIn("16777216", probe.render_text(report))
        self.assertTrue(any("nem szabványos 0/1 válasz" in note for note in report["interpretation"]))
        self.assertFalse(any("feloldási engedélyt jelez" in note for note in report["interpretation"]))
        for argv in fake.calls:
            self.assertFalse({"unlock", "unlock_critical", "lock", "flash", "erase", "format", "reboot", "oem"} & set(argv))

    def test_fastboot_missing_unlock_ability_is_not_zero_or_one(self):
        fake = FakeDevice("fastboot", responses={"get_unlock_ability_raw": "OKAY\n"})
        report = self.collect("fastboot", fake)
        item = report["data"]["variables"]["get_unlock_ability"]
        self.assertEqual(item["status"], "missing")
        self.assertIsNone(item["value"])
        self.assertFalse(any("get_unlock_ability=0" in note or "get_unlock_ability=1" in note
                             for note in report["interpretation"]))

    def test_fastboot_unsupported_unlock_ability_is_not_permission(self):
        fake = FakeDevice("fastboot", responses={
            "get_unlock_ability_raw": "FAILED (remote: 'unknown command')\n",
        })
        report = self.collect("fastboot", fake)
        item = report["data"]["variables"]["get_unlock_ability"]
        self.assertEqual(item["status"], "unsupported")
        self.assertTrue(any("nem támogatott" in note for note in report["interpretation"]))

    def test_fastbootd_is_identified(self):
        fake = FakeDevice("fastboot", responses={"is-userspace": "yes", "get_unlock_ability": "1"})
        report = self.collect("fastboot", fake)
        self.assertTrue(any("fastbootd" in note for note in report["interpretation"]))
        self.assertTrue(any("nem bizonyítja" in note for note in report["interpretation"]))

    def test_unlocked_flag_is_not_advertised_as_full_tcl_unlock(self):
        fake = FakeDevice(responses={"ro.boot.flash.locked": "0"})
        report = self.collect("adb", fake)
        self.assertTrue(any("nem bizonyít teljes" in note for note in report["interpretation"]))

    def test_no_device_means_no_device_queries(self):
        for mode in ("adb", "fastboot"):
            fake = FakeDevice(mode, listing="")
            report = self.collect(mode, fake)
            self.assertFalse(report["data"]["connected"])
            self.assertEqual(len(fake.calls), 2)

    def test_unauthorized_means_no_shell_queries(self):
        fake = FakeDevice(listing="SECRET\tunauthorized\n")
        report = self.collect("adb", fake)
        self.assertFalse(report["data"]["connected"])
        self.assertFalse(any("shell" in argv for argv in fake.calls))

    def test_multiple_devices_do_not_pick_first(self):
        fake = FakeDevice(listing="A device\nB device\n")
        report = self.collect("adb", fake)
        self.assertFalse(report["data"]["connected"])
        self.assertEqual(len(fake.calls), 2)

    def test_missing_executable_produces_report_without_running_commands(self):
        fake = FakeDevice()
        with mock.patch.object(probe, "find_tool", return_value=None):
            report = probe.collect("adb", None, None, 1, fake)
        self.assertFalse(report["data"]["connected"])
        self.assertEqual(fake.calls, [])
        self.assertIn("nem található", report["data"]["issue"])

    def test_missing_fingerprint_reported(self):
        report = self.collect("adb", FakeDevice())
        self.assertTrue(any("fingerprint" in note for note in report["interpretation"]))


class TokenProbeTests(unittest.TestCase):
    def collect(self, fake):
        with mock.patch.object(probe, "find_tool", return_value="adb"):
            return probe.collect("adb", None, None, 1, fake)

    def test_true_flags_are_clues_not_authorization(self):
        fake = FakeDevice(responses={"ro.boot.oemtoken": "true", "ro.boot.fastboottoken": "TRUE",
                                     "ro.boot.roottoken": "0"})
        report = self.collect(fake)
        self.assertEqual(probe.value_of(report["data"]["properties"], "ro.boot.fastboottoken"), "TRUE")
        self.assertTrue(any("nem igazolt szerver-engedély" in note for note in report["interpretation"]))
        self.assertFalse(any("am" in argv or "start" in argv for argv in fake.calls))

    def test_missing_flags_are_not_false(self):
        report = self.collect(FakeDevice())
        for key in probe.TOKEN_PROPERTIES:
            self.assertEqual(report["data"]["properties"][key]["status"], "missing")
        self.assertTrue(any("Nem olvasható" in note for note in report["interpretation"]))

    def test_false_flags_do_not_disprove_bootloader_auth(self):
        fake = FakeDevice(responses={key: "false" for key in probe.TOKEN_PROPERTIES})
        report = self.collect(fake)
        self.assertTrue(any("nem cáfolja" in note for note in report["interpretation"]))

    def test_nonboolean_flag_is_redacted_in_json_text_and_command_log(self):
        secret = "PRIVATE-TOKEN-VALUE-123"
        report = self.collect(FakeDevice(responses={"ro.boot.oemtoken": secret + "\n"}))
        self.assertEqual(report["data"]["properties"]["ro.boot.oemtoken"]["status"], "redacted")
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn(secret, probe.render_text(report))
        self.assertIn("<token-output-not-exported>", json.dumps(report["commands"]))

    def test_token_flag_error_does_not_export_raw_streams(self):
        secret = "PRIVATE-FLAG-ERROR-123"
        device = FakeDevice()
        def runner(argv, timeout):
            if argv[-1] == "ro.boot.oemtoken":
                return result(secret, secret, "error", 1)
            return device(argv, timeout)
        report = self.collect(runner)
        self.assertEqual(report["data"]["properties"]["ro.boot.oemtoken"]["status"], "error")
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn(secret, probe.render_text(report))

    def test_token_serial_is_presence_only(self):
        secret = "TKSN-PRIVATE-987"
        fake = FakeDevice(responses={probe.TOKEN_SERIAL_PROPERTY: secret + "\n"})
        report = self.collect(fake)
        self.assertEqual(report["data"]["token_serial"]["value"], "present")
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn(secret, probe.render_text(report))
        self.assertIn(probe.TOKEN_SERIAL_PROPERTY, [argv[-1] for argv in fake.calls if "getprop" in argv])

    def test_token_serial_error_does_not_export_raw_streams(self):
        secret = "TKSN-ERROR-PRIVATE"
        device = FakeDevice()
        def runner(argv, timeout):
            if argv[-1] == probe.TOKEN_SERIAL_PROPERTY:
                return result(secret, secret, "error", 1)
            return device(argv, timeout)
        report = self.collect(runner)
        self.assertEqual(report["data"]["token_serial"]["status"], "error")
        self.assertIsNone(report["data"]["token_serial"]["value"])
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn(secret, probe.render_text(report))

    def test_package_name_requires_exact_match(self):
        fake = FakeDevice(responses={"token_package_listing": "package:com.tcl.token.extra\n"})
        report = self.collect(fake)
        self.assertEqual(report["data"]["token_package"]["status"], "missing")

    def test_package_presence_does_not_start_app_or_read_its_data(self):
        fake = FakeDevice(responses={"token_package_listing": "package:com.tcl.token\n"})
        report = self.collect(fake)
        self.assertEqual(report["data"]["token_package"]["status"], "ok")
        package_calls = [argv for argv in fake.calls if "pm" in argv]
        self.assertEqual(package_calls, [["adb", "-s", "SECRET123", "shell", "pm", "list", "packages", "com.tcl.token"]])
        self.assertTrue(any("Nem indítottuk el" in note for note in report["interpretation"]))
        self.assertIn("TCL token nyomok", probe.render_text(report))

    def test_package_timeout_is_not_absence(self):
        device = FakeDevice()
        def runner(argv, timeout):
            if "pm" in argv:
                return result(status="timeout", returncode=None)
            return device(argv, timeout)
        report = self.collect(runner)
        self.assertEqual(report["data"]["token_package"]["status"], "timeout")

    def test_no_connection_does_not_query_or_claim_absence(self):
        fake = FakeDevice(listing="")
        report = self.collect(fake)
        self.assertFalse(any("shell" in argv for argv in fake.calls))
        self.assertEqual(report["data"]["token_package"]["status"], "unavailable")
        self.assertEqual(report["data"]["token_serial"]["status"], "unavailable")

    def test_fastboot_does_not_run_android_token_queries(self):
        device = FakeDevice("fastboot")
        with mock.patch.object(probe, "find_tool", return_value="fastboot"):
            report = probe.collect("fastboot", None, None, 1, device)
        self.assertNotIn("token_package", report["data"])
        self.assertFalse(any("shell" in argv or "getprop" in argv for argv in device.calls))


class RuntimeTests(unittest.TestCase):
    def test_real_subprocess_without_shell(self):
        output = probe.run_command([sys.executable, "-c", "print('diagnostic-ok')"], 5)
        self.assertEqual(output["status"], "ok")
        self.assertEqual(output["stdout"].strip(), "diagnostic-ok")

    def test_real_subprocess_timeout(self):
        output = probe.run_command([sys.executable, "-c", "import time; time.sleep(2)"], 0.1)
        self.assertEqual(output["status"], "timeout")

    def test_missing_program(self):
        output = probe.run_command(["/definitely/missing/tcl505-test-program"], 1)
        self.assertEqual(output["status"], "unavailable")

    def test_reports_are_utf8_valid_json_and_unique(self):
        report = {"schema_version": 1, "tool_version": "test", "created_utc": "test",
                  "mode": "adb", "read_only": True,
                  "data": {"connected": False, "issue": "Nincs eszköz", "properties": {}},
                  "interpretation": "Ékezetes szöveg", "commands": []}
        # render_text expects a list of notes, as produced by collect().
        report["interpretation"] = ["Ékezetes szöveg"]
        with tempfile.TemporaryDirectory() as directory:
            first = probe.write_reports(report, Path(directory))
            second = probe.write_reports(report, Path(directory))
            self.assertNotEqual(first, second)
            self.assertEqual(json.loads(first[1].read_text(encoding="utf-8")), report)
            self.assertIn("Ékezetes", first[0].read_text(encoding="utf-8"))

    def test_cli_rejects_unsafe_timeout_and_unknown_mode(self):
        for args in (["--timeout", "0"], ["--timeout", "121"], ["--mode", "unlock"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                probe.main(args)
            self.assertEqual(caught.exception.code, 2)

    def test_cli_creates_report_even_without_phone(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = FakeDevice(listing="")
            with mock.patch.object(probe, "find_tool", return_value="adb"), \
                    mock.patch.object(probe, "run_command", fake), contextlib.redirect_stdout(io.StringIO()):
                code = probe.main(["--output-dir", directory])
            self.assertEqual(code, 0)
            self.assertEqual(len(list(Path(directory).glob("*.json"))), 1)
            self.assertEqual(len(list(Path(directory).glob("*.txt"))), 1)


if __name__ == "__main__":
    unittest.main()
