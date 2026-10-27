"""Rule-level tests. No Windows host required."""

from __future__ import annotations

import unittest

from drvwatch.analyze import analyze, analyze_driver, worst_severity


def driver(**overrides):
    base = {
        "name": "Example",
        "display_name": "Example Driver",
        "state": "Running",
        "start_mode": "Auto",
        "path": r"C:\Windows\System32\drivers\example.sys",
        "path_exists": True,
        "signature_status": "Valid",
        "signer": "CN=Contoso Hardware Inc, O=Contoso",
        "sha256": "00" * 32,
    }
    base.update(overrides)
    return base


def rules(findings):
    return {f["rule"] for f in findings}


class KnownVulnerableTests(unittest.TestCase):
    def test_flags_documented_byovd_driver(self):
        found = analyze_driver(driver(path=r"C:\Windows\System32\drivers\RTCore64.sys"))
        self.assertIn("known_vulnerable_name", rules(found))

    def test_match_is_case_insensitive(self):
        found = analyze_driver(driver(path=r"C:\Windows\System32\drivers\gdrv.SYS"))
        self.assertIn("known_vulnerable_name", rules(found))

    def test_ordinary_driver_is_not_flagged(self):
        found = analyze_driver(driver())
        self.assertNotIn("known_vulnerable_name", rules(found))


class SignatureTests(unittest.TestCase):
    def test_unsigned_is_high(self):
        found = analyze_driver(driver(signature_status="NotSigned"))
        self.assertEqual(worst_severity(found), "high")

    def test_hash_mismatch_is_critical(self):
        found = analyze_driver(driver(signature_status="HashMismatch"))
        self.assertEqual(worst_severity(found), "critical")

    def test_third_party_signer_is_only_informational(self):
        found = analyze_driver(driver())
        self.assertIn("third_party_signer", rules(found))
        self.assertEqual(worst_severity(found), "info")

    def test_microsoft_signer_adds_no_finding(self):
        found = analyze_driver(driver(signer="CN=Microsoft Windows, O=Microsoft Corporation"))
        self.assertEqual(found, [])


class PathTests(unittest.TestCase):
    def test_user_writable_location_is_critical(self):
        found = analyze_driver(
            driver(path=r"C:\Users\bob\AppData\Local\Temp\evil.sys", signer="CN=Microsoft")
        )
        self.assertIn("user_writable_path", rules(found))
        self.assertEqual(worst_severity(found), "critical")

    def test_driver_outside_os_directories_is_high(self):
        found = analyze_driver(
            driver(path=r"C:\Tools\mydriver.sys", signer="CN=Microsoft")
        )
        self.assertIn("nonstandard_path", rules(found))
        self.assertEqual(worst_severity(found), "high")

    def test_driverstore_is_os_managed(self):
        found = analyze_driver(
            driver(
                path=r"C:\Windows\System32\DriverStore\FileRepository\nv.inf_amd64_1\nvlddmkm.sys",
                signer="CN=Microsoft Windows",
            )
        )
        self.assertEqual(found, [])

    def test_program_files_is_informational_only(self):
        found = analyze_driver(
            driver(path=r"C:\Program Files\Riot Vanguard\vgk.sys", signer="CN=Microsoft Windows")
        )
        self.assertIn("install_dir_path", rules(found))
        self.assertNotIn("nonstandard_path", rules(found))
        self.assertEqual(worst_severity(found), "info")

    def test_missing_image_is_informational(self):
        found = analyze_driver(driver(path_exists=False, signer="CN=Microsoft"))
        self.assertIn("missing_image", rules(found))
        self.assertEqual(worst_severity(found), "info")


class ReportTests(unittest.TestCase):
    def test_counts_and_ordering(self):
        report = analyze(
            [
                driver(name="Clean", signer="CN=Microsoft"),
                driver(name="Evil", path=r"C:\Windows\System32\drivers\RTCore64.sys"),
                driver(name="Unsigned", signature_status="NotSigned"),
            ]
        )
        self.assertEqual(report["summary"]["drivers"], 3)
        self.assertEqual(report["summary"]["findings_by_severity"]["critical"], 1)
        self.assertEqual(report["summary"]["drivers_at_risk"], 2)
        self.assertEqual(report["drivers"][0]["name"], "Evil")

    def test_empty_input(self):
        report = analyze([])
        self.assertEqual(report["summary"]["drivers"], 0)
        self.assertEqual(report["drivers"], [])


if __name__ == "__main__":
    unittest.main()
