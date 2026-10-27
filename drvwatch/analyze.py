"""Risk analysis for collected drivers.

Each rule maps to a concrete attacker technique so a finding can be actioned
rather than just counted. The rules are deliberately conservative: a signature
mismatch is critical because Windows itself would refuse to load it, while a
non-Microsoft signer is only informational because most legitimate third-party
drivers are signed by the hardware vendor.
"""

from __future__ import annotations

import ntpath
from typing import Any

from .data import VULNERABLE_DRIVER_NAMES

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITIES = tuple(SEVERITY_RANK)

# Directories a non-elevated user (or a user-mode implant) can write to, which
# means an attacker can drop a driver there and have it load on next boot.
USER_WRITABLE_SEGMENTS = (
    "\\temp\\",
    "\\appdata\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\$recycle.bin\\",
)

BROKEN_SIGNATURE_STATES = ("HashMismatch", "NotTrusted", "UnknownError", "Incompatible")

MICROSOFT_SIGNER_MARKER = "microsoft"


def _finding(rule: str, severity: str, detail: str, technique: str) -> dict[str, str]:
    return {
        "rule": rule,
        "severity": severity,
        "detail": detail,
        "technique": technique,
    }


def analyze_driver(driver: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    path = (driver.get("path") or "").strip()
    basename = ntpath.basename(path).lower() if path else ""
    signature = driver.get("signature_status") or ""
    signer = (driver.get("signer") or "").lower()

    if basename and basename in VULNERABLE_DRIVER_NAMES:
        findings.append(
            _finding(
                "known_vulnerable_name",
                "critical",
                f"{basename} matches a publicly documented BYOVD driver "
                f"(LOLDrivers). Confirm by SHA-256 before acting.",
                "T1068",
            )
        )

    lowered = path.lower()
    if lowered and any(seg in lowered for seg in USER_WRITABLE_SEGMENTS):
        findings.append(
            _finding(
                "user_writable_path",
                "critical",
                "Driver image lives in a user-writable directory; "
                "a non-admin process could replace it.",
                "T1543.003",
            )
        )

    if signature in BROKEN_SIGNATURE_STATES:
        findings.append(
            _finding(
                "invalid_signature",
                "critical",
                f"Authenticode status is {signature}; the signature does not "
                f"match the binary.",
                "T1553.006",
            )
        )
    elif signature == "NotSigned":
        findings.append(
            _finding(
                "unsigned",
                "high",
                "No embedded Authenticode signature. Windows inbox drivers are "
                "often catalog-signed instead, so confirm against the .cat "
                "file before acting on this.",
                "T1553.006",
            )
        )
    elif signature and signature != "Valid":
        findings.append(
            _finding(
                "unverified_signature",
                "medium",
                f"Signature status is {signature}, not Valid.",
                "T1553.006",
            )
        )

    if lowered and path and "\\system32\\drivers\\" not in lowered:
        findings.append(
            _finding(
                "outside_drivers_dir",
                "high",
                "Image is outside System32\\drivers, which is the standard "
                "location for OS-managed drivers.",
                "T1543.003",
            )
        )

    if driver.get("path") and not driver.get("path_exists"):
        findings.append(
            _finding(
                "missing_image",
                "info",
                "Service is registered but the image file is not present; "
                "likely a leftover entry.",
                "-",
            )
        )

    if signer and MICROSOFT_SIGNER_MARKER not in signer:
        findings.append(
            _finding(
                "third_party_signer",
                "info",
                "Signed by a third-party CA, which is normal for hardware "
                "vendor drivers.",
                "-",
            )
        )

    return findings


def worst_severity(findings: list[dict[str, str]]) -> str:
    if not findings:
        return "none"
    return max(findings, key=lambda f: SEVERITY_RANK[f["severity"]])["severity"]


def analyze(drivers: list[dict[str, Any]]) -> dict[str, Any]:
    results = []
    counts = {severity: 0 for severity in SEVERITIES}

    for driver in drivers:
        findings = analyze_driver(driver)
        severity = worst_severity(findings)
        for finding in findings:
            counts[finding["severity"]] += 1
        results.append({**driver, "findings": findings, "worst": severity})

    results.sort(key=lambda d: (-SEVERITY_RANK.get(d["worst"], 0), str(d["name"]).lower()))

    return {
        "summary": {
            "drivers": len(results),
            "findings_by_severity": counts,
            "drivers_at_risk": sum(1 for d in results if d["worst"] in ("critical", "high")),
        },
        "drivers": results,
    }
