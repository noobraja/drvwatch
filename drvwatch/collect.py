"""Collect the kernel driver inventory from a Windows host.

Enumeration goes through CIM (Win32_SystemDriver) because it is available
without administrator rights and reports the service state, which the registry
ImagePath alone does not. Signature verification uses Get-AuthenticodeSignature,
which is the same trust decision Windows makes at load time.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from typing import Any

PS_SCRIPT = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$checkSig = $env:DRVWATCH_SIG -ne '0'
$drivers = @()

foreach ($d in Get-CimInstance -ClassName Win32_SystemDriver) {
    $raw = [string]$d.PathName
    $path = $null

    if ($raw) {
        $p = $raw -replace '^\\\?\?\\', ''
        $p = [Environment]::ExpandEnvironmentVariables($p)

        if ($p -match '^\\SystemRoot\\') {
            $p = $p -replace '^\\SystemRoot\\', ($env:SystemRoot + '\')
        } elseif ($p -match '^System32\\') {
            $p = Join-Path $env:SystemRoot $p
        } elseif ($p -notmatch '^[A-Za-z]:') {
            $p = Join-Path $env:SystemRoot ('System32\drivers\' + $p)
        }
        $path = $p
    }

    $status = $null
    $signer = $null

    if ($checkSig -and $path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
        $sig = Get-AuthenticodeSignature -LiteralPath $path
        if ($sig) {
            $status = [string]$sig.Status
            if ($sig.SignerCertificate) {
                $signer = [string]$sig.SignerCertificate.Subject
            }
        }
    }

    $drivers += [pscustomobject]@{
        name             = [string]$d.Name
        display_name     = [string]$d.DisplayName
        state            = [string]$d.State
        start_mode       = [string]$d.StartMode
        path             = $path
        signature_status = $status
        signer           = $signer
    }
}

$drivers | ConvertTo-Json -Depth 3 -Compress
"""


def _sha256(path: str) -> str | None:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _run_powershell(script: str, check_signature: bool) -> str:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    env = dict(os.environ)
    env["DRVWATCH_SIG"] = "1" if check_signature else "0"
    proc = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=600,
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        message = (proc.stderr or "").strip() or f"PowerShell exited {proc.returncode}"
        raise RuntimeError(message)
    return proc.stdout


def collect(check_signature: bool = True) -> list[dict[str, Any]]:
    if sys.platform != "win32":
        raise RuntimeError("drvwatch reads Windows driver state; run it on Windows.")

    raw = _run_powershell(PS_SCRIPT, check_signature).strip()
    if not raw:
        return []

    parsed = json.loads(raw)
    if isinstance(parsed, dict):
        parsed = [parsed]

    drivers: list[dict[str, Any]] = []
    for entry in parsed:
        path = entry.get("path")
        exists = bool(path) and os.path.isfile(path)
        entry["path_exists"] = exists
        entry["sha256"] = _sha256(path) if exists and path else None
        drivers.append(entry)

    drivers.sort(key=lambda d: str(d.get("name", "")).lower())
    return drivers
