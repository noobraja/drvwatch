# drvwatch

[![test](https://github.com/noobraja/drvwatch/actions/workflows/test.yml/badge.svg)](https://github.com/noobraja/drvwatch/actions/workflows/test.yml)

Inventory the Windows kernel drivers on a host and flag the ones that look like
**Bring Your Own Vulnerable Driver (BYOVD)** risk.

No dependencies. No admin rights. One command.

```console
> python -m drvwatch --html report.html

drvwatch - 397 kernel drivers, 2 at risk
findings: critical=0  high=2  medium=0  low=0  info=4

SEVERITY  DRIVER            STATE    START   SIGNATURE   FINDING
------------------------------------------------------------------
high      BthA2dp           Stopped  Manual  NotSigned   unsigned
high      BthHFEnum         Stopped  Manual  NotSigned   unsigned
info      KProcessHacker3   Stopped  System  Valid       install_dir_path
info      vgk               Running  System  Valid       install_dir_path
------------------------------------------------------------------
393 drivers clean
```

Real output from a Windows 10 host. The two `high` findings are false positives —
see [Limitations](#limitations-read-these). `vgk` is Riot Vanguard's kernel
driver, which is exactly the class of component this tool exists to make visible.

## Why this exists

BYOVD is a standard way around driver signature enforcement: the attacker does
not write a malicious driver, they load a *legitimately signed but vulnerable*
one and use it to map physical memory, patch kernel structures, and kill EDR. It
is used by ransomware crews and, notably, by game cheats, which is where I first
ran into it while researching low-level client security.

The question a defender actually needs answered is boring and specific:

> Which drivers on this host are signed, where do they live, and does any of them
> match a driver that is already publicly known to be abusable?

`drvwatch` answers exactly that.

## Install and run

```console
git clone https://github.com/noobraja/drvwatch.git
cd drvwatch
python -m drvwatch
```

Python 3.9+. Nothing to install — the standard library is enough.

Writes reports and gates CI:

```console
python -m drvwatch --json out.json --html out.html
python -m drvwatch --fail-on high      # exit 1 if anything is high or worse
python -m drvwatch --no-signature      # fast inventory, skips Authenticode
```

## Detection rules

| Rule | Severity | What it means | ATT&CK |
|---|---|---|---|
| `known_vulnerable_name` | critical | Filename matches a publicly documented BYOVD driver | T1068 |
| `user_writable_path` | critical | Image sits in `%TEMP%`, `%APPDATA%`, `Downloads`, `ProgramData`, … — a non-admin process can replace it | T1543.003 |
| `invalid_signature` | critical | Signature does not match the binary (`HashMismatch`, `NotTrusted`, …) | T1553.006 |
| `unsigned` | high | No embedded Authenticode signature | T1553.006 |
| `nonstandard_path` | high | Image is outside both `System32\drivers` and `System32\DriverStore` | T1543.003 |
| `unverified_signature` | medium | Signature status is neither `Valid` nor a hard failure | T1553.006 |
| `install_dir_path` | info | Installed under `Program Files` — normal for anti-cheat and EDR | T1543.003 |
| `missing_image` | info | Service is registered but the file is gone | — |
| `third_party_signer` | info | Signed by a non-Microsoft CA — normal for hardware vendors | — |

The known-vulnerable list is a seeded subset of
[LOLDrivers](https://github.com/magicsword-io/LOLDrivers), matched **by filename**.
That is a heuristic: it produces false positives when a vendor reuses a name for
a patched build, and it misses renamed copies. The authoritative check is a
SHA-256 lookup against the full LOLDrivers set, which is the obvious next step.

## What the first run found

The first run against a Windows 10 desktop flagged **17 drivers as high risk**.
Fifteen were false positives:

- 12 were Microsoft inbox drivers staged under `System32\DriverStore`, which is
  where Windows stages packaged drivers — a normal place for them to live.
- 2 were installed under `Program Files` — Riot Vanguard's `vgk.sys` and Process
  Hacker's `kprocesshacker.sys`. Both are legitimate; admin-only write access
  means installing there already implies a compromised host.

The location rule was wrong, so it was rewritten: `DriverStore` now counts as
OS-managed, `Program Files` is informational, and only genuinely unusual paths
(like `C:\Tools\` or a user profile) escalate. That took the noise from 17 to 2
without dropping any real signal.

## Limitations (read these)

1. **Catalog signing.** Windows inbox drivers are frequently signed via a
   `.cat` catalog rather than an embedded signature. `Get-AuthenticodeSignature`
   reports those as `NotSigned`. On a clean Windows 10 host this produced two
   `unsigned` findings — `BthA2dp.sys` and `bthhfenum.sys`, both Microsoft
   Bluetooth drivers. They are catalog-signed and legitimate. Treat `unsigned`
   as a lead and confirm against the catalog before escalating.
   *(This is not hypothetical — it is what happened the first time I ran the tool.)*
2. **Filename matching, not hashing.** See above. A real deployment should test
   the SHA-256 collected for every driver against a maintained hash set.
3. **Point in time.** This reads the current service configuration. It will not
   catch a driver that was loaded and unloaded between runs.
4. **Requires Windows.** It reads `Win32_SystemDriver` through CIM.
5. **Read-only.** It changes nothing on the host. No writes outside the report
   files you ask for.

## Design notes

- **CIM, not the registry.** `Win32_SystemDriver` gives service state and start
  mode in one call, and works without elevation.
- **The same trust decision Windows makes.** `Get-AuthenticodeSignature` is the
  API backing driver signature enforcement, so the tool sees what the OS sees.
- **Rules live in a pure function.** `analyze_driver()` takes a dict and returns
  findings, with no I/O — which is why the tests need no Windows host.
- **Severity means actionability, not scary-ness.** A third-party signer is
  informational because most legitimate drivers are third-party. A hash mismatch
  is critical because Windows itself would refuse to load it.

## Tests

```console
python -m unittest discover -s tests -v
```

Runs on any platform — no Windows needed. CI runs it on `windows-latest` and
`ubuntu-latest`.

## Roadmap

- [ ] SHA-256 matching against the full LOLDrivers set
- [ ] Catalog-signature verification for inbox drivers
- [ ] Service dependency map (which drivers are actually loaded vs. dormant)
- [ ] Diff mode: compare two reports to catch newly registered drivers
- [ ] Sigma rule export for SIEM ingestion

## License

MIT — see [LICENSE](LICENSE).
