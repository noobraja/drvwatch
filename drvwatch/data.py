"""Seed list of kernel driver image names publicly documented as vulnerable.

Source: LOLDrivers (https://github.com/magicsword-io/LOLDrivers) and the
Mandiant/VMware "Bring Your Own Vulnerable Driver" research. These unsigned or
weakly-signed drivers ship with legitimate motherboard/GPU/overclocking utilities
but can be loaded by an attacker to map physical memory and disable kernel
protections.

Matching is by filename only, which is a heuristic and produces false positives
when a vendor reuses a name for a fixed build. Treat hits as a lead, not proof.
The authoritative check is a SHA-256 lookup against the full LOLDrivers set.
"""

VULNERABLE_DRIVER_NAMES: frozenset[str] = frozenset(
    {
        # Gigabyte
        "gdrv.sys",
        "gdrv2.sys",
        # Intel
        "iqvw64e.sys",
        "iqvw.sys",
        "mhyprot2.sys",
        # MSI / overclocking
        "rtcore64.sys",
        "rtcore32.sys",
        "msio64.sys",
        "msio.sys",
        # ASUS
        "asio.sys",
        "asio2.sys",
        "asio3.sys",
        "eio.sys",
        "eio64.sys",
        "eneio64.sys",
        # Dell
        "dbutil_2_3.sys",
        # CPUID / monitoring
        "cpuz141.sys",
        "cpuz149.sys",
        "winring0.sys",
        "winring0x64.sys",
        "hwinfo.sys",
        "hwinfo64.sys",
        "speedfan.sys",
        "physmem.sys",
        # AMD
        "amdryzenmasterdriver.sys",
        "amdide.sys",
        # debugging / memory access
        "gmer64.sys",
        "truesight.sys",
        "segwindrvx64.sys",
        "viragt64.sys",
        "amifldrv64.sys",
        "nvflash.sys",
        "atillk64.sys",
        "todriver.sys",
    }
)
