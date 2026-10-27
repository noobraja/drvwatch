"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyze import SEVERITY_RANK, analyze
from .collect import collect
from .report import render_console, render_html, render_json


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="drvwatch",
        description="Inventory Windows kernel drivers and flag BYOVD risk.",
    )
    parser.add_argument("--json", type=Path, metavar="FILE", help="write JSON report")
    parser.add_argument("--html", type=Path, metavar="FILE", help="write HTML report")
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "none"),
        default="none",
        help="exit non-zero when a finding at or above this severity exists",
    )
    parser.add_argument("--no-signature", action="store_true", help="skip Authenticode checks")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--quiet", action="store_true", help="suppress console table")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        drivers = collect(check_signature=not args.no_signature)
    except Exception as exc:  # noqa: BLE001 - surfaced to the user verbatim
        print(f"drvwatch: {exc}", file=sys.stderr)
        return 2

    report = analyze(drivers)

    if not args.quiet:
        use_color = sys.stdout.isatty() and not args.no_color
        print(render_console(report, color=use_color))

    if args.json:
        args.json.write_text(render_json(report), encoding="utf-8")
        print(f"wrote {args.json}")

    if args.html:
        args.html.write_text(render_html(report), encoding="utf-8")
        print(f"wrote {args.html}")

    if args.fail_on == "none":
        return 0

    threshold = SEVERITY_RANK[args.fail_on]
    breached = any(
        SEVERITY_RANK.get(driver["worst"], 0) >= threshold for driver in report["drivers"]
    )
    return 1 if breached else 0


if __name__ == "__main__":
    raise SystemExit(main())
