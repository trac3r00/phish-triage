"""Command-line entry point for ``phish-triage``."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .parser import parse_eml, render_markdown


def _add_parse_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "parse",
        help="Stage 1: parse a .eml file and print JSON or markdown.",
    )
    p.add_argument("eml", type=Path, help="Path to the .eml file")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="Output JSON (default)")
    fmt.add_argument(
        "--markdown",
        action="store_true",
        help="Output a human-readable markdown summary",
    )
    p.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Write to file instead of stdout",
    )


def _add_enrich_subparser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "enrich",
        help=(
            "Stage 2: parse + enrich a .eml file with VirusTotal & AbuseIPDB, "
            "produce a markdown triage report with verdict."
        ),
    )
    p.add_argument("eml", type=Path, help="Path to the .eml file")
    p.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Write the markdown report to a file (default: stdout)",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Print the enrichment payload as JSON instead of markdown",
    )
    p.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(".cache"),
        help="Directory for cached API responses (default: ./.cache)",
    )
    p.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable cache reads (writes still happen unless --no-cache-write)",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phish-triage",
        description=(
            "Phishing email triage toolkit — parse .eml files, enrich IOCs, "
            "produce analyst-ready reports."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    _add_parse_subparser(sub)
    _add_enrich_subparser(sub)
    return parser


def _cmd_parse(args: argparse.Namespace) -> int:
    parsed = parse_eml(args.eml)
    if args.markdown:
        out = render_markdown(parsed)
    else:
        out = json.dumps(parsed.to_dict(), indent=2, default=str)
    if args.output:
        args.output.write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
        if not out.endswith("\n"):
            sys.stdout.write("\n")
    return 0


def _cmd_enrich(args: argparse.Namespace) -> int:
    # Imported lazily so `phish-triage parse` works without `requests`.
    from .enrich import enrich_eml, render_report

    parsed = parse_eml(args.eml)
    result = enrich_eml(
        parsed,
        cache_dir=None if args.no_cache else args.cache_dir,
    )
    if args.json:
        payload = {
            "parsed": parsed.to_dict(),
            "enrichment": asdict(result),
        }
        out = json.dumps(payload, indent=2, default=str)
    else:
        out = render_report(parsed, result)
    if args.output:
        args.output.write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
        if not out.endswith("\n"):
            sys.stdout.write("\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "parse":
        return _cmd_parse(args)
    if args.command == "enrich":
        return _cmd_enrich(args)
    parser.error(f"unknown command: {args.command}")
    return 2  # unreachable


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
