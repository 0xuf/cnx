#!/usr/bin/env python3
"""
CNX — Subdomain Takeover Scanner
=================================
High-performance, queue-based async scanner.

Usage examples
--------------
    python main.py -l input/domains.txt
    python main.py -l input/domains.txt -c 300 --rate-limit 200
    python main.py -l input/domains.txt --only-vulnerable --format json
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.engine import Engine
from output.writer import write_reports
from utils.logger import get_logger
from utils.models import Verdict

console = Console()
logger = get_logger("cnx")

_BANNER = """
[bold cyan]
 ██████╗███╗   ██╗██╗  ██╗
██╔════╝████╗  ██║╚██╗██╔╝
██║     ██╔██╗ ██║ ╚███╔╝
██║     ██║╚██╗██║ ██╔██╗
╚██████╗██║ ╚████║██╔╝ ██╗
 ╚═════╝╚═╝  ╚═══╝╚═╝  ╚═╝
[/bold cyan][dim]Subdomain Takeover Scanner[/dim]  [dim cyan]github.com/0xuf/cnx[/dim cyan]
"""


# ─────────────────────────────────────────────────────────────────────────── #
# CLI
# ─────────────────────────────────────────────────────────────────────────── #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cnx",
        description="CNX — High-performance subdomain takeover scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py -l input/domains.txt\n"
            "  python main.py -l input/domains.txt -c 300 --rate-limit 100\n"
            "  python main.py -l input/domains.txt --only-vulnerable --format json\n"
        ),
    )
    parser.add_argument(
        "-l", "--list",
        required=False,
        default=None,
        metavar="FILE",
        help="Path to newline-separated list of domains/subdomains (omit to read from stdin)",
    )
    parser.add_argument(
        "-f", "--fingerprints",
        default="fingerprints.json",
        metavar="FILE",
        help="Path to fingerprints JSON (default: fingerprints.json)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv", "html", "all"],
        default="all",
        help="Report format (default: all)",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=150,
        metavar="N",
        help="Concurrent scan workers (default: 150)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="Per-domain HTTP timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=0,
        metavar="RPS",
        help="Max requests per second — 0 means unlimited (default: 0)",
    )
    parser.add_argument(
        "--only-vulnerable",
        action="store_true",
        help="Only include vulnerable targets in the report",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        metavar="PATH",
        help=(
            "Output base path without extension (e.g. results/scan). "
            "If omitted, results are printed to stdout only."
        ),
    )
    parser.add_argument(
        "--silent",
        action="store_true",
        help=(
            "Suppress banner, dashboard and summary. "
            "Print results line-by-line to stdout in plain text."
        ),
    )
    return parser


# ─────────────────────────────────────────────────────────────────────────── #
# Main
# ─────────────────────────────────────────────────────────────────────────── #


async def _run(args: argparse.Namespace) -> int:
    silent = args.silent

    # ── Validate inputs ────────────────────────────────────────────────
    fp_file = Path(args.fingerprints)

    # ── Load domains (file or stdin) ───────────────────────────────────
    if args.list:
        domains_file = Path(args.list)
        if not domains_file.exists():
            print(f"ERROR: Domains file not found: {domains_file}", file=sys.stderr)
            return 1
        raw_lines = domains_file.read_text(encoding="utf-8").splitlines()
    else:
        if sys.stdin.isatty():
            print("ERROR: No input. Use -l <file> or pipe domains via stdin.", file=sys.stderr)
            return 1
        raw_lines = sys.stdin.read().splitlines()

    domains = [
        line.strip()
        for line in raw_lines
        if line.strip() and not line.startswith("#")
    ]

    if not domains:
        print(f"ERROR: No domains found in {domains_file}", file=sys.stderr)
        return 1

    if not silent:
        console.print(_BANNER)
        console.print(
            Panel(
                f"[bold white]Targets:[/] [cyan]{len(domains):,}[/]   "
                f"[bold white]Concurrency:[/] [cyan]{args.concurrency}[/]   "
                f"[bold white]Timeout:[/] [cyan]{args.timeout}s[/]   "
                f"[bold white]Rate limit:[/] [cyan]"
                f"{'unlimited' if args.rate_limit == 0 else str(args.rate_limit) + ' rps'}[/]",
                border_style="cyan",
                title="[bold cyan]Scan Config[/]",
            )
        )

    # ── Run engine ─────────────────────────────────────────────────────
    start = time.monotonic()

    engine = Engine(
        fingerprints_path=str(fp_file),
        concurrency=args.concurrency,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        silent=silent,
    )

    results = await engine.run(domains)
    elapsed = time.monotonic() - start

    # ── Filter ─────────────────────────────────────────────────────────
    report_results = [r for r in results if r.vulnerable] if args.only_vulnerable else results

    # ── Output ─────────────────────────────────────────────────────────
    if silent:
        # Plain line-by-line stdout — pipe-friendly, vulnerable only
        for r in results:
            if r.vulnerable:
                print(r.domain)
    else:
        # Rich summary panel
        vulnerable = [r for r in results if r.vulnerable]
        edge_cases = [r for r in results if r.verdict == Verdict.EDGE_CASE]
        errors     = [r for r in results if r.error]

        summary = Table.grid(padding=(0, 3))
        summary.add_column(style="bold white", min_width=20)
        summary.add_column(style="bold cyan")
        summary.add_row("Total scanned",         f"{len(results):,}")
        summary.add_row("[red]Vulnerable[/]",     f"[red]{len(vulnerable):,}[/]")
        summary.add_row("[yellow]Edge cases[/]",  f"[yellow]{len(edge_cases):,}[/]")
        summary.add_row("[dim]Errors[/]",         f"[dim]{len(errors):,}[/]")
        summary.add_row("Elapsed",                f"{elapsed:.1f}s")
        summary.add_row(
            "Avg speed",
            f"{len(results) / elapsed:.0f} domains/sec",
        )
        console.print(
            Panel(summary, border_style="cyan", title="[bold cyan]Summary[/]")
        )

    # ── Write reports (only when -o is given) ──────────────────────────
    if args.output:
        formats = (
            {"json", "csv", "html"} if args.format == "all" else {args.format}
        )
        written = write_reports(report_results, args.output, formats)
        if not silent:
            for path in written:
                console.print(f"[green]✓[/] Report saved → [bold]{path}[/]")
        else:
            for path in written:
                print(f"saved: {path}", file=sys.stderr)

    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        exit_code = asyncio.run(_run(args))
    except KeyboardInterrupt:
        if not args.silent:
            console.print("\n[yellow]Scan interrupted by user.[/]")
        else:
            print("\ninterrupted", file=sys.stderr)
        exit_code = 130

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
