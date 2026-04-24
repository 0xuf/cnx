"""
Live terminal dashboard powered by Rich.

Updates a single progress bar + live stats table in-place so the terminal
never scrolls, even when scanning millions of domains.
Vulnerable hits are printed immediately as they are discovered.
"""

from __future__ import annotations

import threading
from typing import List

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

from utils.models import ScanResult, Verdict

console = Console(stderr=False)

_VERDICT_STYLE = {
    Verdict.VULNERABLE:     "bold red",
    Verdict.EDGE_CASE:      "yellow",
    Verdict.NOT_VULNERABLE: "dim green",
    Verdict.ERROR:          "dim red",
    Verdict.UNKNOWN:        "dim white",
}


class LiveDashboard:
    """
    Thread-safe live dashboard.

    Call ``update(result)`` from any worker coroutine; the dashboard
    refreshes atomically.
    Pass ``silent=True`` to disable all output (used with ``--silent``).
    """

    def __init__(self, total: int, silent: bool = False) -> None:
        self._total = total
        self._silent = silent
        self._scanned = 0
        self._vulnerable: List[ScanResult] = []
        self._lock = threading.Lock()

        if silent:
            return   # no Rich objects needed

        self._progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=40, style="cyan", complete_style="green"),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            refresh_per_second=12,
            transient=False,
        )
        self._task_id = self._progress.add_task(
            "Scanning…", total=total
        )
        self._live = Live(
            self._build_renderable(),
            refresh_per_second=12,
            console=console,
            auto_refresh=False,
        )
        self._live.start(refresh=True)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def update(self, result: ScanResult) -> None:
        """Register one completed scan result and refresh the display."""
        with self._lock:
            self._scanned += 1
            if result.vulnerable:
                self._vulnerable.append(result)
            if self._silent:
                return
            self._progress.advance(self._task_id)
            self._live.update(self._build_renderable(), refresh=True)

    def stop(self) -> None:
        """Stop the live display (called automatically by the engine)."""
        if not self._silent:
            self._live.stop()
            # Explicitly restore cursor visibility and move to a clean line
            console.show_cursor(True)
            console.print("")

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    def _build_renderable(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column()
        grid.add_row(self._progress)
        grid.add_row(self._stats_table())

        if self._vulnerable:
            grid.add_row(self._hits_table())

        return Panel(
            grid,
            title="[bold cyan]CNX — Subdomain Takeover Scanner[/]",
            border_style="cyan",
            padding=(0, 1),
        )

    def _stats_table(self) -> Table:
        t = Table.grid(padding=(0, 3))
        t.add_column(style="bold white")
        t.add_column(style="bold cyan")
        t.add_row("Scanned",    str(self._scanned))
        t.add_row("Total",      str(self._total))
        t.add_row(
            "[red]Vulnerable[/]",
            f"[bold red]{len(self._vulnerable)}[/]",
        )
        remaining = self._total - self._scanned
        t.add_row("Remaining", str(remaining))
        return t

    def _hits_table(self) -> Table:
        t = Table(
            "Domain",
            "Service",
            "Verdict",
            "Fingerprint",
            title="[bold red]Hits[/]",
            border_style="red",
            expand=True,
            show_lines=False,
        )
        # Show only the last 15 to keep the panel compact
        for r in self._vulnerable[-15:]:
            style = _VERDICT_STYLE.get(r.verdict, "white")
            t.add_row(
                Text(r.domain, style="bold white"),
                r.service or "-",
                Text(r.verdict.value, style=style),
                (r.fingerprint_matched or "")[:60],
            )
        return t
