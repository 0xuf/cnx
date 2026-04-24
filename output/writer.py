"""
Report writers: JSON, CSV, HTML.

Usage
-----
    from output.writer import write_reports
    write_reports(results, base_path="results/scan_2026", formats={"json", "csv", "html"})
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import List, Set

from utils.models import ScanResult, Verdict

# ────────────────────────────────────────────────────────────────────────── #
# Public entry point
# ────────────────────────────────────────────────────────────────────────── #


def write_reports(
    results: List[ScanResult],
    base_path: str,
    formats: Set[str],
) -> List[str]:
    """
    Write reports in the requested formats.

    Parameters
    ----------
    results:    All ``ScanResult`` objects from the engine.
    base_path:  Output path **without** extension, e.g. ``results/run_01``.
    formats:    One or more of ``{"json", "csv", "html"}``.

    Returns
    -------
    List of file paths written.
    """
    Path(base_path).parent.mkdir(parents=True, exist_ok=True)

    writers = {
        "json": _write_json,
        "csv":  _write_csv,
        "html": _write_html,
    }

    written: List[str] = []
    for fmt in formats:
        fn = writers.get(fmt.lower())
        if fn:
            path = f"{base_path}.{fmt.lower()}"
            fn(results, path)
            written.append(path)

    return written


# ────────────────────────────────────────────────────────────────────────── #
# Writers
# ────────────────────────────────────────────────────────────────────────── #


def _write_json(results: List[ScanResult], path: str) -> None:
    data = [r.to_dict() for r in results]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def _write_csv(results: List[ScanResult], path: str) -> None:
    if not results:
        return

    fieldnames = list(results[0].to_dict().keys())

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            row = r.to_dict()
            row["cname_chain"] = " → ".join(row["cname_chain"])
            writer.writerow(row)


def _write_html(results: List[ScanResult], path: str) -> None:
    total = len(results)
    vulnerable = [r for r in results if r.vulnerable]
    vuln_count = len(vulnerable)
    safe_count = total - vuln_count

    rows_html = ""
    for r in results:
        if r.verdict == Verdict.VULNERABLE:
            row_class = "vuln"
        elif r.verdict == Verdict.EDGE_CASE:
            row_class = "edge"
        else:
            row_class = ""

        badge = (
            '<span class="badge vuln-badge">VULNERABLE</span>'
            if r.vulnerable
            else f'<span class="badge">{r.status_label or r.verdict.value}</span>'
        )
        cname = " → ".join(r.cname_chain) if r.cname_chain else "—"
        fp = (r.fingerprint_matched or "—")[:120]

        rows_html += f"""
        <tr class="{row_class}">
            <td class="domain">{r.domain}</td>
            <td>{badge}</td>
            <td>{r.service or "—"}</td>
            <td class="mono">{cname}</td>
            <td>{"Yes" if r.nxdomain else "No"}</td>
            <td>{r.http_status or "—"}</td>
            <td class="mono fp">{fp}</td>
            <td class="err">{r.error or ""}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CNX — Scan Report</title>
<style>
  :root {{
    --bg:       #0d1117;
    --surface:  #161b22;
    --border:   #30363d;
    --text:     #e6edf3;
    --muted:    #8b949e;
    --blue:     #58a6ff;
    --green:    #3fb950;
    --red:      #f85149;
    --yellow:   #e3b341;
    --mono:     'JetBrains Mono', 'Fira Mono', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 2rem;
    font-size: 14px;
  }}
  header {{ margin-bottom: 1.5rem; }}
  header h1 {{ color: var(--blue); font-size: 1.8rem; letter-spacing: 1px; }}
  header p  {{ color: var(--muted); margin-top: .25rem; }}

  .stats {{
    display: flex;
    gap: 1rem;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
  }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.5rem;
    min-width: 140px;
  }}
  .card .num   {{ font-size: 2rem; font-weight: 700; color: var(--blue); }}
  .card .label {{ color: var(--muted); font-size: .8rem; margin-top: .2rem; }}
  .card.red  .num {{ color: var(--red);   }}
  .card.green .num {{ color: var(--green); }}

  .table-wrap {{
    overflow-x: auto;
    border-radius: 10px;
    border: 1px solid var(--border);
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--surface);
  }}
  thead th {{
    background: #21262d;
    padding: .6rem 1rem;
    text-align: left;
    color: var(--muted);
    font-size: .75rem;
    text-transform: uppercase;
    letter-spacing: .5px;
    white-space: nowrap;
  }}
  tbody td {{
    padding: .55rem 1rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    max-width: 320px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr:hover {{ background: #1c2128; }}
  tbody tr.vuln  {{ background: #1f1118; }}
  tbody tr.edge  {{ background: #1a1a10; }}
  .domain {{ font-weight: 600; color: var(--blue); }}
  .mono   {{ font-family: var(--mono); font-size: .8rem; color: var(--muted); }}
  .fp     {{ color: #c9a; max-width: 260px; }}
  .err    {{ color: var(--red); font-size: .8rem; }}
  .badge  {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 20px;
    font-size: .7rem;
    font-weight: 600;
    background: #21262d;
    color: var(--muted);
  }}
  .vuln-badge {{
    background: #3d1118;
    color: var(--red);
  }}
</style>
</head>
<body>
<header>
  <h1>CNX — Subdomain Takeover Report</h1>
  <p>Automated scan using fingerprints.json</p>
</header>

<div class="stats">
  <div class="card">
    <div class="num">{total}</div>
    <div class="label">Total Scanned</div>
  </div>
  <div class="card red">
    <div class="num">{vuln_count}</div>
    <div class="label">Vulnerable</div>
  </div>
  <div class="card green">
    <div class="num">{safe_count}</div>
    <div class="label">Not Vulnerable</div>
  </div>
</div>

<div class="table-wrap">
<table>
  <thead>
    <tr>
      <th>Domain</th>
      <th>Status</th>
      <th>Service</th>
      <th>CNAME Chain</th>
      <th>NXDOMAIN</th>
      <th>HTTP</th>
      <th>Fingerprint</th>
      <th>Error</th>
    </tr>
  </thead>
  <tbody>
    {rows_html}
  </tbody>
</table>
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
