"""Render a run's `monitor.jsonl` as one self-contained HTML dashboard.

Usage: python3 render_dashboard.py RUN_DIR [OUT_FILE]

Writes `RUN_DIR/dashboard.html` by default and prints the path. The page holds
only counts, flags and ids: no alert text, no scores and no triage reasons, so
nothing of the competition tasks leaves the traces directory except numbers.
Publish it with the Artifact tool using the same path every time, so the URL
stays the same and open viewers see the update.
"""

import html
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyze-task"))

from runview import (  # noqa: E402
    deep_candidates,
    eta,
    expected_total,
    progress,
    read_rows,
    run_tag,
    run_totals,
    short_count,
    symbol,
    triage_answers,
)

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#14181f;--muted:#5b6573;--line:#dfe3e8;
--ok:#1a7f4b;--warn:#a36200;--fail:#c0262d;--accent:#2f5fd0;--bar:#9db4ee}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f1318;--card:#171c23;
--ink:#e6e9ee;--muted:#98a2b0;--line:#2a313b;--ok:#4cc38a;--warn:#e0a82e;--fail:#ff6b6b;
--accent:#7aa2ff;--bar:#3a528f}}
:root[data-theme="dark"]{--bg:#0f1318;--card:#171c23;--ink:#e6e9ee;--muted:#98a2b0;--line:#2a313b;
--ok:#4cc38a;--warn:#e0a82e;--fail:#ff6b6b;--accent:#7aa2ff;--bar:#3a528f}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.45 system-ui,sans-serif;padding:20px 16px}
main{max-width:1000px;margin:0 auto}h1{font-size:20px;margin:0 0 4px}
.sub{color:var(--muted);margin:0 0 16px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:16px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.kpi b{display:block;font-size:20px}.kpi span{color:var(--muted);font-size:12px}
.progress{height:8px;background:var(--line);border-radius:4px;overflow:hidden;margin-bottom:16px}
.progress i{display:block;height:100%;background:var(--accent)}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;min-width:640px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--muted);font-weight:600;font-size:12px}tr:last-child td{border-bottom:0}
.ok{color:var(--ok)}.warn{color:var(--warn)}.fail{color:var(--fail)}
.chip{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:0 7px;
margin-right:4px;font-size:12px;color:var(--muted)}
.bar{display:inline-block;height:8px;background:var(--bar);border-radius:3px;vertical-align:middle}
.deep{font-weight:700;color:var(--warn)}
"""

GLYPH_CLASS = {"✔": "ok", "⚠": "warn", "✖": "fail"}


def render(run_dir: Path) -> str:
    """Return the dashboard HTML for a run directory."""
    rows = read_rows(run_dir)
    first = rows[0] if rows else {}
    mode = first.get("mode") or "practice"
    tag = first.get("tag") or run_tag(run_dir.name, mode)
    t = run_totals(rows, expected_total(mode, first.get("total")))
    deep = set(deep_candidates(run_dir))
    triaged = set(triage_answers(run_dir))
    peak = max((r.get("tokens") or 0 for r in rows), default=1) or 1
    body = []
    for r in rows:
        number = f"{r['number']:03d}"
        glyph = symbol(r)
        chips = "".join(f'<span class="chip">{html.escape(f)}</span>' for f in r.get("flags") or [])
        width = round(90 * (r.get("tokens") or 0) / peak)
        tokens = short_count(r.get("tokens") or 0)
        mark = (
            '<span class="deep">DEEP</span>'
            if number in deep
            else ("SKIP" if number in triaged else "")
        )
        body.append(
            f'<tr><td class="{GLYPH_CLASS[glyph]}">{glyph} {number}</td>'
            f"<td>{html.escape(str(r.get('verdict', '?')))}</td><td>{chips}</td>"
            f"<td>{r.get('calls', 0)}</td>"
            f'<td><span class="bar" style="width:{width}px"></span> {tokens}</td>'
            f"<td>{(r.get('duration_s') or 0) / 60:.1f}m</td><td>{mark}</td></tr>"
        )
    pct = min(100, round(100 * t["done"] / t["total"])) if t["total"] else 0
    kpis = [
        (progress(t), "tasks"),
        (f"{t['ok']} / {t['warn']} / {t['fail']}", "✔ / ⚠ / ✖"),
        (f"{t['calls']:.0f}", "calls per task"),
        (short_count(t["tokens"]), "LLM tokens"),
        (eta(t), "ETA"),
        (", ".join(sorted(deep)) or "-", "DEEP candidates"),
    ]
    cards = "".join(
        f'<div class="kpi"><b>{html.escape(v)}</b><span>{k}</span></div>' for v, k in kpis
    )
    title = " · ".join(
        html.escape(str(x))
        for x in (first.get("mode"), first.get("agent"), first.get("label"), first.get("model"))
        if x
    )
    stamp = time.strftime("%H:%M:%S")
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>Run {html.escape(tag)}</title><style>{CSS}</style></head><body><main>"
        f"<h1>Run {html.escape(tag)}</h1>"
        f'<p class="sub">{title or "no tasks yet"} · updated {stamp}</p>'
        f'<div class="kpis">{cards}</div>'
        f'<div class="progress"><i style="width:{pct}%"></i></div>'
        '<div class="wrap"><table><thead><tr><th>Task</th><th>Verdict</th><th>Flags</th>'
        "<th>Calls</th><th>Tokens</th><th>Time</th><th>Triage</th></tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table></div></main></body></html>"
    )


def main() -> None:
    """Write the dashboard next to the run's traces and print its path."""
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    run_dir = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else run_dir / "dashboard.html"
    out.write_text(render(run_dir))
    print(out)


if __name__ == "__main__":
    main()
