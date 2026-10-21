"""
Build the remediation report from a folder of snapshots.

  python src/report.py sample/snapshots --out reports
  python src/report.py sample/snapshots --out reports --sla Critical=7 --sla High=30

Writes reports/metrics.json, reports/summary.md and reports/dashboard.html.
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from vulnmetrics import SEVERITY_ORDER, build_lifecycles, compute, load_snapshots  # noqa: E402

SEV_COLORS = {"Critical": "#c92a2a", "High": "#e8590c", "Medium": "#f59f00", "Low": "#74b816"}


def fmt(v, suffix=""):
    return "—" if v is None else f"{v}{suffix}"


def summary_md(m: dict) -> str:
    t = m["totals"]
    lines = [f"# Vulnerability remediation report — as of {m['as_of']}", "",
             f"Findings tracked: **{t['findings']}** · open **{t['open']}** · remediated **{t['remediated']}** · on retired devices **{t['retired']}**", "",
             "| Severity | SLA | Remediated | MTTR (days) | Median | SLA compliance | Open | Overdue |",
             "|---|---|---|---|---|---|---|---|"]
    for r in m["by_severity"]:
        lines.append(f"| {r['severity']} | {r['sla_days']}d | {r['remediated']} | {fmt(r['mttr_days'])} | "
                     f"{fmt(r['median_days'])} | {fmt(r['sla_compliance_pct'], '%')} | {r['open']} | {r['overdue']} |")
    lines += ["", "**SLA compliance** = findings fixed within SLA ÷ (all fixed + still-open past SLA).", "",
              "## Oldest open Critical/High", "", "| Device | CVE | Severity | Software | Age (days) |", "|---|---|---|---|---|"]
    for o in m["oldest_open_crit_high"]:
        lines.append(f"| {o['device']} | {o['cve']} | {o['severity']} | {o['software']} | {o['age_days']} |")
    return "\n".join(lines) + "\n"


def _bar_chart(trend: list[dict]) -> str:
    """Monthly Critical+High SLA compliance as an inline SVG bar chart."""
    w, h, pad = 560, 220, 36
    n = max(len(trend), 1)
    bw = (w - pad * 2) / n
    parts = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="Monthly SLA compliance">']
    for pct in (0, 50, 100):
        y = h - pad - (h - pad * 2) * pct / 100
        parts.append(f'<line x1="{pad}" x2="{w - pad}" y1="{y}" y2="{y}" class="grid"/>'
                     f'<text x="{pad - 6}" y="{y + 4}" class="axis" text-anchor="end">{pct}%</text>')
    for i, row in enumerate(trend):
        pct = row["sla_compliance_pct"] or 0
        bh = (h - pad * 2) * pct / 100
        x = pad + i * bw + bw * 0.2
        y = h - pad - bh
        cls = "good" if pct >= 90 else "warn" if pct >= 75 else "bad"
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw * 0.6:.1f}" height="{bh:.1f}" rx="3" class="{cls}">'
                     f'<title>{row["month"]}: {pct}% within SLA, {row["remediated"]} fixed, MTTR {row["mttr_days"]}d</title></rect>'
                     f'<text x="{x + bw * 0.3:.1f}" y="{y - 5:.1f}" class="val" text-anchor="middle">{pct:.0f}%</text>'
                     f'<text x="{x + bw * 0.3:.1f}" y="{h - pad + 16}" class="axis" text-anchor="middle">{row["month"][2:]}</text>')
    y90 = h - pad - (h - pad * 2) * 0.9
    parts.append(f'<line x1="{pad}" x2="{w - pad}" y1="{y90}" y2="{y90}" class="target"/>'
                 f'<text x="{w - pad}" y="{y90 - 4}" class="axis" text-anchor="end">90% target</text></svg>')
    return "".join(parts)


def _aging_table(aging: dict) -> str:
    max_v = max([v for b in aging.values() for v in b.values()] + [1])
    rows = []
    for bucket, sevs in aging.items():
        cells = "".join(
            f'<td><span class="cell" style="--a:{0.12 + 0.88 * sevs.get(s, 0) / max_v:.2f};--c:{SEV_COLORS[s]}">{sevs.get(s, 0)}</span></td>'
            for s in SEVERITY_ORDER)
        rows.append(f"<tr><th>{bucket}</th>{cells}</tr>")
    head = "".join(f"<th>{s}</th>" for s in SEVERITY_ORDER)
    return f"<table class='aging'><thead><tr><th>Age</th>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def dashboard_html(m: dict) -> str:
    t = m["totals"]
    crit = next(r for r in m["by_severity"] if r["severity"] == "Critical")
    high = next(r for r in m["by_severity"] if r["severity"] == "High")
    kpis = [
        ("Critical MTTR", fmt(crit["mttr_days"], " d"), f"SLA {crit['sla_days']}d"),
        ("Critical SLA compliance", fmt(crit["sla_compliance_pct"], "%"), f"{crit['overdue']} overdue"),
        ("High SLA compliance", fmt(high["sla_compliance_pct"], "%"), f"{high['overdue']} overdue"),
        ("Open findings", str(t["open"]), f"{t['remediated']} remediated"),
    ]
    kpi_html = "".join(f'<div class="kpi"><span>{html.escape(a)}</span><b>{html.escape(b)}</b><small>{html.escape(c)}</small></div>'
                       for a, b, c in kpis)
    sev_rows = "".join(
        f"<tr><td><i style='background:{SEV_COLORS[r['severity']]}'></i>{r['severity']}</td><td>{r['sla_days']}d</td>"
        f"<td>{r['remediated']}</td><td>{fmt(r['mttr_days'])}</td><td>{fmt(r['median_days'])}</td>"
        f"<td>{fmt(r['sla_compliance_pct'], '%')}</td><td>{r['open']}</td><td>{r['overdue']}</td></tr>"
        for r in m["by_severity"])
    oldest = "".join(
        f"<tr><td>{html.escape(o['device'])}</td><td>{html.escape(o['cve'])}</td><td>{o['severity']}</td>"
        f"<td>{html.escape(o['software'])}</td><td>{o['age_days']}</td></tr>" for o in m["oldest_open_crit_high"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Remediation Metrics</title>
<style>
:root{{--bg:#f6f5f1;--surface:#fff;--ink:#14171c;--muted:#5b6270;--line:#e2e0d8;--good:#2b8a3e;--warn:#e8590c;--bad:#c92a2a}}
@media (prefers-color-scheme: dark){{:root:not([data-theme="light"]){{--bg:#0f1115;--surface:#171a20;--ink:#e9eaee;--muted:#9aa1ad;--line:#272b33;--good:#51cf66;--warn:#ff922b;--bad:#ff6b6b}}}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1000px;margin:0 auto;padding:32px 16px}} h1{{font-size:26px;margin:0}} h2{{font-size:17px;margin:0 0 12px}}
.sub{{color:var(--muted);margin:4px 0 24px}} .kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}}
@media (max-width:720px){{.kpis{{grid-template-columns:repeat(2,1fr)}}}}
.kpi,.card{{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px}}
.kpi span{{display:block;color:var(--muted);font-size:13px}} .kpi b{{display:block;font-size:28px;margin:4px 0}} .kpi small{{color:var(--muted)}}
.grid2{{display:grid;grid-template-columns:1.3fr 1fr;gap:16px;margin-bottom:16px}} @media (max-width:820px){{.grid2{{grid-template-columns:1fr}}}}
.card{{margin-bottom:16px;overflow-x:auto}} table{{width:100%;border-collapse:collapse;font-size:14px}}
th,td{{text-align:left;padding:8px;border-bottom:1px solid var(--line);white-space:nowrap}} th{{color:var(--muted);font-weight:500}}
td i{{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:8px}}
svg{{width:100%;height:auto}} .grid{{stroke:var(--line)}} .target{{stroke:var(--muted);stroke-dasharray:4 4}}
.axis{{fill:var(--muted);font-size:11px}} .val{{fill:var(--ink);font-size:11px}}
.good{{fill:var(--good)}} .warn{{fill:var(--warn)}} .bad{{fill:var(--bad)}}
.aging td{{text-align:center}} .cell{{display:inline-block;min-width:42px;padding:4px 8px;border-radius:6px;
background:color-mix(in srgb,var(--c) calc(var(--a)*100%),transparent);color:var(--ink);font-weight:600}}
footer{{color:var(--muted);font-size:13px}}
</style></head><body><main>
<h1>Vulnerability remediation</h1>
<p class="sub">As of {m['as_of']} · {t['findings']} findings tracked · synthetic demo data</p>
<div class="kpis">{kpi_html}</div>
<div class="grid2">
<div class="card"><h2>Critical + High: share fixed within SLA, by month</h2>{_bar_chart(m['trend_crit_high'])}</div>
<div class="card"><h2>Open findings by age</h2>{_aging_table(m['open_aging'])}</div>
</div>
<div class="card"><h2>By severity</h2><table><thead><tr><th>Severity</th><th>SLA</th><th>Remediated</th><th>MTTR (d)</th><th>Median (d)</th><th>SLA compliance</th><th>Open</th><th>Overdue</th></tr></thead><tbody>{sev_rows}</tbody></table></div>
<div class="card"><h2>Oldest open Critical/High</h2><table><thead><tr><th>Device</th><th>CVE</th><th>Severity</th><th>Software</th><th>Age (d)</th></tr></thead><tbody>{oldest}</tbody></table></div>
<footer>SLA compliance = fixed within SLA ÷ (all fixed + still open past SLA). Generated by vuln-remediation-metrics.</footer>
</main></body></html>
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("snapshots", type=Path)
    ap.add_argument("--out", type=Path, default=Path("reports"))
    ap.add_argument("--sla", action="append", default=[], help="Severity=days, e.g. Critical=7")
    args = ap.parse_args(argv)

    sla = {k: int(v) for k, v in (s.split("=") for s in args.sla)}
    snaps = load_snapshots(args.snapshots)
    findings = build_lifecycles(snaps)
    m = compute(findings, as_of=snaps[-1][0], sla_days=sla)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "metrics.json").write_text(json.dumps(m, indent=2) + "\n")
    (args.out / "summary.md").write_text(summary_md(m))
    (args.out / "dashboard.html").write_text(dashboard_html(m))
    print(summary_md(m))
    return 0


if __name__ == "__main__":
    sys.exit(main())
