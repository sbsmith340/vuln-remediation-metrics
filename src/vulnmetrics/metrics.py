"""Compute leadership metrics from finding lifecycles."""
from __future__ import annotations

from collections import defaultdict
from datetime import date
from statistics import mean, median

from .lifecycle import SEVERITY_ORDER, Finding

DEFAULT_SLA_DAYS = {"Critical": 15, "High": 30, "Medium": 90, "Low": 180}
AGE_BUCKETS = [(0, 15, "0-15d"), (16, 30, "16-30d"), (31, 60, "31-60d"), (61, 90, "61-90d"), (91, 10_000, "90d+")]


def _pct(n: int, d: int) -> float | None:
    return round(100 * n / d, 1) if d else None


def compute(findings: list[Finding], as_of: date, sla_days: dict[str, int] | None = None) -> dict:
    sla = {**DEFAULT_SLA_DAYS, **(sla_days or {})}
    by_sev: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_sev[f.severity].append(f)

    severity_rows = []
    for sev in SEVERITY_ORDER:
        fs = by_sev.get(sev, [])
        fixed = [f for f in fs if f.status == "remediated"]
        open_ = [f for f in fs if f.status == "open"]
        days = [f.days_to_remediate for f in fixed]
        within = sum(1 for d in days if d <= sla[sev])
        overdue = [f for f in open_ if f.age_on(as_of) > sla[sev]]
        severity_rows.append({
            "severity": sev,
            "sla_days": sla[sev],
            "remediated": len(fixed),
            "open": len(open_),
            "overdue": len(overdue),
            "mttr_days": round(mean(days), 1) if days else None,
            "median_days": round(float(median(days)), 1) if days else None,
            # SLA compliance counts closed-in-time vs closed-late + open-overdue,
            # so a backlog of old open findings can't hide behind fast easy fixes.
            "sla_compliance_pct": _pct(within, len(fixed) + len(overdue)),
        })

    aging = {label: {s: 0 for s in SEVERITY_ORDER} for _, _, label in AGE_BUCKETS}
    for f in findings:
        if f.status != "open":
            continue
        age = f.age_on(as_of)
        for lo, hi, label in AGE_BUCKETS:
            if lo <= age <= hi:
                aging[label][f.severity] = aging[label].get(f.severity, 0) + 1
                break

    monthly: dict[str, dict] = defaultdict(lambda: {"remediated": 0, "within_sla": 0, "days": []})
    for f in findings:
        if f.status == "remediated" and f.severity in ("Critical", "High"):
            m = f.remediated_on.strftime("%Y-%m")
            monthly[m]["remediated"] += 1
            monthly[m]["days"].append(f.days_to_remediate)
            monthly[m]["within_sla"] += f.days_to_remediate <= sla[f.severity]
    trend = [{"month": m, "remediated": v["remediated"],
              "mttr_days": round(mean(v["days"]), 1),
              "sla_compliance_pct": _pct(v["within_sla"], v["remediated"])}
             for m, v in sorted(monthly.items())]

    worst = sorted((f for f in findings if f.status == "open" and f.severity in ("Critical", "High")),
                   key=lambda f: f.age_on(as_of), reverse=True)[:10]
    top_overdue = [{"device": f.device_name, "cve": f.cve_id, "severity": f.severity,
                    "software": f.software, "age_days": f.age_on(as_of)} for f in worst]

    return {
        "as_of": as_of.isoformat(),
        "sla_days": sla,
        "totals": {
            "findings": len(findings),
            "open": sum(f.status == "open" for f in findings),
            "remediated": sum(f.status == "remediated" for f in findings),
            "retired": sum(f.status == "retired" for f in findings),
        },
        "by_severity": severity_rows,
        "open_aging": aging,
        "trend_crit_high": trend,
        "oldest_open_crit_high": top_overdue,
    }
