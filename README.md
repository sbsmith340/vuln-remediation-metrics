# Vulnerability Remediation Metrics

> Turns Microsoft Defender vulnerability snapshots into the numbers leadership asks for: mean time to remediate, SLA compliance by severity, the aging backlog, and the oldest open Critical/High findings. Delivered as a one-page dashboard.

![ci](https://github.com/sbsmith340/vuln-remediation-metrics/actions/workflows/ci.yml/badge.svg)
![data](https://img.shields.io/badge/data-synthetic-blue)
![deps](https://img.shields.io/badge/runtime%20deps-none-brightgreen)

**[Live demo dashboard →](https://sbsmith340.github.io/demos/remediation-dashboard.html)**

## Problem
"How fast do we patch critical vulnerabilities?" sounds simple. Defender Vulnerability Management can't answer it directly, because `DeviceTvmSoftwareVulnerabilities` shows only what is vulnerable **right now**. It has no "remediated on" date. Teams end up reporting open counts, which say nothing about speed, and those counts look better whenever a device drops offline.

## Approach
Export a snapshot on a schedule (daily or weekly) and diff the snapshots:

| Event | Rule |
|---|---|
| **First seen** | first snapshot where the (device, CVE) pair appears |
| **Remediated** | first snapshot where the device **still reports** but the pair is gone |
| **Retired** | the device stopped reporting entirely, so it is **not** counted as a fix |
| **Regression** | the pair returns after a fix, so a new finding starts with its own clock |

A fully patched device has no rows in the vulnerability table. The [export query](kql/export-snapshot.kql) therefore adds a **heartbeat row** per active device from `DeviceInfo`. Without it, a device's final fixes would be miscounted as retirements.

**SLA compliance is calculated honestly:**
`fixed within SLA ÷ (all fixed + still open past SLA)`
A backlog of old open findings can't hide behind a stream of quick, easy fixes.

## Output
`python src/report.py <snapshots>` writes three files:
- `reports/dashboard.html`: a single self-contained page with KPIs, a monthly Critical+High SLA trend against a 90% target, an aging heatmap, a severity table, and the oldest open findings. It works in light and dark mode and on phones.
- `reports/summary.md`: the same figures as Markdown, ready to paste into a status report.
- `reports/metrics.json`: machine-readable output for other tools.

### Demo results (synthetic fleet: 120 devices, 26 weekly snapshots)
| Severity | SLA | Remediated | MTTR | Median | SLA compliance | Open | Overdue |
|---|---|---|---|---|---|---|---|
| Critical | 15d | 191 | 11.5d | 7d | 88.1% | 2 | 2 |
| High | 30d | 355 | 24.5d | 21d | 76.2% | 52 | 19 |
| Medium | 90d | 262 | 55.7d | 49d | 68.5% | 233 | 75 |
| Low | 180d | 60 | 86.3d | 77d | 100% | 176 | 0 |

The generator deliberately includes "stuck" findings and retired devices, so the dashboard shows the problems a real program has. The interesting signal: combined Critical+High SLA compliance slides from 100% to 76% over six months as stuck findings age past their deadlines, even though the Critical MTTR (11.5 days against a 15-day SLA) looks healthy on its own.

## How to run it
```bash
git clone https://github.com/sbsmith340/vuln-remediation-metrics.git
cd vuln-remediation-metrics
python sample/generate_snapshots.py --weeks 26 --devices 120 --seed 11
python src/report.py sample/snapshots --out reports
open reports/dashboard.html          # or double-click it
pytest -q tests                      # 8 tests
```
Custom SLAs: `python src/report.py sample/snapshots --sla Critical=7 --sla High=14`

**With real data:**
1. Run [`kql/export-snapshot.kql`](kql/export-snapshot.kql) in Defender Advanced Hunting.
2. Export the results to CSV and save as `snapshots/YYYY-MM-DD.csv`.
3. Repeat on a schedule. A Logic App or Power Automate flow calling the Advanced Hunting API automates it.
4. Point `report.py` at the folder.

No runtime dependencies beyond the Python standard library.

## Framework mapping
| Control | How this supports it |
|---|---|
| NIST CSF 2.0 **ID.RA-01 / ID.RA-08** | Vulnerabilities identified and tracked through response |
| NIST CSF 2.0 **GV.OV-03** | Performance of the program measured and reported to leadership |
| NIST SP 800-53 **RA-5, SI-2** | Vulnerability monitoring; flaw remediation within defined timeframes |
| CIS Controls v8 **7.2 / 7.7** | Remediation process; remediate detected vulnerabilities |

## Limitations & what's next
- Snapshot cadence sets precision. With weekly snapshots, a fix is only known to within 7 days, so run them daily where the SLA is tight (Critical = 15d).
- Risk-accepted exceptions aren't modeled yet. Add an `exceptions.csv` (device, CVE, expiry) and exclude those findings from the overdue counts.
- Add exposure context (internet-facing, crown-jewel tags) so "oldest open" is ranked by risk, not just by age.
- Automate snapshot collection with a scheduled Logic App that writes to Blob storage.

## Repo layout
```
src/vulnmetrics/lifecycle.py   snapshots -> finding lifecycles
src/vulnmetrics/metrics.py     MTTR, SLA compliance, aging, trend
src/report.py                  CLI: JSON + Markdown + HTML dashboard
kql/export-snapshot.kql        Defender export with device heartbeats
sample/generate_snapshots.py   synthetic fleet generator
reports/                       demo output
tests/                         unit + end-to-end tests
```

---
All devices, CVE numbers, and results are synthetic. Built by [Shawn Smith](https://sbsmith340.github.io).
