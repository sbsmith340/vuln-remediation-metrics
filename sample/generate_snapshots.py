"""
Generate synthetic weekly Defender-style vulnerability snapshots.

Simulates a fleet where new CVEs are disclosed each week, patch teams fix them
with severity-dependent speed, a few findings get stuck, and some devices are
retired. All device names, IDs and software are fictional.

Usage: python sample/generate_snapshots.py --weeks 26 --devices 120 --seed 11
Output: sample/snapshots/YYYY-MM-DD.csv (or --out DIR)
"""
import argparse
import csv
import random
from datetime import date, timedelta
from pathlib import Path

FIELDS = ["DeviceId", "DeviceName", "OSPlatform", "CveId", "VulnerabilitySeverityLevel", "SoftwareName"]
SOFTWARE = {
    "Windows11": ["windows_11", "edge", "office", "teams", "7-zip", "chrome", "zoom"],
    "WindowsServer2022": ["windows_server_2022", "iis", ".net", "openssl", "chrome"],
    "Linux": ["openssl", "openssh", "sudo", "glibc", "curl"],
}
# median days to fix by severity, and the chance a finding is "stuck" for months
FIX_PROFILE = {"Critical": (9, 0.05), "High": (20, 0.10), "Medium": (55, 0.20), "Low": (120, 0.30)}
SEV_WEIGHTS = [("Critical", 0.10), ("High", 0.35), ("Medium", 0.40), ("Low", 0.15)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--weeks", type=int, default=26)
    ap.add_argument("--devices", type=int, default=120)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--start", default="2026-04-06")
    ap.add_argument("--out", default=str(Path(__file__).with_name("snapshots")))
    args = ap.parse_args()
    rng = random.Random(args.seed)
    start = date.fromisoformat(args.start)

    devices = []
    for i in range(args.devices):
        osp = rng.choices(list(SOFTWARE), weights=[0.75, 0.15, 0.10])[0]
        prefix = {"Windows11": "WKS", "WindowsServer2022": "SRV", "Linux": "LNX"}[osp]
        retire_week = rng.randint(4, args.weeks - 1) if rng.random() < 0.05 else None
        devices.append({"id": f"dev-{i:04d}", "name": f"CONTOSO-{prefix}-{i:03d}", "os": osp, "retire": retire_week})

    # findings: (device, cve, sev, software, opened_week, fixed_week or None)
    findings = []
    cve_n = 1000
    for week in range(args.weeks):
        for _ in range(rng.randint(3, 6)):              # CVEs disclosed this week
            cve_n += 1
            cve = f"CVE-2026-{cve_n}"
            sev = rng.choices([s for s, _ in SEV_WEIGHTS], weights=[w for _, w in SEV_WEIGHTS])[0]
            osp = rng.choice(list(SOFTWARE))
            sw = rng.choice(SOFTWARE[osp])
            affected = [d for d in devices if d["os"] == osp and rng.random() < 0.35]
            median_days, stuck_p = FIX_PROFILE[sev]
            for d in affected:
                if rng.random() < stuck_p:
                    days = rng.randint(median_days * 3, median_days * 6)
                else:
                    days = max(1, int(rng.lognormvariate(0, 0.5) * median_days))
                fixed_week = week + max(1, round(days / 7))
                findings.append((d, cve, sev, sw, week, fixed_week))

    out = Path(args.out)
    out.mkdir(exist_ok=True)
    for old in out.glob("*.csv"):
        old.unlink()
    for week in range(args.weeks):
        snap_date = start + timedelta(weeks=week)
        rows = []
        for d, cve, sev, sw, opened, fixed in findings:
            if d["retire"] is not None and week >= d["retire"]:
                continue
            if opened <= week < fixed:
                rows.append({"DeviceId": d["id"], "DeviceName": d["name"], "OSPlatform": d["os"],
                             "CveId": cve, "VulnerabilitySeverityLevel": sev, "SoftwareName": sw})
        # a device with zero findings still "reports": emit nothing for it, but the
        # pipeline treats absence of the device as retirement, so keep a heartbeat row
        reporting = {r["DeviceId"] for r in rows}
        for d in devices:
            if d["id"] not in reporting and (d["retire"] is None or week < d["retire"]):
                rows.append({"DeviceId": d["id"], "DeviceName": d["name"], "OSPlatform": d["os"],
                             "CveId": "", "VulnerabilitySeverityLevel": "", "SoftwareName": ""})
        with (out / f"{snap_date.isoformat()}.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            w.writeheader()
            w.writerows(rows)
    print(f"wrote {args.weeks} snapshots for {args.devices} devices -> {out}")


if __name__ == "__main__":
    main()
