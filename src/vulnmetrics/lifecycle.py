"""
Turn a series of point-in-time vulnerability snapshots into finding lifecycles.

Defender Vulnerability Management (DeviceTvmSoftwareVulnerabilities) only tells
you what is vulnerable *right now* - it has no "remediated on" column. So the
reliable way to measure remediation time is to export a snapshot on a schedule
and diff them:

  first_seen   = first snapshot in which (device, CVE) appears
  last_seen    = last snapshot in which it appears
  remediated   = first snapshot after last_seen in which the DEVICE still reports
                 but the (device, CVE) pair is gone
  retired      = the device itself stopped reporting -> not counted as a fix

Snapshot CSV columns (case-sensitive):
  DeviceId, DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, SoftwareName

A row with an empty CveId is a heartbeat: the device reported that day with no
open findings. Without heartbeats, a fully patched device would look retired and
its last fixes would never be counted. kql/export-snapshot.kql emits them.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date
from pathlib import Path

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


@dataclass
class Finding:
    device_id: str
    device_name: str
    os_platform: str
    cve_id: str
    severity: str
    software: str
    first_seen: date
    last_seen: date
    status: str                    # "open" | "remediated" | "retired"
    remediated_on: date | None = None

    @property
    def days_to_remediate(self) -> int | None:
        return (self.remediated_on - self.first_seen).days if self.remediated_on else None

    def age_on(self, as_of: date) -> int:
        return (as_of - self.first_seen).days


def load_snapshots(folder: Path) -> list[tuple[date, list[dict]]]:
    """Read every YYYY-MM-DD.csv in a folder, oldest first."""
    snaps = []
    for p in sorted(folder.glob("*.csv")):
        try:
            d = date.fromisoformat(p.stem)
        except ValueError:
            continue
        with p.open(newline="") as f:
            snaps.append((d, list(csv.DictReader(f))))
    if not snaps:
        raise FileNotFoundError(f"no YYYY-MM-DD.csv snapshots in {folder}")
    return snaps


def build_lifecycles(snapshots: list[tuple[date, list[dict]]]) -> list[Finding]:
    """
    Returns one Finding per lifecycle. If a CVE comes back on a device after it
    was remediated (e.g. software reinstalled), that is a NEW finding with its
    own first_seen; the earlier, closed one is kept.
    """
    active: dict[tuple[str, str], Finding] = {}
    closed: list[Finding] = []
    for snap_date, rows in sorted(snapshots, key=lambda s: s[0]):
        devices_reporting = {r["DeviceId"] for r in rows}
        present = set()
        for r in rows:
            if not r.get("CveId"):
                continue  # heartbeat row: device reported with no open findings
            key = (r["DeviceId"], r["CveId"])
            present.add(key)
            if key in active:
                active[key].last_seen = snap_date
            else:
                active[key] = Finding(
                    device_id=r["DeviceId"], device_name=r["DeviceName"], os_platform=r["OSPlatform"],
                    cve_id=r["CveId"], severity=r["VulnerabilitySeverityLevel"], software=r["SoftwareName"],
                    first_seen=snap_date, last_seen=snap_date, status="open")
        for key in [k for k in active if k not in present]:
            f = active.pop(key)
            if f.device_id in devices_reporting:
                f.status, f.remediated_on = "remediated", snap_date
            else:
                f.status = "retired"
            closed.append(f)
    return closed + list(active.values())
