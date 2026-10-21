import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vulnmetrics import build_lifecycles, compute  # noqa: E402

D = [date(2026, 1, 5) + timedelta(weeks=i) for i in range(8)]


def row(dev, cve="", sev="", name=None):
    return {"DeviceId": dev, "DeviceName": name or dev.upper(), "OSPlatform": "Windows11",
            "CveId": cve, "VulnerabilitySeverityLevel": sev, "SoftwareName": "app"}


def test_remediated_when_device_still_reports():
    snaps = [(D[0], [row("d1", "CVE-1", "Critical")]),
             (D[1], [row("d1", "CVE-1", "Critical")]),
             (D[2], [row("d1")])]                      # heartbeat only -> fixed
    [f] = build_lifecycles(snaps)
    assert f.status == "remediated" and f.remediated_on == D[2] and f.days_to_remediate == 14


def test_retired_device_not_counted_as_fix():
    snaps = [(D[0], [row("d1", "CVE-1", "High"), row("d2")]),
             (D[1], [row("d2")])]                      # d1 vanished entirely
    [f] = build_lifecycles(snaps)
    assert f.status == "retired" and f.remediated_on is None


def test_still_open():
    snaps = [(D[0], [row("d1", "CVE-1", "High")]), (D[1], [row("d1", "CVE-1", "High")])]
    [f] = build_lifecycles(snaps)
    assert f.status == "open" and f.last_seen == D[1]


def test_regression_creates_new_lifecycle():
    snaps = [(D[0], [row("d1", "CVE-1", "High")]),
             (D[1], [row("d1")]),
             (D[3], [row("d1", "CVE-1", "High")])]
    fs = sorted(build_lifecycles(snaps), key=lambda f: f.first_seen)
    assert [f.status for f in fs] == ["remediated", "open"]
    assert fs[1].first_seen == D[3]


def test_heartbeat_rows_never_become_findings():
    snaps = [(D[0], [row("d1"), row("d2")]), (D[1], [row("d1")])]
    assert build_lifecycles(snaps) == []


def test_sla_compliance_penalizes_overdue_open():
    snaps = [(D[0], [row("d1", "CVE-1", "Critical"), row("d2", "CVE-2", "Critical")]),
             (D[1], [row("d1"), row("d2", "CVE-2", "Critical")])]       # CVE-1 fixed in 7d
    snaps += [(D[i], [row("d1"), row("d2", "CVE-2", "Critical")]) for i in range(2, 5)]  # CVE-2 open 28d
    m = compute(build_lifecycles(snaps), as_of=D[4])
    crit = next(r for r in m["by_severity"] if r["severity"] == "Critical")
    assert crit["remediated"] == 1 and crit["overdue"] == 1
    assert crit["mttr_days"] == 7
    assert crit["sla_compliance_pct"] == 50.0      # 1 on time / (1 fixed + 1 overdue)


def test_custom_sla_and_aging_buckets():
    snaps = [(D[0], [row("d1", "CVE-1", "High")])] + [(D[i], [row("d1", "CVE-1", "High")]) for i in range(1, 6)]
    m = compute(build_lifecycles(snaps), as_of=D[5], sla_days={"High": 60})
    high = next(r for r in m["by_severity"] if r["severity"] == "High")
    assert high["sla_days"] == 60 and high["overdue"] == 0
    assert m["open_aging"]["31-60d"]["High"] == 1


def test_end_to_end_on_synthetic_sample(tmp_path):
    import subprocess
    root = Path(__file__).resolve().parents[1]
    snaps = tmp_path / "snaps"
    subprocess.run([sys.executable, str(root / "sample/generate_snapshots.py"), "--weeks", "10", "--devices", "30",
                    "--out", str(snaps)], check=True, capture_output=True)
    sys.path.insert(0, str(root / "src"))
    import report
    assert report.main([str(snaps), "--out", str(tmp_path)]) == 0
    assert (tmp_path / "dashboard.html").read_text().startswith("<!doctype html>")
