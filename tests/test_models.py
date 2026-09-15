from vuln_weaver.models import (
    Severity,
    Vulnerability,
    Host,
    ScanReport,
    DiffStatus,
    DiffReport,
    DiffItem,
)
from vuln_weaver.comparator.diff import VulnerabilityComparator


def test_severity_zh_tw():
    assert Severity.CRITICAL.zh_tw == "極高"
    assert Severity.HIGH.zh_tw == "高"
    assert Severity.MEDIUM.zh_tw == "中"
    assert Severity.LOW.zh_tw == "低"
    assert Severity.INFO.zh_tw == "資訊"


def test_scan_report_summary():
    vuln1 = Vulnerability(id="1", title="Test High", severity=Severity.HIGH)
    vuln2 = Vulnerability(id="2", title="Test Low", severity=Severity.LOW)
    report = ScanReport(
        scanner_name="nessus",
        scan_name="Unit Test Scan",
        vulnerabilities=[vuln1, vuln2],
    )
    stats = report.summary_stats
    assert stats["High"] == 1
    assert stats["Low"] == 1
    assert stats["Critical"] == 0


def test_comparator_fixed_open_new():
    target = ["10.0.0.1:443/tcp"]
    v1 = Vulnerability(id="CVE-2023-0001", title="Fixed Bug", severity=Severity.HIGH, affected_hosts=target)
    v2 = Vulnerability(id="CVE-2023-0002", title="Still Open Bug", severity=Severity.MEDIUM, affected_hosts=target)
    v3 = Vulnerability(id="CVE-2023-0003", title="Newly Appeared Bug", severity=Severity.LOW, affected_hosts=target)

    baseline = ScanReport(
        scanner_name="nessus",
        scan_name="Baseline Scan",
        hosts=[Host(ip="10.0.0.1")],
        vulnerabilities=[v1, v2],
    )
    rescan = ScanReport(
        scanner_name="nessus",
        scan_name="Rescan Scan",
        hosts=[Host(ip="10.0.0.1")],
        vulnerabilities=[v2, v3],
    )

    diff = VulnerabilityComparator.compare(baseline, rescan)
    assert diff.fixed_count == 1
    assert diff.open_count == 1
    assert diff.new_count == 1
