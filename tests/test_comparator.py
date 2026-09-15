import pytest
from click.testing import CliRunner
from docx import Document

from vuln_weaver.cli import main
from vuln_weaver.comparator.diff import VulnerabilityComparator
from vuln_weaver.models import DiffStatus, Host, ScanReport, Vulnerability
from vuln_weaver.reporters.docx_reporter import DocxReporter


def make_report(scanner="nessus", hosts=("10.0.0.1", "10.0.0.2"), targets=()):
    return ScanReport(
        scanner_name=scanner,
        scan_name="測試掃描",
        hosts=[Host(ip=host) for host in hosts],
        vulnerabilities=[
            Vulnerability(id="TLS-OLD", title="TLS 1.0", affected_hosts=list(targets))
        ] if targets else [],
    )


def test_same_finding_has_different_results_per_host_and_port(tmp_path):
    baseline = make_report(targets=("10.0.0.1:443/tcp", "10.0.0.2:443/tcp"))
    rescan = make_report(targets=("10.0.0.1:8443/tcp", "10.0.0.2:443/tcp"))

    result = VulnerabilityComparator.compare(baseline, rescan)
    assert [(item.status, item.affected_hosts) for item in result.items] == [
        (DiffStatus.FIXED, ["10.0.0.1:443/tcp"]),
        (DiffStatus.OPEN, ["10.0.0.2:443/tcp"]),
        (DiffStatus.NEW, ["10.0.0.1:8443/tcp"]),
    ]
    assert (result.fixed_count, result.open_count, result.new_count) == (1, 1, 1)

    doc_path = DocxReporter().generate_diff(result, tmp_path / "comparison.docx")
    doc = Document(doc_path)
    cells = [row.cells[1].text for table in doc.tables for row in table.rows]
    assert any("10.0.0.1:443/tcp" in cell for cell in cells)
    assert any("10.0.0.2:443/tcp" in cell for cell in cells)
    assert any("10.0.0.1:8443/tcp" in cell for cell in cells)


def test_different_scan_coverage_cannot_claim_fixed():
    baseline = make_report(targets=("10.0.0.1:443/tcp",))
    rescan = make_report(hosts=("10.0.0.2",))

    with pytest.raises(ValueError, match="受檢主機範圍不同"):
        VulnerabilityComparator.compare(baseline, rescan)


def test_mixed_scanners_cannot_match_unrelated_plugin_ids():
    with pytest.raises(ValueError, match="相同掃描器"):
        VulnerabilityComparator.compare(make_report(), make_report(scanner="nmap"))


def test_cli_rejects_partial_rescan(tmp_path):
    baseline = tmp_path / "baseline.xml"
    rescan = tmp_path / "rescan.xml"
    baseline.write_text(
        '<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>',
        encoding="utf-8",
    )
    rescan.write_text(
        '<nmaprun><host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/></host></nmaprun>',
        encoding="utf-8",
    )

    output = tmp_path / "comparison.docx"
    result = CliRunner().invoke(main, ["diff", str(baseline), str(rescan), "-o", str(output)])
    assert result.exit_code != 0
    assert "主機範圍不同" in result.output
    assert not output.exists()
