from pathlib import Path
from vuln_weaver.parsers.nessus import NessusParser
from vuln_weaver.models import Severity

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample.nessus"


def test_nessus_parser_basic():
    parser = NessusParser()
    report = parser.parse(FIXTURE_PATH)

    assert report.scanner_name == "nessus"
    assert report.scan_name == "2026 Q1 Internal Security Audit"
    assert len(report.hosts) == 2

    # Host 1 check
    h1 = next(h for h in report.hosts if h.ip == "192.168.10.50")
    assert h1.hostname == "web-app01.local"
    assert h1.os == "Ubuntu Linux 20.04"
    assert 443 in h1.open_ports
    assert 80 in h1.open_ports

    # Host 2 check
    h2 = next(h for h in report.hosts if h.ip == "192.168.10.51")
    assert h2.hostname == "db-cluster01.local"
    assert 22 in h2.open_ports

    # Vulnerability deduplication & aggregation check
    # 2 hosts share plugin 104743 (TLS 1.0)
    tls_vuln = next(v for v in report.vulnerabilities if v.id == "104743")
    assert tls_vuln.severity == Severity.MEDIUM
    assert len(tls_vuln.affected_hosts) == 2
    assert "192.168.10.50:443/tcp" in tls_vuln.affected_hosts
    assert "192.168.10.51:443/tcp" in tls_vuln.affected_hosts
    assert tls_vuln.cvss_score == 7.4
    assert "CVE-2011-3389" in tls_vuln.cve_list

    # Traditional Chinese Enrichment check
    assert tls_vuln.title_zh == "伺服器支援過期之 TLS 1.0 通訊協定"
    assert "TLS 1.2" in tls_vuln.solution_zh

    # Server header info disclosure check
    server_header = next(v for v in report.vulnerabilities if v.id == "11229")
    assert server_header.severity == Severity.LOW
    assert server_header.title_zh == "網頁伺服器回應標頭洩漏詳細版本資訊"

    # Total unique vulnerabilities
    assert len(report.vulnerabilities) == 3
