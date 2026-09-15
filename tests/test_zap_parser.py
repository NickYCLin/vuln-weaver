import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from vuln_weaver.cli import main, get_parser_for_file
from vuln_weaver.comparator.diff import VulnerabilityComparator
from vuln_weaver.models import DiffStatus, Severity
from vuln_weaver.parsers.nmap import NmapParser
from vuln_weaver.parsers.zap import ZapParser
from vuln_weaver.reporters.docx_reporter import DocxReporter


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_zap.xml"


def test_zap_xml_hosts_and_alerts():
    report = ZapParser().parse(FIXTURE_PATH)

    assert report.scanner_name == "zap"
    assert report.scan_date.year == 2026 and report.scan_date.month == 9
    assert [(h.ip, h.open_ports) for h in report.hosts] == [
        ("portal.example.gov.tw", [443]),
        ("intranet.example.gov.tw", [8080]),
    ]
    assert report.hosts[0].vuln_count == {"Critical": 0, "High": 1, "Medium": 1, "Low": 1, "Info": 0}
    assert report.hosts[1].vuln_count == {"Critical": 0, "High": 0, "Medium": 1, "Low": 0, "Info": 1}

    # 依 pluginid 合併，同一弱點跨兩個站台
    csp = next(v for v in report.vulnerabilities if v.id == "10038")
    assert csp.severity == Severity.MEDIUM
    assert csp.affected_hosts == ["portal.example.gov.tw:443/tcp", "intranet.example.gov.tw:8080/tcp"]
    assert csp.cwe_list == ["CWE-693"]
    assert csp.title_zh == "缺少 Content-Security-Policy (CSP) 內容安全政策標頭"
    assert "https://portal.example.gov.tw/login" in csp.raw_plugin_output
    assert "http://intranet.example.gov.tw:8080/" in csp.raw_plugin_output

    # HTML 標籤要拿掉，reference 要拆成清單
    sqli = next(v for v in report.vulnerabilities if v.id == "40018")
    assert sqli.severity == Severity.HIGH
    assert sqli.title_zh == "網站存在 SQL 資料隱碼攻擊 (SQL Injection) 弱點"
    assert "<p>" not in sqli.description and "<p>" not in sqli.solution
    assert "補充資訊" in sqli.description
    assert sqli.references == [
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
    ]

    assert [v.id for v in report.vulnerabilities] == ["40018", "10038", "10035", "10015"]


def test_zap_json_matches_xml(tmp_path):
    data = {
        "@version": "2.15.0",
        "@generated": "Tue, 3 Sep 2026 10:15:42",
        "site": [
            {
                "@name": "https://portal.example.gov.tw",
                "@host": "portal.example.gov.tw",
                "@port": "443",
                "@ssl": "true",
                "alerts": [
                    {
                        "pluginid": "10035",
                        "alertRef": "10035-1",
                        "alert": "Strict-Transport-Security Header Not Set",
                        "name": "Strict-Transport-Security Header Not Set",
                        "riskcode": "1",
                        "confidence": "3",
                        "desc": "<p>HSTS is a web security policy mechanism.</p>",
                        "instances": [{"uri": "https://portal.example.gov.tw/", "method": "GET"}],
                        "count": "1",
                        "solution": "<p>Enforce HSTS.</p>",
                        "reference": "<p>https://example.org/hsts</p>",
                        "cweid": "319",
                        "wascid": "15",
                    }
                ],
            }
        ],
    }
    json_file = tmp_path / "zap.json"
    json_file.write_text(json.dumps(data), encoding="utf-8")

    report = ZapParser().parse(json_file)
    assert report.hosts[0].ip == "portal.example.gov.tw"
    vuln = report.vulnerabilities[0]
    assert vuln.id == "10035"
    assert vuln.severity == Severity.LOW
    assert vuln.affected_hosts == ["portal.example.gov.tw:443/tcp"]
    assert vuln.title_zh == "未啟用 HTTP 嚴格傳輸安全標頭 (Missing HSTS Header)"
    assert vuln.references == ["https://example.org/hsts"]


def test_zap_site_without_explicit_port_uses_url_scheme(tmp_path):
    xml = """<OWASPZAPReport><site name="http://shop.example.com"><alerts/></site></OWASPZAPReport>"""
    file_path = tmp_path / "zap.xml"
    file_path.write_text(xml, encoding="utf-8")

    report = ZapParser().parse(file_path)
    assert report.hosts[0].ip == "shop.example.com"
    assert report.hosts[0].open_ports == [80]
    assert report.vulnerabilities == []


@pytest.mark.parametrize(
    ("filename", "content", "message"),
    [
        ("zap.xml", "<nmaprun/>", "OWASPZAPReport"),
        ("zap.xml", "<OWASPZAPReport/>", "site"),
        ("zap.json", '{"foo": 1}', "site"),
        ("zap.json", "not json", "JSON"),
    ],
)
def test_zap_parser_rejects_wrong_format(tmp_path, filename, content, message):
    file_path = tmp_path / filename
    file_path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        ZapParser().parse(file_path)


def test_cli_picks_parser_by_xml_root(tmp_path):
    nmap_file = tmp_path / "scan.xml"
    nmap_file.write_text("<nmaprun/>", encoding="utf-8")
    assert isinstance(get_parser_for_file(nmap_file), NmapParser)

    assert isinstance(get_parser_for_file(FIXTURE_PATH), ZapParser)
    assert isinstance(get_parser_for_file(tmp_path / "zap.json"), ZapParser)

    broken = tmp_path / "broken.xml"
    broken.write_text("<<<", encoding="utf-8")
    assert isinstance(get_parser_for_file(broken), NmapParser)


def test_cli_parses_zap_to_json_and_docx(tmp_path):
    runner = CliRunner()

    json_out = tmp_path / "zap_report.json"
    result = runner.invoke(main, ["parse", str(FIXTURE_PATH), "-f", "json", "-o", str(json_out)])
    assert result.exit_code == 0, result.output
    assert '"scanner_name": "zap"' in json_out.read_text(encoding="utf-8")

    docx_out = tmp_path / "zap_report.docx"
    result = runner.invoke(main, ["parse", str(FIXTURE_PATH), "-f", "docx", "-o", str(docx_out)])
    assert result.exit_code == 0, result.output
    assert docx_out.stat().st_size > 5000


def test_zap_diff_by_site(tmp_path):
    baseline = ZapParser().parse(FIXTURE_PATH)

    rescan_xml = FIXTURE_PATH.read_text(encoding="utf-8")
    # 複掃時 portal 已修掉 SQL Injection，其餘照舊
    start = rescan_xml.index("<alertitem>\n        <pluginid>40018</pluginid>")
    end = rescan_xml.index("</alertitem>", start) + len("</alertitem>")
    rescan_file = tmp_path / "rescan.xml"
    rescan_file.write_text(rescan_xml[:start] + rescan_xml[end:], encoding="utf-8")
    rescan = ZapParser().parse(rescan_file)

    diff = VulnerabilityComparator.compare(baseline, rescan)
    fixed = [i for i in diff.items if i.status == DiffStatus.FIXED]
    assert [(i.vuln_id, i.affected_hosts) for i in fixed] == [("40018", ["portal.example.gov.tw:443/tcp"])]
    assert diff.open_count == 3 and diff.new_count == 0

    out = DocxReporter().generate_diff(diff, tmp_path / "diff.docx")
    assert out.exists()
