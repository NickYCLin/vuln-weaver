from pathlib import Path

import pytest
from click.testing import CliRunner

from vuln_weaver.cli import main, get_parser_for_file
from vuln_weaver.comparator.diff import VulnerabilityComparator
from vuln_weaver.models import DiffStatus, Severity
from vuln_weaver.parsers.burp import BurpParser


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_burp.xml"


def test_burp_hosts_and_issues():
    report = BurpParser().parse(FIXTURE_PATH)

    assert report.scanner_name == "burp"
    assert report.scanner_version == "2024.5.3"
    assert (report.scan_date.year, report.scan_date.month, report.scan_date.day) == (2026, 9, 3)
    assert [(h.ip, h.open_ports) for h in report.hosts] == [
        ("portal.example.gov.tw", [443]),
        ("intranet.example.gov.tw", [8080]),
    ]
    assert report.hosts[0].vuln_count == {"Critical": 0, "High": 1, "Medium": 0, "Low": 1, "Info": 0}
    assert report.hosts[1].vuln_count == {"Critical": 0, "High": 0, "Medium": 1, "Low": 0, "Info": 1}

    # 同一種 issue type 在兩個路徑只算一筆，位置保留在原始輸出
    xss = next(v for v in report.vulnerabilities if v.id == "1048832")
    assert xss.severity == Severity.HIGH
    assert xss.affected_hosts == ["portal.example.gov.tw:443/tcp"]
    assert xss.cwe_list == ["CWE-79", "CWE-80"]
    assert xss.title_zh == "網站存在跨站腳本攻擊 (Cross-Site Scripting, XSS) 弱點"
    assert "https://portal.example.gov.tw/search [q parameter]（確信度：Certain）" in xss.raw_plugin_output
    assert "https://portal.example.gov.tw/news [id parameter]（確信度：Firm）" in xss.raw_plugin_output
    assert "<p>" not in xss.description and "<b>" not in xss.description
    assert "檢出細節" in xss.description
    assert xss.references == ["https://portswigger.net/web-security/cross-site-scripting/reflected"]

    hsts = next(v for v in report.vulnerabilities if v.id == "5243392")
    assert hsts.severity == Severity.LOW
    assert hsts.title_zh == "未啟用 HTTP 嚴格傳輸安全標頭 (Missing HSTS Header)"

    cleartext = next(v for v in report.vulnerabilities if v.id == "2097920")
    assert cleartext.severity == Severity.MEDIUM
    assert "針對本次檢出的處置" in cleartext.solution and "Move the login form to HTTPS." in cleartext.solution

    assert [v.id for v in report.vulnerabilities] == ["1048832", "2097920", "5243392", "8389632"]


def test_burp_host_without_url_falls_back_to_ip(tmp_path):
    xml = """<issues><issue><type>1</type><name>Demo</name><host ip="10.0.0.5"></host>
    <severity>Information</severity></issue></issues>"""
    file_path = tmp_path / "burp.xml"
    file_path.write_text(xml, encoding="utf-8")

    report = BurpParser().parse(file_path)
    assert report.hosts[0].ip == "10.0.0.5"
    assert report.hosts[0].open_ports == [80]
    assert report.vulnerabilities[0].affected_hosts == ["10.0.0.5:80/tcp"]
    assert report.vulnerabilities[0].severity == Severity.INFO


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("<nmaprun/>", "issues"),
        ("<issues/>", "沒有任何 issue"),
    ],
)
def test_burp_parser_rejects_wrong_format(tmp_path, content, message):
    file_path = tmp_path / "burp.xml"
    file_path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        BurpParser().parse(file_path)


def test_cli_picks_burp_by_root():
    assert isinstance(get_parser_for_file(FIXTURE_PATH), BurpParser)


def test_cli_parses_burp_to_json_and_docx(tmp_path):
    runner = CliRunner()
    json_out = tmp_path / "burp.json"
    result = runner.invoke(main, ["parse", str(FIXTURE_PATH), "-f", "json", "-o", str(json_out)])
    assert result.exit_code == 0, result.output
    assert '"scanner_name": "burp"' in json_out.read_text(encoding="utf-8")

    docx_out = tmp_path / "burp.docx"
    result = runner.invoke(main, ["parse", str(FIXTURE_PATH), "-o", str(docx_out)])
    assert result.exit_code == 0, result.output
    assert docx_out.stat().st_size > 5000


def test_burp_diff_by_site(tmp_path):
    baseline = BurpParser().parse(FIXTURE_PATH)
    xml = FIXTURE_PATH.read_text(encoding="utf-8")
    # 複掃時 intranet 的明文登入已修掉
    start = xml.index("<issue>\n    <serialNumber>5316302013512591364")
    end = xml.index("</issue>", start) + len("</issue>")
    rescan_file = tmp_path / "rescan.xml"
    rescan_file.write_text(xml[:start] + xml[end:], encoding="utf-8")
    rescan = BurpParser().parse(rescan_file)

    diff = VulnerabilityComparator.compare(baseline, rescan)
    fixed = [(i.vuln_id, i.affected_hosts) for i in diff.items if i.status == DiffStatus.FIXED]
    assert fixed == [("2097920", ["intranet.example.gov.tw:8080/tcp"])]
    assert diff.open_count == 3 and diff.new_count == 0
