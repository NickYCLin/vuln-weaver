import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from vuln_weaver.cli import main, get_parser_for_file
from vuln_weaver.comparator.diff import VulnerabilityComparator
from vuln_weaver.merger import merge_reports
from vuln_weaver.models import DiffStatus, ScanReport, Severity
from vuln_weaver.parsers.nessus import NessusParser
from vuln_weaver.parsers.nmap import NmapParser
from vuln_weaver.parsers.vulnweaver_json import VulnWeaverJsonParser
from vuln_weaver.parsers.zap import ZapParser

FIX = Path(__file__).parent / "fixtures"


def test_single_report_passthrough():
    report = NessusParser().parse(FIX / "sample.nessus")
    assert merge_reports([report]) is report


def test_merge_same_scanner_keeps_ids_and_unions_hosts(tmp_path):
    base = NessusParser().parse(FIX / "sample.nessus")
    xml = (FIX / "sample.nessus").read_text(encoding="utf-8")
    # 第二份：同一個 plugin 打在另一台主機
    other = xml.replace("192.168.10.50", "192.168.10.60").replace("192.168.10.51", "192.168.10.61")
    other_file = tmp_path / "subnet2.nessus"
    other_file.write_text(other, encoding="utf-8")
    second = NessusParser().parse(other_file)

    merged = merge_reports([base, second], scan_name="全院健診")
    assert merged.scanner_name == "nessus"
    assert merged.scan_name == "全院健診"
    assert [h.ip for h in merged.hosts] == ["192.168.10.50", "192.168.10.51", "192.168.10.60", "192.168.10.61"]
    tls = next(v for v in merged.vulnerabilities if v.id == "104743")
    assert len(tls.affected_hosts) == 4
    assert len(merged.vulnerabilities) == 3


def test_merge_across_scanners_prefixes_ids():
    nessus = NessusParser().parse(FIX / "sample.nessus")
    nmap = NmapParser().parse(FIX / "sample_nmap.xml")
    zap = ZapParser().parse(FIX / "sample_zap.xml")

    merged = merge_reports([nessus, nmap, zap])
    assert merged.scanner_name == "nessus+nmap+zap"
    assert merged.scanner_label == "Tenable Nessus + Nmap + OWASP ZAP"
    ids = {v.id for v in merged.vulnerabilities}
    assert "nessus:104743" in ids and "nmap:NMAP-TELNET-OPEN" in ids and "zap:40018" in ids
    assert len(merged.hosts) == 2 + 2 + 2
    assert merged.summary_stats["High"] == 1  # 只有 ZAP 的 SQLi
    assert merged.vulnerabilities[0].severity == Severity.HIGH
    assert "2026 Q1 Internal Security Audit" in merged.scan_name and "OWASP ZAP" in merged.scan_name


def test_merge_same_host_from_two_scanners_unions_ports(tmp_path):
    nmap_xml = """<nmaprun><host><status state="up"/><address addr="192.168.10.50" addrtype="ipv4"/>
    <os><osmatch name="Linux 5.x"/></os>
    <ports><port protocol="tcp" portid="8443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>"""
    nmap_file = tmp_path / "nmap.xml"
    nmap_file.write_text(nmap_xml, encoding="utf-8")
    nessus = NessusParser().parse(FIX / "sample.nessus")
    nmap = NmapParser().parse(nmap_file)

    merged = merge_reports([nessus, nmap])
    host = next(h for h in merged.hosts if h.ip == "192.168.10.50")
    assert host.hostname == "web-app01.local"      # 來自 Nessus
    assert host.os == "Ubuntu Linux 20.04"         # Nessus 先到，保留
    assert 8443 in host.open_ports and 443 in host.open_ports
    assert len(merged.hosts) == 2


def test_merge_empty_raises():
    with pytest.raises(ValueError, match="沒有任何"):
        merge_reports([])


def test_vulnweaver_json_roundtrip_and_detection(tmp_path):
    report = NessusParser().parse(FIX / "sample.nessus")
    json_file = tmp_path / "report.json"
    json_file.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    assert isinstance(get_parser_for_file(json_file), VulnWeaverJsonParser)
    loaded = VulnWeaverJsonParser().parse(json_file)
    assert loaded == report

    zap_json = tmp_path / "zap.json"
    zap_json.write_text(json.dumps({"site": []}), encoding="utf-8")
    assert isinstance(get_parser_for_file(zap_json), ZapParser)

    bad = tmp_path / "bad.json"
    bad.write_text('{"scanner_name": "x", "vulnerabilities": "oops"}', encoding="utf-8")
    with pytest.raises(ValueError, match="VulnWeaver"):
        VulnWeaverJsonParser().parse(bad)


def test_cli_merges_multiple_files_and_diffs_merged_json(tmp_path):
    runner = CliRunner()
    merged_json = tmp_path / "merged.json"
    result = runner.invoke(main, [
        "parse", str(FIX / "sample.nessus"), str(FIX / "sample_nmap.xml"),
        "-f", "json", "-o", str(merged_json), "-n", "第一次健診",
    ])
    assert result.exit_code == 0, result.output
    assert "已合併 2 份掃描結果" in result.output
    merged = ScanReport.model_validate_json(merged_json.read_text(encoding="utf-8"))
    assert merged.scanner_name == "nessus+nmap"
    assert merged.scan_name == "第一次健診"

    docx_out = tmp_path / "merged.docx"
    result = runner.invoke(main, ["parse", str(FIX / "sample.nessus"), str(FIX / "sample_zap.xml"), "-o", str(docx_out)])
    assert result.exit_code == 0, result.output
    assert docx_out.stat().st_size > 5000

    # 合併後的 JSON 可以直接當初掃／複掃做比對
    diff_out = tmp_path / "diff.docx"
    result = runner.invoke(main, ["diff", str(merged_json), str(merged_json), "-o", str(diff_out)])
    assert result.exit_code == 0, result.output
    assert diff_out.exists()


def test_cli_reports_which_file_failed(tmp_path):
    bad = tmp_path / "broken.xml"
    bad.write_text("<nope/>", encoding="utf-8")
    result = CliRunner().invoke(main, ["parse", str(FIX / "sample.nessus"), str(bad), "-f", "json", "-o", str(tmp_path / "x.json")])
    assert result.exit_code != 0
    assert "broken.xml" in result.output


def test_diff_merged_vs_single_scanner_is_rejected():
    nessus = NessusParser().parse(FIX / "sample.nessus")
    nmap = NmapParser().parse(FIX / "sample_nmap.xml")
    merged = merge_reports([nessus, nmap])
    with pytest.raises(ValueError, match="相同掃描器"):
        VulnerabilityComparator.compare(merged, nessus)
    diff = VulnerabilityComparator.compare(merged, merge_reports([nessus, nmap]))
    assert diff.new_count == 0 and diff.fixed_count == 0
    assert all(i.status == DiffStatus.OPEN for i in diff.items)
