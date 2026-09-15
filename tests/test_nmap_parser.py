from pathlib import Path

import pytest
from click.testing import CliRunner

from vuln_weaver.cli import main
from vuln_weaver.models import Severity
from vuln_weaver.parsers.nmap import NmapParser


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_nmap.xml"


def test_nmap_inventory_and_observed_findings():
    report = NmapParser().parse(FIXTURE_PATH)

    assert report.scanner_name == "nmap"
    assert [host.ip for host in report.hosts] == ["192.168.1.100", "192.168.1.101"]
    assert report.hosts[0].open_ports == [21, 22, 23, 443]
    assert report.hosts[0].hostname == "router.internal.lab"
    assert report.hosts[1].vuln_count["Medium"] == 0
    assert {v.id for v in report.vulnerabilities} == {"NMAP-TELNET-OPEN", "NMAP-TLS-1.0"}
    assert all(v.severity == Severity.MEDIUM for v in report.vulnerabilities)


def test_nmap_script_does_not_claim_unconfirmed_vulnerability(tmp_path):
    xml = """<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80"><state state="open"/>
    <script id="http-vuln-demo" output="State: NOT VULNERABLE"/>
    <script id="http-vuln-unknown" output="Could not determine status"/>
    <script id="http-vuln-confirmed" output="State: VULNERABLE&#xa;Details: confirmed"/>
    </port></ports></host></nmaprun>"""
    file_path = tmp_path / "scan.xml"
    file_path.write_text(xml, encoding="utf-8")

    report = NmapParser().parse(file_path)
    assert [v.id for v in report.vulnerabilities] == ["NMAP-HTTP-VULN-CONFIRMED"]
    assert report.hosts[0].vuln_count["High"] == 1


def test_open_port_alone_does_not_imply_telnet_or_ftp_risk(tmp_path):
    xml = """<nmaprun><host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/></port>
    <port protocol="tcp" portid="23"><state state="open"/><service name="unknown"/></port>
    </ports></host></nmaprun>"""
    file_path = tmp_path / "scan.xml"
    file_path.write_text(xml, encoding="utf-8")

    report = NmapParser().parse(file_path)
    assert report.hosts[0].open_ports == [21, 23]
    assert report.vulnerabilities == []


def test_nmap_parser_rejects_other_xml(tmp_path):
    file_path = tmp_path / "not-nmap.xml"
    file_path.write_text("<NessusClientData_v2/>", encoding="utf-8")
    with pytest.raises(ValueError, match="nmaprun"):
        NmapParser().parse(file_path)


def test_cli_exports_nmap_json(tmp_path):
    output = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["parse", str(FIXTURE_PATH), "-f", "json", "-o", str(output)])
    assert result.exit_code == 0, result.output
    assert output.exists()
    assert '"scanner_name": "nmap"' in output.read_text(encoding="utf-8")


def test_cli_rejects_xml_with_wrong_root(tmp_path):
    file_path = tmp_path / "scan.xml"
    file_path.write_text("<not-nmap/>", encoding="utf-8")
    result = CliRunner().invoke(main, ["parse", str(file_path), "-f", "json", "-o", str(tmp_path / "report.json")])
    assert result.exit_code != 0
    assert "nmaprun" in result.output
    assert not (tmp_path / "report.json").exists()
