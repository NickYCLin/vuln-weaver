import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Union, Dict, List, Set
from datetime import datetime

from vuln_weaver.parsers.base import BaseParser
from vuln_weaver.models import ScanReport, Host, Vulnerability, Severity
from vuln_weaver.knowledge.kb_zh_tw import enrich_vulnerability


class NessusParser(BaseParser):
    """Parser for Tenable Nessus (.nessus) XML scan files."""

    @property
    def scanner_name(self) -> str:
        return "nessus"

    def parse(self, file_path: Union[str, Path]) -> ScanReport:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Nessus scan file not found: {file_path}")

        tree = ET.parse(str(path))
        root = tree.getroot()

        report_elem = root.find("Report")
        scan_name = report_elem.get("name", path.stem) if report_elem is not None else path.stem

        hosts: List[Host] = []
        vuln_dict: Dict[str, Vulnerability] = {}

        if report_elem is not None:
            for host_elem in report_elem.findall("ReportHost"):
                host_ip = host_elem.get("name", "")
                hostname = None
                operating_system = None
                mac_address = None
                open_ports: Set[int] = set()
                host_vuln_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

                # Parse HostProperties tags
                host_props = host_elem.find("HostProperties")
                if host_props is not None:
                    for tag in host_props.findall("tag"):
                        tag_name = tag.get("name", "")
                        tag_val = tag.text or ""
                        if tag_name == "host-ip":
                            host_ip = tag_val
                        elif tag_name == "host-fqdn":
                            hostname = tag_val
                        elif tag_name == "operating-system":
                            operating_system = tag_val
                        elif tag_name == "mac-address":
                            mac_address = tag_val

                # Parse ReportItem tags (Vulnerabilities and Open Ports)
                for item in host_elem.findall("ReportItem"):
                    plugin_id = item.get("pluginID", "")
                    plugin_name = item.get("pluginName", "")
                    port_str = item.get("port", "0")
                    port = int(port_str) if port_str.isdigit() else 0
                    protocol = item.get("protocol", "tcp")
                    raw_severity = int(item.get("severity", "0"))

                    if port > 0:
                        open_ports.add(port)

                    # Map severity
                    severity = self._map_severity(raw_severity)
                    host_vuln_counts[severity.value] += 1

                    # Extract CVEs
                    cves = [cve.text.strip() for cve in item.findall("cve") if cve.text]
                    # Extract CWEs
                    cwes = [cwe.text.strip() for cwe in item.findall("cwe") if cwe.text]

                    # Extract CVSS
                    cvss3_elem = item.find("cvss3_base_score")
                    cvss2_elem = item.find("cvss_base_score")
                    cvss_score = None
                    if cvss3_elem is not None and cvss3_elem.text:
                        try:
                            cvss_score = float(cvss3_elem.text)
                        except ValueError:
                            pass
                    elif cvss2_elem is not None and cvss2_elem.text:
                        try:
                            cvss_score = float(cvss2_elem.text)
                        except ValueError:
                            pass

                    description = self._get_text(item, "description")
                    solution = self._get_text(item, "solution")
                    raw_output = self._get_text(item, "plugin_output")
                    see_also = [ref.strip() for ref in self._get_text(item, "see_also").split("\n") if ref.strip()]

                    # Host target format: "192.168.1.10:443/tcp"
                    host_target_str = f"{host_ip}:{port}/{protocol}" if port > 0 else host_ip

                    # Aggregate vulnerability by plugin_id
                    if plugin_id in vuln_dict:
                        existing_v = vuln_dict[plugin_id]
                        if host_target_str not in existing_v.affected_hosts:
                            existing_v.affected_hosts.append(host_target_str)
                    else:
                        # Enrich with Traditional Chinese Knowledge Base
                        zh_enrichment = enrich_vulnerability(plugin_name, description, solution)

                        vuln_dict[plugin_id] = Vulnerability(
                            id=plugin_id,
                            title=plugin_name,
                            title_zh=zh_enrichment.get("title_zh"),
                            severity=severity,
                            cvss_score=cvss_score,
                            cve_list=cves,
                            cwe_list=cwes,
                            description=description,
                            description_zh=zh_enrichment.get("description_zh"),
                            solution=solution,
                            solution_zh=zh_enrichment.get("solution_zh"),
                            affected_hosts=[host_target_str],
                            port=port if port > 0 else None,
                            protocol=protocol,
                            references=see_also,
                            raw_plugin_output=raw_output,
                        )

                hosts.append(
                    Host(
                        ip=host_ip,
                        hostname=hostname,
                        os=operating_system,
                        mac_address=mac_address,
                        open_ports=sorted(list(open_ports)),
                        vuln_count=host_vuln_counts,
                    )
                )

        # Sort vulnerabilities: Critical -> High -> Medium -> Low -> Info
        sorted_vulns = sorted(
            list(vuln_dict.values()),
            key=lambda v: (v.severity.rank, v.cvss_score or 0.0),
            reverse=True,
        )

        return ScanReport(
            scanner_name=self.scanner_name,
            scan_name=scan_name,
            scan_date=datetime.now(),
            target_scope=[h.ip for h in hosts],
            hosts=hosts,
            vulnerabilities=sorted_vulns,
        )

    @staticmethod
    def _map_severity(raw_sev: int) -> Severity:
        mapping = {
            4: Severity.CRITICAL,
            3: Severity.HIGH,
            2: Severity.MEDIUM,
            1: Severity.LOW,
            0: Severity.INFO,
        }
        return mapping.get(raw_sev, Severity.INFO)

    @staticmethod
    def _get_text(parent: ET.Element, tag: str) -> str:
        elem = parent.find(tag)
        return elem.text.strip() if elem is not None and elem.text else ""
