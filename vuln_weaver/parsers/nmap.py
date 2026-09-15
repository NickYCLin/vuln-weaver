import xml.etree.ElementTree as ET
import re
from pathlib import Path
from typing import Union, Dict, List, Set
from datetime import datetime

from vuln_weaver.parsers.base import BaseParser
from vuln_weaver.models import ScanReport, Host, Vulnerability, Severity
from vuln_weaver.knowledge.kb_zh_tw import enrich_vulnerability


class NmapParser(BaseParser):
    """Parser for Nmap XML output files (-oX)."""

    @property
    def scanner_name(self) -> str:
        return "nmap"

    def parse(self, file_path: Union[str, Path]) -> ScanReport:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Nmap XML file not found: {file_path}")

        tree = ET.parse(str(path))
        root = tree.getroot()

        if root.tag != "nmaprun":
            raise ValueError(f"不是有效的 Nmap XML：根節點應為 nmaprun（實際為 {root.tag}）")

        scan_name = f"Nmap 網路掃描 - {path.stem}"

        hosts: List[Host] = []
        vuln_dict: Dict[str, Vulnerability] = {}

        for host_elem in root.findall("host"):
            # Check host status (up/down)
            status_elem = host_elem.find("status")
            if status_elem is not None and status_elem.get("state") != "up":
                continue  # Skip hosts that are down

            # Extract IP & MAC
            host_ip = "Unknown"
            mac_addr = None
            for addr in host_elem.findall("address"):
                atype = addr.get("addrtype", "")
                if atype == "ipv4" or (atype == "ipv6" and host_ip == "Unknown"):
                    host_ip = addr.get("addr", "")
                elif atype == "mac":
                    mac_addr = addr.get("addr", "")

            # Extract Hostname
            hostname = None
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                hname_elem = hostnames_elem.find("hostname")
                if hname_elem is not None:
                    hostname = hname_elem.get("name", "")

            # Extract OS
            os_name = None
            os_elem = host_elem.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    os_name = osmatch.get("name", "")

            open_ports: Set[int] = set()
            host_vuln_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

            # Extract Ports & Services
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    proto = port_elem.get("protocol", "tcp")
                    port_id_str = port_elem.get("portid", "0")
                    port_id = int(port_id_str) if port_id_str.isdigit() else 0

                    state_elem = port_elem.find("state")
                    is_open = state_elem is not None and state_elem.get("state") == "open"

                    if is_open and port_id > 0:
                        open_ports.add(port_id)

                        svc_elem = port_elem.find("service")
                        svc_name = svc_elem.get("name", "") if svc_elem is not None else ""
                        target_str = f"{host_ip}:{port_id}/{proto}"

                        # Heuristic 1: Insecure cleartext Telnet
                        if svc_name.lower() == "telnet":
                            self._add_finding(
                                vuln_dict=vuln_dict,
                                host_vuln_counts=host_vuln_counts,
                                plugin_id="NMAP-TELNET-OPEN",
                                title="Telnet Server Detection (Cleartext Protocol)",
                                severity=Severity.MEDIUM,
                                target_str=target_str,
                                desc="偵測到目標主機開啟 Telnet (Port 23) 服務。Telnet 通訊過程完全以明文傳輸，極易遭受網路監聽截獲帳號密碼。",
                                solution="立即停用並關閉 Telnet 服務，全數改以安全加密之 SSH 通訊協定進行伺服器管理。",
                            )

                        # Parse Nmap NSE Scripts on this port
                        for script in port_elem.findall("script"):
                            script_id = script.get("id", "")
                            script_output = script.get("output", "").strip()

                            # Parse ssl-enum-ciphers
                            if "ssl-enum-ciphers" in script_id:
                                if "TLSv1.0" in script_output:
                                    self._add_finding(
                                        vuln_dict=vuln_dict,
                                        host_vuln_counts=host_vuln_counts,
                                        plugin_id="NMAP-TLS-1.0",
                                        title="TLS Version 1.0 Protocol Detection",
                                        severity=Severity.MEDIUM,
                                        target_str=target_str,
                                        desc=f"Nmap 偵測到目標通訊埠支援已廢棄之 TLS 1.0 通訊協定。\n輸出詳情：\n{script_output[:300]}",
                                        solution="請於伺服器組態中禁用 TLS 1.0，將傳輸加密門檻提升至 TLS 1.2 及 TLS 1.3 以上。",
                                    )
                                if "SSLv3" in script_output:
                                    self._add_finding(
                                        vuln_dict=vuln_dict,
                                        host_vuln_counts=host_vuln_counts,
                                        plugin_id="NMAP-SSL-3.0",
                                        title="SSL Version 2 and 3 Protocol Detection",
                                        severity=Severity.HIGH,
                                        target_str=target_str,
                                        desc=f"Nmap 偵測到目標通訊埠仍支援具破綻之 SSLv3 協定。\n輸出詳情：\n{script_output[:300]}",
                                        solution="停用所有 SSLv2 及 SSLv3 通訊協定，伺服器僅保留 TLS 1.2 及 TLS 1.3 協定支援。",
                                    )

                            # Parse generic vuln scripts
                            elif re.search(r"(?im)^\s*(?:state:\s*)?VULNERABLE\b", script_output):
                                self._add_finding(
                                    vuln_dict=vuln_dict,
                                    host_vuln_counts=host_vuln_counts,
                                    plugin_id=f"NMAP-{script_id.upper()}",
                                    title=f"Nmap Script Finding: {script_id}",
                                    severity=Severity.HIGH,
                                    target_str=target_str,
                                    desc=f"Nmap NSE 弱點腳本 [{script_id}] 檢出潛在風險。\n輸出結果：\n{script_output[:400]}",
                                    solution="請參考 Nmap NSE 腳本檢測說明，檢視相應組態或升級應用軟體版本。",
                                )

            hosts.append(
                Host(
                    ip=host_ip,
                    hostname=hostname,
                    os=os_name,
                    mac_address=mac_addr,
                    open_ports=sorted(list(open_ports)),
                    vuln_count=host_vuln_counts,
                )
            )

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

    def _add_finding(
        self,
        vuln_dict: Dict[str, Vulnerability],
        host_vuln_counts: Dict[str, int],
        plugin_id: str,
        title: str,
        severity: Severity,
        target_str: str,
        desc: str,
        solution: str,
    ):
        if plugin_id in vuln_dict:
            existing = vuln_dict[plugin_id]
            if target_str not in existing.affected_hosts:
                existing.affected_hosts.append(target_str)
                host_vuln_counts[severity.value] += 1
        else:
            host_vuln_counts[severity.value] += 1
            zh = enrich_vulnerability(title, desc, solution)
            vuln_dict[plugin_id] = Vulnerability(
                id=plugin_id,
                title=title,
                title_zh=zh.get("title_zh"),
                severity=severity,
                description=desc,
                description_zh=zh.get("description_zh") or desc,
                solution=solution,
                solution_zh=zh.get("solution_zh") or solution,
                affected_hosts=[target_str],
            )
