import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse

from vuln_weaver.parsers.base import BaseParser
from vuln_weaver.parsers.zap import _strip_html
from vuln_weaver.models import ScanReport, Host, Vulnerability, Severity
from vuln_weaver.knowledge.kb_zh_tw import enrich_vulnerability

_HREF_RE = re.compile(r'href="([^"]+)"')
_CWE_RE = re.compile(r"\bCWE-(\d+)\b")


class BurpParser(BaseParser):
    """Parser for Burp Suite 'Report issues' XML exports (root element <issues>)."""

    @property
    def scanner_name(self) -> str:
        return "burp"

    def parse(self, file_path: Union[str, Path]) -> ScanReport:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Burp report file not found: {file_path}")

        root = ET.parse(str(path)).getroot()
        if root.tag != "issues":
            raise ValueError(f"不是有效的 Burp Suite XML 報告：根節點應為 issues（實際為 {root.tag}）")

        hosts: Dict[str, Host] = {}
        vuln_dict: Dict[str, Vulnerability] = {}

        for issue in root.findall("issue"):
            issue_type = self._text(issue, "type")
            name = self._text(issue, "name")
            if not issue_type or not name:
                continue

            host_elem = issue.find("host")
            site_url = (host_elem.text or "").strip() if host_elem is not None else ""
            host_ip = (host_elem.get("ip") or "").strip() if host_elem is not None else ""
            host_name, port = self._endpoint(site_url, host_ip)
            target_str = f"{host_name}:{port}/tcp"

            severity = self._map_severity(self._text(issue, "severity"))
            host = hosts.setdefault(
                host_name,
                Host(ip=host_name, hostname=host_name, os=f"IP: {host_ip}" if host_ip else None, open_ports=[]),
            )
            if port not in host.open_ports:
                host.open_ports.append(port)
                host.open_ports.sort()

            location = self._text(issue, "location") or self._text(issue, "path")
            confidence = self._text(issue, "confidence")
            location_line = f"{site_url}{location}" if location else site_url
            if confidence:
                location_line = f"{location_line}（確信度：{confidence}）"

            if issue_type in vuln_dict:
                existing = vuln_dict[issue_type]
                if target_str not in existing.affected_hosts:
                    existing.affected_hosts.append(target_str)
                    host.vuln_count[severity.value] += 1
                existing.raw_plugin_output = self._merge_lines(existing.raw_plugin_output, location_line)
                continue

            host.vuln_count[severity.value] += 1

            description = self._join_sections(
                _strip_html(self._text(issue, "issueBackground")),
                _strip_html(self._text(issue, "issueDetail")),
                second_label="檢出細節",
            )
            solution = self._join_sections(
                _strip_html(self._text(issue, "remediationBackground")),
                _strip_html(self._text(issue, "remediationDetail")),
                second_label="針對本次檢出的處置",
            )
            classifications = self._text(issue, "vulnerabilityClassifications")
            cwes = []
            for cwe_id in _CWE_RE.findall(classifications):
                if f"CWE-{cwe_id}" not in cwes:
                    cwes.append(f"CWE-{cwe_id}")
            references = _HREF_RE.findall(self._text(issue, "references"))

            zh = enrich_vulnerability(name, description, solution)
            vuln_dict[issue_type] = Vulnerability(
                id=issue_type,
                title=name,
                title_zh=zh.get("title_zh"),
                severity=severity,
                cwe_list=cwes,
                description=description,
                description_zh=zh.get("description_zh"),
                solution=solution,
                solution_zh=zh.get("solution_zh"),
                affected_hosts=[target_str],
                port=port,
                protocol="tcp",
                references=references,
                raw_plugin_output=self._merge_lines(None, location_line),
            )

        if not hosts:
            raise ValueError("Burp Suite 報告中沒有任何 issue，無法建立主機清冊")

        sorted_vulns = sorted(
            vuln_dict.values(),
            key=lambda v: (v.severity.rank, v.cvss_score or 0.0),
            reverse=True,
        )
        return ScanReport(
            scanner_name=self.scanner_name,
            scanner_version=root.get("burpVersion"),
            scan_name=f"Burp Suite 網站弱點掃描 - {path.stem}",
            scan_date=self._parse_export_time(root.get("exportTime")) or datetime.now(),
            target_scope=list(hosts),
            hosts=list(hosts.values()),
            vulnerabilities=sorted_vulns,
        )

    # --- Helpers -------------------------------------------------------

    @staticmethod
    def _text(parent: ET.Element, tag: str) -> str:
        elem = parent.find(tag)
        return (elem.text or "").strip() if elem is not None else ""

    @staticmethod
    def _endpoint(site_url: str, host_ip: str):
        parsed = urlparse(site_url) if site_url else None
        host_name = (parsed.hostname if parsed else None) or host_ip or "Unknown"
        if parsed and parsed.port:
            port = parsed.port
        else:
            port = 443 if parsed and parsed.scheme == "https" else 80
        return host_name, port

    @staticmethod
    def _map_severity(raw: str) -> Severity:
        mapping = {
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "information": Severity.INFO,
            "info": Severity.INFO,
        }
        return mapping.get(raw.strip().lower(), Severity.INFO)

    @staticmethod
    def _join_sections(first: str, second: str, second_label: str) -> str:
        if first and second:
            return f"{first}\n\n{second_label}：\n{second}"
        return first or second

    @staticmethod
    def _merge_lines(existing: Optional[str], line: str, limit: int = 20) -> Optional[str]:
        lines: List[str] = [item for item in (existing or "").splitlines() if item]
        if line and line not in lines:
            lines.append(line)
        if not lines:
            return existing
        shown = lines[:limit]
        if len(lines) > limit:
            shown.append(f"...（另有 {len(lines) - limit} 個位置未列出）")
        return "\n".join(shown)

    @staticmethod
    def _parse_export_time(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        # Burp 格式範例：Wed Sep 03 10:15:42 CST 2026（時區名稱因地區而異，先拿掉再解析）
        parts = value.strip().split()
        if len(parts) == 6:
            parts = parts[:4] + parts[5:]
        try:
            return datetime.strptime(" ".join(parts), "%a %b %d %H:%M:%S %Y")
        except ValueError:
            return None
