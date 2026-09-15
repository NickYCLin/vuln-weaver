import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from vuln_weaver.parsers.base import BaseParser
from vuln_weaver.models import ScanReport, Host, Vulnerability, Severity
from vuln_weaver.knowledge.kb_zh_tw import enrich_vulnerability


_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(text: Optional[str]) -> str:
    """ZAP 的 desc / solution 內含 <p> 等 HTML 標籤，報告中不需要。"""
    if not text:
        return ""
    cleaned = _TAG_RE.sub("", text)
    cleaned = cleaned.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    return "\n".join(line.strip() for line in cleaned.splitlines() if line.strip())


class ZapParser(BaseParser):
    """Parser for OWASP ZAP traditional XML (.xml) and JSON (.json) reports."""

    @property
    def scanner_name(self) -> str:
        return "zap"

    def parse(self, file_path: Union[str, Path]) -> ScanReport:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"ZAP report file not found: {file_path}")

        if path.suffix.lower() == ".json":
            sites, generated = self._load_json(path)
        else:
            sites, generated = self._load_xml(path)

        hosts: List[Host] = []
        vuln_dict: Dict[str, Vulnerability] = {}

        for site in sites:
            host_name, port, ssl = self._site_endpoint(site)
            target_str = f"{host_name}:{port}/tcp"
            host_vuln_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

            for alert in site["alerts"]:
                plugin_id = str(alert.get("pluginid") or alert.get("alertRef") or "").strip()
                name = (alert.get("alert") or alert.get("name") or "").strip()
                if not plugin_id or not name:
                    continue

                severity = self._map_severity(alert.get("riskcode"))
                instances = alert.get("instances") or []
                uris = [inst.get("uri", "") for inst in instances if inst.get("uri")]

                if plugin_id in vuln_dict:
                    existing = vuln_dict[plugin_id]
                    if target_str not in existing.affected_hosts:
                        existing.affected_hosts.append(target_str)
                        host_vuln_counts[severity.value] += 1
                    existing.raw_plugin_output = self._merge_output(existing.raw_plugin_output, uris)
                    continue

                host_vuln_counts[severity.value] += 1
                description = _strip_html(alert.get("desc"))
                solution = _strip_html(alert.get("solution"))
                other_info = _strip_html(alert.get("otherinfo"))
                if other_info:
                    description = f"{description}\n\n補充資訊：\n{other_info}" if description else other_info

                zh = enrich_vulnerability(name, description, solution)
                cwe_id = str(alert.get("cweid") or "").strip()
                references = [
                    ref.strip()
                    for ref in _strip_html(alert.get("reference")).splitlines()
                    if ref.strip()
                ]

                vuln_dict[plugin_id] = Vulnerability(
                    id=plugin_id,
                    title=name,
                    title_zh=zh.get("title_zh"),
                    severity=severity,
                    cwe_list=[f"CWE-{cwe_id}"] if cwe_id and cwe_id not in ("-1", "0") else [],
                    description=description,
                    description_zh=zh.get("description_zh"),
                    solution=solution,
                    solution_zh=zh.get("solution_zh"),
                    affected_hosts=[target_str],
                    port=port,
                    protocol="tcp",
                    references=references,
                    raw_plugin_output=self._merge_output(None, uris),
                )

            hosts.append(
                Host(
                    ip=host_name,
                    hostname=host_name,
                    os=None,
                    open_ports=[port],
                    vuln_count=host_vuln_counts,
                )
            )

        if not hosts:
            raise ValueError("ZAP 報告中沒有任何 site 節點，無法建立主機清冊")

        sorted_vulns = sorted(
            vuln_dict.values(),
            key=lambda v: (v.severity.rank, v.cvss_score or 0.0),
            reverse=True,
        )

        return ScanReport(
            scanner_name=self.scanner_name,
            scan_name=f"OWASP ZAP 網站弱點掃描 - {path.stem}",
            scan_date=generated or datetime.now(),
            target_scope=[h.ip for h in hosts],
            hosts=hosts,
            vulnerabilities=sorted_vulns,
        )

    # --- Loaders -------------------------------------------------------

    @staticmethod
    def _load_xml(path: Path):
        root = ET.parse(str(path)).getroot()
        if root.tag != "OWASPZAPReport":
            raise ValueError(f"不是有效的 ZAP XML 報告：根節點應為 OWASPZAPReport（實際為 {root.tag}）")

        sites: List[Dict[str, Any]] = []
        for site_elem in root.findall("site"):
            alerts: List[Dict[str, Any]] = []
            alerts_elem = site_elem.find("alerts")
            for item in (alerts_elem.findall("alertitem") if alerts_elem is not None else []):
                alert: Dict[str, Any] = {}
                for child in item:
                    if child.tag == "instances":
                        alert["instances"] = [
                            {sub.tag: (sub.text or "") for sub in inst}
                            for inst in child.findall("instance")
                        ]
                    else:
                        alert[child.tag] = child.text or ""
                alerts.append(alert)
            sites.append(
                {
                    "name": site_elem.get("name", ""),
                    "host": site_elem.get("host", ""),
                    "port": site_elem.get("port", ""),
                    "ssl": site_elem.get("ssl", ""),
                    "alerts": alerts,
                }
            )
        return sites, ZapParser._parse_generated(root.get("generated"))

    @staticmethod
    def _load_json(path: Path):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"不是有效的 ZAP JSON 報告：{exc}") from exc

        if not isinstance(data, dict) or "site" not in data:
            raise ValueError("不是有效的 ZAP JSON 報告：缺少 site 欄位")

        raw_sites = data["site"]
        if isinstance(raw_sites, dict):
            raw_sites = [raw_sites]

        sites: List[Dict[str, Any]] = []
        for site in raw_sites:
            sites.append(
                {
                    "name": site.get("@name", ""),
                    "host": site.get("@host", ""),
                    "port": site.get("@port", ""),
                    "ssl": site.get("@ssl", ""),
                    "alerts": site.get("alerts") or [],
                }
            )
        return sites, ZapParser._parse_generated(data.get("@generated"))

    # --- Helpers -------------------------------------------------------

    @staticmethod
    def _site_endpoint(site: Dict[str, Any]):
        parsed = urlparse(site.get("name") or "")
        host_name = site.get("host") or parsed.hostname or site.get("name") or "Unknown"
        ssl = str(site.get("ssl", "")).lower() == "true" or parsed.scheme == "https"

        port_raw = str(site.get("port") or "")
        if port_raw.isdigit():
            port = int(port_raw)
        elif parsed.port:
            port = parsed.port
        else:
            port = 443 if ssl else 80
        return host_name, port, ssl

    @staticmethod
    def _map_severity(riskcode: Any) -> Severity:
        mapping = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}
        return mapping.get(str(riskcode).strip(), Severity.INFO)

    @staticmethod
    def _parse_generated(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        # ZAP 格式範例：Tue, 3 Sep 2026 10:15:42
        for fmt in ("%a, %d %b %Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(value.strip(), fmt)
            except ValueError:
                continue
        return None

    @staticmethod
    def _merge_output(existing: Optional[str], uris: List[str], limit: int = 20) -> Optional[str]:
        seen: List[str] = [line for line in (existing or "").splitlines() if line]
        for uri in uris:
            if uri not in seen:
                seen.append(uri)
        if not seen:
            return existing
        shown = seen[:limit]
        if len(seen) > limit:
            shown.append(f"...（另有 {len(seen) - limit} 個 URL 未列出）")
        return "\n".join(shown)
