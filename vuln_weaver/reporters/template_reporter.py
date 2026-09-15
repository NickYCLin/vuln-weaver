"""
以 docxtpl (Jinja2) 套用使用者自訂的 Word 範本。

範本可用變數見 README「自訂 Word 範本」一節；build_context / build_diff_context
是唯一的資料來源，改欄位時請同步更新文件。
"""
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from docx.shared import Inches
from docxtpl import DocxTemplate, InlineImage

from vuln_weaver.models import DiffReport, DiffStatus, ReportMeta, ScanReport
from vuln_weaver.reporters.base import BaseReporter
from vuln_weaver.reporters.charts import generate_severity_chart

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
DEFAULT_REPORT_TEMPLATE = TEMPLATE_DIR / "default_tw.docx"
DEFAULT_DIFF_TEMPLATE = TEMPLATE_DIR / "default_diff_tw.docx"

SCANNER_LABELS = {"nessus": "Tenable Nessus", "nmap": "Nmap", "zap": "OWASP ZAP", "burp": "Burp Suite"}
STATUS_ZH = {DiffStatus.FIXED: "已修復", DiffStatus.OPEN: "未修復", DiffStatus.NEW: "新發現"}


def _fmt_date(value: datetime) -> str:
    return value.strftime("%Y 年 %m 月 %d 日")


def _meta_context(meta: ReportMeta) -> Dict[str, Any]:
    data = {
        "org": meta.org or "",
        "vendor": meta.vendor or "",
        "project_code": meta.project_code or "",
        "tester": meta.tester or "",
        "reviewer": meta.reviewer or "",
        "approver": meta.approver or "",
        "signers": meta.signers,
    }
    data.update(meta.extra)
    return data


def build_context(report: ScanReport, meta: Optional[ReportMeta] = None) -> Dict[str, Any]:
    """單次掃描報告的範本變數（不含圖片，圖片由 reporter 另外注入）。"""
    meta = meta or ReportMeta()
    stats = report.summary_stats
    hosts: List[Dict[str, Any]] = [
        {
            "index": idx,
            "ip": host.ip,
            "hostname": host.hostname or "-",
            "os": host.os or "未明確辨識",
            "open_ports": ", ".join(map(str, host.open_ports)) if host.open_ports else "無開放",
            "open_port_list": host.open_ports,
            "vuln_count": host.vuln_count,
        }
        for idx, host in enumerate(report.hosts, start=1)
    ]
    vulns: List[Dict[str, Any]] = [
        {
            "index": idx,
            "id": v.id,
            "title": v.title,
            "title_zh": v.title_zh or "",
            "display_title": v.title_zh or v.title,
            "severity": v.severity.value,
            "severity_zh": v.severity.zh_tw,
            "cvss": f"{v.cvss_score:.1f}" if v.cvss_score is not None else "未提供",
            "cves": ", ".join(v.cve_list) if v.cve_list else "無特定 CVE",
            "cve_list": v.cve_list,
            "cwes": ", ".join(v.cwe_list),
            "affected_hosts": ", ".join(v.affected_hosts),
            "affected_host_list": v.affected_hosts,
            "description": v.description_zh or v.description or "暫無描述",
            "description_en": v.description,
            "solution": v.solution_zh or v.solution or "請諮詢軟體原廠以取得最新補丁更新。",
            "solution_en": v.solution,
            "references": v.references,
            "raw_output": v.raw_plugin_output or "",
        }
        for idx, v in enumerate(report.vulnerabilities, start=1)
    ]
    return {
        "scan_name": report.scan_name,
        "scanner": report.scanner_name,
        "scanner_label": SCANNER_LABELS.get(report.scanner_name, report.scanner_name),
        "scan_date": _fmt_date(report.scan_date),
        "scan_date_iso": report.scan_date.strftime("%Y-%m-%d"),
        "generated_at": _fmt_date(datetime.now()),
        "host_count": len(report.hosts),
        "vuln_count": len(report.vulnerabilities),
        "stats": {**stats, "total": sum(stats.values())},
        "hosts": hosts,
        "vulns": vulns,
        "meta": _meta_context(meta),
        "report": report,
    }


def build_diff_context(diff_report: DiffReport, meta: Optional[ReportMeta] = None) -> Dict[str, Any]:
    meta = meta or ReportMeta()
    items = [
        {
            "index": idx,
            "vuln_id": item.vuln_id,
            "title": item.title,
            "severity": item.severity.value,
            "severity_zh": item.severity.zh_tw,
            "status": item.status.value,
            "status_zh": STATUS_ZH[item.status],
            "affected_hosts": ", ".join(item.affected_hosts),
            "affected_host_list": item.affected_hosts,
            "solution": item.solution or "",
        }
        for idx, item in enumerate(diff_report.items, start=1)
    ]
    return {
        "baseline_scan_name": diff_report.baseline_scan_name,
        "rescan_name": diff_report.rescan_name,
        "comparison_date": _fmt_date(diff_report.comparison_date),
        "comparison_date_iso": diff_report.comparison_date.strftime("%Y-%m-%d"),
        "generated_at": _fmt_date(datetime.now()),
        "fixed_count": diff_report.fixed_count,
        "open_count": diff_report.open_count,
        "new_count": diff_report.new_count,
        "total_count": len(diff_report.items),
        "items": items,
        "fixed_items": [i for i in items if i["status"] == DiffStatus.FIXED.value],
        "open_items": [i for i in items if i["status"] == DiffStatus.OPEN.value],
        "new_items": [i for i in items if i["status"] == DiffStatus.NEW.value],
        "meta": _meta_context(meta),
        "diff_report": diff_report,
    }


class TemplateReporter(BaseReporter):
    """Render reports through a user-supplied .docx template (docxtpl)."""

    def __init__(self, template_path: Optional[Union[str, Path]] = None, diff_template_path: Optional[Union[str, Path]] = None):
        self.template_path = Path(template_path) if template_path else DEFAULT_REPORT_TEMPLATE
        self.diff_template_path = Path(diff_template_path) if diff_template_path else DEFAULT_DIFF_TEMPLATE

    def generate(
        self,
        report: ScanReport,
        output_path: Union[str, Path],
        meta: Optional[ReportMeta] = None,
        **kwargs,
    ) -> Path:
        tpl = self._load(self.template_path)
        context = build_context(report, meta)
        chart_path = generate_severity_chart(report.summary_stats)
        context["chart"] = InlineImage(tpl, chart_path, width=Inches(5.0)) if chart_path else ""
        try:
            return self._render(tpl, context, output_path)
        finally:
            if chart_path:
                try:
                    os.remove(chart_path)
                except OSError:
                    pass

    def generate_diff(
        self,
        diff_report: DiffReport,
        output_path: Union[str, Path],
        meta: Optional[ReportMeta] = None,
        **kwargs,
    ) -> Path:
        tpl = self._load(self.diff_template_path)
        return self._render(tpl, build_diff_context(diff_report, meta), output_path)

    @staticmethod
    def _load(path: Path) -> DocxTemplate:
        if not path.exists():
            raise FileNotFoundError(f"找不到 Word 範本：{path}")
        return DocxTemplate(str(path))

    @staticmethod
    def _render(tpl: DocxTemplate, context: Dict[str, Any], output_path: Union[str, Path]) -> Path:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        tpl.render(context, autoescape=True)
        tpl.save(str(out_file))
        return out_file
