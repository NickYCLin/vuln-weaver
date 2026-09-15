from enum import Enum
from typing import List, Optional, Dict
from datetime import datetime
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def rank(self) -> int:
        ranks = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return ranks.get(self, 0)

    @property
    def zh_tw(self) -> str:
        names = {
            Severity.CRITICAL: "極高",
            Severity.HIGH: "高",
            Severity.MEDIUM: "中",
            Severity.LOW: "低",
            Severity.INFO: "資訊",
        }
        return names.get(self, "資訊")


class Vulnerability(BaseModel):
    id: str = Field(description="Unique vulnerability plugin or scan ID")
    title: str = Field(description="Vulnerability title (English)")
    title_zh: Optional[str] = Field(default=None, description="Localized Traditional Chinese title")
    severity: Severity = Field(default=Severity.INFO)
    cvss_score: Optional[float] = Field(default=None)
    cve_list: List[str] = Field(default_factory=list)
    cwe_list: List[str] = Field(default_factory=list)
    description: str = Field(default="")
    description_zh: Optional[str] = Field(default=None)
    solution: str = Field(default="")
    solution_zh: Optional[str] = Field(default=None)
    affected_hosts: List[str] = Field(default_factory=list)
    port: Optional[int] = Field(default=None)
    protocol: Optional[str] = Field(default=None)
    references: List[str] = Field(default_factory=list)
    raw_plugin_output: Optional[str] = Field(default=None)


class Host(BaseModel):
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    mac_address: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    vuln_count: Dict[str, int] = Field(
        default_factory=lambda: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    )


SCANNER_LABELS = {
    "nessus": "Tenable Nessus",
    "nmap": "Nmap",
    "zap": "OWASP ZAP",
    "burp": "Burp Suite",
}


def scanner_label(scanner_name: str) -> str:
    """把 scanner_name（含合併後的 nessus+nmap）轉成報告上的顯示名稱。"""
    return " + ".join(SCANNER_LABELS.get(part, part) for part in scanner_name.split("+"))


class ScanReport(BaseModel):
    scanner_name: str
    scanner_version: Optional[str] = None
    scan_name: str
    scan_date: datetime = Field(default_factory=datetime.now)
    target_scope: List[str] = Field(default_factory=list)
    hosts: List[Host] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)

    @property
    def scanner_label(self) -> str:
        return scanner_label(self.scanner_name)

    @property
    def summary_stats(self) -> Dict[str, int]:
        stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for v in self.vulnerabilities:
            stats[v.severity.value] += 1
        return stats


class ReportMeta(BaseModel):
    """報告封面與簽章欄位；欄位留空時報告會保留空白給人工填寫。"""

    org: Optional[str] = Field(default=None, description="受測單位")
    vendor: Optional[str] = Field(default=None, description="執行單位／廠商")
    project_code: Optional[str] = Field(default=None, description="專案或案號")
    tester: Optional[str] = Field(default=None, description="執行人員")
    reviewer: Optional[str] = Field(default=None, description="審核人員")
    approver: Optional[str] = Field(default=None, description="核定主管")
    extra: Dict[str, str] = Field(default_factory=dict, description="自訂範本額外變數")

    @property
    def signers(self) -> List[Dict[str, str]]:
        return [
            {"role": "執行人員", "name": self.tester or ""},
            {"role": "審核人員", "name": self.reviewer or ""},
            {"role": "核定主管", "name": self.approver or ""},
        ]


class DiffStatus(str, Enum):
    FIXED = "Fixed"       # 弱點已修復 (出現在初掃，未出現在複掃)
    OPEN = "Open"         # 弱點仍存在 (初掃與複掃皆存在)
    NEW = "New"           # 新增弱點 (初掃未出現，複掃新發現)


class DiffItem(BaseModel):
    vuln_id: str
    title: str
    severity: Severity
    status: DiffStatus
    affected_hosts: List[str] = Field(default_factory=list)
    solution: Optional[str] = None


class DiffReport(BaseModel):
    baseline_scan_name: str
    rescan_name: str
    comparison_date: datetime = Field(default_factory=datetime.now)
    items: List[DiffItem] = Field(default_factory=list)

    @property
    def fixed_count(self) -> int:
        return sum(1 for i in self.items if i.status == DiffStatus.FIXED)

    @property
    def open_count(self) -> int:
        return sum(1 for i in self.items if i.status == DiffStatus.OPEN)

    @property
    def new_count(self) -> int:
        return sum(1 for i in self.items if i.status == DiffStatus.NEW)
