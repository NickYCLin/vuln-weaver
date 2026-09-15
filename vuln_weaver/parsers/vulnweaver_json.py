import json
from pathlib import Path
from typing import Union

from pydantic import ValidationError

from vuln_weaver.parsers.base import BaseParser
from vuln_weaver.models import ScanReport


class VulnWeaverJsonParser(BaseParser):
    """回讀 `parse -f json` 匯出的 ScanReport JSON，讓合併結果也能拿來做複測比對。"""

    @property
    def scanner_name(self) -> str:
        return "vulnweaver"

    def parse(self, file_path: Union[str, Path]) -> ScanReport:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"VulnWeaver JSON not found: {file_path}")
        try:
            return ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
        except (ValidationError, json.JSONDecodeError) as exc:
            raise ValueError(f"不是有效的 VulnWeaver 報告 JSON：{exc}") from exc


def looks_like_vulnweaver_json(path: Path) -> bool:
    """只看最外層 key，不整份載入，用來和 ZAP JSON 區分。"""
    try:
        with path.open("r", encoding="utf-8") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    return '"scanner_name"' in head and '"vulnerabilities"' in head or '"scanner_name"' in head and '"hosts"' in head
