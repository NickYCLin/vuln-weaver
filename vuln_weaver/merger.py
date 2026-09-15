"""
把多份掃描結果合併成一份 ScanReport。

同一專案常會同時交 Nessus、Nmap、ZAP 的結果，或同一掃描器分子網段跑多次；
驗收報告要的是一份彙整清冊，所以這裡把主機與弱點各自合併。
"""
from typing import Dict, List, Optional, Sequence

from vuln_weaver.models import Host, ScanReport, Vulnerability


def merge_reports(reports: Sequence[ScanReport], scan_name: Optional[str] = None) -> ScanReport:
    if not reports:
        raise ValueError("沒有任何掃描結果可以合併")
    if len(reports) == 1 and not scan_name:
        return reports[0]

    scanners = sorted({r.scanner_name for r in reports})
    multi_scanner = len(scanners) > 1

    hosts: Dict[str, Host] = {}
    vulns: Dict[str, Vulnerability] = {}

    for report in reports:
        for host in report.hosts:
            _merge_host(hosts, host)
        for vuln in report.vulnerabilities:
            # 不同掃描器的 ID 空間互不相關（Nessus plugin 10038 和 ZAP 10038 是兩回事），
            # 跨掃描器合併時把掃描器名稱冠在前面；同掃描器合併則沿用原 ID 讓複測比對照常運作。
            key = f"{report.scanner_name}:{vuln.id}" if multi_scanner else vuln.id
            _merge_vuln(vulns, key, vuln)

    sorted_vulns = sorted(vulns.values(), key=lambda v: (v.severity.rank, v.cvss_score or 0.0), reverse=True)
    name = scan_name or "、".join(dict.fromkeys(r.scan_name for r in reports))
    versions = [r.scanner_version for r in reports if r.scanner_version]

    return ScanReport(
        scanner_name="+".join(scanners),
        scanner_version=", ".join(dict.fromkeys(versions)) if versions else None,
        scan_name=name,
        scan_date=max(r.scan_date for r in reports),
        target_scope=list(hosts),
        hosts=list(hosts.values()),
        vulnerabilities=sorted_vulns,
    )


def _merge_host(hosts: Dict[str, Host], host: Host) -> None:
    existing = hosts.get(host.ip)
    if existing is None:
        hosts[host.ip] = host.model_copy(deep=True)
        return
    existing.hostname = existing.hostname or host.hostname
    existing.os = existing.os or host.os
    existing.mac_address = existing.mac_address or host.mac_address
    existing.open_ports = sorted(set(existing.open_ports) | set(host.open_ports))
    for level, count in host.vuln_count.items():
        existing.vuln_count[level] = existing.vuln_count.get(level, 0) + count


def _merge_vuln(vulns: Dict[str, Vulnerability], key: str, vuln: Vulnerability) -> None:
    existing = vulns.get(key)
    if existing is None:
        copied = vuln.model_copy(deep=True)
        copied.id = key
        vulns[key] = copied
        return
    for target in vuln.affected_hosts:
        if target not in existing.affected_hosts:
            existing.affected_hosts.append(target)
    _extend_unique(existing.cve_list, vuln.cve_list)
    _extend_unique(existing.cwe_list, vuln.cwe_list)
    _extend_unique(existing.references, vuln.references)
    if vuln.cvss_score is not None and (existing.cvss_score is None or vuln.cvss_score > existing.cvss_score):
        existing.cvss_score = vuln.cvss_score
    if vuln.severity.rank > existing.severity.rank:
        existing.severity = vuln.severity
    if vuln.raw_plugin_output and vuln.raw_plugin_output != existing.raw_plugin_output:
        existing.raw_plugin_output = "\n".join(
            filter(None, [existing.raw_plugin_output, vuln.raw_plugin_output])
        )


def _extend_unique(target: List[str], items: List[str]) -> None:
    for item in items:
        if item not in target:
            target.append(item)
