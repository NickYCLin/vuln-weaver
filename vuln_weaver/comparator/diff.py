from typing import Dict
from vuln_weaver.models import ScanReport, DiffReport, DiffItem, DiffStatus, Vulnerability


class VulnerabilityComparator:
    """Compare findings by host and service, not just by plugin ID."""

    @staticmethod
    def compare(baseline: ScanReport, rescan: ScanReport) -> DiffReport:
        if baseline.scanner_name != rescan.scanner_name:
            raise ValueError("初掃與複掃必須使用相同掃描器，否則弱點 ID 無法直接比對")

        baseline_hosts = {host.ip for host in baseline.hosts}
        rescan_hosts = {host.ip for host in rescan.hosts}
        if not baseline_hosts or baseline_hosts != rescan_hosts:
            raise ValueError("初掃與複掃的受檢主機範圍不同，不能將未複掃的主機判定為已修復")

        baseline_map: Dict[str, Vulnerability] = {v.id: v for v in baseline.vulnerabilities}
        rescan_map: Dict[str, Vulnerability] = {v.id: v for v in rescan.vulnerabilities}
        diff_items = []

        for vuln_id in list(baseline_map) + [key for key in rescan_map if key not in baseline_map]:
            base_v = baseline_map.get(vuln_id)
            res_v = rescan_map.get(vuln_id)
            base_targets = set(base_v.affected_hosts) if base_v else set()
            rescan_targets = set(res_v.affected_hosts) if res_v else set()

            if (base_v and not base_targets) or (res_v and not rescan_targets):
                raise ValueError(f"弱點 {vuln_id} 缺少受影響主機，無法判斷複掃結果")

            for status, targets, source in (
                (DiffStatus.FIXED, base_targets - rescan_targets, base_v),
                (DiffStatus.OPEN, base_targets & rescan_targets, base_v),
                (DiffStatus.NEW, rescan_targets - base_targets, res_v),
            ):
                if targets:
                    diff_items.append(
                        DiffItem(
                            vuln_id=vuln_id,
                            title=source.title_zh or source.title,
                            severity=source.severity,
                            status=status,
                            affected_hosts=sorted(targets),
                            solution=source.solution_zh or source.solution,
                        )
                    )

        return DiffReport(
            baseline_scan_name=baseline.scan_name,
            rescan_name=rescan.scan_name,
            items=diff_items,
        )
