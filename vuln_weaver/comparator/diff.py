from typing import Set, Dict
from vuln_weaver.models import ScanReport, DiffReport, DiffItem, DiffStatus, Vulnerability


class VulnerabilityComparator:
    """Compares baseline scan report with re-scan report to track remediation status."""

    @staticmethod
    def compare(baseline: ScanReport, rescan: ScanReport) -> DiffReport:
        baseline_map: Dict[str, Vulnerability] = {v.id: v for v in baseline.vulnerabilities}
        rescan_map: Dict[str, Vulnerability] = {v.id: v for v in rescan.vulnerabilities}

        diff_items = []

        # Check items in baseline
        for vuln_id, base_v in baseline_map.items():
            if vuln_id in rescan_map:
                # Still exists in rescan -> OPEN
                diff_items.append(
                    DiffItem(
                        vuln_id=vuln_id,
                        title=base_v.title_zh or base_v.title,
                        severity=base_v.severity,
                        status=DiffStatus.OPEN,
                        affected_hosts=rescan_map[vuln_id].affected_hosts or base_v.affected_hosts,
                        solution=base_v.solution_zh or base_v.solution,
                    )
                )
            else:
                # Disappeared in rescan -> FIXED
                diff_items.append(
                    DiffItem(
                        vuln_id=vuln_id,
                        title=base_v.title_zh or base_v.title,
                        severity=base_v.severity,
                        status=DiffStatus.FIXED,
                        affected_hosts=base_v.affected_hosts,
                        solution=base_v.solution_zh or base_v.solution,
                    )
                )

        # Check newly appeared items in rescan -> NEW
        for vuln_id, res_v in rescan_map.items():
            if vuln_id not in baseline_map:
                diff_items.append(
                    DiffItem(
                        vuln_id=vuln_id,
                        title=res_v.title_zh or res_v.title,
                        severity=res_v.severity,
                        status=DiffStatus.NEW,
                        affected_hosts=res_v.affected_hosts,
                        solution=res_v.solution_zh or res_v.solution,
                    )
                )

        return DiffReport(
            baseline_scan_name=baseline.scan_name,
            rescan_name=rescan.scan_name,
            items=diff_items,
        )
