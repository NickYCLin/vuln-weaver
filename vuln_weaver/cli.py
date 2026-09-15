import sys
import xml.etree.ElementTree as ET
from pathlib import Path
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from vuln_weaver import __version__
from vuln_weaver.parsers.nessus import NessusParser
from vuln_weaver.parsers.nmap import NmapParser
from vuln_weaver.parsers.zap import ZapParser
from vuln_weaver.parsers.burp import BurpParser
from vuln_weaver.parsers.vulnweaver_json import VulnWeaverJsonParser, looks_like_vulnweaver_json
from vuln_weaver.merger import merge_reports
from vuln_weaver.models import ReportMeta
from vuln_weaver.reporters.docx_reporter import DocxReporter
from vuln_weaver.reporters.template_reporter import TemplateReporter
from vuln_weaver.reporters.xlsx_reporter import XlsxReporter
from vuln_weaver.comparator.diff import VulnerabilityComparator

# Ensure console supports UTF-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

console = Console()


XML_ROOT_PARSERS = {
    "nmaprun": NmapParser,
    "OWASPZAPReport": ZapParser,
    "issues": BurpParser,
    "NessusClientData_v2": NessusParser,
}


def _xml_root_tag(file_path: Path):
    """只讀到第一個起始標籤就停，避免為了辨識格式把整份掃描檔載入記憶體。"""
    try:
        for _event, elem in ET.iterparse(str(file_path), events=("start",)):
            return elem.tag
    except ET.ParseError:
        return None
    return None


def get_parser_for_file(file_path: Path):
    suffix = file_path.suffix.lower()
    if suffix == ".nessus":
        return NessusParser()
    if suffix == ".json":
        return VulnWeaverJsonParser() if looks_like_vulnweaver_json(file_path) else ZapParser()
    if suffix == ".xml":
        # Nmap、ZAP、Burp 都輸出 .xml，依根節點分辨；根節點無法辨識時交給 Nmap 解析器回報錯誤
        parser_cls = XML_ROOT_PARSERS.get(_xml_root_tag(file_path), NmapParser)
        return parser_cls()
    return None


def _parse_extra_vars(pairs):
    extra = {}
    for pair in pairs:
        if "=" not in pair:
            raise click.BadParameter(f"--var 需要 key=value 格式，收到：{pair}")
        key, value = pair.split("=", 1)
        extra[key.strip()] = value
    return extra


def report_meta_options(func):
    """parse 與 diff 共用的封面／簽章欄位與範本參數。"""
    options = [
        click.option("-t", "--template", "template_file", type=click.Path(exists=True, dir_okay=False),
                     default=None, help="使用自訂 docxtpl Word 範本（.docx）"),
        click.option("--org", default=None, help="受測單位名稱"),
        click.option("--vendor", default=None, help="執行單位／廠商名稱"),
        click.option("--project-code", default=None, help="專案或案號"),
        click.option("--tester", default=None, help="執行人員姓名"),
        click.option("--reviewer", default=None, help="審核人員姓名"),
        click.option("--approver", default=None, help="核定主管姓名"),
        click.option("--var", "extra_vars", multiple=True, metavar="KEY=VALUE",
                     help="自訂範本額外變數，可重複；範本內以 {{ meta.KEY }} 取用"),
    ]
    for option in reversed(options):
        func = option(func)
    return func


def build_meta(org, vendor, project_code, tester, reviewer, approver, extra_vars) -> ReportMeta:
    return ReportMeta(
        org=org, vendor=vendor, project_code=project_code,
        tester=tester, reviewer=reviewer, approver=approver,
        extra=_parse_extra_vars(extra_vars),
    )


def pick_reporter(output_format, template_file):
    if output_format == "xlsx":
        if template_file:
            raise click.ClickException("--template 只適用於 Word (docx) 輸出，Excel 匯出沒有範本機制。")
        return XlsxReporter()
    return TemplateReporter(template_path=template_file, diff_template_path=template_file) if template_file else DocxReporter()


def resolve_output(output_file, output_format, default_stem):
    """沒指定 -o 時依格式決定副檔名；有指定但副檔名不符時提醒。"""
    if not output_file:
        return f"{default_stem}.{output_format}"
    if Path(output_file).suffix.lower() != f".{output_format}":
        console.print(f"[yellow]提醒：輸出格式為 {output_format.upper()}，但檔名副檔名是 {Path(output_file).suffix or '（無）'}。[/yellow]")
    return output_file


@click.group()
@click.version_option(__version__, prog_name="VulnWeaver")
def main():
    """VulnWeaver (弱點編織者) - 專業弱點掃描報表整合與複掃比對引擎。"""
    pass


def load_report(file_path: Path):
    """解析單一掃描檔；格式不支援或內容不對時以 ClickException 回報。"""
    parser = get_parser_for_file(file_path)
    if not parser:
        raise click.ClickException(
            f"目前副檔名 {file_path.suffix} 尚不支援，請使用 .nessus、.xml (Nmap / ZAP / Burp) 或 .json (ZAP / VulnWeaver) 檔案。"
        )
    try:
        return parser.parse(file_path)
    except (ValueError, ET.ParseError) as exc:
        raise click.ClickException(f"掃描檔 {file_path.name} 解析失敗：{exc}") from exc


@main.command()
@click.argument("scan_files", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("-f", "--format", "output_format", type=click.Choice(["docx", "xlsx", "json"]), default="docx", help="輸出格式")
@click.option("-o", "--output", "output_file", type=click.Path(), default=None, help="輸出檔案路徑（預設 report.<格式>）")
@click.option("-l", "--lang", "language", type=click.Choice(["zh-TW", "en"]), default="zh-TW", help="報告語言")
@click.option("-n", "--scan-name", "scan_name", default=None, help="報告上的專案標的名稱；合併多檔時建議指定")
@report_meta_options
def parse(scan_files, output_format, output_file, language, scan_name, template_file,
          org, vendor, project_code, tester, reviewer, approver, extra_vars):
    """解析一或多份掃描檔 (Nessus / Nmap / OWASP ZAP / Burp Suite)，合併後生成標準報告。"""
    file_paths = [Path(f) for f in scan_files]
    output_file = resolve_output(output_file, output_format, "report")
    file_list = "\n".join(f"檔案: {p.name}" for p in file_paths)
    console.print(Panel.fit(f"[bold cyan]VulnWeaver 解析任務[/bold cyan]\n{file_list}\n輸出目標: {output_file} ({output_format.upper()})", border_style="cyan"))

    with console.status("[bold green]正在解析掃描檔並對齊繁體中文知識庫...[/bold green]"):
        reports = [load_report(p) for p in file_paths]
        try:
            report = merge_reports(reports, scan_name=scan_name)
        except ValueError as exc:
            raise click.ClickException(f"合併掃描結果失敗：{exc}") from exc

    if len(reports) > 1:
        console.print(f"[dim]已合併 {len(reports)} 份掃描結果（{report.scanner_label}）[/dim]")

    # Display summary
    stats = report.summary_stats
    table = Table(title=f"掃描概況: {report.scan_name}")
    table.add_column("受檢測主機數", justify="center", style="cyan")
    table.add_column("極高 (Critical)", justify="center", style="bold red")
    table.add_column("高 (High)", justify="center", style="red")
    table.add_column("中 (Medium)", justify="center", style="yellow")
    table.add_column("低 (Low)", justify="center", style="blue")
    table.add_column("資訊 (Info)", justify="center", style="dim")

    table.add_row(
        str(len(report.hosts)),
        str(stats["Critical"]),
        str(stats["High"]),
        str(stats["Medium"]),
        str(stats["Low"]),
        str(stats["Info"]),
    )
    console.print(table)

    if output_format in ("docx", "xlsx"):
        meta = build_meta(org, vendor, project_code, tester, reviewer, approver, extra_vars)
        reporter = pick_reporter(output_format, template_file)
        label = "Word 報告書" if output_format == "docx" else "Excel 弱點清冊"
        with console.status(f"[bold green]正在生成{label} ({output_file})...[/bold green]"):
            out_path = reporter.generate(report, output_file, meta=meta)
            console.print(f"[bold green][V] 成功產出{label}: {out_path.resolve()}[/bold green]")
    elif output_format == "json":
        out_path = Path(output_file)
        out_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"[bold green][V] 成功匯出 JSON 資料: {out_path.resolve()}[/bold green]")

    console.print(f"[green]✔ 作業完成！共彙整 {len(report.vulnerabilities)} 個獨立弱點項。[/green]")


@main.command()
@click.argument("baseline_file", type=click.Path(exists=True))
@click.argument("rescan_file", type=click.Path(exists=True))
@click.option("-f", "--format", "output_format", type=click.Choice(["docx", "xlsx"]), default="docx", help="輸出格式")
@click.option("-o", "--output", "output_file", type=click.Path(), default=None, help="輸出比對報告路徑（預設 diff_report.<格式>）")
@report_meta_options
def diff(baseline_file, rescan_file, output_format, output_file, template_file,
         org, vendor, project_code, tester, reviewer, approver, extra_vars):
    """比對初掃 (Baseline) 與複掃 (Rescan) 結果，自動計算修復狀態 (Fixed / Open / New)。"""
    base_path = Path(baseline_file)
    rescan_path = Path(rescan_file)
    output_file = resolve_output(output_file, output_format, "diff_report")

    console.print(Panel.fit(f"[bold cyan]VulnWeaver 複測比對任務[/bold cyan]\n初掃 (Baseline): {base_path.name}\n複掃 (Rescan): {rescan_path.name}\n輸出目標: {output_file}", border_style="cyan"))

    with console.status("[bold green]正在解析掃描檔案並進行差異比對...[/bold green]"):
        base_report = load_report(base_path)
        rescan_report = load_report(rescan_path)
        try:
            diff_report = VulnerabilityComparator.compare(base_report, rescan_report)
        except ValueError as exc:
            raise click.ClickException(f"複測比對失敗：{exc}") from exc

    diff_table = Table(title="複測比對成效統計")
    diff_table.add_column("項目", style="bold")
    diff_table.add_column("數量", justify="center")
    diff_table.add_column("狀態說明", style="dim")

    diff_table.add_row("[green]已修復 (Fixed)[/green]", str(diff_report.fixed_count), "初掃檢出，複測已成功排除")
    diff_table.add_row("[red]未修復 (Open)[/red]", str(diff_report.open_count), "初掃檢出，複測仍持續存在")
    diff_table.add_row("[yellow]新發現 (New)[/yellow]", str(diff_report.new_count), "初掃未檢出，複測新發現風險")

    console.print(diff_table)

    meta = build_meta(org, vendor, project_code, tester, reviewer, approver, extra_vars)
    reporter = pick_reporter(output_format, template_file)
    label = "複測對照報告書" if output_format == "docx" else "複測列管表 (Excel)"
    with console.status(f"[bold green]正在生成{label} ({output_file})...[/bold green]"):
        out_path = reporter.generate_diff(diff_report, output_file, meta=meta)
        console.print(f"[bold green][V] 成功產出{label}: {out_path.resolve()}[/bold green]")

    console.print(f"[green]✔ 比對完成！總比對項目: {len(diff_report.items)} 項。[/green]")


if __name__ == "__main__":
    main()
