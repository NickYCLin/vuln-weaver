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
from vuln_weaver.models import ReportMeta
from vuln_weaver.reporters.docx_reporter import DocxReporter
from vuln_weaver.reporters.template_reporter import TemplateReporter
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
        return ZapParser()
    if suffix == ".xml":
        # Nmap 與 ZAP 都輸出 .xml，依根節點分辨；根節點無法辨識時交給 Nmap 解析器回報錯誤
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


def pick_reporter(template_file):
    return TemplateReporter(template_path=template_file, diff_template_path=template_file) if template_file else DocxReporter()


@click.group()
@click.version_option(__version__, prog_name="VulnWeaver")
def main():
    """VulnWeaver (弱點編織者) - 專業弱點掃描報表整合與複掃比對引擎。"""
    pass


@main.command()
@click.argument("scan_file", type=click.Path(exists=True))
@click.option("-f", "--format", "output_format", type=click.Choice(["docx", "json"]), default="docx", help="輸出格式")
@click.option("-o", "--output", "output_file", type=click.Path(), default="report.docx", help="輸出檔案路徑")
@click.option("-l", "--lang", "language", type=click.Choice(["zh-TW", "en"]), default="zh-TW", help="報告語言")
@report_meta_options
def parse(scan_file, output_format, output_file, language, template_file,
          org, vendor, project_code, tester, reviewer, approver, extra_vars):
    """解析弱點掃描檔案 (Nessus / Nmap / OWASP ZAP) 並生成標準報告。"""
    file_path = Path(scan_file)
    console.print(Panel.fit(f"[bold cyan]VulnWeaver 解析任務[/bold cyan]\n檔案: {file_path.name}\n輸出目標: {output_file} ({output_format.upper()})", border_style="cyan"))

    parser = get_parser_for_file(file_path)
    if not parser:
        raise click.ClickException(f"目前副檔名 {file_path.suffix} 尚不支援，請使用 .nessus、.xml (Nmap / ZAP) 或 .json (ZAP) 檔案。")

    with console.status(f"[bold green]正在使用 {parser.scanner_name.upper()} 解析器處理並對齊繁體中文知識庫...[/bold green]"):
        try:
            report = parser.parse(file_path)
        except (ValueError, ET.ParseError) as exc:
            raise click.ClickException(f"掃描檔解析失敗：{exc}") from exc

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

    # Generate document if docx format requested
    if output_format == "docx":
        meta = build_meta(org, vendor, project_code, tester, reviewer, approver, extra_vars)
        with console.status(f"[bold green]正在生成 Word 報告文件 ({output_file})...[/bold green]"):
            reporter = pick_reporter(template_file)
            out_path = reporter.generate(report, output_file, meta=meta)
            console.print(f"[bold green][V] 成功產出專業 Word 報告書: {out_path.resolve()}[/bold green]")
    elif output_format == "json":
        out_path = Path(output_file)
        out_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"[bold green][V] 成功匯出 JSON 資料: {out_path.resolve()}[/bold green]")

    console.print(f"[green]✔ 作業完成！共彙整 {len(report.vulnerabilities)} 個獨立弱點項。[/green]")


@main.command()
@click.argument("baseline_file", type=click.Path(exists=True))
@click.argument("rescan_file", type=click.Path(exists=True))
@click.option("-o", "--output", "output_file", type=click.Path(), default="diff_report.docx", help="輸出比對報告路徑")
@report_meta_options
def diff(baseline_file, rescan_file, output_file, template_file,
         org, vendor, project_code, tester, reviewer, approver, extra_vars):
    """比對初掃 (Baseline) 與複掃 (Rescan) 結果，自動計算修復狀態 (Fixed / Open / New)。"""
    base_path = Path(baseline_file)
    rescan_path = Path(rescan_file)

    console.print(Panel.fit(f"[bold cyan]VulnWeaver 複測比對任務[/bold cyan]\n初掃 (Baseline): {base_path.name}\n複掃 (Rescan): {rescan_path.name}\n輸出目標: {output_file}", border_style="cyan"))

    base_parser = get_parser_for_file(base_path)
    rescan_parser = get_parser_for_file(rescan_path)

    if not base_parser or not rescan_parser:
        raise click.ClickException("比對檔案格式不支援，請使用 .nessus、.xml 或 .json 檔案。")

    with console.status("[bold green]正在解析掃描檔案並進行差異比對...[/bold green]"):
        try:
            base_report = base_parser.parse(base_path)
            rescan_report = rescan_parser.parse(rescan_path)
            diff_report = VulnerabilityComparator.compare(base_report, rescan_report)
        except (ValueError, ET.ParseError) as exc:
            raise click.ClickException(f"掃描檔解析或比對失敗：{exc}") from exc

    diff_table = Table(title="複測比對成效統計")
    diff_table.add_column("項目", style="bold")
    diff_table.add_column("數量", justify="center")
    diff_table.add_column("狀態說明", style="dim")

    diff_table.add_row("[green]已修復 (Fixed)[/green]", str(diff_report.fixed_count), "初掃檢出，複測已成功排除")
    diff_table.add_row("[red]未修復 (Open)[/red]", str(diff_report.open_count), "初掃檢出，複測仍持續存在")
    diff_table.add_row("[yellow]新發現 (New)[/yellow]", str(diff_report.new_count), "初掃未檢出，複測新發現風險")

    console.print(diff_table)

    # Generate diff Word document
    meta = build_meta(org, vendor, project_code, tester, reviewer, approver, extra_vars)
    with console.status(f"[bold green]正在生成複測對照 Word 文件 ({output_file})...[/bold green]"):
        reporter = pick_reporter(template_file)
        out_path = reporter.generate_diff(diff_report, output_file, meta=meta)
        console.print(f"[bold green][V] 成功產出複測對照報告書: {out_path.resolve()}[/bold green]")

    console.print(f"[green]✔ 比對完成！總比對項目: {len(diff_report.items)} 項。[/green]")


if __name__ == "__main__":
    main()
