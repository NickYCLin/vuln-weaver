import sys
from pathlib import Path
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from vuln_weaver import __version__
from vuln_weaver.parsers.nessus import NessusParser
from vuln_weaver.reporters.docx_reporter import DocxReporter
from vuln_weaver.comparator.diff import VulnerabilityComparator

# Ensure console supports UTF-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

console = Console()


@click.group()
@click.version_option(__version__, prog_name="VulnWeaver")
def main():
    """VulnWeaver (弱點編織者) - 專業弱點掃描報表整合與複掃比對引擎。"""
    pass


@main.command()
@click.argument("scan_file", type=click.Path(exists=True))
@click.option("-f", "--format", "output_format", type=click.Choice(["docx", "json", "html"]), default="docx", help="輸出格式")
@click.option("-o", "--output", "output_file", type=click.Path(), default="report.docx", help="輸出檔案路徑")
@click.option("-l", "--lang", "language", type=click.Choice(["zh-TW", "en"]), default="zh-TW", help="報告語言")
def parse(scan_file, output_format, output_file, language):
    """解析弱點掃描檔案並生成標準報告。"""
    file_path = Path(scan_file)
    console.print(Panel.fit(f"[bold cyan]VulnWeaver 解析任務[/bold cyan]\n檔案: {file_path.name}\n輸出目標: {output_file} ({output_format.upper()})", border_style="cyan"))

    # Determine parser
    if file_path.suffix.lower() == ".nessus":
        parser = NessusParser()
    else:
        console.print(f"[bold red][X] 目前副檔名 {file_path.suffix} 尚不支援，請使用 .nessus 檔案。[/bold red]")
        return

    with console.status("[bold green]正在解析掃描檔案並對齊繁體中文知識庫...[/bold green]"):
        report = parser.parse(file_path)

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
        with console.status(f"[bold green]正在生成 Word 報告文件 ({output_file})...[/bold green]"):
            reporter = DocxReporter()
            out_path = reporter.generate(report, output_file)
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
def diff(baseline_file, rescan_file, output_file):
    """比對初掃 (Baseline) 與複掃 (Rescan) 結果，自動計算修復狀態 (Fixed / Open / New)。"""
    console.print(Panel.fit(f"[bold cyan]VulnWeaver 複測比對任務[/bold cyan]\n初掃 (Baseline): {baseline_file}\n複掃 (Rescan): {rescan_file}\n輸出目標: {output_file}", border_style="cyan"))

    parser = NessusParser()
    with console.status("[bold green]正在解析掃描檔案並進行差異比對...[/bold green]"):
        base_report = parser.parse(baseline_file)
        rescan_report = parser.parse(rescan_file)
        diff_report = VulnerabilityComparator.compare(base_report, rescan_report)

    diff_table = Table(title="複測比對成效統計")
    diff_table.add_column("項目", style="bold")
    diff_table.add_column("數量", justify="center")
    diff_table.add_column("狀態說明", style="dim")

    diff_table.add_row("[green]已修復 (Fixed)[/green]", str(diff_report.fixed_count), "初掃檢出，複測已成功排除")
    diff_table.add_row("[red]未修復 (Open)[/red]", str(diff_report.open_count), "初掃檢出，複測仍持續存在")
    diff_table.add_row("[yellow]新發現 (New)[/yellow]", str(diff_report.new_count), "初掃未檢出，複測新發現風險")

    console.print(diff_table)

    # Generate diff Word document
    with console.status(f"[bold green]正在生成複測對照 Word 文件 ({output_file})...[/bold green]"):
        reporter = DocxReporter()
        out_path = reporter.generate_diff(diff_report, output_file)
        console.print(f"[bold green][V] 成功產出複測對照報告書: {out_path.resolve()}[/bold green]")

    console.print(f"[green]✔ 比對完成！總比對項目: {len(diff_report.items)} 項。[/green]")


if __name__ == "__main__":
    main()
