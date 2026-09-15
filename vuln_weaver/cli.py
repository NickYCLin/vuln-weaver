import click
from rich.console import Console
from rich.table import Table
from vuln_weaver import __version__

console = Console()


@click.group()
@click.version_option(__version__, prog_name="VulnWeaver")
def main():
    """🕸️ VulnWeaver (弱點編織者) - 專業弱點掃描報表整合與複掃比對引擎。"""
    pass


@main.command()
@click.argument("scan_file", type=click.Path(exists=True))
@click.option("-f", "--format", "output_format", type=click.Choice(["docx", "json", "html"]), default="docx", help="輸出格式")
@click.option("-o", "--output", "output_file", type=click.Path(), default="report.docx", help="輸出檔案路徑")
@click.option("-l", "--lang", "language", type=click.Choice(["zh-TW", "en"]), default="zh-TW", help="報告語言")
def parse(scan_file, output_format, output_file, language):
    """解析弱點掃描檔案並生成標準報告。"""
    console.print(f"[bold cyan]🔍 正在解析掃描檔案:[/bold cyan] {scan_file}")
    console.print(f"[bold green]📄 輸出格式:[/bold green] {output_format} -> {output_file} ({language})")
    # TODO: Connect to parser and reporter implementation
    console.print("[yellow]⚠️ 解析器模組建置中，即將支援完整 Nessus / Nmap 解析。[/yellow]")


@main.command()
@click.argument("baseline_file", type=click.Path(exists=True))
@click.argument("rescan_file", type=click.Path(exists=True))
@click.option("-o", "--output", "output_file", type=click.Path(), default="diff_report.docx", help="輸出比對報告路徑")
def diff(baseline_file, rescan_file, output_file):
    """比對初掃 (Baseline) 與複掃 (Rescan) 結果，自動計算修復狀態 (Fixed / Open / New)。"""
    console.print(f"[bold cyan]📊 基準掃描 (初掃):[/bold cyan] {baseline_file}")
    console.print(f"[bold cyan]🔄 複掃檔案 (複測):[/bold cyan] {rescan_file}")
    console.print(f"[bold green]📄 比對報告輸出至:[/bold green] {output_file}")
    # TODO: Connect to comparator implementation
    console.print("[yellow]⚠️ 比對引擎建置中。[/yellow]")


if __name__ == "__main__":
    main()
