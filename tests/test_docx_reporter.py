import docx
from pathlib import Path
from vuln_weaver.parsers.nessus import NessusParser
from vuln_weaver.reporters.docx_reporter import DocxReporter
from vuln_weaver.comparator.diff import VulnerabilityComparator

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample.nessus"


def test_docx_report_generation(tmp_path):
    parser = NessusParser()
    report = parser.parse(FIXTURE_PATH)

    output_doc = tmp_path / "test_audit_report.docx"
    reporter = DocxReporter()
    result_path = reporter.generate(report, output_doc)

    assert result_path.exists()
    assert result_path.stat().st_size > 5000  # Has content + embedded chart image

    # Verify document structure by re-opening with python-docx
    doc = docx.Document(str(result_path))
    assert len(doc.tables) >= 3  # Metadata, Risk summary, Host inventory, Findings tables
    assert any("資訊系統弱點掃描與安全健診報告書" in p.text for p in doc.paragraphs)


def test_docx_diff_generation(tmp_path):
    parser = NessusParser()
    report1 = parser.parse(FIXTURE_PATH)
    report2 = parser.parse(FIXTURE_PATH)

    diff_report = VulnerabilityComparator.compare(report1, report2)
    output_diff = tmp_path / "test_diff_report.docx"

    reporter = DocxReporter()
    result_path = reporter.generate_diff(diff_report, output_diff)

    assert result_path.exists()
    assert result_path.stat().st_size > 2000

    doc = docx.Document(str(result_path))
    assert any("弱點改善複測比對與成效驗證報告" in p.text for p in doc.paragraphs)
