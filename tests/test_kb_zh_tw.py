from vuln_weaver.knowledge.kb_zh_tw import enrich_vulnerability


def test_cve_is_localized_without_obsolete_mitigation():
    finding = enrich_vulnerability("CVE-2021-44228")
    assert "Log4j" in finding["title_zh"]
    assert "不要只靠" in finding["solution_zh"]


def test_description_word_does_not_match_des_cipher():
    finding = enrich_vulnerability("Generic Finding", "Potential deserialization issue")
    assert finding["title_zh"] is None


def test_unrelated_log4j_notice_is_not_log4shell():
    finding = enrich_vulnerability("Apache Log4j configuration notice")
    assert finding["title_zh"] is None
