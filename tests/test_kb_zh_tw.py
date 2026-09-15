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


def test_zap_alert_names_are_localized():
    csp = enrich_vulnerability("Content Security Policy (CSP) Header Not Set")
    assert "Content-Security-Policy" in csp["title_zh"]

    server = enrich_vulnerability('Server Leaks Version Information via "Server" HTTP Response Header Field')
    assert "版本資訊" in server["title_zh"]

    samesite = enrich_vulnerability(
        "Cookie without SameSite Attribute",
        "The SameSite attribute is an effective counter measure to cross-site request forgery.",
    )
    assert samesite["title_zh"] == "Cookie 未設定 SameSite 屬性"

    csrf = enrich_vulnerability("Absence of Anti-CSRF Tokens")
    assert "CSRF" in csrf["title_zh"]


def test_xss_mention_in_csp_description_does_not_override_csp():
    finding = enrich_vulnerability(
        "Content Security Policy (CSP) Header Not Set",
        "helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS)",
    )
    assert "Content-Security-Policy" in finding["title_zh"]
