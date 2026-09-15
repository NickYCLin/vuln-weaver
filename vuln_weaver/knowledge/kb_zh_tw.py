"""
台灣資安健診常見弱點與修復指引繁體中文知識庫 (TW InfoSec Knowledge Base)
提供常見弱點標題、風險描述與符合公部門/標案驗收標準的繁體中文修補建議。
"""

import re
from typing import Dict, Any, Optional

# 核心字典：依關鍵字正則或特徵匹配
TW_VULN_KB = [
    {
        "pattern": r"SSL Version 2 and 3 Protocol Detection|SSLv2|SSLv3",
        "title_zh": "伺服器支援不安全的 SSLv2 / SSLv3 通訊協定",
        "description_zh": "目標伺服器仍啟用已被證實存在嚴重密碼學缺陷之 SSLv2 或 SSLv3 通訊協定，攻擊者可透過 POODLE 等攻擊手法解密傳輸流量，竊取機敏資訊。",
        "solution_zh": "停用所有 SSLv2 及 SSLv3 通訊協定，伺服器僅保留 TLS 1.2 及 TLS 1.3 協定支援，並重啟相關網頁與傳輸服務。",
    },
    {
        "pattern": r"TLS Version 1\.0 Protocol Detection|TLSv1\.0",
        "title_zh": "伺服器支援過期之 TLS 1.0 通訊協定",
        "description_zh": "目標主機啟用已過期之 TLS 1.0 通訊協定，該協定不支援現代加密套件，且易受 BEAST、POODLE 等已知弱點影響，不符合行政院資安規範要求。",
        "solution_zh": "於 Web 伺服器或負載平衡器設定檔中停用 TLS 1.0，建議僅啟用 TLS 1.2 及 TLS 1.3，並確認舊版客戶端已升級相容版本。",
    },
    {
        "pattern": r"TLS Version 1\.1 Protocol Detection|TLSv1\.1",
        "title_zh": "伺服器支援過期之 TLS 1.1 通訊協定",
        "description_zh": "目標主機啟用已被各大主流瀏覽器及國際標準（RFC 8996）廢棄之 TLS 1.1 協定，存在降級攻擊風險。",
        "solution_zh": "於伺服器組態中禁用 TLS 1.1，將傳輸加密門檻提升至 TLS 1.2 及 TLS 1.3 以上。",
    },
    {
        "pattern": r"Sweet32|Birthday attacks on 64-bit block ciphers|DES|3DES",
        "title_zh": "SSL/TLS 支援 64 位元區塊加密演算法 (Sweet32 弱點)",
        "description_zh": "目標伺服器支援使用 64 位元區塊加密演算法（如 3DES、DES），攻擊者透過碰撞攻擊（Sweet32）可在捕獲大量加密流量後解密敏感 Session Cookie。",
        "solution_zh": "移除伺服器加密套件設定中之 3DES/DES 演算法，改用 128 位元或 256 位元 AES-GCM 或 ChaCha20-Poly1305 加密套件。",
    },
    {
        "pattern": r"RC4",
        "title_zh": "SSL/TLS 支援已被破解之 RC4 串流加密演算法",
        "description_zh": "目標服務仍支援 RC4 加密演算法，RC4 存在已知的統計學偏差弱點，攻擊者可在合理時間內破解密文內容。",
        "solution_zh": "自 Web / Mail 伺服器之 SSL/TLS 密碼組中徹底移除所有包含 RC4 的加密演算法。",
    },
    {
        "pattern": r"HTTP Strict Transport Security|HSTS",
        "title_zh": "未啟用 HTTP 嚴格傳輸安全標頭 (Missing HSTS Header)",
        "description_zh": "網頁伺服器未於 HTTP 回應標頭中加入 Strict-Transport-Security，導致使用者可能透過不安全之 HTTP 連線存取網站，面臨中間人降級劫持風險。",
        "solution_zh": "於 Web 伺服器設定加入回應標頭：Strict-Transport-Security: max-age=31536000; includeSubDomains; preload，強制客戶端僅透過 HTTPS 存取。",
    },
    {
        "pattern": r"X-Content-Type-Options|MIME-sniffing",
        "title_zh": "缺少 X-Content-Type-Options 安全標頭",
        "description_zh": "伺服器未設定 X-Content-Type-Options: nosniff 標頭，瀏覽器可能會嘗試對檔案進行 MIME-sniffing 解析，提高遭受跨站腳本攻擊 (XSS) 風險。",
        "solution_zh": "於 Web 伺服器（Nginx、Apache、IIS）全域設定中增加 HTTP 標頭：X-Content-Type-Options: nosniff。",
    },
    {
        "pattern": r"X-Frame-Options|Clickjacking",
        "title_zh": "缺少 X-Frame-Options 安全標頭 (點擊劫持風險)",
        "description_zh": "網站未透過 X-Frame-Options 限制頁面被嵌入 iframe，攻擊者可透過假網頁將該網站嵌入為透明框架，誘騙使用者點擊，造成點擊劫持 (Clickjacking)。",
        "solution_zh": "於 HTTP 回應標頭設定 X-Frame-Options: SAMEORIGIN 或 DENY，或透過 Content-Security-Policy (CSP) frame-ancestors 限制授權嵌入之網域。",
    },
    {
        "pattern": r"Web Server Information Disclosure|Server Header|Apache Version",
        "title_zh": "網頁伺服器回應標頭洩漏詳細版本資訊",
        "description_zh": "HTTP 回應標頭中之 Server 或 X-Powered-By 洩漏了詳細的軟體與版本資訊（如 Apache/2.4.41、PHP/7.4.3），有助於攻擊者鎖定已知 CVE 漏洞發動精準攻擊。",
        "solution_zh": "修改伺服器設定隱藏或自訂版本資訊。Nginx 請設定 server_tokens off; Apache 請設定 ServerTokens Prod 及 ServerSignature Off。",
    },
    {
        "pattern": r"SSH Weak MAC Algorithms|SSH Weak KEX|SSH Insecure",
        "title_zh": "SSH 服務支援不安全的金鑰交換或 MAC 雜湊演算法",
        "description_zh": "SSH 伺服器啟用了已被標註為弱安全等級之金鑰交換演算法（如 diffie-hellman-group1-sha1）或 MAC 演算法（如 MD5、96 位元 HMAC），可能面臨被被動側錄與破解風險。",
        "solution_zh": "編輯 /etc/ssh/sshd_config，在 KexAlgorithms 與 MACs 中移除 SHA1、MD5 等舊版演算法，僅保留 curve25519-sha256 與 hmac-sha2-512 等強健演算法。",
    },
    {
        "pattern": r"Self-Signed Certificate|Untrusted Root",
        "title_zh": "SSL/TLS 憑證使用自簽憑證或未獲信任之發證單位",
        "description_zh": "服務使用自簽憑證（Self-Signed）或過期憑證，瀏覽器與客戶端將出現安全告警，使用者易養成忽略警告之不良習慣，亦無法有效防範中間人攻擊。",
        "solution_zh": "向具公信力之合格憑證授權單位（CA）申請正式 SSL/TLS 憑證（或透過 Let's Encrypt 免費申請），並定期排程檢查憑證效期。",
    },
    {
        "pattern": r"SMB Signing|SMBv1|Server Message Block",
        "title_zh": "SMB 服務未強制簽章或啟用 SMBv1 協定",
        "description_zh": "目標 Windows 主機啟用過期之 SMBv1 通訊協定（易遭 WannaCry、EternalBlue 攻擊），或 SMB 未要求強制封包簽章（Signing），可能導致中間人轉發攻擊。",
        "solution_zh": "透過本機群組原則或 PowerShell 徹底停用 SMBv1 (Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol)，並啟用 SMB 封包簽章政策。",
    },
    {
        "pattern": r"Default Credentials|Default Password|admin/admin",
        "title_zh": "設備或應用系統使用預設管理者帳號密碼",
        "description_zh": "偵測到管理後台、網路設備或資料庫仍保留出廠預設帳號與密碼（如 admin/admin、root/root），攻擊者可不經身分認證直接取得最高控制權。",
        "solution_zh": "立即變更預設管理者帳密，採用具足夠複雜度（12碼以上並包含大小寫英文、數字、特殊符號）之強密碼，並建議啟用多因子身分驗證 (MFA)。",
    },
]


def enrich_vulnerability(vuln_title: str, description: str = "", solution: str = "") -> Dict[str, Optional[str]]:
    """
    根據漏洞英文名稱及內容，比對繁體中文知識庫，回傳在地的繁中標題、說明與修復指引。
    """
    search_text = f"{vuln_title} {description}"
    
    for item in TW_VULN_KB:
        if re.search(item["pattern"], search_text, re.IGNORECASE):
            return {
                "title_zh": item["title_zh"],
                "description_zh": item["description_zh"],
                "solution_zh": item["solution_zh"],
            }

    # 若無精確匹配，提供格式化繁中佔位
    return {
        "title_zh": None,
        "description_zh": None,
        "solution_zh": None,
    }
