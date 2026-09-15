"""
台灣資安健診常見弱點與修復指引繁體中文知識庫 (TW InfoSec Knowledge Base)
提供常見弱點標題、風險描述與符合公部門/標案驗收標準的繁體中文修補建議。
"""

import re
from typing import Dict, Optional

# 核心字典：依關鍵字正則或特徵匹配
TW_VULN_KB = [
    # --- SSL / TLS 通訊加密 ---
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
        "pattern": r"Sweet32|Birthday attacks on 64-bit block ciphers|\b(?:3DES|DES)\b",
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
        "pattern": r"Self-Signed Certificate|Untrusted Root|Certificate Expired",
        "title_zh": "SSL/TLS 憑證使用自簽憑證、過期或未獲信任之發證單位",
        "description_zh": "服務使用自簽憑證（Self-Signed）或過期憑證，瀏覽器與客戶端將出現安全告警，使用者易養成忽略警告之不良習慣，亦無法有效防範中間人攻擊。",
        "solution_zh": "向具公信力之合格憑證授權單位（CA）申請正式 SSL/TLS 憑證（或透過 Let's Encrypt 免費申請），並定期排程檢查憑證效期。",
    },

    # --- HTTP 安全標頭與 Web 基礎防禦 ---
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
        "pattern": r"Content-Security-Policy|CSP Header Missing",
        "title_zh": "缺少 Content-Security-Policy (CSP) 內容安全政策標頭",
        "description_zh": "網站未配置 CSP 標頭以限制資源（腳本、圖片、樣式）加載來源，當系統存在 XSS 漏洞時，攻擊者將輕易載入惡意外部腳本竊取憑證。",
        "solution_zh": "規劃並佈署 Content-Security-Policy 回應標頭，限制 script-src、object-src 等資源載入來源為合法白名單。",
    },
    {
        "pattern": r"Web Server Information Disclosure|Server Header|Apache Version",
        "title_zh": "網頁伺服器回應標頭洩漏詳細版本資訊",
        "description_zh": "HTTP 回應標頭中之 Server 或 X-Powered-By 洩漏了詳細的軟體與版本資訊（如 Apache/2.4.41、PHP/7.4.3），有助於攻擊者鎖定已知 CVE 漏洞發動精準攻擊。",
        "solution_zh": "修改伺服器設定隱藏或自訂版本資訊。Nginx 請設定 server_tokens off; Apache 請設定 ServerTokens Prod 及 ServerSignature Off。",
    },
    {
        "pattern": r"Directory Browsing|Directory Indexing|Index of /",
        "title_zh": "網頁目錄瀏覽功能未停用 (Directory Listing Enabled)",
        "description_zh": "當目錄下缺乏預設索引檔案（如 index.html）時，伺服器自動列出目錄檔案清單，攻擊者可藉此探索未授權檔案、備份檔或原始程式碼。",
        "solution_zh": "關閉 Web 伺服器之目錄索引功能。Apache 請移除 Indexes 選項 (Options -Indexes)；Nginx 請確保 autoindex off。",
    },

    # --- 遠端服務與通訊協定安全 ---
    {
        "pattern": r"SSH Weak MAC Algorithms|SSH Weak KEX|SSH Insecure",
        "title_zh": "SSH 服務支援不安全的金鑰交換或 MAC 雜湊演算法",
        "description_zh": "SSH 伺服器啟用了已被標註為弱安全等級之金鑰交換演算法（如 diffie-hellman-group1-sha1）或 MAC 演算法（如 MD5、96 位元 HMAC），可能面臨被被動側錄與破解風險。",
        "solution_zh": "編輯 /etc/ssh/sshd_config，在 KexAlgorithms 與 MACs 中移除 SHA1、MD5 等舊版演算法，僅保留 curve25519-sha256 與 hmac-sha2-512 等強健演算法。",
    },
    {
        "pattern": r"Telnet Server Detection|Telnet Service|telnet",
        "title_zh": "系統啟用明文傳輸之 Telnet 遠端管理服務",
        "description_zh": "偵測到目標主機開啟 Telnet (Port 23) 服務。Telnet 通訊過程完全以明文傳輸，管理者帳號與密碼極易遭受網路監聽側錄截獲。",
        "solution_zh": "立即停用並關閉 Telnet 服務，全數改以安全加密之 SSH (Secure Shell) 通訊協定進行遠端伺服器管理。",
    },
    {
        "pattern": r"Anonymous FTP|FTP Insecure|Cleartext FTP",
        "title_zh": "FTP 服務允許匿名登入或以明文傳輸資料",
        "description_zh": "FTP 服務允許 anonymous 匿名存取，或傳輸憑證過程未予加密，可能造成資料非預期外洩或遭到未授權篡改。",
        "solution_zh": "關閉 FTP 伺服器之匿名登入權限，並強制改用 FTPS (FTP over TLS) 或 SFTP (SSH File Transfer Protocol) 確保通道加密。",
    },
    {
        "pattern": r"SMB Signing|SMBv1|Server Message Block",
        "title_zh": "SMB 服務未強制簽章或啟用過期之 SMBv1 協定",
        "description_zh": "目標 Windows 主機啟用過期之 SMBv1 通訊協定（易遭 WannaCry、EternalBlue 攻擊），或 SMB 未要求強制封包簽章（Signing），可能導致中間人轉發攻擊。",
        "solution_zh": "透過本機群組原則或 PowerShell 徹底停用 SMBv1 (Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol)，並啟用 SMB 封包簽章政策。",
    },
    {
        "pattern": r"SNMP Default Public|SNMP Community Name|public community",
        "title_zh": "SNMP 服務使用預設社群字串 (Default Public Community)",
        "description_zh": "SNMP 網路管理協定使用預設字串（如 public 或 private），外部攻擊者可讀取網路設備組態、路由表、甚至發送變更指令奪取設備控制權。",
        "solution_zh": "修改或移除預設的 public/private 社群名稱，改用複雜自訂字串，或全面升級至支援認證與加密的 SNMPv3 協定。",
    },

    # --- 重大與高風險 CVE 漏洞 ---
    {
        "pattern": r"Log4Shell|CVE-2021-44228",
        "title_zh": "Apache Log4j 遠端程式碼執行重大漏洞 (Log4Shell)",
        "description_zh": "目標系統使用存在嚴重安全缺陷之 Apache Log4j 2.x 元件，攻擊者可構造 JNDI 注入請求遠端執行任意惡意程式碼，取得伺服器控制權。",
        "solution_zh": "確認受影響元件與 Java 版本，升級 Apache Log4j 至官方仍維護且已修補的版本；無法立即升級時，依 Apache 官方公告採取對應版本的暫時緩解措施，不要只靠設定 formatMsgNoLookups。",
    },
    {
        "pattern": r"Spring4Shell|CVE-2022-22965",
        "title_zh": "Spring Framework 遠端程式碼執行漏洞 (Spring4Shell)",
        "description_zh": "Spring Framework 在特定組態（Java 9+、WAR 打包於 Tomcat）下存在 DataBinder 變數覆寫弱點，攻擊者可上傳惡意 JSP WebShell 癱瘓主機。",
        "solution_zh": "升級 Spring Framework 至 5.3.18 / 5.2.20 以上安全版本，並檢視相關 Web 應用相依性。",
    },
    {
        "pattern": r"BlueKeep|CVE-2019-0708",
        "title_zh": "微軟遠端桌面 RDP 預先驗證遠端程式碼執行漏洞 (BlueKeep)",
        "description_zh": "遠端桌面服務 (RDP) 存在可引發記憶體破壞之重大弱點，攻擊者無需任何帳號密碼即可透過網路發送特製封包取得 SYSTEM 權限。",
        "solution_zh": "立即安裝微軟官方發布之安全性更新修補程式 (KB4499175 / KB4499160 等)，並啟用網路層級驗證 (NLA)。",
    },
    {
        "pattern": r"PrintNightmare|CVE-2021-34527",
        "title_zh": "Windows 列印多工緩衝處理器遠端程式碼執行漏洞 (PrintNightmare)",
        "description_zh": "Windows Print Spooler 服務未能妥善限制驅動程式安裝權限，攻擊者可藉此在網域內提升為 Domain Admin 最高管理權限。",
        "solution_zh": "套用微軟 Print Spooler 安全性修正更新，並於非必要擔任列印伺服器的主機上透過服務管理員停用 Spooler 服務。",
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

    # 若無精確匹配，回傳 None 讓呼叫端 fallback
    return {
        "title_zh": None,
        "description_zh": None,
        "solution_zh": None,
    }
