/*
 * VulnWeaver Web Lite 解析與比對核心。
 * 純函式、不碰 DOM 元素（只用 DOMParser），方便在 headless 瀏覽器中驗證。
 * 行為刻意對齊 vuln_weaver/parsers 與 vuln_weaver/comparator/diff.py。
 */
(function (global) {
  'use strict';

  // ---------------------------------------------------------------------------
  // 繁體中文知識庫（vuln_weaver/knowledge/kb_zh_tw.py 的精簡版：標題 + 修補建議）
  // 依序比對，先符合者優先，所以較特定的樣式要放前面。
  // ---------------------------------------------------------------------------
  const TW_KB = [
    { pattern: /SSL Version 2 and 3 Protocol Detection|SSLv2|SSLv3/i, titleZh: '伺服器支援不安全的 SSLv2 / SSLv3 通訊協定', solutionZh: '停用所有 SSLv2 及 SSLv3 通訊協定，伺服器僅保留 TLS 1.2 及 TLS 1.3 協定支援。' },
    { pattern: /TLS Version 1\.0 Protocol Detection|TLSv1\.0/i, titleZh: '伺服器支援過期之 TLS 1.0 通訊協定', solutionZh: '於伺服器或負載平衡器停用 TLS 1.0，建議僅啟用 TLS 1.2 及 TLS 1.3。' },
    { pattern: /TLS Version 1\.1 Protocol Detection|TLSv1\.1/i, titleZh: '伺服器支援過期之 TLS 1.1 通訊協定', solutionZh: '於伺服器組態中禁用 TLS 1.1，將傳輸加密門檻提升至 TLS 1.2/1.3。' },
    { pattern: /Sweet32|Birthday attacks on 64-bit block ciphers|\b(?:3DES|DES)\b/i, titleZh: 'SSL/TLS 支援 64 位元區塊加密演算法 (Sweet32 弱點)', solutionZh: '移除 3DES/DES 加密套件，改用 AES-GCM 或 ChaCha20-Poly1305。' },
    { pattern: /RC4/i, titleZh: 'SSL/TLS 支援已被破解之 RC4 串流加密演算法', solutionZh: '徹底自密碼組設定中移除所有包含 RC4 的加密演算法。' },
    { pattern: /Self-Signed Certificate|Untrusted Root|Certificate Expired/i, titleZh: 'SSL/TLS 憑證使用自簽憑證或未獲信任之發證單位', solutionZh: '向合格之憑證機構 (CA) 申請正式數位憑證並定期排程巡檢效期。' },
    { pattern: /Strict[- ]Transport[- ]Security|HSTS/i, titleZh: '未啟用 HTTP 嚴格傳輸安全標頭 (Missing HSTS Header)', solutionZh: '增加回應標頭：Strict-Transport-Security: max-age=31536000; includeSubDomains。' },
    { pattern: /X-Content-Type-Options|MIME-sniffing/i, titleZh: '缺少 X-Content-Type-Options 安全標頭', solutionZh: '增加全域 HTTP 標頭：X-Content-Type-Options: nosniff。' },
    { pattern: /X-Frame-Options|Clickjacking/i, titleZh: '缺少 X-Frame-Options 安全標頭 (點擊劫持風險)', solutionZh: '設定 HTTP 回應標頭 X-Frame-Options: SAMEORIGIN 或 DENY。' },
    { pattern: /Content[- ]Security[- ]Policy|CSP Header (?:Missing|Not Set)/i, titleZh: '缺少 Content-Security-Policy (CSP) 內容安全政策標頭', solutionZh: '規劃並佈署 Content-Security-Policy 回應標頭，限制 script-src、object-src 等資源載入來源為合法白名單。' },
    { pattern: /Web Server Information Disclosure|Server Header|Apache Version|Server Leaks (?:Version )?Information|X-Powered-By/i, titleZh: '網頁伺服器回應標頭洩漏詳細版本資訊', solutionZh: '設定 server_tokens off (Nginx) 或 ServerTokens Prod (Apache) 隱藏版本資訊。' },
    { pattern: /Directory Browsing|Directory Indexing|Index of \//i, titleZh: '網站目錄允許瀏覽 (Directory Listing)', solutionZh: '關閉 Web 伺服器的目錄瀏覽功能（Apache: Options -Indexes；Nginx: autoindex off）。' },
    { pattern: /SSH Weak MAC Algorithms|SSH Weak KEX|SSH Insecure/i, titleZh: 'SSH 服務支援不安全的金鑰交換或 MAC 雜湊演算法', solutionZh: '編輯 sshd_config 移除 SHA1、MD5 等舊版演算法，保留強健密碼學演算法。' },
    { pattern: /Telnet Server Detection|Telnet Service|telnet/i, titleZh: '主機開啟明文傳輸之 Telnet 服務', solutionZh: '立即停用並關閉 Telnet 服務，全數改以安全加密之 SSH 通訊協定進行伺服器管理。' },
    { pattern: /Anonymous FTP|FTP Insecure|Cleartext FTP/i, titleZh: 'FTP 服務允許匿名登入或以明文傳輸資料', solutionZh: '關閉 FTP 匿名登入，並強制改用 FTPS 或 SFTP 確保通道加密。' },
    { pattern: /SMB Signing|SMBv1|Server Message Block/i, titleZh: 'SMB 服務未強制簽章或啟用過期之 SMBv1 協定', solutionZh: '停用 SMBv1 並啟用 SMB 封包簽章政策。' },
    { pattern: /SNMP Default Public|SNMP Community Name|public community/i, titleZh: 'SNMP 服務使用預設社群字串 (Default Public Community)', solutionZh: '修改或移除預設的 public/private 社群名稱，或升級至 SNMPv3。' },
    // --- Web 應用程式弱點（OWASP ZAP 常見告警） ---
    { pattern: /\bSQL Injection\b|\bSQLi\b/i, titleZh: '網站存在 SQL 資料隱碼攻擊 (SQL Injection) 弱點', solutionZh: '所有資料庫存取一律改用參數化查詢或 ORM，禁止字串拼接，並對輸入做白名單驗證。' },
    { pattern: /Cross[- ]Site Scripting|\bXSS\b/i, titleZh: '網站存在跨站腳本攻擊 (Cross-Site Scripting, XSS) 弱點', solutionZh: '依輸出位置對所有動態內容做對應的輸出編碼，搭配輸入驗證與 Content-Security-Policy 標頭。' },
    { pattern: /Path Traversal|Directory Traversal/i, titleZh: '網站存在路徑遍歷 (Path Traversal) 弱點', solutionZh: '不要以使用者輸入直接組成檔案路徑，改用索引或白名單對應實際檔案。' },
    { pattern: /Command Injection/i, titleZh: '網站存在作業系統命令注入 (OS Command Injection) 弱點', solutionZh: '避免以 shell 執行外部指令；若無法避免，改用不經 shell 的 API 並嚴格驗證輸入。' },
    { pattern: /Cookie (?:Without|No) Secure Flag|Cookie Without Secure/i, titleZh: 'Cookie 未設定 Secure 旗標', solutionZh: '對所有 Cookie（特別是 Session Cookie）加上 Secure 屬性，並將網站全面導向 HTTPS。' },
    { pattern: /Cookie (?:No|Without) HttpOnly/i, titleZh: 'Cookie 未設定 HttpOnly 旗標', solutionZh: '對 Session 等不需由前端腳本存取的 Cookie 加上 HttpOnly 屬性。' },
    { pattern: /Cookie (?:without|No) SameSite/i, titleZh: 'Cookie 未設定 SameSite 屬性', solutionZh: '對所有 Cookie 設定 SameSite=Lax 或 Strict；需跨站使用的才設為 None 並同時加上 Secure。' },
    { pattern: /Anti-CSRF Tokens|Cross[- ]Site Request Forgery|\bCSRF\b/i, titleZh: '表單缺少防跨站請求偽造 (CSRF) 權杖', solutionZh: '為所有會變更狀態的表單與 API 加入不可預測的 CSRF Token 並於伺服器端驗證。' },
    { pattern: /Cleartext submission of password|Password submitted (?:over|using) (?:cleartext|HTTP)/i, titleZh: '登入表單以未加密的 HTTP 明文傳送密碼', solutionZh: '將登入頁與表單送出的目標網址全面改為 HTTPS，並在伺服器端把 HTTP 導向 HTTPS，搭配 HSTS 標頭。' },
    { pattern: /Application Error Disclosure|Error Message Disclosure/i, titleZh: '應用程式錯誤訊息洩漏內部資訊', solutionZh: '正式環境關閉除錯模式，統一以自訂錯誤頁面回應，詳細錯誤只寫入伺服器端日誌。' },
    { pattern: /Vulnerable JS Library|Vulnerable JavaScript Library/i, titleZh: '網站使用含已知弱點之前端 JavaScript 函式庫', solutionZh: '盤點前端相依函式庫並升級至官方仍維護且已修補的版本。' },
    { pattern: /Re-examine Cache-control|Cache-control Directives|Cacheable HTTPS response/i, titleZh: '敏感頁面未妥善設定 Cache-Control 快取控制標頭', solutionZh: '對含敏感資料的回應設定 Cache-Control: no-cache, no-store, must-revalidate。' },
    { pattern: /Log4Shell|CVE-2021-44228/i, titleZh: 'Apache Log4j 遠端程式碼執行重大漏洞 (Log4Shell)', solutionZh: '升級 Apache Log4j 至官方已修補的版本，依官方公告採取對應的暫時緩解措施。' },
    { pattern: /Default Credentials|Default Password|admin\/admin/i, titleZh: '設備或應用系統使用預設管理者帳號密碼', solutionZh: '立即變更預設管理者帳密，採用足夠複雜度的強密碼並啟用多因子驗證。' },
  ];

  function enrichZh(title, description) {
    const text = `${title || ''} ${description || ''}`;
    for (const rule of TW_KB) {
      if (rule.pattern.test(text)) return { titleZh: rule.titleZh, solutionZh: rule.solutionZh };
    }
    return { titleZh: null, solutionZh: null };
  }

  const SEVERITY_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };

  function emptyStats() {
    return { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  }

  function finalize(scanner, scanName, hosts, vulnMap) {
    const vulns = Array.from(vulnMap.values()).sort((a, b) => b.severityRank - a.severityRank);
    const stats = emptyStats();
    vulns.forEach((v) => { stats[v.severity]++; });
    return { scanner, scanName, hosts, vulns, stats };
  }

  function addFinding(vulnMap, finding, targetStr) {
    if (vulnMap.has(finding.id)) {
      const existing = vulnMap.get(finding.id);
      if (!existing.affectedHosts.includes(targetStr)) existing.affectedHosts.push(targetStr);
      return existing;
    }
    const zh = finding.titleZh ? { titleZh: finding.titleZh, solutionZh: finding.solutionZh || null }
      : enrichZh(finding.title, finding.description);
    const vuln = {
      id: finding.id,
      title: finding.title,
      titleZh: zh.titleZh,
      severity: finding.severity,
      severityRank: SEVERITY_RANK[finding.severity] || 0,
      cves: finding.cves || [],
      affectedHosts: [targetStr],
      description: finding.description || '',
      solution: finding.solution || '',
      solutionZh: zh.solutionZh,
    };
    vulnMap.set(finding.id, vuln);
    return vuln;
  }

  function parseXml(content, expectedRoot, scannerLabel) {
    const xmlDoc = new DOMParser().parseFromString(content, 'text/xml');
    const root = xmlDoc.documentElement;
    if (!root || root.nodeName === 'parsererror' || xmlDoc.querySelector('parsererror')) {
      throw new Error(`${scannerLabel} 檔案不是合法的 XML，無法解析`);
    }
    if (root.nodeName !== expectedRoot) {
      throw new Error(`不是有效的 ${scannerLabel} 檔案：根節點應為 ${expectedRoot}（實際為 ${root.nodeName}）`);
    }
    return xmlDoc;
  }

  function childText(parent, tag) {
    for (const child of parent.children) {
      if (child.nodeName === tag) return (child.textContent || '').trim();
    }
    return '';
  }

  // ---------------------------------------------------------------------------
  // Tenable Nessus (.nessus)
  // ---------------------------------------------------------------------------
  function mapNessusSeverity(level) {
    return ['Info', 'Low', 'Medium', 'High', 'Critical'][level] || 'Info';
  }

  function parseNessusXML(content) {
    const xmlDoc = parseXml(content, 'NessusClientData_v2', 'Nessus');
    const reportElem = xmlDoc.querySelector('Report');
    if (!reportElem) throw new Error('不是有效的 Nessus 掃描檔：缺少 Report 節點');
    const scanName = reportElem.getAttribute('name') || '弱點健診專案';

    const hosts = [];
    const vulnMap = new Map();

    xmlDoc.querySelectorAll('ReportHost').forEach((h) => {
      const hostIpTag = h.querySelector('tag[name="host-ip"]');
      const hostIp = hostIpTag ? hostIpTag.textContent.trim() : (h.getAttribute('name') || 'Unknown');
      const fqdnTag = h.querySelector('tag[name="host-fqdn"]');
      const fqdn = fqdnTag ? fqdnTag.textContent.trim() : '-';
      const osTag = h.querySelector('tag[name="operating-system"]');
      const os = osTag ? osTag.textContent.trim() : '未識別';
      const openPorts = new Set();

      h.querySelectorAll('ReportItem').forEach((item) => {
        const port = parseInt(item.getAttribute('port') || '0', 10);
        const protocol = item.getAttribute('protocol') || 'tcp';
        if (port > 0) openPorts.add(port);
        const targetStr = port > 0 ? `${hostIp}:${port}/${protocol}` : hostIp;
        addFinding(vulnMap, {
          id: item.getAttribute('pluginID') || '',
          title: item.getAttribute('pluginName') || '',
          severity: mapNessusSeverity(parseInt(item.getAttribute('severity') || '0', 10)),
          cves: Array.from(item.querySelectorAll('cve')).map((c) => c.textContent.trim()),
          description: childText(item, 'description'),
          solution: childText(item, 'solution'),
        }, targetStr);
      });

      hosts.push({ ip: hostIp, fqdn, os, openPorts: Array.from(openPorts).sort((a, b) => a - b) });
    });

    return finalize('nessus', scanName, hosts, vulnMap);
  }

  // ---------------------------------------------------------------------------
  // Nmap XML (-oX)
  // 只有 Telnet、過期 TLS 協定或明確回報 VULNERABLE 的 NSE 腳本才算弱點；
  // 開放埠只列入主機清冊，和 CLI 的 NmapParser 一致。
  // ---------------------------------------------------------------------------
  const NSE_VULNERABLE_RE = /^\s*(?:state:\s*)?VULNERABLE\b/im;

  function parseNmapXML(content, fileLabel) {
    const xmlDoc = parseXml(content, 'nmaprun', 'Nmap XML');
    const scanName = `Nmap 網路掃描 - ${fileLabel || 'scan'}`;
    const hosts = [];
    const vulnMap = new Map();

    xmlDoc.querySelectorAll('nmaprun > host').forEach((h) => {
      const status = h.querySelector(':scope > status');
      if (status && status.getAttribute('state') !== 'up') return;

      let hostIp = 'Unknown';
      h.querySelectorAll(':scope > address').forEach((addr) => {
        const type = addr.getAttribute('addrtype') || '';
        if (type === 'ipv4' || (type === 'ipv6' && hostIp === 'Unknown')) hostIp = addr.getAttribute('addr') || hostIp;
      });
      const hostnameElem = h.querySelector(':scope > hostnames > hostname');
      const fqdn = hostnameElem ? (hostnameElem.getAttribute('name') || '-') : '-';
      const osMatch = h.querySelector(':scope > os > osmatch');
      const os = osMatch ? (osMatch.getAttribute('name') || '未識別') : '未識別';
      const openPorts = new Set();

      h.querySelectorAll(':scope > ports > port').forEach((p) => {
        const state = p.querySelector(':scope > state');
        const portId = parseInt(p.getAttribute('portid') || '0', 10);
        if (!state || state.getAttribute('state') !== 'open' || portId <= 0) return;
        openPorts.add(portId);
        const proto = p.getAttribute('protocol') || 'tcp';
        const svc = p.querySelector(':scope > service');
        const svcName = svc ? (svc.getAttribute('name') || '').toLowerCase() : '';
        const targetStr = `${hostIp}:${portId}/${proto}`;

        if (svcName === 'telnet') {
          addFinding(vulnMap, {
            id: 'NMAP-TELNET-OPEN',
            title: 'Telnet Server Detection (Cleartext Protocol)',
            severity: 'Medium',
            description: '偵測到目標主機開啟 Telnet 服務。Telnet 通訊過程完全以明文傳輸，極易遭受網路監聽截獲帳號密碼。',
            solution: '立即停用並關閉 Telnet 服務，全數改以安全加密之 SSH 通訊協定進行伺服器管理。',
          }, targetStr);
        }

        p.querySelectorAll(':scope > script').forEach((script) => {
          const scriptId = script.getAttribute('id') || '';
          const output = (script.getAttribute('output') || '').trim();
          if (scriptId.includes('ssl-enum-ciphers')) {
            if (output.includes('TLSv1.0')) {
              addFinding(vulnMap, {
                id: 'NMAP-TLS-1.0', title: 'TLS Version 1.0 Protocol Detection', severity: 'Medium',
                description: `Nmap 偵測到目標通訊埠支援已廢棄之 TLS 1.0 通訊協定。\n${output.slice(0, 300)}`,
                solution: '請於伺服器組態中禁用 TLS 1.0，將傳輸加密門檻提升至 TLS 1.2 及 TLS 1.3 以上。',
              }, targetStr);
            }
            if (output.includes('SSLv3')) {
              addFinding(vulnMap, {
                id: 'NMAP-SSL-3.0', title: 'SSL Version 2 and 3 Protocol Detection', severity: 'High',
                description: `Nmap 偵測到目標通訊埠仍支援具破綻之 SSLv3 協定。\n${output.slice(0, 300)}`,
                solution: '停用所有 SSLv2 及 SSLv3 通訊協定，伺服器僅保留 TLS 1.2 及 TLS 1.3 協定支援。',
              }, targetStr);
            }
          } else if (NSE_VULNERABLE_RE.test(output)) {
            addFinding(vulnMap, {
              id: `NMAP-${scriptId.toUpperCase()}`, title: `Nmap Script Finding: ${scriptId}`, severity: 'High',
              titleZh: `Nmap NSE 腳本檢出弱點：${scriptId}`,
              description: `Nmap NSE 弱點腳本 [${scriptId}] 檢出潛在風險。\n${output.slice(0, 400)}`,
              solution: '請參考 Nmap NSE 腳本檢測說明，檢視相應組態或升級應用軟體版本。',
              solutionZh: '請參考 Nmap NSE 腳本檢測說明，檢視相應組態或升級應用軟體版本。',
            }, targetStr);
          }
        });
      });

      hosts.push({ ip: hostIp, fqdn, os, openPorts: Array.from(openPorts).sort((a, b) => a - b) });
    });

    return finalize('nmap', scanName, hosts, vulnMap);
  }

  // ---------------------------------------------------------------------------
  // OWASP ZAP（傳統 XML 與 JSON 報告）
  // 以站台（主機 + 通訊埠）當受影響對象；風險等級只有 High / Medium / Low / Info。
  // ---------------------------------------------------------------------------
  function stripHtml(text) {
    if (!text) return '';
    const doc = new DOMParser().parseFromString(`<div>${text}</div>`, 'text/html');
    return (doc.body.textContent || '').split('\n').map((l) => l.trim()).filter(Boolean).join('\n');
  }

  function mapZapSeverity(riskcode) {
    return { 3: 'High', 2: 'Medium', 1: 'Low', 0: 'Info' }[String(riskcode).trim()] || 'Info';
  }

  function siteEndpoint(site) {
    let parsed = null;
    try { parsed = new URL(site.name); } catch (e) { parsed = null; }
    const host = site.host || (parsed && parsed.hostname) || site.name || 'Unknown';
    const ssl = String(site.ssl).toLowerCase() === 'true' || (parsed && parsed.protocol === 'https:');
    let port = parseInt(site.port || '', 10);
    if (!port && parsed && parsed.port) port = parseInt(parsed.port, 10);
    if (!port) port = ssl ? 443 : 80;
    return { host, port };
  }

  function normalizeZapSites(sites, fileLabel) {
    if (!sites.length) throw new Error('ZAP 報告中沒有任何 site 節點，無法建立主機清冊');
    const hosts = [];
    const vulnMap = new Map();

    sites.forEach((site) => {
      const { host, port } = siteEndpoint(site);
      const targetStr = `${host}:${port}/tcp`;
      site.alerts.forEach((alert) => {
        const id = String(alert.pluginid || alert.alertRef || '').trim();
        const title = (alert.alert || alert.name || '').trim();
        if (!id || !title) return;
        let description = stripHtml(alert.desc);
        const other = stripHtml(alert.otherinfo);
        if (other) description = description ? `${description}\n\n補充資訊：\n${other}` : other;
        addFinding(vulnMap, {
          id, title,
          severity: mapZapSeverity(alert.riskcode),
          cves: [],
          description,
          solution: stripHtml(alert.solution),
        }, targetStr);
      });
      hosts.push({ ip: host, fqdn: host, os: '網站應用程式', openPorts: [port] });
    });

    return finalize('zap', `OWASP ZAP 網站弱點掃描 - ${fileLabel || 'report'}`, hosts, vulnMap);
  }

  function parseZapXML(content, fileLabel) {
    const xmlDoc = parseXml(content, 'OWASPZAPReport', 'ZAP XML 報告');
    const sites = Array.from(xmlDoc.querySelectorAll('OWASPZAPReport > site')).map((siteElem) => ({
      name: siteElem.getAttribute('name') || '',
      host: siteElem.getAttribute('host') || '',
      port: siteElem.getAttribute('port') || '',
      ssl: siteElem.getAttribute('ssl') || '',
      alerts: Array.from(siteElem.querySelectorAll(':scope > alerts > alertitem')).map((item) => {
        const alert = {};
        for (const child of item.children) {
          if (child.nodeName !== 'instances') alert[child.nodeName] = child.textContent || '';
        }
        return alert;
      }),
    }));
    return normalizeZapSites(sites, fileLabel);
  }

  function parseZapJSON(content, fileLabel) {
    let data;
    try { data = JSON.parse(content); } catch (e) { throw new Error(`不是有效的 ZAP JSON 報告：${e.message}`); }
    if (!data || typeof data !== 'object' || !('site' in data)) throw new Error('不是有效的 ZAP JSON 報告：缺少 site 欄位');
    const rawSites = Array.isArray(data.site) ? data.site : [data.site];
    const sites = rawSites.map((s) => ({
      name: s['@name'] || '', host: s['@host'] || '', port: s['@port'] || '', ssl: s['@ssl'] || '',
      alerts: s.alerts || [],
    }));
    return normalizeZapSites(sites, fileLabel);
  }

  // ---------------------------------------------------------------------------
  // Burp Suite「Report issues」XML（根節點 issues）
  // 同一種 issue type 合併成一筆，受影響對象是站台（主機 + 通訊埠），路徑進 raw 輸出。
  // ---------------------------------------------------------------------------
  function mapBurpSeverity(raw) {
    return { high: 'High', medium: 'Medium', low: 'Low', information: 'Info', info: 'Info' }[String(raw || '').trim().toLowerCase()] || 'Info';
  }

  function parseBurpXML(content, fileLabel) {
    const xmlDoc = parseXml(content, 'issues', 'Burp Suite XML 報告');
    const hosts = new Map();
    const vulnMap = new Map();

    xmlDoc.querySelectorAll('issues > issue').forEach((issue) => {
      const type = childText(issue, 'type');
      const name = childText(issue, 'name');
      if (!type || !name) return;

      const hostElem = issue.querySelector(':scope > host');
      const siteUrl = hostElem ? (hostElem.textContent || '').trim() : '';
      const hostIp = hostElem ? (hostElem.getAttribute('ip') || '').trim() : '';
      let parsed = null;
      try { parsed = siteUrl ? new URL(siteUrl) : null; } catch (e) { parsed = null; }
      const hostName = (parsed && parsed.hostname) || hostIp || 'Unknown';
      const port = (parsed && parsed.port) ? parseInt(parsed.port, 10) : (parsed && parsed.protocol === 'https:' ? 443 : 80);
      const targetStr = `${hostName}:${port}/tcp`;

      if (!hosts.has(hostName)) hosts.set(hostName, { ip: hostName, fqdn: hostName, os: hostIp ? `IP: ${hostIp}` : '網站應用程式', openPorts: [] });
      const host = hosts.get(hostName);
      if (!host.openPorts.includes(port)) host.openPorts.push(port);

      const background = stripHtml(childText(issue, 'issueBackground'));
      const detail = stripHtml(childText(issue, 'issueDetail'));
      const remBackground = stripHtml(childText(issue, 'remediationBackground'));
      const remDetail = stripHtml(childText(issue, 'remediationDetail'));
      const join = (a, b, label) => (a && b ? `${a}\n\n${label}：\n${b}` : (a || b));

      addFinding(vulnMap, {
        id: type,
        title: name,
        severity: mapBurpSeverity(childText(issue, 'severity')),
        cves: [],
        description: join(background, detail, '檢出細節'),
        solution: join(remBackground, remDetail, '針對本次檢出的處置'),
      }, targetStr);
    });

    if (!hosts.size) throw new Error('Burp Suite 報告中沒有任何 issue，無法建立主機清冊');
    hosts.forEach((h) => h.openPorts.sort((a, b) => a - b));
    return finalize('burp', `Burp Suite 網站弱點掃描 - ${fileLabel || 'report'}`, Array.from(hosts.values()), vulnMap);
  }

  // ---------------------------------------------------------------------------
  // 依副檔名與 XML 根節點自動分辨格式（對齊 cli.get_parser_for_file）
  // ---------------------------------------------------------------------------
  function xmlRootName(content) {
    const m = content.match(/<\s*([A-Za-z_][\w.-]*)[\s>\/]/g);
    if (!m) return null;
    for (const tag of m) {
      const name = tag.replace(/^<\s*/, '').replace(/[\s>\/]$/, '');
      if (!/^(\?xml|!DOCTYPE|!--)/.test(name)) return name;
    }
    return null;
  }

  function parseScanFile(fileName, content) {
    const name = fileName || 'scan';
    const stem = name.replace(/\.[^.]+$/, '');
    const ext = (name.match(/\.([^.]+)$/) || [, ''])[1].toLowerCase();
    if (ext === 'nessus') return parseNessusXML(content);
    if (ext === 'json') return parseZapJSON(content, stem);
    if (ext === 'xml') {
      const root = xmlRootName(content);
      if (root === 'OWASPZAPReport') return parseZapXML(content, stem);
      if (root === 'issues') return parseBurpXML(content, stem);
      if (root === 'NessusClientData_v2') return parseNessusXML(content);
      return parseNmapXML(content, stem);
    }
    throw new Error(`目前副檔名 .${ext || '?'} 尚不支援，請使用 .nessus、.xml (Nmap / ZAP / Burp) 或 .json (ZAP) 檔案。`);
  }

  // ---------------------------------------------------------------------------
  // 複測比對（對齊 comparator/diff.py：按弱點 × 主機／服務判定）
  // ---------------------------------------------------------------------------
  function compareReports(baseline, rescan) {
    if (baseline.scanner !== rescan.scanner) {
      throw new Error('初掃與複掃必須使用相同掃描器，否則弱點 ID 無法直接比對');
    }
    const baseHosts = new Set(baseline.hosts.map((h) => h.ip));
    const rescanHosts = new Set(rescan.hosts.map((h) => h.ip));
    const sameHosts = baseHosts.size === rescanHosts.size && [...baseHosts].every((ip) => rescanHosts.has(ip));
    if (!baseHosts.size || !sameHosts) {
      throw new Error('初掃與複掃的受檢主機範圍不同，不能將未複掃的主機判定為已修復');
    }

    const baseMap = new Map(baseline.vulns.map((v) => [v.id, v]));
    const rescanMap = new Map(rescan.vulns.map((v) => [v.id, v]));
    const ids = [...baseMap.keys(), ...[...rescanMap.keys()].filter((id) => !baseMap.has(id))];
    const items = [];

    ids.forEach((id) => {
      const baseV = baseMap.get(id);
      const resV = rescanMap.get(id);
      const baseTargets = new Set(baseV ? baseV.affectedHosts : []);
      const resTargets = new Set(resV ? resV.affectedHosts : []);
      if ((baseV && !baseTargets.size) || (resV && !resTargets.size)) {
        throw new Error(`弱點 ${id} 缺少受影響主機，無法判斷複掃結果`);
      }
      const buckets = [
        ['Fixed', [...baseTargets].filter((t) => !resTargets.has(t)), baseV],
        ['Open', [...baseTargets].filter((t) => resTargets.has(t)), baseV],
        ['New', [...resTargets].filter((t) => !baseTargets.has(t)), resV],
      ];
      buckets.forEach(([status, targets, source]) => {
        if (!targets.length) return;
        items.push({
          id, status,
          title: source.titleZh || source.title,
          severity: source.severity,
          affectedHosts: targets.sort(),
          solution: source.solutionZh || source.solution || '',
        });
      });
    });

    const count = (s) => items.filter((i) => i.status === s).length;
    return { items, fixed: count('Fixed'), open: count('Open'), newly: count('New') };
  }

  global.VulnWeaver = {
    TW_KB, enrichZh,
    parseNessusXML, parseNmapXML, parseZapXML, parseZapJSON, parseBurpXML, parseScanFile,
    compareReports,
  };
})(typeof window !== 'undefined' ? window : globalThis);
