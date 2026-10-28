"""Recon: DNS, whois, HTTP fingerprint, TLS, hashes, wordlists."""

import hashlib
import hmac
import http.client
import ipaddress
import os
import random
import re
import socket
import string
import ssl
import time
import urllib.parse
import urllib.request

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Version/17.3 Mobile Safari/604.1",
]

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-resource-policy",
]

DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator", "via"]

INTERESTING_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/.svn/entries",
    "/wp-login.php", "/wp-admin/", "/administrator/", "/phpmyadmin/",
    "/admin/", "/login", "/backup.zip", "/backup.sql", "/db.sql",
    "/config.php", "/server-status", "/actuator/health", "/api/",
    "/.well-known/security.txt", "/crossdomain.xml", "/web.config",
]

DEFAULT_WORDLIST = [
    "admin", "administrator", "root", "toor", "password", "passwd", "123456",
    "12345678", "123456789", "qwerty", "letmein", "welcome", "monkey", "dragon",
    "master", "sunshine", "princess", "football", "baseball", "iloveyou",
    "trustno1", "abc123", "secret", "shadow", "superman", "batman", "test",
    "guest", "user", "oracle", "postgres", "mysql", "redis", "changeme",
    "P@ssw0rd", "Passw0rd!", "Adm1n@123", "Winter2024!", "Summer2024!",
]


def dns_lookup(host):
    result = {"host": host, "a": [], "aaaa": [], "reverse": None, "error": None}
    try:
        infos = socket.getaddrinfo(host, None)
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET and sockaddr[0] not in result["a"]:
                result["a"].append(sockaddr[0])
            elif family == socket.AF_INET6 and sockaddr[0] not in result["aaaa"]:
                result["aaaa"].append(sockaddr[0])
    except socket.gaierror as exc:
        result["error"] = str(exc)
    try:
        result["reverse"] = socket.gethostbyaddr(host)[0]
    except OSError:
        pass
    return result


def whois_lookup(target, server="whois.iana.org", timeout=6.0):
    """Raw port-43 whois. No external library needed."""
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.sendall((target + "\r\n").encode())
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks).decode("utf-8", "replace")
    except OSError as exc:
        return "whois error: %s" % exc


class _StopRedirects(urllib.request.HTTPRedirectHandler):
    """Capture the redirect instead of chasing it. A followed redirect hides
    the Location header and can fail DNS on an attacker-controlled host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _no_redirect_opener(context):
    """Opener that stops at 3xx and accepts the given TLS context."""
    return urllib.request.build_opener(
        _StopRedirects, urllib.request.HTTPSHandler(context=context)
    )


def http_fetch(url, timeout=8.0, method="GET", ua=None, follow_redirects=True):
    request = urllib.request.Request(url, method=method)
    request.add_header("User-Agent", ua or random.choice(USER_AGENTS))
    request.add_header("Accept", "*/*")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        if follow_redirects:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                body = b"" if method == "HEAD" else response.read(65536)
                return {
                    "status": response.status,
                    "reason": response.reason,
                    "headers": dict(response.headers.items()),
                    "body": body,
                    "url": response.geturl(),
                    "error": None,
                }
        with _no_redirect_opener(context).open(request, timeout=timeout) as response:
            return {
                "status": response.status,
                "reason": response.reason,
                "headers": dict(response.headers.items()),
                "body": b"",
                "url": url,
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        # 3xx lands here when redirects are not followed; that is the useful case.
        return {
            "status": exc.code, "reason": exc.reason,
            "headers": dict(exc.headers.items()), "body": b"",
            "url": url, "error": None,
        }
    except Exception as exc:
        return {"status": None, "reason": None, "headers": {}, "body": b"", "url": url, "error": str(exc)}


def fingerprint_http(url):
    """Headers, security posture, tech hints and interesting paths."""
    result = http_fetch(url, method="GET")
    if result["error"]:
        return {"error": result["error"], "url": url}

    headers = {k.lower(): v for k, v in result["headers"].items()}
    body = result["body"].decode("utf-8", "replace")
    title = ""
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if match:
        title = match.group(1).strip()[:120]

    missing = [h for h in SECURITY_HEADERS if h not in headers]
    disclosure = {h: headers[h] for h in DISCLOSURE_HEADERS if h in headers}

    tech = []
    joined = (body[:20000] + " " + " ".join(headers.values())).lower()
    for token, name in (
        ("wp-content", "WordPress"), ("drupal", "Drupal"), ("joomla", "Joomla"),
        ("laravel", "Laravel"), ("django", "Django"), ("flask", "Flask"),
        ("react", "React"), ("next.js", "__NEXT_DATA__"), ("nginx", "nginx"),
        ("apache", "Apache"), ("cloudflare", "Cloudflare"), ("iis", "IIS"),
        ("graphql", "GraphQL"), ("swagger", "Swagger"), ("php", "PHP"),
    ):
        if token in joined:
            tech.append(name)

    return {
        "url": result["url"],
        "status": result["status"],
        "server": headers.get("server", "-"),
        "title": title,
        "tech": sorted(set(tech)),
        "missing_security_headers": missing,
        "disclosure": disclosure,
        "redirect": result["url"] if result["url"] != url else None,
        "error": None,
    }


def probe_paths(base_url, paths=None, timeout=5.0, delay=0.0):
    """Check which common paths exist. Only run against hosts you own."""
    paths = paths or INTERESTING_PATHS
    base = base_url.rstrip("/")
    findings = []
    for path in paths:
        url = base + path
        result = http_fetch(url, timeout=timeout, method="GET")
        if result["status"] is not None:
            findings.append((path, result["status"], len(result["body"])))
        if delay:
            time.sleep(delay)
    return findings


def tls_info(host, port=443, timeout=6.0):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher() or ("", "", 0)
                return {
                    "protocol": tls.version(),
                    "cipher": cipher[0],
                    "bits": cipher[2],
                    "subject": dict(x[0] for x in cert.get("subject", ())) if cert else {},
                    "issuer": dict(x[0] for x in cert.get("issuer", ())) if cert else {},
                    "not_after": cert.get("notAfter") if cert else None,
                    "san": [v for k, v in cert.get("subjectAltName", ())] if cert else [],
                    "error": None,
                }
    except Exception as exc:
        return {"error": str(exc)}


def identify_hash(value):
    """Guess the algorithm from shape. Returns list of (name, hashcat mode, john format)."""
    value = value.strip()
    guesses = []
    if re.fullmatch(r"[a-f0-9]{32}", value):
        guesses += [("MD5", 0, "raw-md5"), ("NTLM", 1000, "nt")]
    if re.fullmatch(r"[a-f0-9]{40}", value):
        guesses += [("SHA1", 100, "raw-sha1"), ("MySQL4.1+", 300, "mysql-sha1")]
    if re.fullmatch(r"[a-f0-9]{64}", value):
        guesses += [("SHA256", 1400, "raw-sha256"), ("SHA3-256", 17400, "raw-sha3-256")]
    if re.fullmatch(r"[a-f0-9]{128}", value):
        guesses += [("SHA512", 1700, "raw-sha512"), ("Whirlpool", 6100, "whirlpool")]
    if value.startswith("$2a$") or value.startswith("$2b$") or value.startswith("$2y$"):
        guesses.append(("bcrypt", 3200, "bcrypt"))
    if value.startswith("$1$"):
        guesses.append(("MD5crypt", 500, "md5crypt"))
    if value.startswith("$5$"):
        guesses.append(("SHA256crypt", 7400, "sha256crypt"))
    if value.startswith("$6$"):
        guesses.append(("SHA512crypt", 1800, "sha512crypt"))
    if value.startswith("$argon2"):
        guesses.append(("Argon2", 0, "argon2"))
    if value.startswith("$pbkdf2"):
        guesses.append(("PBKDF2", 10900, "pbkdf2"))
    if re.fullmatch(r"[A-Za-z0-9+/]{27}", value):
        guesses.append(("LM", 3000, "lm"))
    if re.fullmatch(r"[a-f0-9]{16}", value):
        guesses.append(("Half-MD5/DES", 0, "descrypt"))
    return guesses


def hash_text(text, algorithm="sha256"):
    try:
        digest = hashlib.new(algorithm)
    except ValueError:
        raise ValueError("unknown algorithm: %s" % algorithm)
    digest.update(text.encode())
    return digest.hexdigest()


def hmac_text(text, key, algorithm="sha256"):
    return hmac.new(key.encode(), text.encode(), algorithm).hexdigest()


def crack_dictionary(target_hash, words=None, algorithms=None):
    """Dictionary attack against your own hashes. Returns (password, algorithm) or None."""
    words = words or DEFAULT_WORDLIST
    target = target_hash.strip().lower()
    candidates = algorithms or ["md5", "sha1", "sha256", "sha512"]
    for word in words:
        for algo in candidates:
            if hash_text(word, algo) == target:
                return word, algo
    return None


def crack_rules(word):
    """Small mutation set: real crackers use hashcat rules, this is the demo tier."""
    variants = {word, word.lower(), word.upper(), word.capitalize()}
    for suffix in ("1", "12", "123", "1234", "12345", "!", "!!", "@", "2024", "2025", "01"):
        variants.add(word + suffix)
    for prefix in ("!", "@", "1", "123"):
        variants.add(prefix + word)
    leet = word.replace("a", "@").replace("e", "3").replace("i", "1").replace("o", "0").replace("s", "$")
    variants.add(leet)
    capital_leet = word.capitalize().replace("a", "@").replace("e", "3").replace("i", "1").replace("o", "0")
    variants.add(capital_leet)
    variants.add(capital_leet + "1")
    return sorted(variants)


def hashcat_command(hash_value, mode, wordlist="rockyou.txt", rules=True, mask=None):
    parts = ["hashcat", "-m", str(mode), "-a", "3" if mask else "0", hash_value]
    if mask:
        parts.append(mask)
    else:
        parts.append(wordlist)
        if rules:
            parts.append("-r")
            parts.append("/usr/share/hashcat/rules/best64.rule")
    return " ".join(parts)


def john_command(hash_file, wordlist="rockyou.txt", format_name=None):
    parts = ["john"]
    if format_name:
        parts += ["--format=" + format_name]
    parts += ["--wordlist=" + wordlist, hash_file]
    return " ".join(parts)


def generate_wordlist(words, output, rules=True, min_len=6, max_len=32):
    """Write a wordlist: base words plus mutations, deduplicated."""
    seen = []
    seen_set = set()
    for word in words:
        pool = crack_rules(word) if rules else [word]
        for candidate in pool:
            if min_len <= len(candidate) <= max_len and candidate not in seen_set:
                seen_set.add(candidate)
                seen.append(candidate)
    with open(output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(seen) + "\n")
    return len(seen)


def random_password(length=20, symbols=True):
    alphabet = string.ascii_letters + string.digits
    if symbols:
        alphabet += "!@#$%^&*()-_=+[]{}"
    return "".join(random.SystemRandom().choice(alphabet) for _ in range(length))
