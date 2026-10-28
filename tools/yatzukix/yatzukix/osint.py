"""OSINT: username hunting, email/breach-format checks, metadata, dorks."""

import json
import os
import re
import struct
import urllib.parse

from . import recon

# Site name -> profile URL template. No API keys needed: a 200 means the
# handle likely exists, 404 means it likely does not.
SITES = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Bitbucket": "https://bitbucket.org/{}",
    "Twitter/X": "https://x.com/{}",
    "Instagram": "https://instagram.com/{}",
    "Facebook": "https://facebook.com/{}",
    "TikTok": "https://tiktok.com/@{}",
    "Reddit": "https://reddit.com/user/{}",
    "Pinterest": "https://pinterest.com/{}",
    "Medium": "https://medium.com/@{}",
    "Dev.to": "https://dev.to/{}",
    "Keybase": "https://keybase.io/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "Steam": "https://steamcommunity.com/id/{}",
    "Twitch": "https://twitch.tv/{}",
    "YouTube": "https://youtube.com/@{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Spotify": "https://open.spotify.com/user/{}",
    "Telegram": "https://t.me/{}",
    "Docker Hub": "https://hub.docker.com/u/{}",
    "PyPI": "https://pypi.org/user/{}",
    "NPM": "https://npmjs.com/~{}",
    "Patreon": "https://patreon.com/{}",
    "Behance": "https://behance.net/{}",
    "Dribbble": "https://dribbble.com/{}",
    "Flickr": "https://flickr.com/people/{}",
    "Vimeo": "https://vimeo.com/{}",
    "About.me": "https://about.me/{}",
    "Gravatar": "https://gravatar.com/{}",
    "Linktree": "https://linktr.ee/{}",
    "Roblox": "https://roblox.com/user.aspx?username={}",
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwawaymail.com", "yopmail.com", "trashmail.com", "sharklasers.com",
    "getnada.com", "temp-mail.org", "fakeinbox.com", "maildrop.cc",
}

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "icloud.com", "protonmail.com", "proton.me", "gmx.com",
    "yandex.com", "mail.ru", "zoho.com", "tutanota.com",
}

GOOGLE_DORKS = [
    ("Acik dizin listeleri", 'intitle:"index of" "parent directory"'),
    ("Config dosyalari", 'filetype:env "DB_PASSWORD"'),
    ("SQL yedekleri", 'filetype:sql "INSERT INTO" "VALUES"'),
    ("Log dosyalari", 'filetype:log "password" -github'),
    ("Acik .git", 'inurl:".git/config" -github'),
    ("phpMyAdmin panelleri", 'inurl:phpmyadmin "Welcome to phpMyAdmin"'),
    ("Jenkins konsollari", 'intitle:"Dashboard [Jenkins]"'),
    ("Kibana panelleri", 'intitle:"Kibana" inurl:app/kibana'),
    ("Grafana", 'intitle:"Grafana" inurl:login'),
    ("Acik kameralar", 'inurl:"/view.shtml" "Network Camera"'),
    ("S3 bucket listeleri", 'site:s3.amazonaws.com "ListBucketResult"'),
    ("AWS anahtar sizintisi", '"AKIA" filetype:txt -github'),
    ("GitHub token sizintisi", '"ghp_" OR "gho_" filetype:txt'),
    ("Slack webhook", '"hooks.slack.com/services/" -github'),
    ("WordPress config", 'inurl:"wp-config.php.bak"'),
    ("Zafiyetli phpinfo", 'intitle:"phpinfo()" "PHP Version"'),
    ("Acik hassas dosyalar", 'inurl:"/.env" -github -gitlab'),
    ("Jira panelleri", 'intitle:"Jira" inurl:"/secure/Dashboard.jspa"'),
    ("Zimbra mailler", 'intitle:"Zimbra Web Client Sign In"'),
    ("VPN panelleri", 'intitle:"SSL VPN" inurl:login'),
]

SHODAN_QUERIES = [
    ("Acik Elasticsearch", "port:9200 elastic"),
    ("Acik MongoDB", "port:27017 mongodb"),
    ("Acik Redis", "port:6379 redis"),
    ("Acik Docker API", "port:2375 docker"),
    ("Acik VNC", "port:5900 vnc"),
    ("RDP", "port:3389 rdp"),
    ("Default parolali kameralar", "Server: SQ-WEBCAM"),
    ("Acik Jenkins", "http.title:Jenkins"),
    ("Acik Kibana", "http.title:Kibana"),
    ("Acik Grafana", "http.title:Grafana"),
    ("Zafiyetli Apache", "apache 2.4.49"),
    ("Log4Shell adaylari", "http.component:Log4j"),
]

GITHUB_DORKS = [
    'filename:.env "AWS_SECRET_ACCESS_KEY"',
    'filename:credentials "aws_access_key_id"',
    '"-----BEGIN RSA PRIVATE KEY-----"',
    '"xoxb-" OR "xoxp-" OR "xoxa-"',
    'filename:id_rsa',
    '"api_key" OR "apikey" OR "api-key"',
    'filename:.npmrc "_auth"',
    'filename:.dockercfg auth',
    'filename:wp-config.php "DB_PASSWORD"',
    'filename:.bash_history',
    '"mysql://" "password"',
    '"postgres://" "password"',
    '"mongodb://" "password"',
    '"AIza" filetype:js',
    'filename:settings.py "SECRET_KEY"',
    'filename:.git-credentials',
    '"BEGIN OPENSSH PRIVATE KEY"',
    'filename:terraform.tfstate',
    '"sendgrid_api_key" OR "mailgun_api_key"',
    'filename:.htpasswd',
]

HIBP_CHECK_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=true"


def scan_username(username, sites=None, timeout=6.0, delay=0.0):
    """Check a handle across public sites. Returns (found, missing, errors)."""
    import time
    sites = sites or SITES
    found, missing, errors = [], [], []
    for name, template in sites.items():
        url = template.format(urllib.parse.quote(username))
        result = recon.http_fetch(url, timeout=timeout, method="GET")
        status = result["status"]
        if status == 200:
            found.append((name, url))
        elif status in (301, 302, 307, 308):
            found.append((name, result.get("url") or url))
        elif status in (404, 410):
            missing.append(name)
        else:
            errors.append((name, status if status else result.get("error")))
        if delay:
            time.sleep(delay)
    return found, missing, errors


def email_intel(email):
    """Validate format, split parts, flag disposable/freemail, build the MX hint."""
    if not EMAIL_RE.fullmatch(email):
        return {"valid": False, "reason": "gecersiz format"}
    local, _, domain = email.rpartition("@")
    return {
        "valid": True,
        "local": local,
        "domain": domain.lower(),
        "disposable": domain.lower() in DISPOSABLE_DOMAINS,
        "freemail": domain.lower() in FREEMAIL_DOMAINS,
        "mx_hint": "MX kaydini kontrol et: dig +short MX %s" % domain,
        "gravatar": "https://gravatar.com/avatar/%s?d=404" % recon.hash_text(email.lower(), "md5"),
        "hibp_hint": "Manuel kontrol: %s" % HIBP_CHECK_URL.format(urllib.parse.quote(email)),
    }


def extract_emails(text):
    return sorted(set(EMAIL_RE.findall(text)))


def extract_iocs(text):
    """Pull IPs, domains, URLs, emails and hashes out of pasted text."""
    patterns = {
        "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|tr|de|uk|info|xyz|top|onion|gov|edu|co)\b",
        "url": r"https?://[^\s\"'<>]+",
        "email": EMAIL_RE.pattern,
        "md5": r"\b[a-fA-F0-9]{32}\b",
        "sha1": r"\b[a-fA-F0-9]{40}\b",
        "sha256": r"\b[a-fA-F0-9]{64}\b",
        "cve": r"CVE-\d{4}-\d{4,7}",
        "btc": r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b",
        "registry": r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s\"']+",
        "mutex": r"\b(?:Global|Local)\\[A-Za-z0-9_\-\{\}]{6,}\b",
    }
    out = {}
    for name, pattern in patterns.items():
        found = sorted(set(re.findall(pattern, text)))
        if found:
            out[name] = found
    return out


def defang(text):
    return (text.replace("http://", "hxxp://").replace("https://", "hxxps://")
            .replace(".", "[.]"))


def refang(text):
    return (text.replace("hxxps://", "https://").replace("hxxp://", "http://")
            .replace("[.]", ".").replace("(.)", "."))


def metadata(path):
    """Read file metadata without external libraries."""
    result = {"path": path, "size": os.path.getsize(path)}
    with open(path, "rb") as fh:
        head = fh.read(65536)

    if head.startswith(b"\x89PNG"):
        result["type"] = "PNG"
        offset = 8
        while offset + 8 <= len(head):
            length = struct.unpack(">I", head[offset:offset + 4])[0]
            chunk_type = head[offset + 4:offset + 8].decode("latin-1")
            if chunk_type == "tEXt":
                data = head[offset + 8:offset + 8 + length]
                key, _, value = data.partition(b"\x00")
                result.setdefault("text_chunks", []).append(
                    "%s=%s" % (key.decode("latin-1"), value.decode("latin-1", "replace"))
                )
            if chunk_type in ("iTXt", "zTXt"):
                result.setdefault("text_chunks", []).append("%s (compressed)" % chunk_type)
            offset += 12 + length
    elif head.startswith(b"\xff\xd8\xff"):
        result["type"] = "JPEG"
        i = 2
        while i + 4 < len(head):
            if head[i] != 0xFF:
                i += 1
                continue
            marker = head[i + 1]
            if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            seg_len = struct.unpack(">H", head[i + 2:i + 4])[0]
            if 0xE0 <= marker <= 0xEF:
                payload = head[i + 4:i + 2 + seg_len]
                result.setdefault("segments", []).append({
                    "marker": "APP%d" % (marker - 0xE0),
                    "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:80]),
                })
            if marker == 0xDA:
                break
            i += 2 + seg_len
    elif head.startswith(b"%PDF"):
        result["type"] = "PDF"
        result["pdf_version"] = head[1:8].decode("latin-1", "replace")
        result["producer_hint"] = "exiftool veya pdfinfo ile detaylandir"
    elif head.startswith(b"PK\x03\x04"):
        result["type"] = "ZIP/DOCX/XLSX/APK"
        result["note"] = "Office/APK: unzip -l ile icerik, docProps ile yazar bilgisi"
    elif head.startswith(b"\x7fELF"):
        result["type"] = "ELF binary"
    elif head.startswith(b"MZ"):
        result["type"] = "PE (Windows) binary"
        result["note"] = "pefile/strings ile derleyici ve zaman damgasi"
    else:
        result["type"] = "unknown"
        result["head_hex"] = head[:32].hex()

    result["sha256"] = _file_hash(path)
    return result


def _file_hash(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def strings_in_file(path, minimum=4, limit=200):
    """ASCII strings extraction, like the classic `strings` tool."""
    out = []
    with open(path, "rb") as fh:
        data = fh.read()
    current = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= minimum:
                out.append(current.decode("latin-1"))
                if len(out) >= limit:
                    return out
            current = bytearray()
    if len(current) >= minimum and len(out) < limit:
        out.append(current.decode("latin-1"))
    return out


def dorks_for(target, category="google"):
    table = {"google": GOOGLE_DORKS, "github": GITHUB_DORKS}
    if category == "shodan":
        return [(name, query) for name, query in SHODAN_QUERIES]
    entries = table.get(category, GOOGLE_DORKS)
    if category == "github":
        return [(query, "https://github.com/search?q=%s&type=code" % urllib.parse.quote(query)) for query in entries]
    return [(name, query.replace("TARGET", target) if "TARGET" in query else "%s %s" % (query, target)) for name, query in entries]
