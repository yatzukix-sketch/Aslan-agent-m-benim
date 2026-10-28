"""Command dispatcher: interactive menu plus subcommands."""

import argparse
import os
import sys
import time

from . import banner as banner_mod
from . import crypto, net, osint, payloads, recon, web
from . import default_workers, detect_platform
from .ui import UI

AUTHORIZED = False

MENU = [
    ("1", "Ag tarama", "port scan / banner / servis tespiti", "net"),
    ("2", "Host kesfi", "ping sweep ve hedef genisletme", "net"),
    ("3", "Web analiz", "HTTP parmak izi, header ve TLS denetimi", "web"),
    ("4", "Web zafiyet", "SQLi / XSS / LFI / RCE / redirect probu", "web"),
    ("5", "Dizin kesfi", "dizin ve hassas dosya taramasi", "web"),
    ("6", "Payload uret", "reverse shell + listener + msfvenom", "payload"),
    ("7", "OSINT", "kullanici adi, e-posta, IOC, metadata", "osint"),
    ("8", "Hash araclari", "tanimla, kir, hashcat komutu uret", "crypto"),
    ("9", "Kripto", "sifrele, coz, JWT, XOR, encoding", "crypto"),
    ("w", "Wordlist", "mutasyonlu kelime listesi uret", "crypto"),
    ("d", "Dork listesi", "Google / GitHub / Shodan sorgulari", "osint"),
    ("s", "Sistem bilgisi", "ortam, yetenek ve bagimlilik kontrolu", "sys"),
    ("q", "Cikis", "", "sys"),
]


def need_authorization(ui):
    global AUTHORIZED
    if AUTHORIZED:
        return True
    if banner_mod.show_disclaimer(ui, require_accept=True):
        AUTHORIZED = True
        return True
    ui.err("Onay verilmedi. Cikiliyor.")
    return False


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_scan(ui, args):
    target = args.target or ui.ask("Hedef (IP / hostname)")
    if not target:
        return 1
    ports = net.parse_ports(args.ports)
    timeout = args.timeout
    workers = default_workers(args.workers)

    resolved = net.resolve(target)
    ui.header("Port taramasi")
    ui.kv("Hedef", target)
    ui.kv("Cozumlenen IP", resolved or "cozumlenemedi")
    ui.kv("Port sayisi", len(ports))
    ui.kv("Zaman asimi", "%.1fs" % timeout)
    print()

    state = {"last": -1}

    def progress(done, total):
        percent = int(done * 100 / max(1, total))
        if percent != state["last"] and ui.color:
            bar_len = 28
            filled = int(bar_len * done / max(1, total))
            bar = "#" * filled + "." * (bar_len - filled)
            sys.stdout.write("\r  [%s] %3d%%  %d/%d" % (bar, percent, done, total))
            sys.stdout.flush()
            state["last"] = percent

    started = time.time()
    open_ports = net.scan_ports(resolved or target, ports, timeout, workers, progress)
    elapsed = time.time() - started
    if ui.color:
        print()

    ui.ok("%d acik port bulundu (%.1fs)" % (len(open_ports), elapsed))
    if not open_ports:
        return 0

    rows = []
    risky = []
    for port in open_ports:
        banner = net.grab_banner(resolved or target, port, timeout=args.banner_timeout)
        service = net.identify_service(port, banner)
        rows.append((port, service, (banner or "-")[:70]))
        if port in net.RISKY_PORTS:
            risky.append((port, net.RISKY_PORTS[port]))

    print()
    ui.table(["PORT", "SERVIS", "BANNER"], rows)
    if risky:
        ui.header("Riskli servisler", "red")
        for port, note in risky:
            ui.warn("port %d - %s" % (port, note))
    return 0


def cmd_discover(ui, args):
    spec = args.target or ui.ask("Hedef araligi (or. 192.168.1.0/24)")
    if not spec:
        return 1
    hosts = net.expand_targets(spec)
    ui.header("Host kesfi")
    ui.kv("Aralik", spec)
    ui.kv("Aday host", len(hosts))
    print()
    ui.info("TCP probe: %s" % ", ".join(str(p) for p in (80, 443, 22, 445, 3389)))
    started = time.time()
    alive = net.ping_sweep(hosts, timeout=args.timeout, workers=default_workers(args.workers))
    ui.ok("%d canli host (%.1fs)" % (len(alive), time.time() - started))
    if alive:
        print()
        ui.table(["HOST", "ACIK PORT"], [(h, p) for h, p in alive])
    return 0


def cmd_webfp(ui, args):
    url = args.url or ui.ask("URL (or. https://example.com)")
    if not url:
        return 1
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    ui.header("HTTP parmak izi")
    info = recon.fingerprint_http(url)
    if info.get("error"):
        ui.err("Baglanti hatasi: %s" % info["error"])
        return 1
    ui.kv("Durum", "%s %s" % (info["status"], ""))
    ui.kv("Sunucu", info["server"])
    ui.kv("Baslik", info["title"] or "-")
    ui.kv("Teknolojiler", ", ".join(info["tech"]) or "-")
    if info["redirect"]:
        ui.kv("Yonlendirme", info["redirect"])

    ui.header("Guvenlik basliklari", "yellow")
    if info["missing_security_headers"]:
        for header in info["missing_security_headers"]:
            ui.warn("eksik: %s" % header)
    else:
        ui.ok("tum temel basliklar mevcut")

    if info["disclosure"]:
        ui.header("Bilgi sizintisi", "orange")
        for key, value in info["disclosure"].items():
            ui.bullet("%s: %s" % (key, value))

    hints = web.cve_hints(info["server"], info["tech"])
    if hints:
        ui.header("CVE ipuclari", "red")
        for token, description in hints:
            ui.bullet("%s -> %s" % (token, description), "red")

    ui.header("CORS")
    cors = web.cors_check(url)
    ui.kv("Allow-Origin", cors["allow_origin"] or "-")
    ui.kv("Karar", cors["verdict"])
    return 0


def cmd_webscan(ui, args):
    url = args.url or ui.ask("Parametreli URL (or. https://site.tld/page?id=1)")
    if not url:
        return 1
    if not need_authorization(ui):
        return 1

    ui.header("Web zafiyet probu")
    ui.info("Yalnizca yetkili oldugun hedeflerde kullan.")
    params = [p for p in (args.params or "").split(",") if p] or web.extract_params(url)
    ui.kv("URL", url)
    ui.kv("Parametreler", ", ".join(params) or "bulunamadi")
    if not params:
        ui.err("Test edilecek parametre yok.")
        return 1
    print()

    report = web.scan_url(url, params, delay=args.delay)
    if not report["findings"]:
        ui.ok("Bilinen bir zafiyet imzasi bulunamadi.")
        return 0
    ui.err("%d bulgu" % len(report["findings"]))
    print()
    ui.table(
        ["TIP", "PARAMETRE", "PAYLOAD", "KANIT"],
        [(f["type"], f["param"], f["payload"][:28], f["evidence"][:36]) for f in report["findings"]],
        accent="red",
    )
    return 0


def cmd_dirs(ui, args):
    url = args.url or ui.ask("Kok URL (or. https://example.com)")
    if not url:
        return 1
    if not need_authorization(ui):
        return 1
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    words = web.COMMON_DIRS
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8") as fh:
            words = [line.strip() for line in fh if line.strip()]
    extensions = (args.ext or "php,html,txt,bak,zip,json,js").split(",")

    ui.header("Dizin ve dosya kesfi")
    ui.kv("Kok", url)
    ui.kv("Kelime", len(words))
    ui.kv("Uzantilar", ", ".join(extensions))
    print()

    hits = web.dir_bruteforce(url, words, extensions, timeout=args.timeout, delay=args.delay)
    if hits:
        ui.ok("%d kayit" % len(hits))
        print()
        ui.table(["DURUM", "BOYUT", "URL"], [(h["status"], h["size"], h["url"]) for h in hits])
    else:
        ui.info("Kayit bulunamadi.")

    ui.header("Hassas dosyalar", "red")
    sensitive = web.sensitive_file_scan(url, timeout=args.timeout)
    if sensitive:
        for hit in sensitive:
            ui.err("%s (%d bayt)" % (hit["url"], hit["size"]))
            if hit["preview"]:
                ui.bullet(hit["preview"][:100], "grey")
    else:
        ui.ok("Bilinen hassas dosya bulunamadi.")
    return 0


def cmd_payload(ui, args):
    host = args.lhost or ui.ask("LHOST (senin IP'n)", default="127.0.0.1")
    port = args.lport or ui.ask("LPORT", default="4444")
    if not host or not port:
        return 1
    try:
        port = int(port)
    except ValueError:
        ui.err("Gecersiz port.")
        return 1

    ui.header("Reverse shell katalogu")
    ui.kv("LHOST", host)
    ui.kv("LPORT", port)
    print()
    for name, code in payloads.generate_all(host, port).items():
        print(ui.paint("  %s" % name, "green", bold=True))
        print("    " + code)
    print()

    ui.header("Listener komutlari", "cyan")
    for name in payloads.listener_names():
        ui.kv(name, payloads.listener(name, port))
    print()

    ui.header("TTY yukseltme", "yellow")
    for step in payloads.UPGRADE_TTY:
        ui.bullet(step)
    print()

    ui.header("msfvenom katalogu", "magenta")
    for name, command in payloads.msfvenom_catalog(host, port):
        print(ui.paint("  %s" % name, "magenta"))
        print("    " + command)
    print()

    if args.encode:
        ui.header("Kodlanmis varyant", "violet")
        encoded = payloads.encode(args.encode, payloads.generate("bash", host, port))
        print("  " + encoded)
    return 0


def cmd_osint(ui, args):
    if args.username:
        ui.header("Kullanici adi taramasi")
        ui.kv("Kullanici", args.username)
        ui.kv("Site", len(osint.SITES))
        print()
        found, missing, errors = osint.scan_username(args.username, timeout=args.timeout, delay=args.delay)
        ui.ok("%d profil bulundu" % len(found))
        if found:
            print()
            ui.table(["SITE", "URL"], found)
        if errors:
            ui.header("Dogrulanamayan", "yellow")
            for name, status in errors[:12]:
                ui.bullet("%s -> %s" % (name, status), "yellow")
        return 0

    if args.email:
        ui.header("E-posta analizi")
        info = osint.email_intel(args.email)
        for key, value in info.items():
            ui.kv(key, value)
        return 0

    if args.iocs:
        text = args.iocs if args.iocs != "-" else sys.stdin.read()
        ui.header("IOC ayiklama")
        found = osint.extract_iocs(text)
        if not found:
            ui.info("IOC bulunamadi.")
            return 0
        for kind, values in found.items():
            ui.header(kind, "cyan")
            for value in values[:40]:
                ui.bullet(value)
        return 0

    if args.metadata:
        ui.header("Metadata")
        info = osint.metadata(args.metadata)
        for key, value in info.items():
            ui.kv(key, value)
        if args.strings:
            print()
            ui.header("Strings", "cyan")
            for line in osint.strings_in_file(args.metadata, limit=args.strings):
                print("  " + line)
        return 0

    ui.err("Bir secenek ver: --username, --email, --iocs veya --metadata")
    return 1


def cmd_hash(ui, args):
    if args.hash:
        value = args.hash
        ui.header("Hash analizi")
        ui.kv("Deger", value)
        guesses = recon.identify_hash(value)
        if not guesses:
            ui.warn("Bicim taninmadi.")
            return 1
        print()
        ui.table(["ALGORITMA", "HASHCAT -m", "JOHN FORMAT"], guesses)
        print()
        for name, mode, _ in guesses:
            ui.kv(name, recon.hashcat_command(value, mode))
        if args.wordlist:
            ui.header("Sozluk saldirisi")
            with open(args.wordlist, encoding="utf-8") as fh:
                words = [line.strip() for line in fh if line.strip()]
            started = time.time()
            result = recon.crack_dictionary(value, words)
            if result:
                ui.ok("Kirildi: '%s' (%s) - %.2fs" % (result[0], result[1], time.time() - started))
            else:
                ui.warn("Sozlukte bulunamadi (%.2fs)" % (time.time() - started))
        return 0

    if args.text:
        ui.header("Hash uretimi")
        ui.kv("Girdi", args.text)
        print()
        for algo in ("md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b"):
            ui.kv(algo, recon.hash_text(args.text, algo))
        return 0

    ui.err("--hash veya --text ver.")
    return 1


def cmd_crypto(ui, args):
    if args.encrypt:
        password = args.password or ui.ask("Parola", default="")
        if not password:
            ui.err("Parola bos olamaz.")
            return 1
        try:
            out = crypto.encrypt_file(args.encrypt, password, out=args.out)
        except OSError as exc:
            ui.err("Dosya hatasi: %s" % exc)
            return 1
        ui.ok("Sifrelendi: %s" % out)
        return 0

    if args.decrypt:
        password = args.password or ui.ask("Parola", default="")
        try:
            out = crypto.decrypt_file(args.decrypt, password, out=args.out)
        except ValueError as exc:
            ui.err("Cozumleme reddedildi: %s" % exc)
            return 1
        except OSError as exc:
            ui.err("Dosya hatasi: %s" % exc)
            return 1
        ui.ok("Cozuldu: %s" % out)
        return 0

    if args.jwt:
        ui.header("JWT analizi")
        try:
            decoded = crypto.jwt_decode(args.jwt)
        except Exception as exc:
            ui.err("Cozumleme hatasi: %s" % exc)
            return 1
        ui.kv("Header", decoded["header"])
        ui.kv("Payload", decoded["payload"])
        print()
        ui.header("Zayiflik adaylari", "red")
        for name, token in crypto.jwt_attack_tokens(args.jwt).items():
            ui.kv(name, token[:80] + ("..." if len(token) > 80 else ""))
        return 0

    if args.xor:
        data = args.xor.encode()
        ui.header("XOR analizi")
        results = crypto.xor_bruteforce(data)
        for result in results[:8]:
            ui.kv("key=%s" % result["key"], result["text"][:80])
        return 0

    if args.encode:
        ui.header("Encoding")
        ui.kv("base64", crypto.b64_encode(args.encode))
        ui.kv("hex", args.encode.encode().hex())
        ui.kv("rot13", crypto.rot13(args.encode))
        ui.kv("crc32", crypto.crc32(args.encode))
        return 0

    if args.password_gen:
        ui.header("Parola uretimi")
        for _ in range(int(args.password_gen)):
            ui.bullet(crypto.generate_password())
        ui.kv("Passphrase", crypto.passphrase())
        return 0

    ui.err("Islem sec: --encrypt, --decrypt, --jwt, --xor, --encode, --password-gen")
    return 1


def cmd_wordlist(ui, args):
    words = (args.words or "").split(",") if args.words else []
    if not words:
        words = ["admin", "root", "password", "welcome", "company", "user"]
    output = args.out or "wordlist.txt"
    count = recon.generate_wordlist(words, output, rules=not args.no_rules)
    ui.ok("%d satir yazildi: %s" % (count, output))
    return 0


def cmd_dorks(ui, args):
    target = args.target or ui.ask("Hedef alan adi", default="example.com")
    ui.header("Google dorklari", "cyan")
    for name, query in osint.dorks_for(target, "google"):
        ui.kv(name, query)
    ui.header("GitHub dorklari", "violet")
    for query, url in osint.dorks_for(target, "github"):
        print("  " + ui.paint(query, "white"))
        print("    " + ui.paint(url, "grey", dim=True))
    ui.header("Shodan sorgulari", "orange")
    for name, query in osint.dorks_for(target, "shodan"):
        ui.kv(name, query)
    return 0


def cmd_sysinfo(ui, args):
    ui.header("Ortam")
    ui.kv("Python", sys.version.split()[0])
    ui.kv("Isletim sistemi", sys.platform)
    ui.kv("Platform", detect_platform())
    ui.kv("Varsayilan worker", default_workers())
    ui.kv("Terminal genisligi", ui.width)
    ui.kv("Renk destegi", "acik" if ui.color else "kapali")

    ui.header("Yetenekler")
    caps = [
        ("socket", True), ("ssl", True), ("hashlib", True),
        ("hmac", True), ("pbkdf2", True), ("thread pool", True),
        ("raw socket (root gerekir)", os.geteuid() == 0 if hasattr(os, "geteuid") else False),
    ]
    for name, available in caps:
        (ui.ok if available else ui.warn)("%s: %s" % (name, "var" if available else "yok"))

    ui.header("Harici araclar (opsiyonel)", "grey")
    for tool in ("nmap", "hashcat", "john", "hydra", "msfvenom", "sqlmap", "nc", "socat"):
        path = _which(tool)
        (ui.ok if path else ui.warn)("%s: %s" % (tool, path or "kurulu degil"))
    return 0


def _which(tool):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, tool)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

def interactive(ui):
    banner_mod.show_banner(ui, animate=True)
    while True:
        print()
        ui.title("Ana menu")
        for key, name, description, _ in MENU:
            line = "  %s  %s" % (ui.paint(key.rjust(2), "green", bold=True), ui.paint(name.ljust(16), "white", bold=True))
            if description:
                line += ui.paint(description, "grey", dim=True)
            print(line)
        print()
        choice = ui.ask("Secim", default="q")
        if choice is None:
            break
        choice = choice.strip().lower()

        try:
            if choice in ("q", "quit", "exit", "0"):
                break
            if choice == "1":
                cmd_scan(ui, _ns(target=ui.ask("Hedef"), ports=None))
            elif choice == "2":
                cmd_discover(ui, _ns(target=ui.ask("Aralik (CIDR/range)"), timeout=1.0, workers=100))
            elif choice == "3":
                cmd_webfp(ui, _ns(url=ui.ask("URL")))
            elif choice == "4":
                cmd_webscan(ui, _ns(url=ui.ask("URL"), params=None, delay=0.2))
            elif choice == "5":
                cmd_dirs(ui, _ns(url=ui.ask("Kok URL"), wordlist=None, ext="php,html,txt,bak,zip,json,js", timeout=5.0, delay=0.0))
            elif choice == "6":
                cmd_payload(ui, _ns(lhost=ui.ask("LHOST", default="127.0.0.1"), lport=ui.ask("LPORT", default="4444"), encode=None))
            elif choice == "7":
                cmd_osint(ui, _ns(username=ui.ask("Kullanici adi"), email=None, iocs=None, metadata=None, strings=0, timeout=6.0, delay=0.0))
            elif choice == "8":
                cmd_hash(ui, _ns(hash=ui.ask("Hash"), text=None, wordlist=None))
            elif choice == "9":
                cmd_crypto(ui, _ns(encrypt=None, decrypt=None, password=None, jwt=None, xor=None, encode=ui.ask("Metin"), password_gen=0, out=None))
            elif choice == "w":
                cmd_wordlist(ui, _ns(words=ui.ask("Kelimeler (virgulle)"), out="wordlist.txt", no_rules=False))
            elif choice == "d":
                cmd_dorks(ui, _ns(target=ui.ask("Hedef alan adi", default="example.com")))
            elif choice == "s":
                cmd_sysinfo(ui, _ns())
            else:
                ui.warn("Gecersiz secim.")
        except KeyboardInterrupt:
            print()
            ui.warn("Kesildi.")
        except Exception as exc:
            ui.err("Hata: %s" % exc)

        if choice not in ("q",):
            ui.pause()
    print()
    ui.info("Gorusuruz.")


class _ns:
    """Tiny stand-in for argparse.Namespace."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="yatzukix",
        description="yatzukix tool's - offline-first guvenlik araci seti",
        epilog="Sadece yetkili oldugun sistemlerde kullan.",
    )
    parser.add_argument("--no-anim", action="store_true", help="acilis animasyonunu kapat")
    parser.add_argument("--no-color", action="store_true", help="renkleri kapat")
    parser.add_argument("--yes", action="store_true", help="yetki onayini atla")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("scan", help="port taramasi")
    p.add_argument("target", nargs="?", help="IP veya hostname")
    p.add_argument("-p", "--ports", help="port listesi, or. 22,80,1000-2000")
    p.add_argument("-t", "--timeout", type=float, default=1.0)
    p.add_argument("-w", "--workers", type=int, default=100)
    p.add_argument("--banner-timeout", type=float, default=2.0)

    p = sub.add_parser("discover", help="host kesfi")
    p.add_argument("target", nargs="?", help="CIDR veya aralik")
    p.add_argument("-t", "--timeout", type=float, default=1.0)
    p.add_argument("-w", "--workers", type=int, default=100)

    p = sub.add_parser("webfp", help="HTTP parmak izi")
    p.add_argument("url", nargs="?")

    p = sub.add_parser("webscan", help="web zafiyet probu")
    p.add_argument("url", nargs="?")
    p.add_argument("--params", help="virgulle ayrilmis parametreler")
    p.add_argument("--delay", type=float, default=0.2)

    p = sub.add_parser("dirs", help="dizin kesfi")
    p.add_argument("url", nargs="?")
    p.add_argument("--wordlist")
    p.add_argument("--ext", default="php,html,txt,bak,zip,json,js")
    p.add_argument("-t", "--timeout", type=float, default=5.0)
    p.add_argument("--delay", type=float, default=0.0)

    p = sub.add_parser("payload", help="reverse shell uretimi")
    p.add_argument("--lhost")
    p.add_argument("--lport")
    p.add_argument("--encode", help="base64, hex, url, powershell-utf16, gzip-base64")

    p = sub.add_parser("osint", help="OSINT")
    p.add_argument("--username")
    p.add_argument("--email")
    p.add_argument("--iocs", nargs="?", const="-", help="metin veya '-' (stdin)")
    p.add_argument("--metadata", help="dosya yolu")
    p.add_argument("--strings", type=int, default=0, help="metadata ile birlikte strings cikar")
    p.add_argument("-t", "--timeout", type=float, default=6.0)
    p.add_argument("--delay", type=float, default=0.0)

    p = sub.add_parser("hash", help="hash tanima ve kirma")
    p.add_argument("--hash")
    p.add_argument("--text")
    p.add_argument("--wordlist")

    p = sub.add_parser("crypto", help="kripto araclari")
    p.add_argument("--encrypt", help="dosya sifrele")
    p.add_argument("--decrypt", help="dosya coz")
    p.add_argument("--password")
    p.add_argument("--out", help="cikti dosyasi")
    p.add_argument("--jwt", help="JWT coz ve zayifliklari dene")
    p.add_argument("--xor", help="XOR brute-force")
    p.add_argument("--encode", help="encoding tablosu")
    p.add_argument("--password-gen", type=int, default=0, help="N parola uret")

    p = sub.add_parser("wordlist", help="kelime listesi uret")
    p.add_argument("--words", help="virgulle ayrilmis kelimeler")
    p.add_argument("--out", default="wordlist.txt")
    p.add_argument("--no-rules", action="store_true")

    p = sub.add_parser("dorks", help="dork listesi")
    p.add_argument("target", nargs="?")

    sub.add_parser("sysinfo", help="ortam bilgisi")
    sub.add_parser("menu", help="interaktif menu")

    return parser


HANDLERS = {
    "scan": cmd_scan,
    "discover": cmd_discover,
    "webfp": cmd_webfp,
    "webscan": cmd_webscan,
    "dirs": cmd_dirs,
    "payload": cmd_payload,
    "osint": cmd_osint,
    "hash": cmd_hash,
    "crypto": cmd_crypto,
    "wordlist": cmd_wordlist,
    "dorks": cmd_dorks,
    "sysinfo": cmd_sysinfo,
}


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    global AUTHORIZED
    if getattr(args, "yes", False):
        AUTHORIZED = True

    ui = UI(color=False if getattr(args, "no_color", False) else None)

    if args.command in (None, "menu"):
        interactive(ui)
        return 0

    if not getattr(args, "no_anim", False):
        banner_mod.show_banner(ui, animate=True, small=True)

    handler = HANDLERS.get(args.command)
    if not handler:
        parser.print_help()
        return 2
    try:
        return handler(ui, args) or 0
    except KeyboardInterrupt:
        print()
        ui.warn("Kesildi.")
        return 130
    except Exception as exc:
        if os.environ.get("YATZUKIX_DEBUG"):
            raise
        ui.err("Beklenmeyen hata: %s" % exc)
        ui.info("Ayrinti icin: YATZUKIX_DEBUG=1 ile calistir.")
        return 1
