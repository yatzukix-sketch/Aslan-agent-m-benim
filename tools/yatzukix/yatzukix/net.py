"""Network tools: host discovery, port scan, banner grab, service detect."""

import concurrent.futures
import ipaddress
import socket
import ssl
import time

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
    514, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1723, 2049, 2375, 2376,
    3000, 3306, 3389, 4443, 5000, 5432, 5601, 5900, 5984, 6379, 7001, 8000,
    8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017,
]

SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    514: "syslog", 587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 2375: "docker", 2376: "docker-tls", 3000: "dev-http",
    3306: "mysql", 3389: "rdp", 4443: "https-alt", 5000: "http-alt",
    5432: "postgres", 5601: "kibana", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 7001: "weblogic", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9000: "http-alt", 9090: "http-alt", 9200: "elasticsearch", 9300: "es-transport",
    10000: "webmin", 11211: "memcached", 27017: "mongodb",
}

RISKY_PORTS = {
    23: "Telnet: sifresiz trafik",
    21: "FTP: kimlik bilgileri acik metin",
    445: "SMB: fidye yazilimi / lateral hareket",
    3389: "RDP: brute-force ve BlueKeep hedefi",
    5900: "VNC: cogu zaman kimlik dogrulamasiz",
    6379: "Redis: genelde auth yok, RCE riski",
    11211: "Memcached: amplifikasyon ve veri sizmasi",
    27017: "MongoDB: eski surumlerde auth yok",
    9200: "Elasticsearch: acik index, veri sizmasi",
    2375: "Docker API: sifresiz = root",
}


def parse_ports(spec, default=None):
    """'22,80,1000-1010' -> [22, 80, 1000, ...]"""
    if not spec:
        return list(default if default is not None else COMMON_PORTS)
    ports = []
    for chunk in str(spec).replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            lo, _, hi = chunk.partition("-")
            try:
                lo_i, hi_i = int(lo), int(hi)
            except ValueError:
                continue
            if lo_i > hi_i:
                lo_i, hi_i = hi_i, lo_i
            ports.extend(range(lo_i, min(hi_i, 65535) + 1))
        else:
            try:
                value = int(chunk)
            except ValueError:
                continue
            if 0 < value < 65536:
                ports.append(value)
    seen, unique = set(), []
    for port in ports:
        if port not in seen:
            seen.add(port)
            unique.append(port)
    return unique


def expand_targets(spec):
    """CIDR, range or single host -> list of host strings."""
    spec = str(spec).strip()
    hosts = []
    for chunk in spec.replace(" ", "").split(","):
        if not chunk:
            continue
        if "/" in chunk:
            try:
                net = ipaddress.ip_network(chunk, strict=False)
            except ValueError:
                continue
            for ip in net.hosts():
                hosts.append(str(ip))
            continue
        if "-" in chunk and chunk.count(".") == 3:
            head, _, tail = chunk.rpartition(".")
            try:
                lo, hi = int(tail.split("-")[0]), int(tail.split("-")[1])
            except (ValueError, IndexError):
                hosts.append(chunk)
                continue
            for last in range(lo, min(hi, 255) + 1):
                hosts.append("%s.%d" % (head, last))
            continue
        hosts.append(chunk)
    return hosts


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def check_port(host, port, timeout=1.0):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def scan_ports(host, ports, timeout=1.0, workers=100, progress=None):
    """Concurrent TCP connect scan. Returns list of open ports."""
    open_ports = []
    done = 0

    def worker(port):
        return port, check_port(host, port, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(worker, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            done += 1
            if progress:
                progress(done, len(ports))
            try:
                port, is_open = future.result()
            except Exception:
                continue
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)


def grab_banner(host, port, timeout=2.0):
    """Pull the first bytes a service offers, plus TLS certificate info."""
    if port in (443, 8443, 465, 993, 995, 636, 4443, 2376):
        return _grab_tls(host, port, timeout)

    payloads = {
        25: b"EHLO yatzukix\r\n",
    }
    http_probe = b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode()

    # Passive read first: services like SSH and SMTP greet you unprompted.
    banner = _read_banner(host, port, None, timeout)
    if banner:
        return banner

    # Nothing volunteered: probe with HTTP, then a bare newline. Covers web
    # servers on non-standard ports and line-oriented services.
    for payload in (payloads.get(port) or http_probe, b"\r\n"):
        banner = _read_banner(host, port, payload, timeout)
        if banner:
            return banner
    return ""


def _read_banner(host, port, payload, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            if payload:
                sock.sendall(payload)
            data = sock.recv(1024)
            return data.decode("utf-8", "replace").strip().replace("\r\n", " | ")
    except (OSError, socket.timeout):
        return ""


def _grab_tls(host, port, timeout=3.0):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                bits = tls.version() or "?"
                cipher = tls.cipher()
                cert = tls.getpeercert()
                subject = ""
                if cert:
                    subject = "; ".join(
                        "%s=%s" % (k, v) for pair in cert.get("subject", ()) for k, v in pair
                    )
                return "TLS %s %s %s" % (bits, cipher[0] if cipher else "", subject)
    except Exception as exc:
        return "tls-error: %s" % exc


def identify_service(port, banner):
    hint = SERVICE_HINTS.get(port, "unknown")
    if banner:
        low = banner.lower()
        for token, name in (
            ("ssh-", "openssh"), ("http/", "http"), ("smtp", "smtp"),
            ("imap", "imap"), ("pop3", "pop3"), ("redis", "redis"),
            ("mysql", "mysql"), ("mongodb", "mongodb"), ("elastic", "elasticsearch"),
            ("ftp", "ftp"), ("telnet", "telnet"),
        ):
            if token in low:
                hint = name
                break
    return hint


def ping_sweep(hosts, timeout=1.0, workers=100):
    """TCP-based liveness check on common ports (works without raw sockets)."""
    probes = (80, 443, 22, 445, 3389)
    alive = []

    def worker(host):
        for port in probes:
            if check_port(host, port, timeout):
                return host, port
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for result in pool.map(worker, hosts):
            if result:
                alive.append(result)
    return alive
