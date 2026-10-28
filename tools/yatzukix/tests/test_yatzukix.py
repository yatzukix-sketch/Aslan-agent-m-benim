"""Offline self-tests for yatzukix tool's. No network required."""

import contextlib
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from yatzukix import crypto, net, osint, payloads, recon, web
from yatzukix import default_workers, detect_platform


class _EchoHandler(BaseHTTPRequestHandler):
    """Reflects query values into the body, never redirects."""

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        body = "".join("<div>%s</div>" % v[0] for v in query.values()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _RedirectHandler(BaseHTTPRequestHandler):
    """Honours the `next` parameter with a real 302 - an actual open redirect."""

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        target = query.get("next", [""])[0]
        self.send_response(302)
        self.send_header("Location", target)
        self.end_headers()

    def log_message(self, *args):
        pass


@contextlib.contextmanager
def _local_http_server(handler):
    """Run a real HTTP server on a free localhost port for the test body."""
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:%d" % server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class TestPlatformTuning(unittest.TestCase):
    def test_detect_returns_known_platform(self):
        self.assertIn(detect_platform(), ("ish", "termux", "alpine", "macos", "linux"))

    def test_ish_detected_via_proc_marker(self):
        """iSH exposes /proc/ish; the detector must honour it."""
        import tempfile
        from unittest import mock
        with mock.patch("yatzukix.os.path.isdir", side_effect=lambda p: p == "/proc/ish"):
            self.assertEqual(detect_platform(), "ish")

    def test_ish_caps_workers_hard(self):
        from unittest import mock
        with mock.patch("yatzukix.detect_platform", return_value="ish"):
            self.assertLessEqual(default_workers(500), 24)
            self.assertEqual(default_workers(), 24)

    def test_linux_allows_high_workers(self):
        from unittest import mock
        with mock.patch("yatzukix.detect_platform", return_value="linux"):
            self.assertEqual(default_workers(500), 256)

    def test_requested_none_gives_default(self):
        from unittest import mock
        with mock.patch("yatzukix.detect_platform", return_value="termux"):
            self.assertEqual(default_workers(), 100)
            self.assertEqual(default_workers(50), 50)

    def test_workers_never_below_one(self):
        from unittest import mock
        with mock.patch("yatzukix.detect_platform", return_value="ish"):
            self.assertEqual(default_workers(0), 1)
            self.assertEqual(default_workers(-5), 1)


class TestPortParsing(unittest.TestCase):
    def test_range_and_list(self):
        self.assertEqual(net.parse_ports("22,80,100-102"), [22, 80, 100, 101, 102])

    def test_dedupe_and_order(self):
        self.assertEqual(net.parse_ports("80,80,22,22"), [80, 22])

    def test_invalid_tokens_skipped(self):
        self.assertEqual(net.parse_ports("abc,443,"), [443])

    def test_default_is_common(self):
        self.assertEqual(net.parse_ports(None), net.COMMON_PORTS)

    def test_out_of_range_skipped(self):
        self.assertEqual(net.parse_ports("0,70000,8080"), [8080])


class TestTargetExpansion(unittest.TestCase):
    def test_cidr(self):
        hosts = net.expand_targets("192.168.1.0/30")
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])

    def test_range(self):
        self.assertEqual(net.expand_targets("10.0.0.1-3"), ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_single_and_list(self):
        self.assertEqual(net.expand_targets("a.example,b.example"), ["a.example", "b.example"])


class TestServiceId(unittest.TestCase):
    def test_banner_overrides_hint(self):
        self.assertEqual(net.identify_service(1234, "SSH-2.0-OpenSSH_8.9"), "openssh")

    def test_port_hint_used_without_banner(self):
        self.assertEqual(net.identify_service(443, ""), "https")

    def test_unknown_port(self):
        self.assertEqual(net.identify_service(12345, ""), "unknown")


class TestCryptoRoundTrip(unittest.TestCase):
    def test_encrypt_decrypt_bytes(self):
        key = os.urandom(crypto.KEY_LEN)
        data = b"yatzukix payload \x00\xff binary"
        blob = crypto.encrypt_bytes(data, key)
        self.assertNotEqual(blob, data)
        self.assertEqual(crypto.decrypt_bytes(blob, key), data)

    def test_wrong_key_rejected(self):
        key = os.urandom(crypto.KEY_LEN)
        blob = crypto.encrypt_bytes(b"secret", key)
        with self.assertRaises(ValueError):
            crypto.decrypt_bytes(blob, os.urandom(crypto.KEY_LEN))

    def test_tamper_detected(self):
        key = os.urandom(crypto.KEY_LEN)
        blob = bytearray(crypto.encrypt_bytes(b"secret data here", key))
        blob[-1] ^= 0x01
        with self.assertRaises(ValueError):
            crypto.decrypt_bytes(bytes(blob), key)

    def test_empty_payload(self):
        key = os.urandom(crypto.KEY_LEN)
        self.assertEqual(crypto.decrypt_bytes(crypto.encrypt_bytes(b"", key), key), b"")

    def test_file_round_trip_with_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = os.path.join(tmp, "data.bin")
            payload = bytes(range(256)) * 40
            with open(original, "wb") as fh:
                fh.write(payload)
            enc = crypto.encrypt_file(original, "s3cret", iterations=1000)
            self.assertTrue(os.path.exists(enc))
            with open(enc, "rb") as fh:
                self.assertNotEqual(fh.read(), payload)
            dec = crypto.decrypt_file(enc, "s3cret", out=os.path.join(tmp, "out.bin"))
            with open(dec, "rb") as fh:
                self.assertEqual(fh.read(), payload)

    def test_file_wrong_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "data.bin")
            with open(path, "wb") as fh:
                fh.write(b"hello")
            enc = crypto.encrypt_file(path, "right", iterations=1000)
            with self.assertRaises(ValueError):
                crypto.decrypt_file(enc, "wrong", out=os.path.join(tmp, "x.bin"))

    def test_derived_key_is_deterministic(self):
        key1, salt = crypto.derive_key("pw", b"0" * 16, iterations=1000)
        key2, _ = crypto.derive_key("pw", salt, iterations=1000)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), crypto.KEY_LEN)


class TestHashes(unittest.TestCase):
    def test_known_digests(self):
        self.assertEqual(recon.hash_text("abc", "md5"), "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(recon.hash_text("abc", "sha1"), "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(
            recon.hash_text("abc", "sha256"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_unknown_algorithm_raises(self):
        with self.assertRaises(ValueError):
            recon.hash_text("abc", "not-a-hash")

    def test_identify_md5_and_sha256(self):
        names = [name for name, _, _ in recon.identify_hash("900150983cd24fb0d6963f7d28e17f72")]
        self.assertIn("MD5", names)
        names = [name for name, _, _ in recon.identify_hash("a" * 64)]
        self.assertIn("SHA256", names)

    def test_identify_bcrypt_and_sha512crypt(self):
        self.assertEqual(recon.identify_hash("$2b$12$" + "x" * 53)[0][0], "bcrypt")
        self.assertEqual(recon.identify_hash("$6$salt$" + "y" * 86)[0][0], "SHA512crypt")

    def test_dictionary_crack_hits(self):
        target = recon.hash_text("admin", "md5")
        result = recon.crack_dictionary(target, ["nope", "admin"])
        self.assertEqual(result, ("admin", "md5"))

    def test_dictionary_crack_miss(self):
        self.assertIsNone(recon.crack_dictionary(recon.hash_text("zzz", "md5"), ["a", "b"]))

    def test_rules_expand(self):
        variants = recon.crack_rules("pass")
        self.assertIn("pass123", variants)
        self.assertIn("P@ss", variants)

    def test_wordlist_file_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "wl.txt")
            count = recon.generate_wordlist(["admin"], out)
            self.assertGreater(count, 5)
            with open(out, encoding="utf-8") as fh:
                lines = [line.strip() for line in fh if line.strip()]
            self.assertEqual(len(lines), count)
            self.assertEqual(len(lines), len(set(lines)))


class TestJWT(unittest.TestCase):
    def test_forge_and_verify(self):
        token = crypto.jwt_forge({"user": "alice"}, secret="hunter2", algorithm="HS256")
        self.assertTrue(crypto.jwt_verify(token, "hunter2", "HS256"))
        self.assertFalse(crypto.jwt_verify(token, "wrong", "HS256"))

    def test_decode_round_trip(self):
        token = crypto.jwt_forge({"role": "user", "n": 1}, secret="k")
        decoded = crypto.jwt_decode(token)
        self.assertEqual(decoded["payload"]["role"], "user")
        self.assertEqual(decoded["header"]["alg"], "HS256")

    def test_alg_none_variant(self):
        token = crypto.jwt_forge({"role": "admin"}, algorithm="none")
        self.assertTrue(token.endswith("."))
        self.assertEqual(crypto.jwt_decode(token)["header"]["alg"], "none")

    def test_attack_tokens_include_escalation(self):
        token = crypto.jwt_forge({"role": "user"}, secret="real")
        attacks = crypto.jwt_attack_tokens(token)
        self.assertIn("alg_none", attacks)
        escalated = crypto.jwt_decode(attacks["privilege_escalated_none"])
        self.assertTrue(escalated["payload"]["admin"])


class TestXORAndEncoding(unittest.TestCase):
    def test_xor_round_trip(self):
        data = b"the quick brown fox"
        self.assertEqual(crypto.xor_bytes(crypto.xor_bytes(data, b"key"), b"key"), data)

    def test_single_byte_recovery(self):
        plaintext = b"flag{this_is_the_secret}"
        encrypted = crypto.xor_bytes(plaintext, b"\x42")
        results = crypto.xor_bruteforce(encrypted, max_keylen=1)
        self.assertTrue(any(b"flag{" in r["text"] for r in results))

    def test_base64_round_trip(self):
        self.assertEqual(crypto.b64_decode(crypto.b64_encode("merhaba")), b"merhaba")

    def test_rot13_is_involutive(self):
        self.assertEqual(crypto.rot13(crypto.rot13("Hello World")), "Hello World")

    def test_entropy_bounds(self):
        self.assertLess(crypto.entropy(b"a" * 500), 0.1)
        self.assertGreater(crypto.entropy(os.urandom(4096)), 7.0)

    def test_hex_dump_shape(self):
        dump = crypto.hex_dump(b"ABC")
        self.assertIn("00000000", dump)
        self.assertIn("|ABC|", dump)

    def test_password_and_passphrase(self):
        self.assertEqual(len(crypto.generate_password(24)), 24)
        self.assertEqual(len(crypto.passphrase(4).split("-")), 4)


class TestPayloads(unittest.TestCase):
    def test_all_shells_format(self):
        for name in payloads.payload_names():
            code = payloads.generate(name, "10.0.0.5", 4444)
            self.assertIsInstance(code, str)
            self.assertTrue(code.strip())
            self.assertNotIn("{host}", code)
            self.assertNotIn("{port}", code)

    def test_specific_shell(self):
        code = payloads.generate("bash", "1.2.3.4", 9001)
        self.assertIn("1.2.3.4", code)
        self.assertIn("9001", code)

    def test_listeners(self):
        for name in payloads.listener_names():
            command = payloads.listener(name, 4444)
            self.assertTrue(command.strip())

    def test_encoders(self):
        self.assertEqual(payloads.encode("base64", "abc"), "YWJj")
        self.assertEqual(payloads.encode("hex", "abc"), "616263")
        # url encoder fully percent-encodes every byte
        self.assertEqual(payloads.encode("url", "a b"), "%61%20%62")

    def test_msfvenom_catalog(self):
        entries = payloads.msfvenom_catalog("10.0.0.1", 443)
        self.assertGreater(len(entries), 10)
        for _, command in entries:
            self.assertIn("10.0.0.1", command)

    def test_unknown_shell_raises(self):
        with self.assertRaises(KeyError):
            payloads.generate("no-such-shell", "1.2.3.4", 1)


class TestWebHelpers(unittest.TestCase):
    def test_inject_param_replaces_only_target(self):
        url = web.inject_param("http://h/p?a=1&b=2", "a", "' OR 1=1")
        self.assertIn("b=2", url)
        self.assertIn("OR+1%3D1", url)

    def test_extract_forms(self):
        html = '<form action="/login" method="post"><input name="user"><input name="pass"></form>'
        forms = web.extract_forms(html)
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["method"], "POST")
        self.assertEqual(forms[0]["inputs"], ["user", "pass"])

    def test_cve_hints_match(self):
        hints = web.cve_hints("Apache/2.4.49", [])
        self.assertTrue(any("CVE-2021-41773" in description for _, description in hints))

    def test_cve_hints_empty(self):
        self.assertEqual(web.cve_hints("totally-unknown/9", []), [])

    def test_open_redirect_ignores_echoed_query(self):
        """A payload echoed in the URL must not be reported as a redirect."""
        with _local_http_server(_EchoHandler) as base:
            hits = web.test_open_redirect(base + "/search?q=1", "q")
        self.assertEqual(hits, [])

    def test_open_redirect_detects_location_header(self):
        with _local_http_server(_RedirectHandler) as base:
            hits = web.test_open_redirect(base + "/go?next=1", "next")
        self.assertTrue(hits)
        self.assertTrue(all(h["type"] == "open-redirect" for h in hits))
        self.assertIn("evil.example.com", hits[0]["evidence"])


class TestOsint(unittest.TestCase):
    def test_extract_iocs(self):
        text = "C2 45.77.12.9 hit https://evil.example.com/p.sh md5 d41d8cd98f00b204e9800998ecf8427e CVE-2021-44228"
        found = osint.extract_iocs(text)
        self.assertIn("45.77.12.9", found["ipv4"])
        self.assertIn("CVE-2021-44228", found["cve"])
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", found["md5"])

    def test_defang_refang(self):
        self.assertEqual(osint.refang(osint.defang("https://a.b/c")), "https://a.b/c")

    def test_email_intel_valid(self):
        info = osint.email_intel("analyst@example.com")
        self.assertTrue(info["valid"])
        self.assertFalse(info["disposable"])
        self.assertFalse(info["freemail"])

    def test_email_intel_disposable(self):
        info = osint.email_intel("x@mailinator.com")
        self.assertTrue(info["disposable"])

    def test_email_intel_invalid(self):
        self.assertFalse(osint.email_intel("not-an-email")["valid"])

    def test_extract_emails(self):
        self.assertEqual(osint.extract_emails("a@b.com c@d.org"), ["a@b.com", "c@d.org"])

    def test_metadata_reads_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sample.bin")
            with open(path, "wb") as fh:
                fh.write(b"\x7fELF" + b"\x00" * 60)
            info = osint.metadata(path)
            self.assertEqual(info["type"], "ELF binary")
            self.assertEqual(len(info["sha256"]), 64)

    def test_strings_in_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "s.bin")
            with open(path, "wb") as fh:
                fh.write(b"\x00\x01yatzukix-token\x00\x02short")
            found = osint.strings_in_file(path, minimum=6)
            self.assertIn("yatzukix-token", found)

    def test_dorks_available(self):
        self.assertTrue(osint.dorks_for("example.com", "google"))
        self.assertTrue(osint.dorks_for("example.com", "github"))
        self.assertTrue(osint.dorks_for("example.com", "shodan"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
