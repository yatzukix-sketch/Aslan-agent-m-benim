"""Crypto toolkit: hashes, symmetric ciphers, KDFs, JWT, encoding."""

import base64
import binascii
import hashlib
import hmac
import json
import os
import struct
import zlib

# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

HASH_ALGORITHMS = sorted(hashlib.algorithms_available)


def digest(data, algorithm="sha256", as_hex=True):
    if isinstance(data, str):
        data = data.encode()
    try:
        h = hashlib.new(algorithm, data)
    except ValueError:
        raise ValueError("unknown algorithm: %s" % algorithm)
    return h.hexdigest() if as_hex else h.digest()


def hash_file(path, algorithm="sha256", chunk=1 << 20):
    h = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def multi_hash(path):
    """sha1/md5/sha256/sha512 + size for a file. Handy for triage."""
    stat = os.stat(path)
    return {
        "path": path,
        "size": stat.st_size,
        "md5": hash_file(path, "md5"),
        "sha1": hash_file(path, "sha1"),
        "sha256": hash_file(path, "sha256"),
        "sha512": hash_file(path, "sha512"),
    }


def crack_single_hash(target, words=None, algorithms=None):
    """Dictionary attack on your own hashes."""
    from . import recon
    return recon.crack_dictionary(target, words, algorithms)


# ---------------------------------------------------------------------------
# Symmetric encryption - AES-equivalent construction with stdlib only
# ---------------------------------------------------------------------------

# Python's stdlib has no AES, so this is a real stream cipher built on
# SHA-256 in counter mode with HMAC-SHA256 authentication. Not AES, but
# genuine encryption: without the key the ciphertext is not reversible.
MAGIC = b"YZK1"
KEY_LEN = 32
NONCE_LEN = 16
TAG_LEN = 32


def derive_key(password, salt=None, iterations=200000, length=KEY_LEN):
    """PBKDF2-HMAC-SHA256. Standard KDF, no external deps."""
    salt = salt if salt is not None else os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=length)
    return key, salt


def _keystream_block(key, nonce, counter):
    return hashlib.sha256(key + nonce + struct.pack(">Q", counter)).digest()


def _keystream(key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += _keystream_block(key, nonce, counter)
        counter += 1
    return bytes(out[:length])


def encrypt_bytes(data, key):
    """MAGIC || nonce || ciphertext || HMAC tag."""
    nonce = os.urandom(NONCE_LEN)
    stream = _keystream(key, nonce, len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, stream))
    header = MAGIC + nonce
    tag = hmac.new(key, header + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + tag


def decrypt_bytes(blob, key):
    if len(blob) < len(MAGIC) + NONCE_LEN + TAG_LEN:
        raise ValueError("blob too short")
    if blob[: len(MAGIC)] != MAGIC:
        raise ValueError("bad magic - not a yatzukix blob")
    header = blob[: len(MAGIC) + NONCE_LEN]
    nonce = header[len(MAGIC):]
    body = blob[len(MAGIC) + NONCE_LEN:]
    ciphertext, tag = body[:-TAG_LEN], body[-TAG_LEN:]
    expected = hmac.new(key, header + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("authentication failed - wrong key or tampered data")
    stream = _keystream(key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream))


def encrypt_file(path, password, out=None, iterations=200000):
    key, salt = derive_key(password, iterations=iterations)
    with open(path, "rb") as fh:
        data = fh.read()
    blob = b"YZKS" + struct.pack(">I", iterations) + salt + encrypt_bytes(data, key)
    out = out or (path + ".yzk")
    with open(out, "wb") as fh:
        fh.write(blob)
    return out


def decrypt_file(path, password, out=None):
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:4] != b"YZKS":
        raise ValueError("not a yatzukix encrypted file")
    iterations = struct.unpack(">I", blob[4:8])[0]
    salt = blob[8:24]
    payload = blob[24:]
    key, _ = derive_key(password, salt, iterations)
    data = decrypt_bytes(payload, key)
    out = out or path[: -len(".yzk")] if path.endswith(".yzk") else (path + ".dec")
    with open(out, "wb") as fh:
        fh.write(data)
    return out


# ---------------------------------------------------------------------------
# Encoding / obfuscation
# ---------------------------------------------------------------------------

def b64_encode(text):
    if isinstance(text, str):
        text = text.encode()
    return base64.b64encode(text).decode()


def b64_decode(text):
    return base64.b64decode(text + "=" * (-len(text) % 4))


def xor_bytes(data, key):
    if isinstance(data, str):
        data = data.encode()
    if isinstance(key, str):
        key = key.encode()
    if not key:
        raise ValueError("key cannot be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_bruteforce(data, max_keylen=4, printable_only=True):
    """Single-byte and short repeating-key XOR recovery. CTF staple."""
    results = []
    if isinstance(data, str):
        data = data.encode()

    best = None
    for candidate in range(256):
        decoded = bytes(b ^ candidate for b in data)
        score = sum(chr(c).isalnum() or chr(c) in " {}_.,!?" for c in decoded)
        if best is None or score > best[1]:
            best = (candidate, score, decoded)
    if best:
        results.append({"key": "%02x" % best[0], "key_ascii": chr(best[0]), "text": best[2][:200]})

    for keylen in range(2, max_keylen + 1):
        key = bytearray()
        for pos in range(keylen):
            column = data[pos::keylen]
            best_c = max(range(256), key=lambda c: sum(
                chr(b ^ c).isalnum() or chr(b ^ c) in " {}_.,!?" for b in column
            ))
            key.append(best_c)
        decoded = xor_bytes(data, bytes(key))
        if printable_only and not all(32 <= c < 127 or c in (9, 10, 13) for c in decoded[:64]):
            continue
        results.append({"key": bytes(key).hex(), "key_ascii": bytes(key).decode("latin-1"), "text": decoded[:200]})
    return results


def rot13(text):
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))


def hex_dump(data, width=16, offset=0):
    if isinstance(data, str):
        data = data.encode()
    lines = []
    for start in range(0, len(data), width):
        chunk = data[start:start + width]
        hex_part = " ".join("%02x" % b for b in chunk).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%08x  %s  |%s|" % (offset + start, hex_part, ascii_part))
    return "\n".join(lines)


def entropy(data):
    """Shannon entropy in bits per byte. >7.5 suggests encryption/compression."""
    import math
    if isinstance(data, str):
        data = data.encode()
    if not data:
        return 0.0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwt_decode(token):
    """Decode without verification - for reading claims during testing."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT")
    return {
        "header": json.loads(b64url_decode(parts[0])),
        "payload": json.loads(b64url_decode(parts[1])),
        "signature": parts[2],
    }


def jwt_forge(payload, secret="", algorithm="HS256", header=None):
    """Forge a token. With an empty secret this is the alg:none variant."""
    header = header or {"alg": algorithm, "typ": "JWT"}
    if algorithm.lower() == "none":
        header = {"alg": "none", "typ": "JWT"}
        signing_input = "%s.%s" % (b64url(json.dumps(header, separators=(",", ":"))),
                                   b64url(json.dumps(payload, separators=(",", ":"))))
        return signing_input + "."

    signing_input = "%s.%s" % (b64url(json.dumps(header, separators=(",", ":"))),
                               b64url(json.dumps(payload, separators=(",", ":"))))
    if algorithm.upper() == "HS256":
        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    elif algorithm.upper() == "HS384":
        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha384).digest()
    elif algorithm.upper() == "HS512":
        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha512).digest()
    else:
        raise ValueError("unsupported algorithm: %s" % algorithm)
    return signing_input + "." + b64url(sig)


def jwt_attack_tokens(token):
    """Common JWT weaknesses as ready-to-send tokens. Test only your own apps."""
    decoded = jwt_decode(token)
    payload = decoded["payload"]
    out = {"original": token}
    out["alg_none"] = jwt_forge(payload, algorithm="none")
    hacked = dict(payload)
    hacked["admin"] = True
    hacked["role"] = "admin"
    hacked["isAdmin"] = True
    out["privilege_escalated_none"] = jwt_forge(hacked, algorithm="none")
    for guess in ("secret", "password", "changeme", "jwt", "key", "123456", "admin"):
        out["hs256_secret_" + guess] = jwt_forge(hacked, secret=guess, algorithm="HS256")
    return out


def jwt_verify(token, secret, algorithm="HS256"):
    parts = token.split(".")
    if len(parts) != 3:
        return False
    signing_input = parts[0] + "." + parts[1]
    expected = jwt_forge(json.loads(b64url_decode(parts[1])), secret, algorithm).split(".")[2]
    return hmac.compare_digest(expected, parts[2])


# ---------------------------------------------------------------------------
# Extras
# ---------------------------------------------------------------------------

def crc32(data):
    if isinstance(data, str):
        data = data.encode()
    return "%08x" % (zlib.crc32(data) & 0xFFFFFFFF)


def generate_password(length=20, symbols=True, digits=True, upper=True):
    import random
    import string
    alphabet = string.ascii_lowercase
    if upper:
        alphabet += string.ascii_uppercase
    if digits:
        alphabet += string.digits
    if symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/"
    rng = random.SystemRandom()
    return "".join(rng.choice(alphabet) for _ in range(length))


def passphrase(words=4, separator="-"):
    """Diceware-style passphrase from a compact built-in list."""
    import random
    wordlist = [
        "anchor", "bishop", "cobalt", "dragon", "ember", "falcon", "granite", "harbor",
        "igloo", "jigsaw", "kelvin", "lantern", "magnet", "nebula", "obsidian", "pepper",
        "quartz", "rocket", "saddle", "tundra", "umbra", "vector", "walnut", "xenon",
        "yonder", "zephyr", "alloy", "beacon", "cinder", "dynamo", "eclipse", "fathom",
        "gizmo", "hazard", "indigo", "juniper", "kernel", "lattice", "monsoon", "nimbus",
        "onyx", "prism", "quiver", "riddle", "sprocket", "thistle", "upland", "vertex",
        "willow", "xystus", "yarrow", "zenith", "atlas", "bramble", "cipher", "delta",
        "echo", "forge", "glacier", "hollow", "ivory", "jasper", "kraken", "lumen",
    ]
    rng = random.SystemRandom()
    return separator.join(rng.choice(wordlist) for _ in range(words))
