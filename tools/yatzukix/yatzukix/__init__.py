"""yatzukix tools - modular offensive/defensive security toolkit."""

import os
import sys

__version__ = "1.0.0"


def detect_platform():
    """Identify the runtime so defaults can be tuned per platform.

    iSH emulates 32-bit x86 on iOS: correct but slow, and thread-heavy
    scans thrash. Termux is native ARM and handles full concurrency.
    """
    if os.path.isdir("/proc/ish") or "iSH" in _uname_release():
        return "ish"
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix:
        return "termux"
    if os.path.exists("/etc/alpine-release"):
        return "alpine"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _uname_release():
    try:
        return os.uname().release
    except AttributeError:
        return ""


def default_workers(requested=None):
    """Concurrency ceiling. iSH gets a low cap; everything else is generous."""
    platform = detect_platform()
    caps = {"ish": 24, "termux": 128, "alpine": 64, "macos": 200, "linux": 256}
    cap = caps.get(platform, 128)
    if requested is None:
        return min(100, cap)
    return max(1, min(int(requested), cap))

