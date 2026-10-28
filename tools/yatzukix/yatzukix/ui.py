"""Terminal UI helpers. Pure stdlib so it runs on Termux and plain Linux."""

import os
import shutil
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

PALETTE = {
    "red": 196,
    "orange": 208,
    "yellow": 220,
    "green": 46,
    "mint": 49,
    "cyan": 51,
    "blue": 33,
    "violet": 99,
    "magenta": 201,
    "pink": 213,
    "grey": 245,
    "white": 231,
}


def color_enabled():
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("YATZUKIX_NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


class UI:
    def __init__(self, color=None):
        self.color = color_enabled() if color is None else bool(color)
        try:
            self.width = max(48, min(shutil.get_terminal_size((80, 24)).columns, 96))
        except Exception:
            self.width = 80

    def paint(self, text, name=None, bold=False, dim=False):
        if not self.color:
            return str(text)
        prefix = ""
        if bold:
            prefix += BOLD
        if dim:
            prefix += DIM
        if name:
            prefix += "\033[38;5;%dm" % PALETTE.get(name, PALETTE["white"])
        return prefix + str(text) + RESET

    def fg(self, name):
        if not self.color:
            return ""
        return "\033[38;5;%dm" % PALETTE.get(name, PALETTE["white"])

    def out(self, text=""):
        print(text)

    def rule(self, char="-"):
        print(self.paint(char * self.width, "grey", dim=True))

    def title(self, text, accent="cyan"):
        print()
        print(self.paint("  " + text.upper(), accent, bold=True))
        self.rule("=")

    def header(self, text, accent="cyan"):
        print()
        print(self.paint("[ " + text + " ]", accent, bold=True))

    def kv(self, key, value, key_color="grey", value_color="white"):
        print("  %s %s" % (self.paint(str(key).ljust(22), key_color), self.paint(str(value), value_color)))

    def bullet(self, text, color="white"):
        print("  " + self.paint("*", color) + " " + str(text))

    def ok(self, text):
        print(self.paint("  [+]", "green", bold=True) + " " + str(text))

    def warn(self, text):
        print(self.paint("  [!]", "yellow", bold=True) + " " + str(text))

    def err(self, text):
        print(self.paint("  [x]", "red", bold=True) + " " + str(text))

    def info(self, text):
        print(self.paint("  [i]", "cyan", bold=True) + " " + str(text))

    def table(self, headers, rows, accent="cyan"):
        rows = [[("" if c is None else str(c)) for c in row] for row in rows]
        widths = [len(str(h)) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(cell))
        head = "  " + "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers))
        print(self.paint(head, accent, bold=True))
        self.rule("-")
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                cells.append(cell.ljust(widths[i]) if i < len(widths) else cell)
            print("  " + "  ".join(cells))

    def ask(self, prompt, default=None):
        suffix = " [%s]" % default if default is not None else ""
        try:
            raw = input(self.paint("  " + prompt + suffix + ": ", "mint", bold=True)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if not raw and default is not None:
            return default
        return raw

    def pause(self):
        try:
            input(self.paint("\n  devam etmek icin Enter...", "grey", dim=True))
        except (EOFError, KeyboardInterrupt):
            print()
