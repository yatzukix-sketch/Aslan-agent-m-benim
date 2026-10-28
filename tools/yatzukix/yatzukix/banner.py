"""ASCII banner and startup animation for yatzukix tools."""

import random
import shutil
import sys
import time

from .ui import UI

BANNER = r"""
                       __              __   _         
   __  ______  ____  / /_  __  ______/ /__(_)  __    
  / / / / __ \/ __ \/ __/ / / / / __  / __/ / |/_/    
 / /_/ / /_/ / /_/ / /_  / /_/ / / /_/ / /_/ />  <      
 \__, /\____/\____/\__/  \__,_/  \__,_/\__/_/_/|_|      
/____/          y a t z u k i x   t o o l ' s           
"""

BANNER_SMALL = r"""
 __   __    _         _          _         
 \ \ / /_ _| |_ ___  | |_ ___   | |___  ___ 
  \ V / _` |  _/ _ \ | __/ _ \  | / _ \/ __|
   |_|\__,_|\__\___| \__\___/  |_\___/\___|
"""

TAGLINES = [
    "recon - exploit - report",
    "your keys, your kingdom",
    "no root, no glory",
    "kali in your pocket",
    "offense is the best defense",
]

GRADIENT = ["#ff2d55", "#ff6b1a", "#ffd60a", "#30ff6a", "#00d4ff", "#7b5cff", "#ff2d9b"]

ASCII_GRADIENT = [
    "  .:::::::.  ",
    " ::::::::::: ",
    ":::::::::::::",
    " ::::::::::: ",
    "  .:::::::.  ",
]


def matrix_rain(ui, lines=6, width=60, delay=0.02):
    """Short matrix-style flourish on startup. Skipped when not a tty."""
    if not ui.color or not sys.stdout.isatty():
        return
    glyphs = "01アイウエオカキクケコサシスセソタチツテトナニヌネノ"
    for _ in range(lines):
        row = "".join(random.choice(glyphs) if random.random() > 0.35 else " " for _ in range(width))
        print(ui.paint("  " + row, "green", dim=True))
        time.sleep(delay)


def glitch(text, ui, rounds=4, delay=0.05):
    """Quick character-scramble reveal for the title."""
    if not ui.color or not sys.stdout.isatty():
        print(ui.paint(text, "green", bold=True))
        return
    glyphs = "!@#$%&*<>/\\|_+=~^"
    chars = list(text)
    for _ in range(rounds):
        scrambled = "".join(random.choice(glyphs) if c.strip() and random.random() > 0.5 else c for c in chars)
        sys.stdout.write("\r" + ui.paint("  " + scrambled, "green", bold=True))
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\r" + ui.paint("  " + text, "green", bold=True) + "\n")


def show_banner(ui, animate=True, small=False):
    art = BANNER_SMALL if small else BANNER
    if animate and ui.color and sys.stdout.isatty():
        matrix_rain(ui, lines=4, width=min(70, ui.width))
        for line in art.strip("\n").split("\n"):
            print(ui.paint("  " + line, "green", bold=True))
            time.sleep(0.03)
    else:
        for line in art.strip("\n").split("\n"):
            print(ui.paint("  " + line, "green", bold=True))

    tagline = random.choice(TAGLINES)
    print(ui.paint("  " + tagline.center(ui.width - 4), "grey", dim=True))
    print(ui.paint("  " + "v1.0.0".center(ui.width - 4), "grey", dim=True))
    print()
    print(ui.paint("  " + "-" * (ui.width - 4), "grey", dim=True))


def show_disclaimer(ui, require_accept=True):
    """Authorisation gate. One short block, no lecture."""
    print()
    print(ui.paint("  KULLANIM SARTI", "yellow", bold=True))
    print(ui.paint("  Sadece sahibi oldugun veya yazili izin aldigin sistemlerde kullan.", "white"))
    print(ui.paint("  Izinsiz kullanim TCK 243-245 kapsaminda suc teskil eder.", "grey", dim=True))
    print()
    if not require_accept:
        return True
    answer = ui.ask("Yetkin oldugunu onayliyor musun? (evet/hayir)", default="hayir")
    return str(answer).strip().lower() in ("evet", "e", "yes", "y", "evet.", "1", "true")
