#!/usr/bin/env bash
# yatzukix tool's - installer / launcher for Termux, iSH and plain Linux.
#
#   bash install.sh          # bagimliliklari kur, dogrula, testleri calistir
#   bash install.sh run      # kurmadan dogrudan baslat
#
# Saf Python standart kutuphanesi: pip, cryptography veya derleme gerekmez.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTRY="$HERE/yatzukix.py"

RED=$'\033[38;5;196m'; GREEN=$'\033[38;5;46m'; YELLOW=$'\033[38;5;220m'
CYAN=$'\033[38;5;51m'; GREY=$'\033[38;5;245m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

say()  { printf '%s\n' "$1"; }
ok()   { printf '%s[+]%s %s\n' "$GREEN$BOLD" "$RESET" "$1"; }
warn() { printf '%s[!]%s %s\n' "$YELLOW$BOLD" "$RESET" "$1"; }
err()  { printf '%s[x]%s %s\n' "$RED$BOLD" "$RESET" "$1"; }
step() { printf '\n%s%s%s\n' "$CYAN$BOLD" "$1" "$RESET"; }

detect_platform() {
    if [ -n "${PREFIX:-}" ] && [ -d "${PREFIX:-/nonexistent}/bin" ] && printf '%s' "$PREFIX" | grep -q termux; then
        echo "termux"
    elif [ -f /etc/alpine-release ] && [ "$(uname -m)" = "i686" ]; then
        echo "ish"
    elif [ -f /etc/alpine-release ]; then
        echo "alpine"
    elif [ "$(uname -s)" = "Darwin" ]; then
        echo "macos"
    else
        echo "linux"
    fi
}

find_python() {
    for candidate in python3 python python3.12 python3.11 python3.10 python3.9; do
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
                echo "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

install_python() {
    platform="$1"
    case "$platform" in
        termux)
            pkg update -y >/dev/null 2>&1 || true
            pkg install -y python >/dev/null 2>&1 || true
            ;;
        ish|alpine)
            apk add --no-cache python3 >/dev/null 2>&1 || true
            ;;
        macos)
            if command -v brew >/dev/null 2>&1; then
                brew install python3 >/dev/null 2>&1 || true
            fi
            ;;
        linux)
            if command -v apt-get >/dev/null 2>&1; then
                sudo apt-get install -y python3 >/dev/null 2>&1 || apt-get install -y python3 >/dev/null 2>&1 || true
            elif command -v dnf >/dev/null 2>&1; then
                sudo dnf install -y python3 >/dev/null 2>&1 || true
            elif command -v pacman >/dev/null 2>&1; then
                sudo pacman -S --noconfirm python >/dev/null 2>&1 || true
            fi
            ;;
    esac
}

banner() {
    printf '%s' "$GREEN$BOLD"
    cat <<'ART'
                       __              __   _
     __  ______  ____  / /_  __  ______/ /__(_)  __
    / / / / __ \/ __ \/ __/ / / / / __  / __/ / |/_/
   / /_/ / /_/ / /_/ / /_  / /_/ / / /_/ / /_/ />  <
    \__, /\____/\____/\__/  \__,_/  \__,_/\__/_/_/|_|
   /____/          y a t z u k i x   t o o l ' s
ART
    printf '%s' "$RESET"
    printf '%s  %s%s\n' "$GREY" "kurulum / kurulum dogrulamasi" "$RESET"
}

banner
step "1/4  Ortam tespiti"
PLATFORM="$(detect_platform)"
say "  platform : $PLATFORM"
say "  kabuk    : $BASH_VERSION"
say "  dizin    : $HERE"

step "2/4  Python kontrolu"
PY="$(find_python || true)"
if [ -z "${PY:-}" ]; then
    warn "Uygun Python bulunamadi, kuruluyor..."
    install_python "$PLATFORM"
    PY="$(find_python || true)"
fi
if [ -z "${PY:-}" ]; then
    err "Python 3.8+ kurulamadi. Elle kur: python3"
    exit 1
fi
ok "$PY - $("$PY" --version 2>&1)"

step "3/4  Modul dogrulamasi"
if "$PY" - "$HERE" <<'PYEOF'
import os, sys
root = sys.argv[1]
sys.path.insert(0, root)
modules = ["ui", "net", "payloads", "recon", "web", "crypto", "osint", "banner", "cli"]
failed = []
for name in modules:
    try:
        __import__("yatzukix." + name)
    except Exception as exc:
        failed.append("%s: %s" % (name, exc))
if failed:
    print("  BASARISIZ: " + "; ".join(failed))
    raise SystemExit(1)
print("  %d modul yuklendi: %s" % (len(modules), ", ".join(modules)))
PYEOF
then
    ok "Tum moduller saglam."
else
    err "Modul yuklemesi basarisiz."
    exit 1
fi

chmod +x "$ENTRY" 2>/dev/null || true

step "4/4  Testler"
if "$PY" -m unittest discover -s "$HERE/tests" -t "$HERE" 2>&1 | tail -3; then
    ok "Testler tamam."
else
    warn "Testler hata verdi (ag erisimi gerekmez, yine de kullanilabilir)."
fi

step "Hazir"
say "  Calistir : $PY $ENTRY"
say "  Menu     : $PY $ENTRY menu"
say "  Yardim   : $PY $ENTRY --help"
say ""
say "  ${YELLOW}Not:${RESET} Sadece sahibi oldugun veya yazili izin aldigin sistemlerde kullan."

if [ "${1:-}" = "run" ]; then
    printf '\n'
    exec "$PY" "$ENTRY"
fi
