#!/usr/bin/env python3
"""yatzukix tool's - entry point.

    python3 yatzukix.py            # interaktif menu
    python3 yatzukix.py scan -h    # alt komutlar
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from yatzukix.cli import main

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n  [!] Kesildi.")
        raise SystemExit(130)
