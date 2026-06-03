"""Make the src/ layout importable when running tests without an editable
install (so `python -m pytest -q` works straight from a clone)."""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
