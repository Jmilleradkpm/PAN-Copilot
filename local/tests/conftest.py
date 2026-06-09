"""Make local/app.py importable for the security unit tests.

`local/` is not a package, so put it on sys.path the way the app runs in
production (cwd == local/).
"""
import sys
from pathlib import Path

LOCAL_DIR = Path(__file__).resolve().parents[1]
if str(LOCAL_DIR) not in sys.path:
    sys.path.insert(0, str(LOCAL_DIR))
