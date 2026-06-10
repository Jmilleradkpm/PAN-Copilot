"""Test setup for the license server.

Critical secrets are read at module import time, so set safe test values in the
environment BEFORE importing app, and point the DB at a throwaway temp file.
"""
import os
import sys
import tempfile
from pathlib import Path

LS_DIR = Path(__file__).resolve().parents[1]
if str(LS_DIR) not in sys.path:
    sys.path.insert(0, str(LS_DIR))

os.environ.setdefault("DB_PATH", str(Path(tempfile.gettempdir()) / "ls_pytest.db"))
os.environ.setdefault("SECRET_PEPPER", "test-pepper")
os.environ.setdefault("LS_WEBHOOK_SECRET", "test-webhook-secret")
os.environ.setdefault("ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-ant-test-key")
os.environ.setdefault("TRUSTED_PROXY_HOPS", "1")
