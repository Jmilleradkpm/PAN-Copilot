"""
PAN Copilot — Desktop Launcher
================================
This is the PyInstaller entry point.

What it does:
  1. Finds a free localhost port
  2. Starts the FastAPI server on 127.0.0.1:<port> (background thread)
  3. Waits for the server to be ready
  4. Opens a native desktop window (pywebview / WebView2) — no browser required
  5. Window close shuts down the process cleanly

Everything runs on your machine. Your configs never leave.
"""

import os
import socket
import sys
import threading
import time
import traceback

# PyInstaller windowed builds leave sys.stdout/stderr as None.
# Redirect to devnull so nothing crashes on write.
if sys.stdout is None or sys.stderr is None:
    _devnull = open(os.devnull, "w")
    if sys.stdout is None:
        sys.stdout = _devnull
    if sys.stderr is None:
        sys.stderr = _devnull

import logging.config as _logging_config
import uvicorn
import uvicorn.config

# ── isatty() crash fix ───────────────────────────────────────────────────────
# uvicorn's DefaultFormatter calls sys.stdout.isatty() inside dictConfig.
# Patch dictConfig itself to swap out uvicorn formatter factories before they run.

_orig_dictConfig = _logging_config.dictConfig

def _safe_dictConfig(cfg):
    if isinstance(cfg, dict):
        for fmt in cfg.get("formatters", {}).values():
            factory = fmt.get("()")
            if isinstance(factory, str) and "uvicorn" in factory:
                fmt["()"] = "logging.Formatter"
                fmt.pop("use_colors", None)
    _orig_dictConfig(cfg)

_logging_config.dictConfig = _safe_dictConfig
uvicorn.config.Config.configure_logging = lambda self: None
# ─────────────────────────────────────────────────────────────────────────────


def _show_crash_dialog(message: str) -> None:
    """Surface a fatal startup error in a Windows MessageBox."""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(
            0, message, "PAN Copilot — Startup Error", 0x10
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_server(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    port = find_free_port()
    url  = f"http://127.0.0.1:{port}"

    from app import app as fastapi_app

    config = uvicorn.Config(
        fastapi_app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)

    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    if not wait_for_server(port):
        _show_crash_dialog(
            "PAN Copilot server did not start in time.\n"
            f"Try opening manually: {url}"
        )
        sys.exit(1)

    # ── Native window via pywebview ──────────────────────────────────────────
    import webview

    window = webview.create_window(
        "PAN Copilot",
        url,
        width=1280,
        height=820,
        min_size=(900, 600),
        resizable=True,
        text_select=False,
    )

    # When the window closes, signal uvicorn to stop
    def on_closed():
        server.should_exit = True

    window.events.closed += on_closed

    # Start the GUI event loop — blocks until window is closed
    # edgechromium uses WebView2 (built into Windows 10/11 via Edge) — no pythonnet needed
    webview.start(debug=False, gui='edgechromium')

    # Give uvicorn a moment to shut down cleanly
    server_thread.join(timeout=3.0)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        _show_crash_dialog(
            "PAN Copilot failed to start.\n\n"
            f"{traceback.format_exc()}\n\n"
            "Please report this error to support@adkcyber.com."
        )
        sys.exit(1)
