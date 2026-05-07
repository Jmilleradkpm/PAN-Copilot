"""
PAN Copilot — Desktop Launcher
================================
This is the PyInstaller entry point.

What it does:
  1. Finds a free localhost port
  2. Starts the FastAPI server on 127.0.0.1:<port> (background thread)
  3. Waits for the server to be ready
  4. Opens the user's default browser to http://127.0.0.1:<port>
  5. Keeps the process alive until the window is closed

Everything runs on your machine. Your configs never leave.
"""

import os
import socket
import sys
import threading
import time
import traceback
import webbrowser

# PyInstaller bundles without a console window, leaving sys.stdout/stderr as
# None. Uvicorn's DefaultFormatter calls sys.stdout.isatty() and crashes.
# Fix 1: redirect None streams to devnull.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

import logging.config as _logging_config
import uvicorn
import uvicorn.config
import uvicorn.logging as _uvlog

# ── isatty() crash fix ───────────────────────────────────────────────────────
# In a --windowed PyInstaller build sys.stdout/stderr are None.
# uvicorn's DefaultFormatter calls sys.stdout.isatty() inside __init__ and
# crashes before the server ever starts.
#
# Root cause: uvicorn.Config calls logging.config.dictConfig(LOGGING_CONFIG)
# which instantiates DefaultFormatter via its '()' factory string.
# Every higher-level patch (replacing the class, patching the method, making
# configure_logging a no-op) has proven unreliable across Python/PyInstaller
# versions because of how the frozen import machinery resolves names.
#
# The only approach that cannot be bypassed: patch dictConfig itself.
# dictConfig is a plain function in stdlib logging.config — we replace it with
# a wrapper that strips uvicorn's custom formatter factories before the call,
# substituting the safe stdlib logging.Formatter instead.
# No custom formatter → no isatty() call → no crash.

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

# Belt-and-suspenders: also silence configure_logging entirely.
uvicorn.config.Config.configure_logging = lambda self: None
# ─────────────────────────────────────────────────────────────────────────────


def _show_crash_dialog(message: str) -> None:
    """Surface a fatal startup error in a Windows MessageBox so users see what failed.

    Without this, an unhandled exception in a --windowed PyInstaller build either
    crashes silently or pops a generic 'Failed to execute script' dialog that
    doesn't include our app name or contact info.
    """
    try:
        import ctypes
        # MB_ICONERROR (0x10) | MB_OK (0x00)
        ctypes.windll.user32.MessageBoxW(
            0, message, "PAN Copilot — Startup Error", 0x10
        )
    except Exception:
        pass  # If even MessageBox fails, there's nothing more we can do.

# ---------------------------------------------------------------------------
# Find a free port
# ---------------------------------------------------------------------------

def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

# ---------------------------------------------------------------------------
# Wait for server to accept connections
# ---------------------------------------------------------------------------

def wait_for_server(port: int, timeout: float = 15.0):
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

    # Import here so PyInstaller can resolve it
    from app import app

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)

    # Start server in a daemon thread (dies when main thread exits)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    print(f"PAN Copilot starting on {url}")

    # Wait until server is ready, then open browser
    if wait_for_server(port):
        webbrowser.open(url)
        print("Browser opened. PAN Copilot is running.")
        print("Close this window to exit.")
    else:
        print("Server did not start in time. Try opening the browser manually:")
        print(f"  {url}")

    # Keep alive — the daemon thread will keep running
    try:
        server_thread.join()
    except KeyboardInterrupt:
        print("\nShutting down PAN Copilot.")
        sys.exit(0)

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
