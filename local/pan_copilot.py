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

import uvicorn
import uvicorn.logging as _uv_log

# Fix 2: monkey-patch DefaultFormatter so it never calls sys.stdout.isatty().
# This handles uvicorn versions that ignore log_config=None.
_OrigFormatter = _uv_log.DefaultFormatter
class _SafeFormatter(_OrigFormatter):
    def __init__(self, *args, use_colors=None, **kwargs):
        super().__init__(*args, use_colors=False, **kwargs)
_uv_log.DefaultFormatter = _SafeFormatter

# Fix 3: AccessFormatter has the same isatty vulnerability. We set
# access_log=False below, but belt-and-suspenders in case that ever changes
# or a uvicorn version touches AccessFormatter during config setup anyway.
if hasattr(_uv_log, "AccessFormatter"):
    _OrigAccess = _uv_log.AccessFormatter
    class _SafeAccess(_OrigAccess):
        def __init__(self, *args, use_colors=None, **kwargs):
            super().__init__(*args, use_colors=False, **kwargs)
    _uv_log.AccessFormatter = _SafeAccess


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
        log_config=None,       # disable uvicorn log config to avoid isatty crash
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
