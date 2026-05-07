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
import uvicorn.config
import uvicorn.logging as _uvlog

# ── Definitive isatty() fix ──────────────────────────────────────────────────
#
# In a --windowed PyInstaller build sys.stdout/stderr are None.
# uvicorn's DefaultFormatter (and AccessFormatter) call sys.stdout.isatty()
# inside __init__ when use_colors is not explicitly set → AttributeError.
#
# Three layers of defence, all applied before any uvicorn.Config is created:
#
#  Layer 1 – stdout/stderr redirect (above): ensures streams are valid file
#            objects so isatty() won't crash even if layers 2/3 ever miss.
#
#  Layer 2 – Patch __init__ on the class objects themselves.
#            logging.config.dictConfig resolves formatter classes by string
#            ("uvicorn.logging.DefaultFormatter"), gets the class OBJECT, then
#            instantiates it.  Replacing the class reference in the module
#            namespace (the approach that didn't work) can be bypassed by
#            importlib; patching __init__ directly on the object cannot —
#            the class is the same object regardless of how it was imported.
#
_orig_default = _uvlog.DefaultFormatter.__init__
def _safe_default(self, *args, use_colors=None, **kwargs):
    # Force use_colors=False; the isatty() branch is only reached when
    # use_colors is None (neither True nor False).
    _orig_default(self, *args, use_colors=False, **kwargs)
_uvlog.DefaultFormatter.__init__ = _safe_default

if hasattr(_uvlog, "AccessFormatter"):
    _orig_access = _uvlog.AccessFormatter.__init__
    def _safe_access(self, *args, use_colors=None, **kwargs):
        _orig_access(self, *args, use_colors=False, **kwargs)
    _uvlog.AccessFormatter.__init__ = _safe_access

#  Layer 3 – Make configure_logging itself a no-op as belt-and-suspenders.
#            If for any reason layers 1/2 are insufficient, uvicorn will
#            simply skip all logging configuration entirely.
uvicorn.config.Config.configure_logging = lambda self: None
# ────────────────────────────────────────────────────────────────────────────


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
