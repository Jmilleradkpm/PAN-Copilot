"""
PAN Copilot â€" Desktop Launcher
================================
This is the PyInstaller entry point.

What it does:
  1. Finds a free localhost port
  2. Starts the FastAPI server on 127.0.0.1:<port> (background thread)
  3. Waits for the server to be ready
  4. Opens Edge (or Chrome) in --app mode: a borderless window with no URL bar,
     no tabs, no bookmark bar â€" indistinguishable from a native desktop app
  5. Monitors the browser process; when it exits, the server shuts down cleanly

Everything runs on your machine. Your configs never leave.
"""

import ctypes
import os
import socket
import sys
import threading
import time
import traceback
import subprocess
import shutil

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

# â"€â"€ isatty() crash fix â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
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
# â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€


def _show_crash_dialog(message: str) -> None:
    # Production target is Windows (PyInstaller windowed build). On other
    # platforms (dev machines running the launcher directly) fall back to
    # stderr so the error is at least visible somewhere.
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0, message, "ADK Cyber AI - Startup Error", 0x10
            )
        except Exception:
            pass
    else:
        try:
            sys.stderr.write(f"[startup error] {message}\n")
            sys.stderr.flush()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Single-instance mutex (Windows named mutex)
# ---------------------------------------------------------------------------

_MUTEX_NAME   = "ADKCyberAI_SingleInstance_v1"
_mutex_handle = None  # kept alive for the process lifetime

def _acquire_single_instance_lock() -> bool:
    """
    Try to acquire a Windows named mutex.
    Returns True  if this is the first instance (mutex created, server should start).
    Returns False if another instance already holds it (delegate and exit quickly).
    """
    global _mutex_handle
    try:
        _mutex_handle = ctypes.windll.kernel32.CreateMutexW(None, True, _MUTEX_NAME)
        last_error = ctypes.windll.kernel32.GetLastError()
        if last_error == 183:  # ERROR_ALREADY_EXISTS
            return False
        return True
    except Exception:
        return True  # If ctypes fails (non-Windows?), allow startup


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


def find_browser() -> list:
    """
    Return [exe_path] for the first browser that supports --app mode.
    Prefers Edge (always present on Win10/11), then Chrome.
    """
    candidates = [
        # Edge â€" standard install paths
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        # Chrome â€" standard install paths
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return [path]
    # Last resort: PATH lookup
    for name in ("msedge", "microsoft-edge", "chrome", "google-chrome"):
        found = shutil.which(name)
        if found:
            return [found]
    return []


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not _acquire_single_instance_lock():
        # Another instance is already running — its delegation-aware wait will
        # keep the server alive. This process exits immediately so Edge can
        # delegate the window to the existing instance.
        sys.exit(0)

    port = find_free_port()
    url  = f"http://127.0.0.1:{port}"

    from app import app as fastapi_app
    import app as _app_module

    config = uvicorn.Config(
        fastapi_app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)

    # Give app.py a reference so /api/shutdown can call should_exit.
    _app_module._uvicorn_server = server

    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    if not wait_for_server(port):
        _show_crash_dialog(
            "ADK Cyber AI server did not start in time.\n"
            f"Try opening manually: {url}"
        )
        sys.exit(1)

    # ── Open browser in app mode (no URL bar, no tabs) ──────────────────────────
    browser = find_browser()

    # Isolated Edge profile — forces Edge to run as its own process rather than
    # delegating to an existing Edge instance. This means proc.pid is the real
    # window PID, which we write to a file so the installer can kill it cleanly.
    _edge_profile = os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
        "ADKCyberAI", "EdgeProfile"
    )

    # PID file — installer reads this to kill the browser window before
    # overwriting files (avoids "unable to close applications" dialog).
    _pid_file = os.path.join(os.environ.get("TEMP", ""), "adk_cyber_ai_edge.pid")

    if browser:
        app_flags = [
            f"--app={url}",
            f"--user-data-dir={_edge_profile}",
            "--disable-extensions",
            "--no-first-run",
            "--disable-default-apps",
            f"--window-size=1280,820",
        ]
        _launch_time = time.time()
        proc = subprocess.Popen(browser + app_flags)

        # Write browser PID so the installer can kill it precisely
        try:
            with open(_pid_file, "w") as _f:
                _f.write(str(proc.pid))
        except Exception:
            pass

        proc.wait()
        _browser_lifetime = time.time() - _launch_time

        # Clean up PID file
        try:
            os.remove(_pid_file)
        except Exception:
            pass

        if _browser_lifetime < 5.0:
            # Browser delegated to an existing instance — keep server alive.
            # /api/shutdown (called by beforeunload) will set should_exit.
            # Safety net: auto-exit after 60 minutes.
            server_thread.join(timeout=3600)
        server.should_exit = True
    else:
        # No supported browser found â€" fall back to default browser
        import webbrowser
        webbrowser.open(url)
        # Keep alive until interrupted
        try:
            server_thread.join()
        except KeyboardInterrupt:
            pass

    server_thread.join(timeout=3.0)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        _show_crash_dialog(
            "ADK Cyber AI failed to start.\n\n"
            f"{traceback.format_exc()}\n\n"
            "Please report this error to support@adkcyber.com."
        )
        sys.exit(1)

