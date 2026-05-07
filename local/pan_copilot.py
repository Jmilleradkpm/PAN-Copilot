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
import webbrowser

# PyInstaller bundles without a console window, leaving sys.stdout/stderr as
# None. Uvicorn's log formatter calls .isatty() on them and crashes.
# Redirect to devnull so uvicorn starts cleanly.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

import uvicorn

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
    main()
