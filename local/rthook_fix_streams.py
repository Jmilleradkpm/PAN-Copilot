"""
PyInstaller runtime hook — runs before any user code.

In a --windowed (no-console) build sys.stdout and sys.stderr are None.
Several libraries (uvicorn, logging) call sys.stdout.isatty() during
initialisation and crash with AttributeError if the stream is None.
Redirect both to devnull here so they are valid file objects by the time
any library import runs.
"""
import os
import sys

if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")
