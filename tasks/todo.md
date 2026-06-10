# PAN Copilot Executable Crash Investigation

## Plan

- [x] Capture the exact crash evidence from the screenshot and map it to the local source tree.
- [x] Identify the executable entry point, runtime framework, and packaging/build path.
- [x] Trace `uvicorn` logging initialization to find why `sys.stderr` or `sys.stdout` is `None`.
- [x] Reproduce the failure or the failing configuration path locally with the smallest command possible.
- [x] Implement the smallest root-cause fix if the repository contains the executable source.
- [x] Verify the fix with targeted tests/checks and document the result.

## Review

- Root cause: the failing executable was built as a windowed PyInstaller app before the stream/runtime-hook fix was included. In that mode, `sys.stdout`/`sys.stderr` can be `None`; Uvicorn's default logging formatter calls `.isatty()` and aborts during `uvicorn.Config(...)`.
- Evidence: `local/dist/PAN Copilot/PAN Copilot.exe` is older than the current fixed `local/pan_copilot.py`, `local/pan_copilot.spec`, and `local/rthook_fix_streams.py`. The old `local/build/pan_copilot/Analysis-00.toc` does not include `rthook_fix_streams.py`.
- Reproduction: forcing `sys.stdout = None` and `sys.stderr = None`, then applying `logging.config.dictConfig(uvicorn.config.LOGGING_CONFIG)`, fails with `ValueError: Unable to configure formatter 'default'`.
- Fix verification: importing the current launcher under forced `None` streams repairs both streams and allows `uvicorn.Config(...)` construction.
- Build verification: `python -m PyInstaller pan_copilot.spec --noconfirm --workpath "$env:TEMP\pan_copilot_build_verify" --distpath "$env:TEMP\pan_copilot_dist_verify"` succeeded and explicitly included `rthook_fix_streams.py`.
- Runtime smoke test: the rebuilt temp executable stayed running after 6 seconds instead of exiting/crashing, then the test process was stopped.
- Local build caveat: rebuilding directly under the OneDrive workspace failed with Windows `Access is denied` against PyInstaller build artifacts/resource editing; building from/to a non-OneDrive temp path succeeded.

# Working Executable Fix

## Plan

- [ ] Check current git state and identify which local changes are required for the fix.
- [ ] Make helper scripts portable so moving off OneDrive does not break push/build shortcuts.
- [ ] Align the local Git remote with the exact GitHub repository URL.
- [ ] Build the executable from current fixed source using a non-OneDrive build path.
- [ ] Smoke-test the rebuilt executable for startup stability.
- [ ] Package the working executable folder into a zip.
- [ ] Document final output paths and verification results.

## Review

- Pending.
