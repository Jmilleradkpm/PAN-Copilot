@echo off
cd /d "%~dp0"
echo === Force pushing to GitHub (overwrites remote) ===
git push -u origin main --force
echo.
echo === Done! ===
pause
