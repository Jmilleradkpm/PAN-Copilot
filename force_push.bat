@echo off
cd /d "%~dp0"
echo === Force pushing to GitHub (--force-with-lease; aborts if remote moved) ===
git push -u origin main --force-with-lease
echo.
echo === Done! ===
pause
