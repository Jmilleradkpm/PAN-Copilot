@echo off
cd /d "C:\Users\jmill\OneDrive\Documents\Claude\Projects\PAN Copilot"
echo === Force pushing to GitHub (overwrites remote) ===
git push -u origin main --force
echo.
echo === Done! ===
pause
