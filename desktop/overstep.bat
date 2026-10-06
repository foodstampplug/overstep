@echo off
title overstep
echo Starting overstep Pro GUI...
start "overstep server" wsl.exe -e bash -lc "cd ~/overstep && python3 -m overstep gui --no-browser --port 8000"
timeout /t 3 >nul
start "" http://127.0.0.1:8000/
exit
