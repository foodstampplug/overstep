# overstep — desktop launcher

Double-click overstep on your desktop → the Pro GUI opens in your browser. No terminal needed.

## Install (one time)
These three files go on your **Windows Desktop**: `overstep.bat`, `overstep.ico`,
`Create-OverstepShortcut.ps1`. Then make the icon shortcut:

- Right-click **Create-OverstepShortcut.ps1** → **Run with PowerShell**
  (or in a terminal: `powershell -ExecutionPolicy Bypass -File .\Create-OverstepShortcut.ps1`)

That creates an **overstep** shortcut on your Desktop with the custom icon. Double-click it any
time — it starts the GUI (via WSL) on http://127.0.0.1:8000 and opens your browser.

## How it works
`overstep.bat` runs `python3 -m overstep gui` inside WSL (from `~/overstep`) and opens the page.
Closing the little "overstep server" window stops it. Assumes the repo is at `~/overstep` in WSL
(change the path in `overstep.bat` if yours differs).

## Native Windows Python instead of WSL?
If you run Python on Windows directly, replace the `start ... wsl.exe ...` line in `overstep.bat`
with, from the repo folder: `start "overstep server" cmd /k py -m overstep gui --no-browser --port 8000`.

## A true compiled .exe (optional, needs a Windows Python)
```
pip install pyinstaller
pyinstaller --onefile --name overstep --icon desktop\overstep.ico ^
  --add-data "overstep\web;overstep/web" run_gui.py
```
where `run_gui.py` is `from overstep.gui import serve; serve()`. Produces `dist\overstep.exe` with
the icon baked in. (Can't be built from this Linux/WSL environment — run it on Windows.)
