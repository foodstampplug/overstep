# Creates a Desktop shortcut "overstep" that launches the Pro GUI, with the custom icon.
# Run once: right-click this file -> Run with PowerShell  (or:  powershell -ExecutionPolicy Bypass -File .\Create-OverstepShortcut.ps1)
$desktop = [Environment]::GetFolderPath('Desktop')
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut("$desktop\overstep.lnk")
$sc.TargetPath = "$desktop\overstep.bat"
$sc.WorkingDirectory = $desktop
$sc.IconLocation = "$desktop\overstep.ico"
$sc.Description = "Launch the overstep Pro GUI"
$sc.Save()
Write-Host "Created 'overstep' shortcut on your Desktop (icon + double-click to launch)."
