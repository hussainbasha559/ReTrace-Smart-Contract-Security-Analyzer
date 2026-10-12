# Starts the ReTrace backend on Windows:  Heimdall runs in Ubuntu/WSL2, Mythril runs in Docker.
#
#   .\start-backend.ps1                  # uses the WSL distro named "Ubuntu"
#   .\start-backend.ps1 -Distro Ubuntu-22.04
#
# If PowerShell blocks the script:  Set-ExecutionPolicy -Scope Process Bypass
param([string]$Distro = "Ubuntu")

Set-Location $PSScriptRoot
if (-not (Test-Path ".venv")) { python -m venv .venv }
& .\.venv\Scripts\Activate.ps1
pip install -q -r requirements.txt

$env:RETRACE_HEIMDALL_MODE = "wsl"
$env:RETRACE_WSL_DISTRO    = $Distro
$env:RETRACE_MYTHRIL_MODE  = "docker"
# $env:RETRACE_MYTHRIL_TIMEOUT_S = "120"      # raise for larger contracts

Write-Host "Checking tools (Mythril analysis takes about a minute)..."
python verify_tools.py --no-mythril
uvicorn app.main:app --reload --port 8000
