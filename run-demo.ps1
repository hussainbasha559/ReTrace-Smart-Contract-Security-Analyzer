# One-command demo launcher (Windows PowerShell).  Usage:  .\run-demo.ps1
# If blocked:  Set-ExecutionPolicy -Scope Process Bypass
$root = $PSScriptRoot
$be = Join-Path $root "backend"

if (Select-String -Path "$be\.env" -Pattern "^DATABASE_URL=.*PUT_PASSWORD_HERE" -Quiet) {
  Write-Host "Edit backend\.env first: set DATABASE_URL to your Supabase Session-pooler string (see docs/supabase-setup.md)." -ForegroundColor Yellow
  exit 1
}

Set-Location $be
if (-not (Test-Path ".venv")) { python -m venv .venv }
& .\.venv\Scripts\Activate.ps1
pip install -q -r requirements.txt
Write-Host "Testing database connection..."
python -c "from app.db import get_engine; from sqlalchemy import text; print('DB OK:', get_engine().connect().execute(text('select version()')).scalar())"
if ($LASTEXITCODE -ne 0) { Write-Host "DB connection failed - run 'python verify_db.py' in backend for a diagnosis." -ForegroundColor Red; exit 1 }
alembic upgrade head
Write-Host "Create your admin account (once):  python -m app.cli create-admin --email you@example.com --name `"Your Name`"" -ForegroundColor Cyan

# Backend in a new window, frontend in this one
Start-Process powershell -ArgumentList "-NoExit","-Command","cd '$be'; .\.venv\Scripts\Activate.ps1; uvicorn app.main:app --port 8000"
Set-Location (Join-Path $root "frontend")
npm install
npm run dev
