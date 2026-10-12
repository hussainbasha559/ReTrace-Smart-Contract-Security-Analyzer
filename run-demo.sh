#!/usr/bin/env bash
# One-command demo launcher (macOS/Linux/WSL).  Usage: bash run-demo.sh
set -e
cd "$(dirname "$0")/backend"
grep -q "^DATABASE_URL=.*PUT_PASSWORD_HERE" .env && { echo "Edit backend/.env: replace PUT_PASSWORD_HERE with your freedb password."; exit 1; }
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt
python -c "from app.db import get_engine; from sqlalchemy import text; print('DB OK:', get_engine().connect().execute(text('select version()')).scalar())"
alembic upgrade head
echo "Create admin (once): python -m app.cli create-admin --email you@example.com --name 'Your Name'"
uvicorn app.main:app --port 8000 &
cd ../frontend && npm install && npm run dev
