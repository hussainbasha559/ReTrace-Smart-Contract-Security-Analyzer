# MySQL and MySQL Workbench setup

**How the pieces fit.** ReTrace stores its data in a **MySQL Server** (8.x). **MySQL Workbench** is a separate
desktop program you use to *look at and manage* that server. The FastAPI app connects to the server on port 3306,
never to Workbench. So "using Workbench" means: install the server, connect Workbench to it, and point ReTrace at it.

## 1. Install MySQL Server and Workbench

- **Windows**: download *MySQL Installer* from <https://dev.mysql.com/downloads/installer/>, choose *Server only* + *Workbench*
  (or "Developer Default"). Set a strong **root** password when asked; the server runs as a Windows service on port 3306.
- **macOS**: `brew install mysql && brew services start mysql`, and install Workbench from the MySQL site.
- **Ubuntu/WSL**: `sudo apt install mysql-server && sudo service mysql start`.

## 2. Connect Workbench to the server

1. Open Workbench, click the **+** next to *MySQL Connections*.
2. Connection name `Local`, hostname `127.0.0.1`, port `3306`, username `root`, then **Test Connection**, then OK.
3. Double-click the connection and enter the root password.

## 3. Create the database and a least-privilege app user

In Workbench open a **new SQL tab** (Ctrl+T) and run (change the password!):

```sql
CREATE DATABASE evm_security CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER 'retrace_app'@'localhost' IDENTIFIED BY 'CHOOSE-A-LONG-RANDOM-PASSWORD';
-- DDL rights are needed only so Alembic can create/alter tables. For production, run migrations with a
-- separate admin account and give the app user only SELECT, INSERT, UPDATE, DELETE.
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES ON evm_security.* TO 'retrace_app'@'localhost';
```

Never use `root` in the application and never grant `ALL ON *.*`.

## 4. Configure ReTrace

```bash
cd backend
cp .env.example .env          # Windows: copy .env.example .env
```

Edit `.env`: set `DATABASE_URL` (URL-encode special characters in the password: `#`=`%23`, `:`=`%3A`, `/`=`%2F`, `@`=`%40`)
and `RETRACE_SECRET_KEY` (`python -c "import secrets; print(secrets.token_hex(32))"`). `.env` is git-ignored.

```
DATABASE_URL=mysql+pymysql://retrace_app:URL_ENCODED_PASSWORD@127.0.0.1:3306/evm_security?charset=utf8mb4
```

## 5. Create the tables (Alembic migration)

```bash
pip install -r requirements.txt
alembic upgrade head          # creates 10 tables + alembic_version
alembic current               # should print: 0001 (head)
```

No Alembic? Run `backend/sql/schema.mysql.sql` from a Workbench SQL tab after `USE evm_security;`.

## 6. Test the connection

```bash
python -c "from app.db import get_engine; from sqlalchemy import text; print(get_engine().connect().execute(text('select version()')).scalar())"
```

It prints the MySQL version. A password/host error appears as `OperationalError`; check the URL encoding first.

## 7. Create an administrator, then run

```bash
python -m app.cli create-admin --email you@example.com --name "Your Name"   # asks for the password
uvicorn app.main:app --reload
```

Normal users register in the web UI; only the CLI can create admins.

## 8. Inspect tables and relationships in Workbench

- **Data**: *Schemas* panel, `evm_security`, *Tables*, right-click a table, **Select Rows - Limit 1000**.
- **Diagram**: menu **Database > Reverse Engineer...**, pick the `Local` connection, select `evm_security`, finish.
  Workbench draws an EER diagram with all foreign keys.
- **Structure**: right-click a table, *Alter Table...* to view columns, indexes and foreign keys (look, don't edit; change the schema with Alembic).

Tables: `users`, `user_sessions`, `projects`, `uploaded_files`, `scans`, `vulnerabilities`, `scan_reports`, `usage_events`,
`ai_analysis`, `audit_logs`. Deleting a user cascades to their projects/files/scans/sessions/usage/AI rows; `audit_logs.actor_user_id`
becomes NULL so the audit trail survives; deleting a file or project sets `scans.uploaded_file_id`/`project_id` to NULL so history stays.

## 9. Backups and migrations

**Backup** (command line; Workbench: *Server > Data Export*):
```bash
mysqldump --single-transaction --routines -u root -p evm_security > evm_security_backup.sql
```
Also back up the **storage directory** (`RETRACE_STORAGE_DIR`, default `backend/storage`): uploaded bytecode and report files live
there, referenced by the database. A DB backup without it cannot restore files.

**Restore**: `mysql -u root -p evm_security < evm_security_backup.sql`.

**Changing the schema**: edit `app/models.py`, then
```bash
alembic revision --autogenerate -m "describe change"   # review the generated file!
alembic upgrade head
```
Always take a backup before `upgrade` on real data. `alembic downgrade -1` undoes the last migration.

## Troubleshooting
- `Access denied for user`: wrong password or URL-encoding; test the same login in Workbench.
- `Can't connect to MySQL server`: the server service is not running, or the port is not 3306.
- `Unknown database`: run the `CREATE DATABASE` step.
- `cryptography package is required`: `pip install cryptography` (MySQL 8 default auth).
