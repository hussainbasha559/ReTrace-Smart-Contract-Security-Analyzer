"""Supabase / PostgreSQL connection handling."""
import pytest

from app.db import is_transaction_pooler, make_engine, normalize_database_url


@pytest.mark.parametrize("raw", [
    "postgres://u:p@h.example.com:5432/postgres",
    "postgresql://u:p@h.example.com:5432/postgres",
    "postgresql+psycopg2://u:p@h.example.com:5432/postgres",
    '"postgresql://u:p@h.example.com:5432/postgres"',
])
def test_postgres_urls_use_psycopg3(raw):
    assert normalize_database_url(raw).drivername == "postgresql+psycopg"


def test_supabase_host_gets_sslmode():
    u = normalize_database_url("postgresql://postgres.abc:pw@aws-0-ap-south-1.pooler.supabase.com:5432/postgres")
    assert u.query["sslmode"] == "require"


def test_existing_sslmode_is_kept():
    u = normalize_database_url("postgresql://u:p@db.abc.supabase.co:5432/postgres?sslmode=verify-full")
    assert u.query["sslmode"] == "verify-full"


def test_non_supabase_host_not_forced_to_ssl():
    assert "sslmode" not in normalize_database_url("postgresql://u:p@localhost/db").query


def test_transaction_pooler_detected():
    assert is_transaction_pooler(normalize_database_url("postgresql://u:p@x.pooler.supabase.com:6543/postgres"))
    assert not is_transaction_pooler(normalize_database_url("postgresql://u:p@x.pooler.supabase.com:5432/postgres"))


def test_placeholder_password_is_rejected_with_clear_message():
    with pytest.raises(RuntimeError, match="placeholder"):
        normalize_database_url("postgresql://postgres:[YOUR-PASSWORD]@db.abc.supabase.co:5432/postgres")


def test_pool_is_never_size_one():
    # A request thread and a background scan thread must be able to hold a connection at once.
    eng = make_engine("postgresql://u:p@localhost:5432/db")
    assert eng.pool.size() >= 2 and eng.pool._max_overflow >= 1
    eng.dispose()


def test_file_search_is_case_insensitive(alice):
    # MySQL's LIKE ignored case, PostgreSQL's does not: the API must behave the same on both.
    from tests.conftest import VULNERABLE
    alice.post("/api/files/paste", json={"bytecode": VULNERABLE, "name": "MyToken"})
    for q in ("mytoken", "MYTOKEN", "MyTok"):
        assert alice.get("/api/files", params={"q": q}).json()["total"] == 1, q
    assert alice.get("/api/files", params={"q": "nothing-like-this"}).json()["total"] == 0


def test_scan_search_is_case_insensitive(alice, fake_tools):
    from tests.conftest import VULNERABLE, run_scan
    run_scan(alice, VULNERABLE)
    # target_identifier is a lowercase sha256; searching in upper case must still match
    ident = alice.get("/api/scans").json()["items"][0]["target"]
    assert alice.get("/api/scans", params={"q": ident[:10].upper()}).json()["total"] == 1


def test_health_db(make_session):
    r = make_session().get("/health/db")
    assert r.status_code == 200 and r.json()["database"] == "reachable"
