import pytest
from sqlalchemy import select

from app.db import session_factory, utcnow
from app.models import User, UserSession
from app.security import hash_password
from tests.conftest import PW


def test_register_login_logout_cycle(make_session):
    s = make_session()
    r = s.register("a@example.com", "Ann")
    assert r.status_code == 201 and r.json()["user"]["email"] == "a@example.com"
    assert "HttpOnly" in r.headers["set-cookie"] and "samesite=lax" in r.headers["set-cookie"].lower()
    assert s.get("/api/auth/me").json()["user"]["name"] == "Ann"          # persistence across "refresh"
    assert s.post("/api/auth/logout").status_code == 200
    assert s.get("/api/auth/me").status_code == 401                          # session invalidated server-side
    assert s.login("a@example.com").status_code == 200


def test_password_is_hashed_with_argon2id(alice):
    with session_factory()() as db:
        u = db.scalar(select(User))
        assert u.password_hash.startswith("$argon2id$") and PW not in u.password_hash


@pytest.mark.parametrize("pw", ["short1A", "alllowercase123", "ALLUPPERCASE123", "NoDigitsHereAtAll", "Password123"])
def test_weak_passwords_rejected_with_field_errors(make_session, pw):
    r = make_session().register("w@example.com", "W", pw)
    assert r.status_code == 422 and r.json()["detail"]["fields"]["password"]


def test_invalid_email_and_duplicate(make_session, alice):
    assert make_session().register("not-an-email", "X").json()["detail"]["fields"]["email"]
    dup = make_session().register("ALICE@example.com", "Again")      # case-insensitive
    assert dup.status_code == 409 and dup.json()["detail"]["code"] == "email_taken"


def test_login_errors_do_not_reveal_whether_email_exists(make_session, alice):
    a = make_session().login("alice@example.com", "Wrong-Passw0rd!")
    b = make_session().login("nobody@example.com", "Wrong-Passw0rd!")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_login_rate_limited(make_session, alice):
    s = make_session()
    codes = [s.login("alice@example.com", "Wrong-Passw0rd!").status_code for _ in range(10)]
    assert codes[:8] == [401] * 8 and 429 in codes[8:]


def test_unauthenticated_requests_are_rejected(make_session):
    s = make_session()
    for path in ("/api/files", "/api/scans", "/api/dashboard", "/api/profile", "/api/usage/me", "/api/projects"):
        assert s.get(path).status_code == 401, path


def test_csrf_required_on_unsafe_methods(alice):
    alice.csrf = None
    r = alice.post("/api/projects", json={"project_name": "p"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "csrf_failed"
    alice.csrf = "wrong"
    assert alice.post("/api/projects", json={"project_name": "p"}).status_code == 403


def test_cross_origin_unsafe_request_blocked(alice):
    r = alice.post("/api/projects", json={"project_name": "p"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "bad_origin"


def test_session_expiry_absolute_and_idle(alice):
    with session_factory()() as db:
        sess = db.scalar(select(UserSession))
        sess.expires_at = utcnow().replace(year=2000)
        db.commit()
    assert alice.get("/api/auth/me").status_code == 401


def test_idle_timeout(alice):
    with session_factory()() as db:
        sess = db.scalar(select(UserSession))
        sess.last_seen_at = utcnow().replace(year=2000)
        db.commit()
    assert alice.get("/api/auth/me").json()["detail"]["code"] == "session_expired"


def test_change_password_invalidates_other_sessions(make_session, alice):
    other = make_session()
    assert other.login("alice@example.com").status_code == 200
    assert alice.post("/api/auth/change-password", json={"current_password": "bad", "new_password": "New-Passw0rd-xyz"}).status_code == 403
    assert alice.post("/api/auth/change-password", json={"current_password": PW, "new_password": "New-Passw0rd-xyz"}).status_code == 200
    assert other.get("/api/auth/me").status_code == 401        # other device signed out
    assert alice.get("/api/auth/me").status_code == 200        # this one stays
    assert make_session().login("alice@example.com", PW).status_code == 401
    assert make_session().login("alice@example.com", "New-Passw0rd-xyz").status_code == 200


def test_deactivated_user_cannot_use_existing_session(alice):
    with session_factory()() as db:
        db.scalar(select(User)).is_active = False
        db.commit()
    assert alice.get("/api/auth/me").status_code == 401


def test_profile_shows_only_own_activity_and_xss_name_rejected(make_session, alice, bob):
    assert make_session().register("c@example.com", "<script>x</script>").status_code == 422
    p = alice.get("/api/profile").json()
    assert p["email"] == "alice@example.com" and p["activity"]["scans"] == 0
    assert "password" not in str(p).lower()


def test_sql_injection_strings_are_inert(make_session, alice):
    r = make_session().login("' OR '1'='1", "x")
    assert r.status_code == 401
    assert alice.get("/api/files", params={"q": "' OR 1=1 --"}).json()["total"] == 0


def test_delete_account_requires_password(make_session, alice):
    assert alice.request("DELETE", "/api/profile", json={"password": "nope"}).status_code == 403
    assert alice.request("DELETE", "/api/profile", json={"password": PW}).status_code == 200
    assert make_session().login("alice@example.com").status_code == 401
