from app.auth import hash_password, validate_new_password, verify_password
from tests.conftest import NEW_PASSWORD, get_csrf, login_and_change_password


def test_hash_roundtrip():
    h = hash_password("changeme")
    assert verify_password("changeme", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x", "not-a-hash")


def test_validate_new_password_rules():
    assert validate_new_password("short", "short", "changeme") == "New password must be at least 12 characters."
    assert validate_new_password("CorrectHorse-Battery9", "nope", "changeme") == "Passwords do not match."
    assert validate_new_password("changeme-changeme", "changeme-changeme", "changeme-changeme") == "New password must differ from the current one."
    assert validate_new_password("CorrectHorse-Battery9", "CorrectHorse-Battery9", "changeme") is None


def test_unauthenticated_redirects_to_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/login").status_code == 200


def test_bad_login_shows_error(client):
    r = client.post("/login", data={"username": "admin", "password": "nope"})
    assert r.status_code == 401
    assert "Invalid username or password" in r.text


def test_login_rate_limited_after_5_failures(client):
    for _ in range(5):
        client.post("/login", data={"username": "admin", "password": "nope"})
    r = client.post("/login", data={"username": "admin", "password": "changeme"})
    assert r.status_code == 429


def test_first_login_forces_password_change(client):
    r = client.post("/login", data={"username": "admin", "password": "changeme"}, follow_redirects=False)
    assert r.status_code == 303
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/change-password"
    r = client.get("/nmap", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/change-password"
    page = client.get("/change-password")
    assert page.status_code == 200 and "default password must be changed" in page.text


def test_change_password_rejects_weak_and_csrf(client):
    client.post("/login", data={"username": "admin", "password": "changeme"})
    csrf = get_csrf(client, "/change-password")
    r = client.post("/change-password", data={"csrf": "bad", "current_password": "changeme", "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})
    assert r.status_code == 403
    r = client.post("/change-password", data={"csrf": csrf, "current_password": "changeme", "new_password": "short", "confirm_password": "short"})
    assert r.status_code == 400 and "at least 12" in r.text
    r = client.post("/change-password", data={"csrf": csrf, "current_password": "wrong", "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})
    assert r.status_code == 400 and "Current password is incorrect" in r.text


def test_after_change_full_access_and_relogin_with_new_password(client):
    login_and_change_password(client)
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 200
    csrf = get_csrf(client, "/")
    r = client.post("/logout", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/", follow_redirects=False).status_code == 303
    r = client.post("/login", data={"username": "admin", "password": "changeme"})
    assert r.status_code == 401
    r = client.post("/login", data={"username": "admin", "password": NEW_PASSWORD}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/", follow_redirects=False).status_code == 200
