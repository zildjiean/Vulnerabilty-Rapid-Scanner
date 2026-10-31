def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    from app import __version__
    assert r.json() == {"status": "ok", "version": __version__}


def test_sidebar_shows_the_version(auth):
    from app import __version__
    assert f">v{__version__}</a>" in auth.get("/").text
