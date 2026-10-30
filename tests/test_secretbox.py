from app.secretbox import SecretBox


def test_roundtrip_and_tamper():
    box = SecretBox("instance-secret")
    token = box.encrypt({"api_token": "s3cr3t", "url": "https://hooks.example/x"})
    assert "s3cr3t" not in token
    assert box.decrypt(token) == {"api_token": "s3cr3t", "url": "https://hooks.example/x"}
    assert SecretBox("other-secret").decrypt(token) == {}   # wrong key: nothing, no crash
    assert box.decrypt("garbage") == {} and box.decrypt("") == {}
    assert box.encrypt({}) == ""


def test_merge_keeps_blank_fields():
    box = SecretBox("k")
    old = box.encrypt({"token": "a", "url": "u"})
    new = box.merge(old, {"token": "", "url": "v2"})
    assert box.decrypt(new) == {"token": "a", "url": "v2"}
