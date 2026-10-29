from app.config import Settings


def test_settings_creates_dirs_and_persists_secret(tmp_path):
    s1 = Settings(data_dir=tmp_path / "data")
    assert (tmp_path / "data").is_dir()
    assert s1.custom_templates_dir == tmp_path / "data" / "custom-templates"
    assert s1.custom_templates_dir.is_dir()
    assert s1.nuclei_templates_dir == tmp_path / "data" / "nuclei-templates"
    assert len(s1.secret_key) >= 32
    assert (tmp_path / "data" / "secret_key").read_text().strip() == s1.secret_key

    s2 = Settings(data_dir=tmp_path / "data")
    assert s2.secret_key == s1.secret_key


def test_settings_db_url(tmp_path):
    s = Settings(data_dir=tmp_path / "d", secret_key="x")
    assert s.db_url == f"sqlite:///{tmp_path / 'd' / 'scanner.db'}"
