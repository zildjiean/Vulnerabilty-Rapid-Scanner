from app.inventory_groups import (DEFAULT_GROUP, GROUP_MODES, TYPE_ORDER, group_rows, normalize_group_mode,
                                  service_type)
from tests.conftest import get_csrf
from tests.test_inventory import seed_inventory


class _Svc:
    def __init__(self, id, port, name="", product="", tunnel=""):
        self.id, self.port, self.service_name, self.product, self.tunnel = id, port, name, product, tunnel


class _Host:
    def __init__(self, id, address, hostname=None):
        self.id, self.address, self.hostname = id, address, hostname


def test_service_type_by_name():
    assert service_type(_Svc(1, 80, "http")) == "Web"
    assert service_type(_Svc(1, 8443, "http", tunnel="ssl")) == "Web"
    assert service_type(_Svc(1, 4443, "ssl/https")) == "Web"
    assert service_type(_Svc(1, 3306, "mysql")) == "Database"
    assert service_type(_Svc(1, 22, "ssh")) == "Remote access"
    assert service_type(_Svc(1, 3389, "ms-wbt-server")) == "Remote access"
    assert service_type(_Svc(1, 25, "smtp")) == "Mail"
    assert service_type(_Svc(1, 21, "ftp")) == "File sharing"
    assert service_type(_Svc(1, 445, "microsoft-ds")) == "File sharing"
    assert service_type(_Svc(1, 389, "ldap")) == "Directory & auth"
    assert service_type(_Svc(1, 53, "domain")) == "Network services"


def test_service_type_port_fallback_and_other():
    assert service_type(_Svc(1, 3306, "")) == "Database"
    assert service_type(_Svc(1, 5432, "unknown")) == "Database"
    assert service_type(_Svc(1, 8080, "")) == "Web"
    assert service_type(_Svc(1, 9999, "foo")) == "Other"
    assert service_type(_Svc(1, 9999, "")) == "Other"
    assert TYPE_ORDER[0] == "Web" and TYPE_ORDER[-1] == "Other"


def _rows():
    h1, h2 = _Host(1, "10.0.0.1", "web.local"), _Host(2, "10.0.0.2")
    return [
        (_Svc(1, 22, "ssh", "OpenSSH"), h1),
        (_Svc(2, 80, "http", "nginx"), h1),
        (_Svc(3, 3306, "mysql", ""), h2),
        (_Svc(4, 443, "http", "nginx", "ssl"), h2),
    ]


def test_normalize_group_mode():
    assert DEFAULT_GROUP == "host"
    assert set(GROUP_MODES) == {"host", "product", "type", "scope", "none"}
    assert normalize_group_mode("product") == "product"
    assert normalize_group_mode("zzz") == "host"
    assert normalize_group_mode("") == "host"


def test_group_rows_by_host():
    groups = group_rows(_rows(), "host", {2: ["m"]})
    assert [g.label for g in groups] == ["10.0.0.1", "10.0.0.2"]
    assert groups[0].sublabel == "web.local" and groups[1].sublabel == ""
    assert [len(g.rows) for g in groups] == [2, 2]
    assert [g.host_count for g in groups] == [1, 1]
    assert [g.match_count for g in groups] == [1, 0]
    assert groups[0].key != groups[1].key


def test_group_rows_by_product_unknown_last():
    groups = group_rows(_rows(), "product", {})
    assert [g.label for g in groups] == ["nginx", "OpenSSH", "Unknown product"]
    nginx = groups[0]
    assert len(nginx.rows) == 2 and nginx.host_count == 2


def test_group_rows_by_type_in_taxonomy_order():
    groups = group_rows(_rows(), "type", {3: ["m"], 4: ["m", "n"]})
    assert [g.label for g in groups] == ["Web", "Database", "Remote access"]
    assert [len(g.rows) for g in groups] == [2, 1, 1]
    assert [g.match_count for g in groups] == [2, 1, 0]


def test_group_rows_none_and_invalid():
    assert group_rows(_rows(), "none", {}) == []
    assert [g.label for g in group_rows(_rows(), "bogus", {})] == ["10.0.0.1", "10.0.0.2"]


def test_inventory_page_groups(auth):
    seed_inventory(auth)
    r = auth.get("/inventory")
    assert r.status_code == 200
    assert 'class="group-row"' in r.text
    assert "4 services" in r.text and "1 service" in r.text
    assert 'data-group-toggle' in r.text and 'data-groups-collapse' in r.text
    r = auth.get("/inventory?group=product")
    assert "Unknown product" in r.text and "nginx" in r.text
    r = auth.get("/inventory?group=type")
    assert "Remote access" in r.text and "Database" in r.text and "Web" in r.text
    r = auth.get("/inventory?group=none")
    assert 'class="group-row"' not in r.text and "192.168.1.10" in r.text
    r = auth.get("/inventory?group=zzz")
    assert 'class="group-row"' in r.text and "4 services" in r.text
    r = auth.get("/inventory?group=type&port=3306")
    assert "Database" in r.text and "Remote access" not in r.text and "1 service" in r.text


def test_inventory_error_page_keeps_groups(auth):
    seed_inventory(auth)
    csrf = get_csrf(auth, "/inventory")
    r = auth.post("/inventory/to-nuclei", data={"csrf": csrf})
    assert r.status_code == 400 and 'class="group-row"' in r.text
