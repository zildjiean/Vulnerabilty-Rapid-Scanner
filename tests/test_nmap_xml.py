from pathlib import Path

import pytest

from app.parsers.nmap_xml import HostResult, PortResult, parse_nmap_xml

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def test_parses_only_up_hosts_and_open_ports():
    hosts = parse_nmap_xml(FIXTURE.read_text())
    assert [h.address for h in hosts] == ["192.168.1.10", "192.168.1.12"]
    web = hosts[0]
    assert isinstance(web, HostResult)
    assert web.hostname == "web01.lab"
    assert [p.port for p in web.ports] == [22, 80, 8080, 8443]


def test_port_fields():
    hosts = parse_nmap_xml(FIXTURE.read_text())
    ssh = hosts[0].ports[0]
    assert ssh == PortResult(
        port=22, protocol="tcp", state="open", service="ssh", product="OpenSSH",
        version="9.6p1 Ubuntu 3ubuntu13", extra_info="Ubuntu Linux; protocol 2.0",
        cpe="cpe:/a:openbsd:openssh:9.6p1", tunnel="",
    )
    php = hosts[0].ports[2]
    assert php.product == "PHP cli server" and php.version == "8.3.10" and php.cpe == ""
    nginx = hosts[0].ports[3]
    assert nginx.tunnel == "ssl"


def test_service_without_product_or_hostname():
    hosts = parse_nmap_xml(FIXTURE.read_text())
    db = hosts[1]
    assert db.hostname == ""
    assert db.ports[0].service == "mysql"
    assert db.ports[0].product == "" and db.ports[0].version == ""


def test_malformed_xml_raises():
    with pytest.raises(ValueError):
        parse_nmap_xml("<nmaprun><host>")


def test_empty_output_raises():
    with pytest.raises(ValueError):
        parse_nmap_xml("")
