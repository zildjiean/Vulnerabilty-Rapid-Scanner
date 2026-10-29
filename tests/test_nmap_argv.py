import pytest

from app.scanners.nmap_runner import build_nmap_argv


def test_default_top_ports_syn():
    argv = build_nmap_argv("/usr/bin/nmap", ["10.0.0.1", "10.0.0.2"])
    assert argv == ["/usr/bin/nmap", "-sV", "-T3", "-sS", "--privileged", "-oX", "-", "10.0.0.1", "10.0.0.2"]


def test_all_ports_connect_skip_ping_t4():
    argv = build_nmap_argv("nmap", ["h"], port_mode="all", scan_type="connect", skip_ping=True, timing="T4")
    assert argv == ["nmap", "-sV", "-T4", "-sT", "-p-", "-Pn", "-oX", "-", "h"]


def test_custom_ports():
    argv = build_nmap_argv("nmap", ["h"], port_mode="custom", custom_ports="22,80,8000-9000")
    assert "-p" in argv and argv[argv.index("-p") + 1] == "22,80,8000-9000"


@pytest.mark.parametrize("kwargs", [
    dict(port_mode="custom", custom_ports=""),
    dict(port_mode="custom", custom_ports="22; ls"),
    dict(port_mode="weird"),
    dict(timing="T9"),
    dict(scan_type="udp"),
])
def test_invalid_options_raise(kwargs):
    with pytest.raises(ValueError):
        build_nmap_argv("nmap", ["h"], **kwargs)


def test_no_targets_raises():
    with pytest.raises(ValueError):
        build_nmap_argv("nmap", [])
