import pytest

from app.validation import parse_nmap_targets, parse_nuclei_targets


def test_nmap_targets_accepts_ip_cidr_range_hostname_and_trims():
    text = "192.168.1.0/24\n  scanme.nmap.org \n\n10.0.0.1-20\n2001:db8::1\n"
    assert parse_nmap_targets(text) == ["192.168.1.0/24", "scanme.nmap.org", "10.0.0.1-20", "2001:db8::1"]


@pytest.mark.parametrize("bad", [
    "",
    "   \n  ",
    "-oN /tmp/x",
    "1.2.3.4; rm -rf /",
    "host name with spaces",
    "a" * 300,
    "$(whoami)",
])
def test_nmap_targets_rejects(bad):
    with pytest.raises(ValueError):
        parse_nmap_targets(bad)


def test_nuclei_targets_accept_urls_and_hostports():
    text = "http://10.0.0.1:8080\nhttps://web01.lab/\n10.0.0.2:443\nscanme.nmap.org"
    assert parse_nuclei_targets(text) == ["http://10.0.0.1:8080", "https://web01.lab/", "10.0.0.2:443", "scanme.nmap.org"]


@pytest.mark.parametrize("bad", ["", "-l /etc/passwd", "http://x y", "ftp://a b"])
def test_nuclei_targets_reject(bad):
    with pytest.raises(ValueError):
        parse_nuclei_targets(bad)


def test_nuclei_targets_reject_non_http_scheme():
    with pytest.raises(ValueError):
        parse_nuclei_targets("ftp://example.com/x")


def test_duplicates_removed_preserving_order():
    assert parse_nmap_targets("a.lab\nb.lab\na.lab") == ["a.lab", "b.lab"]
