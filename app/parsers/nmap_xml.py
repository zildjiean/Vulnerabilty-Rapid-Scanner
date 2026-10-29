"""Parse `nmap -oX -` output into plain dataclasses. No I/O, no DB."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass(frozen=True)
class PortResult:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: str = ""
    tunnel: str = ""


@dataclass
class HostResult:
    address: str
    hostname: str = ""
    ports: list[PortResult] = field(default_factory=list)


def parse_nmap_xml(xml_text: str) -> list[HostResult]:
    if not xml_text or not xml_text.strip():
        raise ValueError("nmap produced no XML output")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise ValueError(f"invalid nmap XML: {e}") from e
    if root.tag != "nmaprun":
        raise ValueError("not an nmap XML document")

    hosts: list[HostResult] = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue
        address = _pick_address(host_el)
        if not address:
            continue
        hn = host_el.find("hostnames/hostname")
        hostname = hn.get("name", "") if hn is not None else ""
        ports: list[PortResult] = []
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state != "open":
                continue
            svc = port_el.find("service")
            cpe_el = svc.find("cpe") if svc is not None else None
            ports.append(PortResult(
                port=int(port_el.get("portid", "0")),
                protocol=port_el.get("protocol", "tcp"),
                state=state,
                service=svc.get("name", "") if svc is not None else "",
                product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "",
                extra_info=svc.get("extrainfo", "") if svc is not None else "",
                cpe=(cpe_el.text or "").strip() if cpe_el is not None else "",
                tunnel=svc.get("tunnel", "") if svc is not None else "",
            ))
        hosts.append(HostResult(address=address, hostname=hostname, ports=ports))
    return hosts


def _pick_address(host_el: ET.Element) -> str:
    addrs = {a.get("addrtype"): a.get("addr", "") for a in host_el.findall("address")}
    return addrs.get("ipv4") or addrs.get("ipv6") or ""
