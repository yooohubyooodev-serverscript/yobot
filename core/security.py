"""URL / SSRF protection and safe path helpers."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return True
    for net in PRIVATE_NETWORKS:
        if ip in net:
            return True
    return False


def validate_public_url(url: str) -> str:
    """
    Validate that the URL is http(s) and resolves only to public IPs.
    Returns the cleaned URL or raises ValueError.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are allowed")

    host = parsed.hostname
    if not host:
        raise ValueError("URL has no hostname")

    host_lower = host.lower()
    if host_lower in ("localhost", "localhost.localdomain", "metadata", "metadata.google.internal"):
        raise ValueError("Hostname is not allowed")

    # Resolve DNS and check every address
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed: {exc}") from exc

    if not infos:
        raise ValueError("DNS resolution returned no addresses")

    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _is_private(ip):
            raise ValueError(f"Resolved address {addr} is private / reserved")

    return url
