"""SSRF protection for administrator-supplied integration endpoints.

Organization admins enter SIEM URLs, so the server must not be steerable at internal services (cloud
metadata, localhost, the VPC). Loopback, link-local (including 169.254.169.254), multicast and
reserved ranges are ALWAYS blocked. Private ranges (10/8, 172.16/12, 192.168/16, fc00::/7) are
blocked unless ALLOW_PRIVATE_INTEGRATION_ENDPOINTS=true, because on-premise SIEMs commonly live there.

Residual risk: DNS can change between this check and the request (rebinding). Redirects are disabled
by callers, and production deployments should additionally restrict egress at the network layer.
"""
import ipaddress
import socket
from urllib.parse import urlsplit

from app.config import get_settings
from app.errors import AppError


def _is_blocked(ip: ipaddress._BaseAddress, allow_private: bool) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    if ip.is_private and not allow_private:
        return True
    return False


def validate_outbound_url(url: str) -> str:
    settings = get_settings()
    allow_private = settings.allow_private_endpoints
    parts = urlsplit(url.strip())
    if parts.scheme not in ("https", "http"):
        raise AppError("INVALID_ENDPOINT", "The endpoint must be an http(s) URL.", 422)
    if parts.scheme == "http" and settings.is_production:
        raise AppError("INVALID_ENDPOINT", "The endpoint must use https.", 422)
    if not parts.hostname or parts.username or parts.password:
        raise AppError("INVALID_ENDPOINT", "The endpoint must include a host and must not embed credentials.", 422)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(parts.hostname, port, type=socket.SOCK_STREAM)}
    except socket.gaierror:
        raise AppError("INVALID_ENDPOINT", "The endpoint host could not be resolved.", 422)
    for address in addresses:
        if _is_blocked(ipaddress.ip_address(address), allow_private):
            raise AppError(
                "ENDPOINT_NOT_ALLOWED",
                "That endpoint resolves to an address this server is not allowed to contact.",
                422,
            )
    return url.strip().rstrip("/")
