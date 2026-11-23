"""Block outbound connections unless their target is a loopback IP address."""

import ipaddress
import socket
from typing import Any


class EgressBlockedError(OSError):
    """Raised when application code attempts non-loopback network access."""


def _host_from_address(address: Any) -> str | None:
    if isinstance(address, tuple) and address:
        host = address[0]
        return host.decode() if isinstance(host, bytes) else str(host)
    return None


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def check_address(address: Any) -> None:
    global _blocked_attempt_count
    host = _host_from_address(address)
    if not is_loopback_host(host):
        _blocked_attempt_count += 1
        raise EgressBlockedError(f"Blocked non-loopback network connection to {host or 'unknown target'}")


_installed = False
_blocked_attempt_count = 0


def blocked_attempt_count() -> int:
    """Number of non-loopback connection or name-resolution attempts blocked in this process."""
    return _blocked_attempt_count


def install_egress_guard() -> None:
    """Install process-wide socket guards. Calls to local Ollama remain allowed."""
    global _installed
    if _installed:
        return

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_create_connection = socket.create_connection
    original_getaddrinfo = socket.getaddrinfo
    original_sendto = socket.socket.sendto

    def guarded_connect(sock, address):
        check_address(address)
        return original_connect(sock, address)

    def guarded_connect_ex(sock, address):
        check_address(address)
        return original_connect_ex(sock, address)

    def guarded_create_connection(address, *args, **kwargs):
        check_address(address)
        return original_create_connection(address, *args, **kwargs)

    def guarded_getaddrinfo(host, port, *args, **kwargs):
        check_address((host.decode() if isinstance(host, bytes) else str(host), port))
        return original_getaddrinfo(host, port, *args, **kwargs)

    def guarded_sendto(sock, data, address, *args, **kwargs):
        check_address(address)
        return original_sendto(sock, data, address, *args, **kwargs)

    socket.socket.connect = guarded_connect
    socket.socket.connect_ex = guarded_connect_ex
    socket.create_connection = guarded_create_connection
    socket.getaddrinfo = guarded_getaddrinfo
    socket.socket.sendto = guarded_sendto
    _installed = True
