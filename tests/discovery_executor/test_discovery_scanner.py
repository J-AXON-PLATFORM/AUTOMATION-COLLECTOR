from __future__ import annotations

import socket
from contextlib import AbstractContextManager

import pytest

from jaxon_discovery_executor.scanner import MAX_CONCURRENCY, TCP_PORTS, scan_basic


class Connection(AbstractContextManager):
    def close(self) -> None:
        pass

    def __exit__(self, *_args):
        self.close()


def test_basic_scan_uses_only_approved_ports_timeout_and_scope() -> None:
    attempts = []

    def connect(target, timeout):
        attempts.append((target, timeout))
        if target[1] == 443:
            return Connection()
        raise ConnectionRefusedError

    result = scan_basic(
        "127.0.0.1/32",
        connection_factory=connect,
        arp_reader=lambda: {"127.0.0.1": "02:00:00:00:00:01"},
    )

    assert attempts == [(("127.0.0.1", port), 2) for port in TCP_PORTS]
    assert result.targetsConsidered == result.targetsScanned == 1
    assert result.observations == [
        {
            "evidence": ["ARP", "TCP"],
            "hostname": None,
            "ipAddress": "127.0.0.1",
            "macAddress": "02:00:00:00:00:01",
            "openTcpPorts": [443],
        }
    ]
    assert MAX_CONCURRENCY == 32


def test_basic_scan_does_not_probe_oversized_scope() -> None:
    def unexpected(*_args, **_kwargs):
        raise AssertionError("network probe must not run")

    result = scan_basic("10.0.0.0/19", connection_factory=unexpected, arp_reader=lambda: {})
    assert result.targetsConsidered == 8192
    assert result.targetsScanned == 0
    assert result.observations == []


def test_basic_scan_rejects_non_linux(monkeypatch) -> None:
    monkeypatch.setattr("jaxon_discovery_executor.scanner.platform.system", lambda: "Windows")
    with pytest.raises(RuntimeError):
        scan_basic("127.0.0.1/32")


def test_basic_scan_real_network_is_restricted_to_loopback() -> None:
    listener = socket.socket()
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 3389))
        listener.listen()
        result = scan_basic("127.0.0.1/32", arp_reader=lambda: {})
    finally:
        listener.close()
    assert result.targetsConsidered == result.targetsScanned == 1
    assert result.observations[0]["ipAddress"] == "127.0.0.1"
    assert 3389 in result.observations[0]["openTcpPorts"]
