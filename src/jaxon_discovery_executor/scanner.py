"""Bounded non-intrusive BASIC discovery probes."""

from __future__ import annotations

import ipaddress
import platform
import socket
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

MAX_TARGETS = 4096
MAX_CONCURRENCY = 32
PROBE_TIMEOUT_SECONDS = 2
TCP_PORTS = (22, 53, 80, 443, 445, 3389)


class UnsupportedDiscoveryPlatformError(RuntimeError):
    pass


@dataclass(frozen=True)
class BasicScanResult:
    targetsConsidered: int
    targetsScanned: int
    observations: list[dict[str, object]]


def scan_basic(
    scope_cidr: str,
    *,
    connection_factory=socket.create_connection,
    arp_reader=None,
) -> BasicScanResult:
    """Scan one bounded CIDR with passive ARP evidence and fixed TCP probes."""
    if platform.system() != "Linux":
        raise UnsupportedDiscoveryPlatformError
    network = ipaddress.ip_network(scope_cidr, strict=True)
    considered = network.num_addresses
    if considered > MAX_TARGETS:
        return BasicScanResult(considered, 0, [])
    addresses = list(network)
    arp = (arp_reader or _read_passive_arp)()

    def inspect(address: ipaddress.IPv4Address | ipaddress.IPv6Address):
        value = str(address)
        open_ports: list[int] = []
        for port in TCP_PORTS:
            if address not in network:
                raise ValueError("Discovery target escaped its authorized scope")
            try:
                with closing(connection_factory((value, port), timeout=PROBE_TIMEOUT_SECONDS)):
                    open_ports.append(port)
            except ConnectionError, TimeoutError, OSError:
                continue
        evidence: list[str] = []
        mac_address = arp.get(value)
        if mac_address is not None:
            evidence.append("ARP")
        if open_ports:
            evidence.append("TCP")
        if not evidence:
            return None
        return {
            "evidence": evidence,
            "hostname": None,
            "ipAddress": value,
            "macAddress": mac_address,
            "openTcpPorts": open_ports,
        }

    with ThreadPoolExecutor(max_workers=MAX_CONCURRENCY) as executor:
        observations = [value for value in executor.map(inspect, addresses) if value is not None]
    return BasicScanResult(considered, len(addresses), observations)


def _read_passive_arp() -> dict[str, str]:
    path = Path("/proc/net/arp")
    try:
        lines = path.read_text(encoding="ascii").splitlines()[1:]
    except OSError, UnicodeError:
        return {}
    result: dict[str, str] = {}
    for line in lines:
        fields = line.split()
        if len(fields) < 6:
            continue
        address, flags, mac = fields[0], fields[2], fields[3].lower()
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if (
            parsed.version == 4
            and flags != "0x0"
            and len(mac) == 17
            and all(character in "0123456789abcdef:" for character in mac)
        ):
            result[str(parsed)] = mac
    return result
