"""Active PC / endpoint discovery + switch-port matching.

This is the same workflow as :mod:`cameras`, but for ordinary computers:

1. **IP and MAC** - ARP (Windows ``SendARP``) resolves the addresses that are
   directly connected.  Routed addresses are still probed and can be matched
   through the switch ARP table / ``Load ARP table...``.
2. **Host name** - reverse DNS, then a NetBIOS node-status query (UDP 137),
   then mDNS (UDP 5353).  All three are best effort.
3. **Device type** - a short TCP probe guesses Windows / Linux / macOS /
   printer / phone from the open ports.
4. **Switch port** - the MAC is matched against the MAC tables collected by
   :mod:`cisco`, using the exact same logic as the camera tab.

Only the Python standard library is used.
"""

from __future__ import annotations

import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from cameras import (
    MAX_TARGETS,
    TargetRange,
    _is_local,
    _merge_ranges,
    discover_arp,
    iter_targets,
    local_ipv4_networks,
    match_devices,
    target_count,
)

# Ports that say something about the operating system.  135/139/445/3389 are
# Windows, 22 is Unix/Linux, 548 is macOS, the rest are printers/phones.
HOST_PROBE_PORTS = (
    22,
    80,
    135,
    139,
    443,
    445,
    515,
    548,
    631,
    3389,
    5900,
    8080,
    9100,
    62078,
)

# A small set used to decide whether a *routed* address is worth probing.
# Scanning every port on every routed address would be too slow.
HOST_SIGNATURE_PORTS = (22, 135, 139, 445, 3389)

WINDOWS_PORTS = {135, 139, 445, 3389}
PRINTER_PORTS = {515, 631, 9100}
PHONE_PORTS = {62078}

MAX_TARGETS_HOSTS = MAX_TARGETS

_LABEL_PREFIX = "Host discovery"


class HostCancelled(Exception):
    """The user cancelled host discovery."""


# ---------------------------------------------------------------------------
# host name resolution
# ---------------------------------------------------------------------------


def _reverse_dns(ip: str) -> str:
    """PTR lookup through the operating system resolver (best effort)."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
    except OSError:
        return ""
    name = (name or "").strip().rstrip(".")
    if not name or name == ip:
        return ""
    return name


def _netbios_encode_name(name: bytes) -> bytes:
    """First-level encoding used by NetBIOS name service packets."""
    encoded = bytearray([32])
    for byte in name:
        encoded.append(ord("A") + (byte >> 4))
        encoded.append(ord("A") + (byte & 0x0F))
    encoded.append(0)
    return bytes(encoded)


def _read_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode a (possibly compressed) DNS name; return name and next offset."""
    labels: List[str] = []
    end_offset = offset
    jumped = False
    for _ in range(64):
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            if not jumped:
                end_offset = offset + 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        if offset + 1 + length > len(data):
            break
        if not jumped:
            end_offset = offset + 1 + length
        labels.append(data[offset + 1 : offset + 1 + length].decode("utf-8", "ignore"))
        offset += 1 + length
    return ".".join(label for label in labels if label), end_offset


def _parse_nbstat(data: bytes) -> str:
    """Pick the workstation name out of a NetBIOS node-status answer."""
    if len(data) < 12:
        return ""
    questions, answers = struct.unpack(">HH", data[4:8])
    offset = 12
    for _ in range(questions):
        _, offset = _read_dns_name(data, offset)
        offset += 4  # QTYPE + QCLASS
        if offset > len(data):
            return ""
    if answers < 1:
        return ""
    _, offset = _read_dns_name(data, offset)
    if offset + 10 > len(data):
        return ""
    _, _, _, data_length = struct.unpack(">HHIH", data[offset : offset + 10])
    offset += 10
    end = offset + data_length
    if end > len(data) or offset >= len(data):
        return ""
    count = data[offset]
    offset += 1
    for _ in range(count):
        if offset + 18 > len(data):
            break
        raw = data[offset : offset + 15]
        suffix = data[offset + 15]
        flags = struct.unpack(">H", data[offset + 16 : offset + 18])[0]
        offset += 18
        # 0x00 = workstation service, group bit clear = unique name.
        if suffix != 0x00 or flags & 0x8000:
            continue
        name = raw.decode("ascii", "ignore").strip()
        if name:
            return name
    return ""


def netbios_name(ip: str, timeout: float = 0.4) -> str:
    """Ask a Windows machine for its NetBIOS name (UDP 137, no login)."""
    request_name = b"*" + b" " * 15
    packet = (
        struct.pack(">HHHHHH", 0x4E42, 0x0000, 1, 0, 0, 0)
        + _netbios_encode_name(request_name)
        + struct.pack(">HH", 0x0021, 0x0001)
    )
    connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connection.settimeout(timeout)
    try:
        connection.sendto(packet, (ip, 137))
        data, _ = connection.recvfrom(2048)
    except OSError:
        return ""
    finally:
        connection.close()
    return _parse_nbstat(data)


def _parse_dns_ptr(data: bytes) -> str:
    """Return the first PTR target in a DNS response."""
    if len(data) < 12:
        return ""
    questions, answers = struct.unpack(">HH", data[4:8])
    offset = 12
    for _ in range(questions):
        _, offset = _read_dns_name(data, offset)
        offset += 4
    for _ in range(answers):
        _, offset = _read_dns_name(data, offset)
        if offset + 10 > len(data):
            return ""
        record_type, _, _, data_length = struct.unpack(
            ">HHIH", data[offset : offset + 10]
        )
        offset += 10
        if record_type == 12:
            name, _ = _read_dns_name(data, offset)
            return name.rstrip(".")
        offset += data_length
    return ""


def mdns_name(ip: str, timeout: float = 0.5) -> str:
    """Reverse mDNS lookup (UDP 5353) for ``<name>.local`` hosts."""
    labels = ip.split(".")[::-1] + ["in-addr", "arpa"]
    question = b"".join(
        bytes([len(label)]) + label.encode("ascii", "ignore") for label in labels
    ) + b"\x00"
    packet = (
        struct.pack(">HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
        + question
        + struct.pack(">HH", 12, 0x8001)  # PTR, unicast response requested
    )
    connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connection.settimeout(timeout)
    try:
        connection.sendto(packet, ("224.0.0.251", 5353))
        deadline = time.monotonic() + timeout
        while time.monotonic() <= deadline:
            try:
                data, address = connection.recvfrom(4096)
            except socket.timeout:
                break
            if address[0] != ip:
                continue
            name = _parse_dns_ptr(data)
            if name:
                return name
    except OSError:
        return ""
    finally:
        connection.close()
    return ""


def resolve_name(
    ip: str,
    timeout: float = 0.5,
    use_dns: bool = True,
    use_netbios: bool = True,
    use_mdns: bool = True,
) -> Tuple[str, str]:
    """Try DNS, NetBIOS and mDNS; return ``(name, source)``."""
    if use_dns:
        name = _reverse_dns(ip)
        if name:
            return name, "DNS"
    if use_netbios:
        name = netbios_name(ip, timeout)
        if name:
            return name, "NetBIOS"
    if use_mdns:
        name = mdns_name(ip, timeout)
        if name:
            return name, "mDNS"
    return "", ""


# ---------------------------------------------------------------------------
# port probe + classification
# ---------------------------------------------------------------------------


def probe_ports(
    ip: str,
    ports: Sequence[int] = HOST_PROBE_PORTS,
    timeout: float = 0.45,
) -> List[int]:
    """Return the ports of ``ip`` that accept a TCP connection."""
    open_ports: List[int] = []
    for port in ports:
        try:
            connection = socket.create_connection((ip, port), timeout=timeout)
        except OSError:
            continue
        try:
            connection.close()
        except OSError:
            pass
        open_ports.append(port)
    return open_ports


@dataclass
class Host:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    os_hint: str = ""
    confidence: str = "Low"
    score: int = 0
    open_ports: List[int] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    source: str = "ARP scan"
    is_pc: bool = True
    serial: str = ""

    @property
    def ports_text(self) -> str:
        return ", ".join(str(port) for port in self.open_ports)

    @property
    def model(self) -> str:
        return self.hostname or self.os_hint or "(unknown)"


def classify_pc(
    ip: str,
    mac: str,
    hostname: str = "",
    name_via: str = "",
    open_ports: Sequence[int] = (),
    oui: Optional[Dict[str, str]] = None,
) -> Host:
    """Turn raw host data into a :class:`Host` record."""
    from oui import lookup_vendor  # local import keeps this module standalone

    vendor = lookup_vendor(mac, oui or {}) if mac else ""
    ports = sorted({int(port) for port in open_ports})
    evidence: List[str] = []
    score = 0

    if mac:
        score += 1
        evidence.append("Answered ARP")
    if hostname:
        score += 2
        if name_via:
            evidence.append(f"Name via {name_via}: {hostname}")
        else:
            evidence.append(f"Name: {hostname}")
    if ports:
        evidence.append("Open ports: " + ", ".join(str(port) for port in ports))

    device_type = "Unknown device"
    if any(port in PRINTER_PORTS for port in ports):
        device_type = "Printer"
        score += 2
    elif any(port in PHONE_PORTS for port in ports):
        device_type = "Phone / tablet"
        score += 2
    elif 548 in ports:
        device_type = "macOS"
        score += 3
    elif 3389 in ports or 135 in ports:
        device_type = "Windows PC"
        score += 3
    elif 22 in ports:
        device_type = "Linux host"
        score += 2
    elif 445 in ports or 139 in ports:
        device_type = "Windows PC"
        score += 2

    if vendor:
        score += 1
        evidence.append("MAC vendor: " + vendor)
    if device_type == "Windows PC" and 3389 in ports:
        evidence.append("RDP (3389) is open")
    if device_type == "Linux host":
        evidence.append("SSH (22) is open")
    if not ports:
        evidence.append("No probed TCP port answered (firewall?)")

    confidence = "High" if score >= 4 else "Medium" if score >= 2 else "Low"
    is_pc = device_type not in ("Printer", "Phone / tablet")

    if mac:
        source = "ARP scan"
    elif hostname:
        source = "name lookup"
    else:
        source = "port scan"

    return Host(
        ip=ip,
        mac=mac,
        hostname=hostname,
        vendor=vendor,
        os_hint=device_type,
        confidence=confidence,
        score=score,
        open_ports=ports,
        evidence=list(dict.fromkeys(evidence)),
        source=source,
        is_pc=is_pc,
    )


# ---------------------------------------------------------------------------
# discovery entry point
# ---------------------------------------------------------------------------


def discover_hosts(
    ranges: Sequence[TargetRange],
    cancel=None,
    log: Optional[Callable[[str], None]] = None,
    progress: Optional[Callable[[int, int], None]] = None,
    oui: Optional[Dict[str, str]] = None,
    include_all: bool = True,
    resolve_names: bool = True,
    timeout: float = 0.45,
    max_workers: int = 48,
) -> List[Host]:
    """Discover PCs/endpoints in ``ranges`` and describe each one."""
    log = log or (lambda message: None)
    progress = progress or (lambda done, total: None)
    ranges = _merge_ranges(ranges)
    total = target_count(ranges)
    if total > MAX_TARGETS_HOSTS:
        raise ValueError(
            f"{total} addresses is too many (limit {MAX_TARGETS_HOSTS}). "
            "Narrow the subnet, e.g. use /24 or /23."
        )
    targets = list(iter_targets(ranges))
    log(f"{_LABEL_PREFIX}: {total} address(es) to check")

    networks = local_ipv4_networks()
    routed = sum(1 for ip in targets if not _is_local(ip, networks))
    if routed:
        log(
            f"{_LABEL_PREFIX}: {routed} address(es) are routed; they are still "
            "checked, but their MAC is only visible through the switch ARP table"
        )

    macs = discover_arp(targets, cancel=cancel, log=log)
    log(f"{_LABEL_PREFIX}: {len(macs)} host(s) answered ARP on local subnets")
    log(
        f"{_LABEL_PREFIX}: probing ports and resolving names"
        + (" (DNS / NetBIOS / mDNS)" if resolve_names else " (names disabled)")
    )

    def inspect(ip: str) -> Optional[Host]:
        if cancel is not None and cancel.is_set():
            return None
        local = ip in macs
        name, via = ("", "")
        if resolve_names:
            name, via = resolve_name(ip, timeout)
        if local:
            ports = probe_ports(ip, HOST_PROBE_PORTS, timeout)
        else:
            # Routed: only spend time on addresses that look alive.
            ports = probe_ports(ip, HOST_SIGNATURE_PORTS, timeout)
            if not name and not ports:
                return None
        host = classify_pc(ip, macs.get(ip, ""), name, via, ports, oui)
        if not include_all and not host.is_pc:
            return None
        return host

    hosts: List[Host] = []
    done = 0
    batch_size = 64
    workers = min(max_workers, max(4, len(targets) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for start in range(0, len(targets), batch_size):
            if cancel is not None and cancel.is_set():
                raise HostCancelled("Host discovery cancelled")
            batch = targets[start : start + batch_size]
            futures = [pool.submit(inspect, ip) for ip in batch]
            for future in futures:
                try:
                    host = future.result()
                except Exception as exc:  # one bad host must not stop the scan
                    log(f"host probe failed: {exc}")
                    host = None
                done += 1
                if host is not None:
                    hosts.append(host)
            progress(done, len(targets))
    if cancel is not None and cancel.is_set():
        raise HostCancelled("Host discovery cancelled")

    hosts.sort(key=lambda item: tuple(int(part) for part in item.ip.split(".")))
    computers = sum(1 for host in hosts if host.is_pc)
    log(f"{_LABEL_PREFIX}: {len(hosts)} host(s), {computers} computer(s)")
    return hosts


# ---------------------------------------------------------------------------
# matching
# ---------------------------------------------------------------------------


def match_hosts(
    hosts: Sequence[Host],
    mac_ports: Dict[str, List[dict]],
    ip_to_mac: Optional[Dict[str, str]] = None,
    ip_ports: Optional[Dict[str, List[dict]]] = None,
) -> List[dict]:
    """Match each host MAC to a switch port (same logic as cameras)."""
    return match_devices(
        hosts, mac_ports, ip_to_mac, ip_ports, label="Host"
    )


def names_from_switch_rows(rows: Sequence[dict]) -> Dict[str, str]:
    """Best-effort ``ip -> name`` map from CDP/LLDP neighbour rows.

    When a PC also speaks LLDP (or the switch reports it through CDP), the
    switch already knows its name even if DNS and NetBIOS do not answer.
    """
    names: Dict[str, str] = {}
    for row in rows:
        ip = str(row.get("ip", "")).strip()
        name = str(row.get("neighbor", "")).strip()
        if not ip or not name:
            continue
        if name.lower() in {"unknown", "not advertised", "-", "n/a"}:
            continue
        names.setdefault(ip, name)
    return names
