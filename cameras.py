"""Active camera discovery on the LAN + switch-port matching.

Two independent jobs live here:

1. **Discovery** - find cameras by their IP address.  ARP (Windows
   ``SendARP``) gives the ``IP <-> MAC`` pair for hosts on a directly
   connected subnet; RTSP, ONVIF and vendor web pages are then used to
   decide whether an address really belongs to a camera / NVR.

2. **Matching** - the MAC addresses learned by :mod:`cisco` from the
   switches' MAC tables are indexed by MAC, so every camera can be mapped
   to ``switch + port + VLAN``.  Ports that carry many MACs (uplinks /
   trunks) are ignored when picking the access port.

Nothing outside the Python standard library is used.
"""

from __future__ import annotations

import ctypes
import http.client
import ipaddress
import os
import re
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from cisco import _looks_like_switch_neighbor

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

MAX_TARGETS = 65536

PROBE_PORTS = (80, 443, 554, 8000, 8080, 8443, 8554, 2020, 37777)
HTTP_PORTS = (80, 8080)
HTTPS_PORTS = (443, 8443)
RTSP_PORTS = (554, 8554)

# Vendor endpoints that answer without credentials and reveal the model.
# Hikvision answers ISAPI with an XML ``DeviceInfo`` document (or 401 with a
# ``Digest realm="IP Camera(...)"`` challenge).  Dahua answers its magicBox
# CGI with ``key=value`` lines.  Both are excellent proof of the vendor even
# when the camera needs a password for video.
HIKVISION_PATHS = ("/ISAPI/System/deviceInfo",)
HIKVISION_NETWORK_PATH = "/ISAPI/System/Network/interfaces"
DAHUA_PATHS = (
    "/cgi-bin/magicBox.cgi?action=getSystemInfo",
    "/cgi-bin/magicBox.cgi?action=getMachineName",
)

# Ports that are typical for one camera vendor but not exclusive to cameras.
VENDOR_PORTS = {
    37777: "Dahua SDK port",
    8000: "Hikvision/device SDK port",
}

# Devices that are "camera-ish" but not cameras are kept as well: the user
# often needs the NVR / encoder port as much as the camera port.
CAMERA_VENDORS: Tuple[Tuple[str, str], ...] = (
    ("hikvision", "Hikvision"),
    ("dahua", "Dahua"),
    ("axis", "Axis"),
    ("vivotek", "Vivotek"),
    ("uniview", "Uniview"),
    ("hanwha", "Hanwha"),
    ("wisenet", "Hanwha Wisenet"),
    ("techwin", "Samsung Techwin"),
    ("reolink", "Reolink"),
    ("amcrest", "Amcrest"),
    ("foscam", "Foscam"),
    ("bosch", "Bosch"),
    ("pelco", "Pelco"),
    ("avigilon", "Avigilon"),
    ("mobotix", "Mobotix"),
    ("arecont", "Arecont"),
    ("geovision", "GeoVision"),
    ("panasonic", "Panasonic"),
    ("honeywell", "Honeywell"),
    ("tiandy", "Tiandy"),
    ("milesight", "Milesight"),
    ("xiongmai", "Xiongmai"),
    ("netsurveillance", "Xiongmai (NETSurveillance)"),
    ("dallmeier", "Dallmeier"),
    ("indigovision", "IndigoVision"),
    ("videotec", "Videotec"),
    ("acti", "ACTi"),
    ("sv3c", "SV3C"),
    ("escam", "Escam"),
    ("zosi", "ZOSI"),
    ("lorex", "Lorex"),
    ("swann", "Swann"),
    ("annke", "Annke"),
    ("d-link", "D-Link"),
    ("tp-link", "TP-Link"),
    ("tapo", "TP-Link Tapo"),
    ("ezviz", "EZVIZ"),
)

CAMERA_WORDS = (
    "ip camera",
    "network camera",
    "megapixel camera",
    "speed dome",
    "video server",
    "video encoder",
    "digital video recorder",
    "network video recorder",
    "web camera",
)

# Model-name prefixes from the two most common camera families.  These are
# matched as plain substrings because the real model continues with digits
# (``DS-2CD2143``, ``IPC-HDW2231``), so a word-boundary match would fail.
CAMERA_MODEL_TOKENS: Tuple[Tuple[str, str], ...] = (
    ("ds-2cd", "Hikvision"),
    ("ds-2de", "Hikvision"),
    ("ds-2td", "Hikvision"),
    ("ds-2se", "Hikvision"),
    ("ds-760", "Hikvision"),
    ("ds-770", "Hikvision"),
    ("ds-960", "Hikvision"),
    ("ipc-h", "Dahua"),
    ("ipc-b", "Dahua"),
    ("dh-ipc", "Dahua"),
    ("dh-nvr", "Dahua"),
    ("dh-xvr", "Dahua"),
    ("dh-sd", "Dahua"),
    ("dh-hc", "Dahua"),
)

# ``Server: webs`` is used by both Hikvision and Dahua web servers.  On its own
# it is only a hint, but it strengthens a match that already saw RTSP/ONVIF.
WEB_SERVER_HINTS = ("webs", "hikvision-webs", "dahua-webs")

GENERIC_TITLES = {
    "",
    "login",
    "log in",
    "web login",
    "web client",
    "web configuration",
    "configuration",
    "document",
    "index",
    "home",
    "camera",
    "ip camera",
    "network camera",
    "web service",
    "web server",
}

MAC_RE = re.compile(r"[0-9A-Fa-f]{2}(?:[.\-:]?[0-9A-Fa-f]{2}){5}")
IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")

_MAC_TEXT = (
    r"(?:[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}"
    r"|[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2})"
)
_IP_TEXT = r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])"
_ARP_LINE_RE = re.compile(
    rf"(?P<ip>{_IP_TEXT})[^\n]*?(?P<mac>{_MAC_TEXT})",
    re.M,
)
_ARP_LINE_REV_RE = re.compile(
    rf"(?P<mac>{_MAC_TEXT})[^\n]*?(?P<ip>{_IP_TEXT})",
    re.M,
)

_TARGET_SPLIT = re.compile(r"[\s,;]+")


class CameraCancelled(Exception):
    """Raised when the user stops a running camera discovery."""


# ---------------------------------------------------------------------------
# target parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetRange:
    first: int
    last: int

    def __len__(self) -> int:
        return max(0, self.last - self.first + 1)


def _ip_to_text(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def _strip_comments(text: str) -> str:
    """Drop ``#`` comments so annotated lists can be pasted into the UI."""
    lines: List[str] = []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0]
        if line.strip():
            lines.append(line)
    return "\n".join(lines)


def _range_end(start: ipaddress.IPv4Address, end_text: str) -> ipaddress.IPv4Address:
    """Resolve the right-hand side of a range.

    Supports the full form (``192.168.217.1-192.168.217.254``) and the
    common shorthand where only the last octet is given
    (``192.168.217.1-254``).
    """
    end_text = end_text.strip()
    if not end_text:
        raise ValueError("missing range end")
    if end_text == "*":
        end_text = "255"
    if end_text.isdigit():
        parts = str(start).split(".")
        end_text = ".".join(parts[:3] + [end_text])
    return ipaddress.ip_address(end_text)


def parse_targets(text: str) -> List[TargetRange]:
    """Parse subnets, ranges and single addresses.

    Accepted forms (separated by spaces, commas, semicolons or newlines)::

        10.0.0.0/24
        192.168.217.1-192.168.217.254
        192.168.217.1-254        # last octet shorthand
        192.168.217.*            # whole /24
        10.0.0.7
        # a comment line is ignored

    The user can paste many VLAN ranges at once, one per line.
    """
    ranges: List[TargetRange] = []
    for token in _TARGET_SPLIT.split(_strip_comments(text).strip()):
        if not token:
            continue
        token = token.replace("\u2013", "-").replace("\u2014", "-")
        try:
            if token.endswith(".*"):
                base = token[:-2]
                octets = base.split(".")
                if len(octets) != 3 or any(
                    not part.isdigit() or int(part) > 255 for part in octets
                ):
                    raise ValueError("wildcard needs three octets")
                ranges.append(
                    TargetRange(
                        int(ipaddress.ip_address(base + ".1")),
                        int(ipaddress.ip_address(base + ".254")),
                    )
                )
            elif "/" in token:
                network = ipaddress.ip_network(token, strict=False)
                if network.version != 4:
                    raise ValueError("only IPv4 is supported")
                first = int(network.network_address)
                last = int(network.broadcast_address)
                if network.prefixlen < 31:
                    first += 1
                    last -= 1
                ranges.append(TargetRange(first, last))
            elif "-" in token:
                start_text, _, end_text = token.partition("-")
                start = ipaddress.ip_address(start_text.strip())
                if start.version != 4:
                    raise ValueError("only IPv4 is supported")
                end = _range_end(start, end_text)
                if end.version != 4:
                    raise ValueError("only IPv4 is supported")
                if int(start) > int(end):
                    raise ValueError("range start is after range end")
                ranges.append(TargetRange(int(start), int(end)))
            else:
                address = ipaddress.ip_address(token)
                if address.version != 4:
                    raise ValueError("only IPv4 is supported")
                ranges.append(TargetRange(int(address), int(address)))
        except ValueError as exc:
            raise ValueError(
                f"'{token}' is not a valid IPv4 address, range or subnet"
            ) from exc
    if not ranges:
        raise ValueError("Enter at least one IPv4 subnet, range or address.")
    return ranges


def target_count(ranges: Sequence[TargetRange]) -> int:
    return sum(len(item) for item in ranges)


def iter_targets(ranges: Sequence[TargetRange]) -> Iterator[str]:
    for item in ranges:
        for value in range(item.first, item.last + 1):
            yield _ip_to_text(value)


def _merge_ranges(ranges: Sequence[TargetRange]) -> List[TargetRange]:
    ordered = sorted(ranges, key=lambda item: (item.first, item.last))
    merged: List[TargetRange] = []
    for item in ordered:
        if merged and item.first <= merged[-1].last + 1:
            last = max(merged[-1].last, item.last)
            merged[-1] = TargetRange(merged[-1].first, last)
        else:
            merged.append(item)
    return merged


# ---------------------------------------------------------------------------
# local network detection
# ---------------------------------------------------------------------------

_LOCAL_NETWORKS: Optional[List[ipaddress.IPv4Network]] = None


def _run_quiet(args: Sequence[str], timeout: float = 10.0) -> str:
    try:
        finished = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return finished.stdout or ""


def _powershell_networks() -> List[ipaddress.IPv4Network]:
    if os.name != "nt":
        return []
    command = (
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Where-Object { $_.IPAddress -notlike '127.*' -and "
        "$_.IPAddress -notlike '169.254.*' } | "
        "ForEach-Object { \"$($_.IPAddress)/$($_.PrefixLength)\" }"
    )
    output = _run_quiet(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command]
    )
    networks: List[ipaddress.IPv4Network] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            interface = ipaddress.ip_interface(line)
        except ValueError:
            continue
        if interface.ip.is_loopback or interface.ip.is_link_local:
            continue
        networks.append(interface.network)
    return networks


def _socket_networks() -> List[ipaddress.IPv4Network]:
    """Best-effort fallback: assume /24 around every local address."""
    addresses = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addresses.add(info[4][0])
    except OSError:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))
            addresses.add(probe.getsockname()[0])
        finally:
            probe.close()
    except OSError:
        pass
    networks: List[ipaddress.IPv4Network] = []
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local:
            continue
        networks.append(ipaddress.ip_network(f"{address}/24", strict=False))
    return networks


def local_ipv4_networks(refresh: bool = False) -> List[ipaddress.IPv4Network]:
    global _LOCAL_NETWORKS
    if _LOCAL_NETWORKS is not None and not refresh:
        return _LOCAL_NETWORKS
    networks = _powershell_networks() or _socket_networks()
    _LOCAL_NETWORKS = networks
    return networks


def default_targets_text() -> str:
    """Quick guess for the UI (no PowerShell call, so startup stays fast)."""
    networks = _socket_networks()
    if not networks:
        return ""
    return ", ".join(str(network) for network in networks[:2])


def _is_local(ip: str, networks: Sequence[ipaddress.IPv4Network]) -> bool:
    if not networks:
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in networks)


# ---------------------------------------------------------------------------
# ARP: IP -> MAC
# ---------------------------------------------------------------------------


def normalize_mac(value: str) -> str:
    digits = re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()
    if len(digits) < 12:
        return (value or "").upper()
    digits = digits[:12]
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


_SEND_ARP = None


def _windows_send_arp(ip: str) -> str:
    """Ask Windows for the MAC of ``ip`` (works without admin rights)."""
    global _SEND_ARP
    if os.name != "nt":
        return ""
    try:
        if _SEND_ARP is None:
            library = ctypes.windll.iphlpapi  # type: ignore[attr-defined]
            library.SendARP.argtypes = [
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_ulong),
            ]
            library.SendARP.restype = ctypes.c_ulong
            _SEND_ARP = library
        destination = int.from_bytes(socket.inet_aton(ip), "little")
        buffer = (ctypes.c_ubyte * 8)()
        length = ctypes.c_ulong(6)
        result = _SEND_ARP.SendARP(
            destination, 0, ctypes.byref(buffer), ctypes.byref(length)
        )
        if result != 0 or length.value < 6:
            return ""
        return ":".join(f"{buffer[index]:02X}" for index in range(6))
    except Exception:
        return ""


def _system_arp_table() -> Dict[str, str]:
    """Read the operating system's ARP cache as a fallback."""
    table: Dict[str, str] = {}
    if os.name == "nt":
        text = _run_quiet(["arp", "-a"], timeout=8)
        pattern = re.compile(
            r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})",
            re.M,
        )
        for match in pattern.finditer(text):
            table[match.group(1)] = normalize_mac(match.group(2))
        return table
    try:
        with open("/proc/net/arp", "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    table[parts[0]] = normalize_mac(parts[3])
    except OSError:
        pass
    return table


def parse_arp_table(text: str) -> Dict[str, str]:
    """Extract ``ip -> MAC`` pairs from any ARP table text.

    Works with the output of FortiGate ``get system arp``, Cisco
    ``show ip arp``, Windows ``arp -a``, and similar tables.  This lets a
    user copy the ARP table from the L3 router (for example the FortiGate
    that owns all VLAN gateways) and still map routed cameras to switch
    ports, where ARP cannot cross the router.
    """
    table: Dict[str, str] = {}
    for pattern in (_ARP_LINE_RE, _ARP_LINE_REV_RE):
        for match in pattern.finditer(text or ""):
            ip = match.group("ip")
            mac = normalize_mac(match.group("mac"))
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if address.is_multicast or address.is_unspecified or address.is_loopback:
                continue
            if ip == "255.255.255.255":
                continue
            if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                continue
            table.setdefault(ip, mac)
    return table


def _ping_sweep(hosts: Sequence[str], workers: int = 64) -> None:
    """Populate the ARP cache on platforms without a SendARP equivalent."""
    if not hosts:
        return
    if os.name == "nt":
        command = ["ping", "-n", "1", "-w", "400"]
    else:
        command = ["ping", "-c", "1", "-W", "1"]

    def ping_one(ip: str) -> None:
        _run_quiet(command + [ip], timeout=2.0)

    with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
        list(pool.map(ping_one, hosts))


def discover_arp(
    hosts: Sequence[str],
    cancel=None,
    log: Optional[Callable[[str], None]] = None,
) -> Dict[str, str]:
    """Resolve as many ``ip -> MAC`` pairs as possible.

    Only directly connected subnets can be resolved: for routed subnets the
    MAC seen by ARP would be the router's.  Those addresses are left without
    a MAC and are matched later through the switch ARP table, if available.
    """
    log = log or (lambda message: None)
    networks = local_ipv4_networks()
    local_hosts = [ip for ip in hosts if _is_local(ip, networks)]
    skipped = len(hosts) - len(local_hosts)
    if skipped:
        log(
            f"MAC lookup skipped for {skipped} address(es) outside the directly "
            "connected subnets (their MAC is not visible through a router)"
        )
    result: Dict[str, str] = {}
    if not local_hosts:
        return result

    if os.name == "nt":
        workers = min(64, max(4, len(local_hosts)))
        chunk_size = 96
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for start in range(0, len(local_hosts), chunk_size):
                if cancel is not None and cancel.is_set():
                    break
                chunk = local_hosts[start : start + chunk_size]
                for ip, mac in zip(chunk, pool.map(_windows_send_arp, chunk)):
                    if mac:
                        result[ip] = mac
    else:
        _ping_sweep(local_hosts)

    # Pick up hosts Windows/Linux already had in the cache.
    for ip, mac in _system_arp_table().items():
        if ip in local_hosts and ip not in result:
            result[ip] = mac
    return result


# ---------------------------------------------------------------------------
# TCP / HTTP / RTSP / ONVIF probes
# ---------------------------------------------------------------------------


def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        connection = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return False
    try:
        connection.close()
    except OSError:
        pass
    return True


def _decode_body(raw: bytes) -> str:
    return raw.decode("utf-8", "ignore")


def _extract_title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not match:
        return ""
    title = re.sub(r"<[^>]+>", " ", match.group(1))
    return " ".join(title.replace("&nbsp;", " ").split())[:80]


def _http_fetch(
    ip: str, port: int, path: str = "/", timeout: float = 1.2, tls: bool = False
) -> Optional[dict]:
    connection = None
    try:
        if tls:
            connection = http.client.HTTPSConnection(
                ip, port, timeout=timeout, context=ssl._create_unverified_context()
            )
        else:
            connection = http.client.HTTPConnection(ip, port, timeout=timeout)
        connection.request(
            "GET",
            path,
            headers={
                "User-Agent": "CiscoPortMapper/1.0",
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        body = _decode_body(response.read(32768))
        headers = {key.lower(): value for key, value in response.getheaders()}
        return {
            "status": response.status,
            "headers": headers,
            "body": body,
            "title": _extract_title(body),
            "port": port,
            "tls": tls,
        }
    except Exception:
        return None
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def _soap_post(ip: str, port: int, body: bytes, timeout: float) -> Optional[dict]:
    connection = None
    try:
        connection = http.client.HTTPConnection(ip, port, timeout=timeout)
        connection.request(
            "POST",
            "/onvif/device_service",
            body=body,
            headers={
                "Content-Type": "application/soap+xml; charset=utf-8",
                "User-Agent": "CiscoPortMapper/1.0",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        text = _decode_body(response.read(32768))
        headers = {key.lower(): value for key, value in response.getheaders()}
        return {"status": response.status, "headers": headers, "text": text}
    except Exception:
        return None
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


_ONVIF_HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
)


def _onvif_tag(text: str, tag: str) -> str:
    match = re.search(
        r"<(?:tds:|tt:)?%s[^>]*>(.*?)</(?:tds:|tt:)?%s>" % (tag, tag),
        text,
        re.I | re.S,
    )
    return " ".join(match.group(1).split())[:120] if match else ""


def _onvif_probe(ip: str, ports: Sequence[int], timeout: float) -> Optional[dict]:
    if not ports:
        return None
    date_body = (
        _ONVIF_HEADER + "<s:Body><tds:GetSystemDateAndTime/></s:Body></s:Envelope>"
    ).encode("utf-8")
    info_body = (
        _ONVIF_HEADER + "<s:Body><tds:GetDeviceInformation/></s:Body></s:Envelope>"
    ).encode("utf-8")
    network_body = (
        _ONVIF_HEADER + "<s:Body><tds:GetNetworkInterfaces/></s:Body></s:Envelope>"
    ).encode("utf-8")

    for port in ports:
        response = _soap_post(ip, port, date_body, timeout)
        if not response:
            continue
        text = response.get("text", "")
        headers = response.get("headers", {})
        blob = (text[:1500] + " " + headers.get("www-authenticate", "")).lower()
        detected = "getsystemdateandtimeresponse" in text.lower() or "onvif" in blob
        if not detected and response.get("status") not in (200, 401):
            continue
        if not detected:
            continue
        details = {
            "detected": True,
            "port": port,
            "manufacturer": "",
            "model": "",
            "firmware": "",
            "serial": "",
            "mac": "",
        }
        device = _soap_post(ip, port, info_body, timeout)
        if device and device.get("text"):
            details["manufacturer"] = _onvif_tag(device["text"], "Manufacturer")
            details["model"] = _onvif_tag(device["text"], "Model")
            details["firmware"] = _onvif_tag(device["text"], "FirmwareVersion")
            details["serial"] = _onvif_tag(device["text"], "SerialNumber")
        # The MAC from GetNetworkInterfaces is valid across a router, which
        # ARP cannot do.  It is the key that still allows port matching for a
        # camera sitting in another VLAN.
        network = _soap_post(ip, port, network_body, timeout)
        if network and network.get("text"):
            hw = _onvif_tag(network["text"], "HwAddress") or _onvif_tag(
                network["text"], "MACAddress"
            )
            if hw:
                details["mac"] = normalize_mac(hw)
        return details
    return None


# ---------------------------------------------------------------------------
# Hikvision / Dahua vendor fingerprints
# ---------------------------------------------------------------------------


def _header_realm(headers: Dict[str, str]) -> str:
    auth = headers.get("www-authenticate", "")
    match = re.search(r'realm="([^"]+)"', auth, re.I)
    return match.group(1) if match else ""


def _hikvision_details(body: str) -> Dict[str, str]:
    """Pull the useful fields out of a Hikvision ISAPI DeviceInfo reply."""
    return {
        "name": _onvif_tag(body, "deviceName"),
        "model": _onvif_tag(body, "model"),
        "serial": _onvif_tag(body, "serialNumber"),
        "firmware": _onvif_tag(body, "firmwareVersion"),
        "type": _onvif_tag(body, "deviceType"),
        "manufacturer": _onvif_tag(body, "manufacturer"),
    }


def _key_values(body: str) -> Dict[str, str]:
    """Parse Dahua's ``key=value`` CGI replies into a lower-case dict."""
    values: Dict[str, str] = {}
    for line in (body or "").splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key and value:
            values[key] = value
    return values


def _vendor_http_probe(
    ip: str, open_ports: Sequence[int], timeout: float
) -> Dict[str, dict]:
    """Ask Hikvision/Dahua-only endpoints who they are.

    This is the strongest vendor signal short of logging in: it works even
    when the camera requires a password, because the 401 challenge and the
    URL layout are enough to identify the family.
    """
    result: Dict[str, dict] = {}
    http_ports = [port for port in (80, 8080, 443, 8443) if port in open_ports]
    if not http_ports:
        return result

    for port in http_ports:
        tls = port in HTTPS_PORTS
        for path in HIKVISION_PATHS:
            reply = _http_fetch(ip, port, path, timeout, tls)
            if not reply:
                continue
            status = int(reply.get("status") or 0)
            headers = reply.get("headers", {})
            body = reply.get("body", "")
            realm = _header_realm(headers)
            lowered = body.lower()
            server = headers.get("server", "")
            looks = status in (200, 401) and (
                "<deviceinfo" in lowered
                or "hikvision" in lowered
                or "ds-2" in lowered
                or "isapi" in lowered
                or "hikvision" in server.lower()
                or (status == 401 and "ip camera(" in realm.lower())
            )
            if not looks:
                continue
            details = _hikvision_details(body)
            network = _http_fetch(ip, port, HIKVISION_NETWORK_PATH, timeout, tls)
            if network and network.get("body"):
                mac = _onvif_tag(network["body"], "MACAddress") or _onvif_tag(
                    network["body"], "macAddress"
                )
                if mac:
                    details["mac"] = normalize_mac(mac)
            result["hikvision"] = {
                "matched": True,
                "endpoint": True,
                "port": port,
                "status": status,
                "realm": realm,
                "server": server,
                **details,
            }
            break
        if "hikvision" in result:
            break
    if "hikvision" in result:
        return result

    for port in http_ports:
        tls = port in HTTPS_PORTS
        for path in DAHUA_PATHS:
            reply = _http_fetch(ip, port, path, timeout, tls)
            if not reply:
                continue
            status = int(reply.get("status") or 0)
            headers = reply.get("headers", {})
            body = reply.get("body", "")
            realm = _header_realm(headers)
            lowered = body.lower()
            server = headers.get("server", "")
            values = _key_values(body)
            looks = status in (200, 401) and (
                "dahua" in lowered
                or "magicbox" in lowered
                or "devicetype" in values
                or "serialnumber" in values
                or "dahua" in server.lower()
                or (status == 401 and "dahua" in realm.lower())
            )
            if not looks:
                continue
            result["dahua"] = {
                "matched": True,
                "endpoint": True,
                "port": port,
                "status": status,
                "realm": realm,
                "server": server,
                "type": values.get("devicetype", ""),
                "model": values.get("devicetype", ""),
                "serial": values.get("serialnumber", ""),
                "firmware": values.get("softwareversion", ""),
                "name": values.get("machinename", ""),
                "manufacturer": "Dahua" if "dahua" in lowered else "",
            }
            break
        if "dahua" in result:
            break

    # Remember that a bare 'webs' server was seen; both families use it.
    if "hikvision" not in result and "dahua" not in result:
        for port in http_ports:
            reply = _http_fetch(ip, port, "/", timeout, port in HTTPS_PORTS)
            if not reply:
                continue
            server = reply.get("headers", {}).get("server", "").strip().lower()
            token = server.split()[0] if server.split() else ""
            if token in WEB_SERVER_HINTS or server.startswith("webs"):
                result["webs"] = {"matched": True, "port": port, "server": server}
                break

    return result


def _rtsp_probe(ip: str, port: int, timeout: float) -> Optional[dict]:
    request = (
        f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: CiscoPortMapper/1.0\r\n\r\n"
    ).encode("ascii", "ignore")
    try:
        connection = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    try:
        connection.sendall(request)
        data = connection.recv(4096)
    except OSError:
        return None
    finally:
        try:
            connection.close()
        except OSError:
            pass
    text = _decode_body(data)
    headers: Dict[str, str] = {}
    for line in text.splitlines()[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    realm = ""
    auth = headers.get("www-authenticate", "")
    realm_match = re.search(r'realm="([^"]+)"', auth, re.I)
    if realm_match:
        realm = realm_match.group(1)
    return {
        "server": headers.get("server", ""),
        "realm": realm,
        "public": headers.get("public", ""),
        "status": text.splitlines()[0] if text else "",
    }


def probe_host(ip: str, timeout: float = 0.6) -> Optional[dict]:
    """Probe one address; ``None`` means no camera-ish port was open."""
    open_ports: List[int] = []
    for port in PROBE_PORTS:
        if _tcp_open(ip, port, timeout):
            open_ports.append(port)
    if not open_ports:
        return None

    http_results: List[dict] = []
    for port in HTTP_PORTS:
        if port in open_ports:
            result = _http_fetch(ip, port, timeout=timeout + 0.6)
            if result:
                http_results.append(result)
    for port in HTTPS_PORTS:
        if port in open_ports:
            result = _http_fetch(ip, port, timeout=timeout + 0.6, tls=True)
            if result:
                http_results.append(result)

    rtsp_results: List[dict] = []
    for port in RTSP_PORTS:
        if port in open_ports:
            result = _rtsp_probe(ip, port, timeout + 0.4)
            if result:
                rtsp_results.append(result)

    onvif_ports = [port for port in (80, 8080) if port in open_ports]
    onvif = _onvif_probe(ip, onvif_ports, timeout + 0.6) if onvif_ports else None

    vendor = _vendor_http_probe(ip, open_ports, timeout + 0.6)

    return {
        "open_ports": sorted(open_ports),
        "http": http_results,
        "rtsp": rtsp_results,
        "onvif": onvif,
        "vendor": vendor,
    }


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------


@dataclass
class Camera:
    ip: str
    mac: str = ""
    vendor: str = ""
    model: str = ""
    confidence: str = "Low"
    score: int = 0
    open_ports: List[int] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    source: str = "ARP scan"
    is_camera: bool = True
    onvif_manufacturer: str = ""
    onvif_model: str = ""
    serial: str = ""

    @property
    def ports_text(self) -> str:
        return ", ".join(str(port) for port in self.open_ports)


def _word_in(token: str, haystack: str) -> bool:
    return bool(
        re.search(
            r"(?<![a-z0-9])" + re.escape(token.lower()) + r"(?![a-z0-9])",
            haystack,
        )
    )


def _camera_vendor_hits(haystack: str) -> List[str]:
    hits: List[str] = []
    for token, name in CAMERA_VENDORS:
        if _word_in(token, haystack) and name not in hits:
            hits.append(name)
    for token, name in CAMERA_MODEL_TOKENS:
        if token in haystack and name not in hits:
            hits.append(name)
    return hits


def _meaningful_title(title: str) -> str:
    cleaned = " ".join((title or "").split())
    if cleaned.lower() in GENERIC_TITLES:
        return ""
    if len(cleaned) > 70:
        cleaned = cleaned[:70]
    return cleaned


def classify_host(
    ip: str,
    mac: str,
    probe: dict,
    oui: Optional[Dict[str, str]] = None,
) -> Camera:
    """Turn raw probe data into a :class:`Camera` record."""
    from oui import lookup_vendor  # local import keeps this module standalone

    database = oui or {}
    open_ports = list(probe.get("open_ports") or [])
    parts: List[str] = []
    titles: List[str] = []
    for item in probe.get("http", []):
        headers = item.get("headers", {})
        parts.extend(
            [
                headers.get("server", ""),
                headers.get("www-authenticate", ""),
                headers.get("x-powered-by", ""),
                headers.get("location", ""),
                item.get("title", ""),
                item.get("body", "")[:6000],
            ]
        )
        if item.get("title"):
            titles.append(item["title"])
    for item in probe.get("rtsp", []):
        parts.extend([item.get("server", ""), item.get("realm", ""), item.get("public", "")])
    onvif = probe.get("onvif") or {}
    vendor_probe = probe.get("vendor") or {}
    hik = vendor_probe.get("hikvision") or {}
    dah = vendor_probe.get("dahua") or {}
    webs = vendor_probe.get("webs") or {}
    parts.extend(
        [
            onvif.get("manufacturer", ""),
            onvif.get("model", ""),
        ]
    )
    haystack = " ".join(part for part in parts if part).lower()

    vendor_hits = _camera_vendor_hits(haystack)
    oui_vendor = lookup_vendor(mac, database) if mac else ""
    score = 0
    evidence: List[str] = []

    if 554 in open_ports or 8554 in open_ports:
        score += 4
        evidence.append("RTSP port is open")
    rtsp_servers = [item.get("server", "") for item in probe.get("rtsp", []) if item.get("server")]
    if rtsp_servers:
        score += 2
        evidence.append("RTSP answered: " + ", ".join(rtsp_servers[:2]))
    realms = [item.get("realm", "") for item in probe.get("rtsp", []) if item.get("realm")]
    if realms:
        score += 1
        evidence.append("RTSP realm: " + ", ".join(realms[:2]))
    if onvif.get("detected"):
        score += 4
        evidence.append(f"ONVIF device service answered on port {onvif.get('port', '')}")
    for port, label in VENDOR_PORTS.items():
        if port in open_ports:
            score += 3 if port == 37777 else 2
            evidence.append(f"{label} ({port}) is open")

    vendor_probe_name = ""
    vendor_probe_model = ""
    vendor_probe_serial = ""
    if hik.get("matched"):
        score += 6
        vendor_probe_name = "Hikvision"
        details = hik.get("model") or hik.get("type") or ""
        vendor_probe_model = " ".join(
            part for part in ("Hikvision", details) if part
        ).strip()
        vendor_probe_serial = hik.get("serial", "")
        evidence.append(
            f"Hikvision ISAPI answered on port {hik.get('port', '')}"
            + (f" (HTTP {hik.get('status')})" if hik.get("status") else "")
        )
    if dah.get("matched"):
        score += 6
        vendor_probe_name = "Dahua"
        details = dah.get("model") or dah.get("type") or ""
        vendor_probe_model = " ".join(
            part for part in ("Dahua", details) if part
        ).strip()
        vendor_probe_serial = dah.get("serial", "")
        evidence.append(
            f"Dahua CGI answered on port {dah.get('port', '')}"
            + (f" (HTTP {dah.get('status')})" if dah.get("status") else "")
        )
    if webs.get("matched"):
        score += 1
        evidence.append(
            f"Web server header '{webs.get('server', 'webs')}' "
            "(common on Hikvision/Dahua)"
        )
    port_vendor = ""
    if 37777 in open_ports:
        port_vendor = "Dahua"
        evidence.append("Port 37777 is the Dahua SDK port")
    elif 8000 in open_ports and (
        554 in open_ports or 8554 in open_ports or onvif.get("detected")
    ):
        port_vendor = "Hikvision"
        evidence.append("Port 8000 with RTSP/ONVIF suggests Hikvision")
    if port_vendor and port_vendor not in vendor_hits:
        vendor_hits.append(port_vendor)
    if vendor_probe_name and vendor_probe_name not in vendor_hits:
        vendor_hits.insert(0, vendor_probe_name)

    if vendor_hits:
        score += 3 + min(2, len(vendor_hits) - 1)
        evidence.append("Fingerprint: " + ", ".join(vendor_hits[:4]))
    camera_words = [
        word for word in CAMERA_WORDS if _word_in(word, haystack)
    ]
    if camera_words:
        score += 1
        evidence.append("Web page mentions " + ", ".join(camera_words[:3]))
    if not vendor_hits:
        camera_brand = _camera_vendor_hits(oui_vendor.lower()) if oui_vendor else []
        if camera_brand:
            score += 1
            evidence.append("MAC vendor: " + oui_vendor)
    if 80 in open_ports or 443 in open_ports:
        evidence.append("Web interface is open")

    confidence = "High" if score >= 8 else "Medium" if score >= 5 else "Low"
    is_camera = score >= 3

    onvif_name = " ".join(
        part for part in (onvif.get("manufacturer", ""), onvif.get("model", "")) if part
    ).strip()
    title = next((_meaningful_title(value) for value in titles if _meaningful_title(value)), "")
    model = (
        onvif_name
        or vendor_probe_model
        or (vendor_hits[0] if vendor_hits else "")
        or title
        or (rtsp_servers[0] if rtsp_servers else "")
        or oui_vendor
        or ("Unknown camera" if is_camera else "Unknown host")
    )
    vendor = (
        oui_vendor
        or onvif.get("manufacturer", "")
        or vendor_probe_name
        or (vendor_hits[0] if vendor_hits else "")
    )
    serial = onvif.get("serial", "") or vendor_probe_serial

    discovered_mac = ""
    if not mac:
        discovered_mac = onvif.get("mac", "") or hik.get("mac", "")
        if discovered_mac:
            via = "ONVIF" if onvif.get("mac") else "Hikvision ISAPI"
            evidence.append(f"MAC read via {via} (works across a router)")

    if mac:
        source = "ARP scan"
    elif discovered_mac:
        source = "ONVIF/ISAPI scan"
    else:
        source = "port scan"

    return Camera(
        ip=ip,
        mac=normalize_mac(mac or discovered_mac) if (mac or discovered_mac) else "",
        vendor=vendor,
        model=model,
        confidence=confidence,
        score=score,
        open_ports=open_ports,
        evidence=list(dict.fromkeys(evidence)),
        source=source,
        is_camera=is_camera,
        onvif_manufacturer=onvif.get("manufacturer", ""),
        onvif_model=onvif.get("model", ""),
        serial=serial,
    )


# ---------------------------------------------------------------------------
# discovery entry point
# ---------------------------------------------------------------------------

_LABEL_PREFIX = "Camera discovery"


def discover_cameras(
    ranges: Sequence[TargetRange],
    cancel=None,
    log: Optional[Callable[[str], None]] = None,
    progress: Optional[Callable[[int, int], None]] = None,
    oui: Optional[Dict[str, str]] = None,
    include_all: bool = False,
    timeout: float = 0.6,
    max_workers: int = 48,
) -> List[Camera]:
    log = log or (lambda message: None)
    progress = progress or (lambda done, total: None)
    ranges = _merge_ranges(ranges)
    total = target_count(ranges)
    if total > MAX_TARGETS:
        raise ValueError(
            f"{total} addresses is too many (limit {MAX_TARGETS}). "
            "Narrow the subnet, e.g. use /24 or /23."
        )
    hosts = list(iter_targets(ranges))
    log(f"{_LABEL_PREFIX}: {total} address(es) to check")
    networks = local_ipv4_networks()
    remote = sum(1 for ip in hosts if not _is_local(ip, networks))
    if remote:
        log(
            f"{_LABEL_PREFIX}: {remote} address(es) are routed; they are still "
            "probed, but their MAC is only visible through the switch ARP table"
        )

    macs = discover_arp(hosts, cancel=cancel, log=log)
    log(f"{_LABEL_PREFIX}: {len(macs)} host(s) answered ARP on local subnets")

    probe_targets = [
        ip for ip in hosts if (ip in macs) or not _is_local(ip, networks)
    ]
    log(f"{_LABEL_PREFIX}: probing {len(probe_targets)} address(es) (RTSP/ONVIF/HTTP)")

    cameras: List[Camera] = []
    done = 0
    batch_size = 64
    workers = min(max_workers, max(4, len(probe_targets) or 1))
    stopped = False
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for start in range(0, len(probe_targets), batch_size):
            if cancel is not None and cancel.is_set():
                stopped = True
                break
            batch = probe_targets[start : start + batch_size]
            futures = [pool.submit(probe_host, ip, timeout) for ip in batch]
            for ip, future in zip(batch, futures):
                try:
                    probe = future.result()
                except Exception:
                    probe = None
                done += 1
                if probe:
                    try:
                        camera = classify_host(ip, macs.get(ip, ""), probe, oui)
                    except Exception as exc:  # never lose the whole scan for one host
                        log(f"{ip}: could not evaluate probe result: {exc}")
                        camera = None
                    if camera and (include_all or camera.is_camera):
                        cameras.append(camera)
            progress(done, len(probe_targets))
    if stopped:
        raise CameraCancelled("Camera discovery cancelled")
    cameras.sort(key=lambda item: tuple(int(part) for part in item.ip.split(".")))
    found = sum(1 for camera in cameras if camera.is_camera)
    log(f"{_LABEL_PREFIX}: {found} camera-like device(s), {len(cameras)} row(s)")
    return cameras


# ---------------------------------------------------------------------------
# cameras seen from the switch side (CDP / LLDP / MAC vendor)
# ---------------------------------------------------------------------------


def _first_mac(text: str) -> str:
    match = MAC_RE.search(text or "")
    return normalize_mac(match.group(0)) if match else ""


def _first_ip(text: str) -> str:
    match = IPV4_RE.search(text or "")
    return match.group(0) if match else ""


def cameras_from_switch_rows(
    rows: Sequence[dict], oui: Optional[Dict[str, str]] = None
) -> List[Camera]:
    """Find camera-like neighbours in the Ports table.

    Useful when the scanner is not in the camera VLAN: switch CDP/LLDP still
    knows the device name/platform, so the port can be reported even though
    the camera itself cannot be reached from this PC.
    """
    cameras: List[Camera] = []
    for row in rows:
        haystack = " ".join(
            str(row.get(key, ""))
            for key in ("neighbor", "platform", "description", "remote_port")
        ).lower()
        hits = _camera_vendor_hits(haystack)
        camera_word = any(
            _word_in(word, haystack) for word in CAMERA_WORDS
        ) or bool(re.search(r"\bcam(?:era)?\b", haystack))
        if not hits and not camera_word:
            continue
        ip = str(row.get("ip", "")).strip() or _first_ip(str(row.get("macs", "")))
        mac = _first_mac(str(row.get("macs", "")))
        if not ip and not mac:
            continue
        name = (
            str(row.get("neighbor", "")).strip()
            or str(row.get("platform", "")).strip()
            or (hits[0] if hits else "Camera")
        )
        cameras.append(
            Camera(
                ip=ip,
                mac=mac,
                vendor=hits[0] if hits else "",
                model=name,
                confidence="Switch side",
                score=5,
                open_ports=[],
                evidence=[
                    f"seen on {row.get('switch', '?')} {row.get('interface', '?')} "
                    f"({row.get('source', '')})"
                ],
                source="switch (CDP/LLDP)",
            )
        )
    return cameras


def merge_cameras(
    discovered: Sequence[Camera], from_switches: Sequence[Camera]
) -> List[Camera]:
    """Merge active discoveries with switch-side neighbours, without duplicates."""
    merged: List[Camera] = list(discovered)
    by_ip = {camera.ip: camera for camera in merged if camera.ip}
    by_mac = {camera.mac: camera for camera in merged if camera.mac}
    for candidate in from_switches:
        existing = by_ip.get(candidate.ip) if candidate.ip else None
        if existing is None and candidate.mac:
            existing = by_mac.get(candidate.mac)
        if existing is None:
            merged.append(candidate)
            if candidate.ip:
                by_ip[candidate.ip] = candidate
            if candidate.mac:
                by_mac[candidate.mac] = candidate
            continue
        if not existing.vendor and candidate.vendor:
            existing.vendor = candidate.vendor
        if not existing.mac and candidate.mac:
            existing.mac = candidate.mac
        for item in candidate.evidence:
            if item not in existing.evidence:
                existing.evidence.append(item)
    merged.sort(key=lambda item: tuple(int(part) for part in item.ip.split(".")) if item.ip else (999,))
    return merged


# ---------------------------------------------------------------------------
# switch MAC table matching
# ---------------------------------------------------------------------------

MAX_ACCESS_PORT_MACS = 8

# Port match states.  A port is only claimed for confirmed/probable rows;
# candidates and unknown rows keep the switch/interface columns empty.
PORT_STATUS_CONFIRMED = "confirmed"
PORT_STATUS_PROBABLE = "probable"
PORT_STATUS_CANDIDATES = "candidates"
PORT_STATUS_UNKNOWN = "unknown"

PORT_STATUS_LABELS = {
    PORT_STATUS_CONFIRMED: "Confirmed",
    PORT_STATUS_PROBABLE: "Probable",
    PORT_STATUS_CANDIDATES: "Candidates",
    PORT_STATUS_UNKNOWN: "Unknown",
}

# Label only, not a score: the MVP does not calibrate numbers yet.
PORT_STATUS_CONFIDENCE = {
    PORT_STATUS_CONFIRMED: "High",
    PORT_STATUS_PROBABLE: "Medium",
    PORT_STATUS_CANDIDATES: "Low",
    PORT_STATUS_UNKNOWN: "None",
}

_UP_PORT_STATES = {"connected", "up", "up/up"}


def _entry_key(entry: dict) -> Tuple[str, str]:
    return (str(entry.get("switch", "")), str(entry.get("interface", "")))


def _entry_candidate(
    entry: dict, counts: Dict[Tuple[str, str], int]
) -> dict:
    key = _entry_key(entry)
    return {
        "switch": key[0],
        "interface": key[1],
        "vlan": str(entry.get("vlan", "")),
        "macs": counts.get(key, 0),
        "uplink": bool(entry.get("uplink")),
        "mode": str(entry.get("mode", "") or ""),
    }


def resolve_port(
    entries: Sequence[dict],
    access: Sequence[dict],
    counts: Dict[Tuple[str, str], int],
    mac: str,
    mac_source: str,
    ip_only: bool = False,
) -> dict:
    """Decide the switch port without guessing.

    ``access`` holds the entries that look like real access ports.  The
    result has a ``status`` (confirmed/probable/candidates/unknown), the
    chosen ``best`` entry (empty unless a port is actually claimed), display
    text and a human-readable reason.
    """
    candidates = [_entry_candidate(entry, counts) for entry in entries]

    if not entries:
        if not mac:
            text = "Unknown: MAC unknown (not on a directly connected subnet)"
            reason = (
                "The device MAC is not known, so no switch port can be matched."
            )
        else:
            text = "Unknown: MAC not found in scanned switches"
            reason = (
                f"MAC {mac} was not seen in the MAC tables of the scanned "
                "switches."
            )
        return {
            "status": PORT_STATUS_UNKNOWN,
            "best": {},
            "match": text,
            "reason": reason,
            "reasons": [reason],
            "candidates": candidates,
        }

    if not access:
        text = (
            f"Candidates: only seen on uplink/shared ports "
            f"({len(entries)} port{'s' if len(entries) != 1 else ''})"
        )
        reason = (
            "The MAC was only seen on trunk/uplink ports or on ports that "
            "carry many other MACs, so the device may sit behind another "
            "switch. No single port is claimed."
        )
        return {
            "status": PORT_STATUS_CANDIDATES,
            "best": {},
            "match": text,
            "reason": reason,
            "reasons": [reason],
            "candidates": candidates,
        }

    if len(access) > 1:
        text = f"Candidates: {len(access)} possible access ports"
        reason = (
            "The MAC was seen on more than one access port, so no single "
            "port can be claimed."
        )
        return {
            "status": PORT_STATUS_CANDIDATES,
            "best": {},
            "match": text,
            "reason": reason,
            "reasons": [reason],
            "candidates": candidates,
        }

    best = access[0]
    key = _entry_key(best)
    mac_count = counts.get(key, 0)
    state = str(best.get("status", "") or "").strip()
    reasons: List[str] = []

    if ip_only:
        status = PORT_STATUS_PROBABLE
        text = "Probable: IP matched via switch (MAC not visible)"
        reasons.append(
            "The switch reports this IP through CDP/LLDP/ARP on the port, "
            "but the device MAC was not seen in the MAC table."
        )
    elif not state:
        status = PORT_STATUS_PROBABLE
        text = f"Probable: MAC matched ({mac_source})"
        reasons.append(
            "The MAC was learned on this access port, but the port state is "
            "unknown."
        )
    elif state.lower() not in _UP_PORT_STATES:
        status = PORT_STATUS_PROBABLE
        text = f"Probable: MAC matched ({mac_source})"
        reasons.append(
            f"The MAC was learned on this access port, but the port state is "
            f"'{state}'."
        )
    elif mac_count > 1:
        status = PORT_STATUS_PROBABLE
        text = f"Probable: MAC matched ({mac_source})"
        reasons.append(
            f"The MAC was learned on this access port, but the port carries "
            f"{mac_count} MACs (possible downstream switch or hub)."
        )
    else:
        status = PORT_STATUS_CONFIRMED
        text = f"Confirmed: MAC matched ({mac_source})"
        reasons.append(
            "The MAC was learned on this access port, the port is up and it "
            "is the only MAC on the port."
        )
        if str(best.get("mode", "") or "").lower() == "access":
            reasons.append("The switchport is configured as access mode.")

    if len(entries) > len(access):
        reasons.append(
            f"{len(entries) - len(access)} other port(s) were ignored because "
            "they look like uplinks/trunks or carry many MACs."
        )

    return {
        "status": status,
        "best": best,
        "match": text,
        "reason": " ".join(reasons),
        "reasons": reasons,
        "candidates": candidates,
    }


def _port_counts(mac_ports: Dict[str, List[dict]]) -> Dict[Tuple[str, str], int]:
    counts: Dict[Tuple[str, str], int] = {}
    for entries in mac_ports.values():
        for entry in entries:
            key = (str(entry.get("switch", "")), str(entry.get("interface", "")))
            counts[key] = counts.get(key, 0) + 1
    return counts


def _row_is_uplink(row: dict) -> bool:
    """True when a switch row looks like an uplink/trunk port."""
    if str(row.get("mode", "") or "").lower() == "trunk":
        return True
    vlan = str(row.get("vlan", "") or "").lower()
    if "trunk" in vlan:
        return True
    description = str(row.get("description", "") or "").lower()
    if any(
        word in description
        for word in (
            "uplink", "up-link", "trunk", "interswitch", "inter-switch",
            "backbone", "to core", "to-core", "core-link", "core link",
        )
    ):
        return True
    # A CDP/LLDP neighbour whose platform is a switch model means the port
    # leads to another switch, even when it is not configured as a trunk.
    return _looks_like_switch_neighbor(
        {"neighbor_platform": row.get("platform", "")}
    )


def build_ip_port_index(rows: Sequence[dict]) -> Dict[str, List[dict]]:
    """Index switch rows by the neighbour IP they report (CDP/LLDP/ARP).

    This is the fallback for a routed camera VLAN: even when ARP cannot see
    the camera's MAC, CDP/LLDP on the switch still reports its IP and the
    switch port it is connected to.
    """
    index: Dict[str, List[dict]] = {}
    for row in rows:
        ip = str(row.get("ip", "")).strip() or _first_ip(str(row.get("macs", "")))
        if not ip:
            continue
        index.setdefault(ip, []).append(
            {
                "switch": row.get("switch", ""),
                "host": "",
                "interface": row.get("interface", ""),
                "vlan": row.get("vlan", ""),
                "type": row.get("source", ""),
                "description": row.get("description", ""),
                "status": row.get("status", ""),
                "uplink": _row_is_uplink(row),
                "mode": row.get("mode", ""),
            }
        )
    return index


def match_devices(
    devices: Sequence,
    mac_ports: Dict[str, List[dict]],
    ip_to_mac: Optional[Dict[str, str]] = None,
    ip_ports: Optional[Dict[str, List[dict]]] = None,
    label: str = "Device",
) -> List[dict]:
    """Build one display row per device, with the best switch port.

    Used for both cameras and ordinary PCs; any object with ``ip``, ``mac``,
    ``vendor``, ``model``, ``confidence``, ``ports_text``, ``source``,
    ``evidence`` and ``serial`` attributes works.

    A MAC that is learned on a trunk/uplink is seen on many ports.  Ports with
    more than :data:`MAX_ACCESS_PORT_MACS` MACs are ignored when choosing the
    access port; the remaining candidates are listed in the detail window.
    """
    ip_to_mac = ip_to_mac or {}
    ip_ports = ip_ports or {}
    counts = _port_counts(mac_ports)
    rows: List[dict] = []
    title = (label or "Device").strip() or "Device"
    pad = " " * max(0, 13 - len(title))

    for camera in devices:
        mac = camera.mac
        mac_source = "ONVIF/ISAPI" if camera.source.startswith("ONVIF") else "ARP"
        if not mac:
            mac = ip_to_mac.get(camera.ip, "")
            if mac:
                mac_source = "switch ARP"
                camera.mac = mac
        mac = normalize_mac(mac) if mac else ""

        entries_from_ip = False
        entries = list(mac_ports.get(mac, [])) if mac else []
        if not entries:
            # CDP/LLDP (or the switch ARP table) may know the camera IP even
            # when this PC cannot resolve its MAC because of routing.
            by_ip = list(ip_ports.get(camera.ip, []))
            if by_ip:
                entries = by_ip
                entries_from_ip = True
                mac_source = "switch CDP/LLDP/ARP by IP"
        access = [
            entry
            for entry in entries
            if not entry.get("uplink")
            and str(entry.get("mode", "") or "").lower() != "trunk"
            and counts.get((str(entry.get("switch", "")), str(entry.get("interface", ""))), 0)
            <= MAX_ACCESS_PORT_MACS
        ]
        access.sort(
            key=lambda entry: (
                counts.get((str(entry.get("switch", "")), str(entry.get("interface", ""))), 0),
                str(entry.get("switch", "")),
                str(entry.get("interface", "")),
            )
        )
        ignored = len(entries) - len(access)
        match_info = resolve_port(
            entries, access, counts, mac, mac_source, ip_only=entries_from_ip
        )
        best = match_info["best"]
        match_text = match_info["match"]
        port_status = match_info["status"]
        port_confidence = PORT_STATUS_CONFIDENCE.get(port_status, "None")
        port_reason = match_info["reason"]
        port_reasons = match_info["reasons"]
        candidates = match_info["candidates"]

        switch_name = str(best.get("switch", ""))
        interface = str(best.get("interface", ""))
        vlan = str(best.get("vlan", ""))
        port_desc = str(best.get("description", ""))
        port_state = str(best.get("status", ""))

        detail_lines = [
            f"{title}{pad}: {camera.ip or '(no IP)'}",
            f"MAC          : {camera.mac or '(unknown)'}",
            f"Vendor       : {camera.vendor or '(unknown)'}",
            f"Name / model : "
            f"{getattr(camera, 'hostname', '') or camera.model or '(unknown)'}",
            f"Confidence   : {camera.confidence} (score {camera.score})",
            f"Open ports   : {camera.ports_text or '(none)'}",
            f"Source       : {camera.source}",
        ]
        if camera.serial:
            detail_lines.append(f"Serial       : {camera.serial}")
        detail_lines.append("Evidence     :")
        for item in camera.evidence or ["(none)"]:
            detail_lines.append(f"  - {item}")
        detail_lines.append("")
        detail_lines.append(
            f"Port match   : {PORT_STATUS_LABELS.get(port_status, 'Unknown')} "
            f"(confidence {port_confidence})"
        )
        detail_lines.append(f"Reason       : {port_reason}")
        detail_lines.append(f"Switch match : {match_text}")
        if best:
            detail_lines.extend(
                [
                    f"Switch       : {switch_name}",
                    f"Port         : {interface}",
                    f"Port desc.   : {port_desc or '(none)'}",
                    f"Port status  : {port_state or '(unknown)'}",
                    f"VLAN         : {vlan or '(unknown)'}",
                    f"Port type    : "
                    f"{'uplink / trunk' if best.get('uplink') else 'access'}",
                    f"MACs on port : {counts.get((switch_name, interface), 0)}",
                ]
            )
        if port_status == PORT_STATUS_CANDIDATES and candidates:
            detail_lines.append("")
            detail_lines.append("Candidate ports (no single port claimed):")
            for item in candidates:
                kind = "uplink/trunk" if item["uplink"] else (item["mode"] or "access")
                detail_lines.append(
                    f"  {item['switch'] or '?'} {item['interface'] or '?'} "
                    f"(VLAN {item['vlan'] or '?'}, {item['macs']} MACs, {kind})"
                )
            detail_lines.append(
                "Verify the device location manually; it may be behind "
                "another switch or an unmanaged device."
            )
        if ignored and best:
            detail_lines.append("")
            detail_lines.append(
                "Ports ignored because they look like trunks/uplinks:"
            )
            for entry in entries:
                if entry in access:
                    continue
                key = (str(entry.get("switch", "")), str(entry.get("interface", "")))
                reason = (
                    "uplink/trunk"
                    if entry.get("uplink")
                    else f"{counts.get(key, 0)} MACs"
                )
                detail_lines.append(
                    f"  {entry.get('switch', '?')} {entry.get('interface', '?')} "
                    f"({reason})"
                )
        if camera.source.startswith("switch"):
            detail_lines.append("")
            detail_lines.append(
                f"This {title.lower()} was not found by the active scan; the row "
                "comes from the switch's own CDP/LLDP/MAC information."
            )

        rows.append(
            {
                "ip": camera.ip,
                "mac": camera.mac,
                "vendor": camera.vendor,
                "model": camera.model,
                "hostname": getattr(camera, "hostname", ""),
                "os_hint": getattr(camera, "os_hint", ""),
                "confidence": camera.confidence,
                "ports": camera.ports_text,
                "switch": switch_name,
                "interface": interface,
                "vlan": vlan,
                "port_desc": port_desc,
                "match": match_text,
                "port_status": port_status,
                "port_status_label": PORT_STATUS_LABELS.get(port_status, "Unknown"),
                "port_confidence": port_confidence,
                "port_reason": port_reason,
                "port_reasons": port_reasons,
                "candidates": candidates,
                "ignored": ignored,
                "evidence": "; ".join(camera.evidence[:3]),
                "local": bool(access),
                "uplink_only": bool(entries and not access),
                "_camera": camera,
                "_detail": "\n".join(detail_lines),
            }
        )

    rows.sort(
        key=lambda row: tuple(int(part) for part in row["ip"].split("."))
        if row.get("ip")
        else (999,)
    )
    return rows


def match_cameras(
    cameras: Sequence[Camera],
    mac_ports: Dict[str, List[dict]],
    ip_to_mac: Optional[Dict[str, str]] = None,
    ip_ports: Optional[Dict[str, List[dict]]] = None,
) -> List[dict]:
    """Backwards-compatible wrapper around :func:`match_devices`."""
    return match_devices(
        cameras, mac_ports, ip_to_mac, ip_ports, label="Camera"
    )


def summarize(rows: Sequence[dict]) -> dict:
    """Small counters for the status line / log."""
    confirmed = sum(
        1 for row in rows if row.get("port_status") == PORT_STATUS_CONFIRMED
    )
    probable = sum(
        1 for row in rows if row.get("port_status") == PORT_STATUS_PROBABLE
    )
    candidates = sum(
        1 for row in rows if row.get("port_status") == PORT_STATUS_CANDIDATES
    )
    unknown = sum(
        1 for row in rows if row.get("port_status") == PORT_STATUS_UNKNOWN
    )
    unknown_mac = sum(
        1
        for row in rows
        if row.get("match", "").startswith("Unknown: MAC unknown")
    )
    missing = sum(
        1
        for row in rows
        if row.get("match", "").startswith("Unknown: MAC not found")
    )
    return {
        "total": len(rows),
        "matched": confirmed + probable,
        "confirmed": confirmed,
        "probable": probable,
        "candidates": candidates,
        "unknown": unknown,
        "unknown_mac": unknown_mac,
        "missing": missing,
    }
