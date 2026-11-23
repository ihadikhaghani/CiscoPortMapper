"""SSH based Cisco switch port discovery (no SNMP, no Python SSH library).

Commands are executed through plink.exe (PuTTY) or the Windows OpenSSH
client, so only the Python standard library is needed.

Data collected from the device:

  show version
  show interfaces status
  show cdp neighbors detail
  show lldp neighbors detail
  show mac address-table   (+ show mac-address-table fallback)
  show ip arp              (+ show arp fallback)

CDP / LLDP give the device name, platform, IP and remote port.
The MAC table is used as a fallback when a neighbour protocol is not
available/enabled; ARP adds IP addresses for the learned MAC addresses.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from oui import lookup_vendor
from sshexec import (
    ExecCancelled,
    ExecError,
    run_commands,
    split_transcript,
    strip_ansi,
)

# Words that usually mean a port is an uplink/trunk rather than an access port.
_UPLINK_WORDS = (
    "uplink",
    "up-link",
    "trunk",
    "interswitch",
    "inter-switch",
    "backbone",
    "to core",
    "to-core",
    "core-link",
    "core link",
)

# CDP/LLDP platforms that identify a switch or router.  Matching on the model
# (WS-C2960X, C9300, N9K, EX4300, ...) is much safer than matching "cisco",
# because Cisco also makes phones and access points.
_SWITCH_PLATFORM_RE = re.compile(
    r"\b(?:"
    r"WS-C\d\w*|C9\d{3}|C3\d{3}|N[3579]K|Nexus|Catalyst|"
    r"SG\d{3}|SF\d{3}|Aruba|ProCurve|PowerConnect|FortiSwitch|"
    r"EX\d{3,4}|QFX|Juniper|Huawei\s+S\d{3,4}|"
    r"switch"
    r")\b",
    re.IGNORECASE,
)


def _looks_like_switch_neighbor(neighbor: Optional[dict]) -> bool:
    """True when a CDP/LLDP neighbour looks like a switch/router."""
    if not neighbor:
        return False
    platform = str(neighbor.get("neighbor_platform", "") or "")
    if _SWITCH_PLATFORM_RE.search(platform):
        return True
    med_type = str(neighbor.get("med_type", "") or "").lower()
    return "bridge" in med_type


def _port_is_uplink(interface: str, info: dict,
                    cdp: Optional[Dict[str, dict]] = None,
                    lldp: Optional[Dict[str, dict]] = None,
                    switchport_info: Optional[dict] = None,
                    trunk_info: Optional[dict] = None) -> bool:
    """Best-effort: does this port connect to another switch?

    Used by the 'only directly connected devices' filter.  The MAC-count
    heuristic in :mod:`cameras` catches large trunks; this function catches
    small uplinks as well (real trunk mode, trunk VLAN, description, or a
    switch neighbour).
    """
    if _port_mode(switchport_info, trunk_info) == "trunk":
        return True
    vlan = str(info.get("vlan", "") or "").lower()
    if "trunk" in vlan:
        return True
    description = str(info.get("description", "") or "").lower()
    if any(word in description for word in _UPLINK_WORDS):
        return True
    neighbor = (cdp or {}).get(interface) or (lldp or {}).get(interface)
    return _looks_like_switch_neighbor(neighbor)


class ScanError(Exception):
    """Connection or command failure.

    ``transcript`` carries the raw SSH output when the connection worked but
    the CLI output could not be understood, so the caller can save it.
    """

    def __init__(self, message: str, transcript: str = "") -> None:
        super().__init__(message)
        self.transcript = transcript


class ScanCancelled(ScanError):
    """Raised when the user cancels a running scan."""


@dataclass
class SwitchConfig:
    host: str
    username: str
    password: str
    secret: str = ""
    port: int = 22
    label: str = ""
    enable_lldp: bool = False
    timeout: int = 20
    rid: str = ""


@dataclass
class ScanResult:
    switch_name: str
    host: str
    rows: List[dict] = field(default_factory=list)
    raw: Dict[str, str] = field(default_factory=dict)
    transcript: str = ""
    # Structured indexes used by cameras.py to map a MAC (or IP) to a port.
    mac_ports: Dict[str, List[dict]] = field(default_factory=dict)
    ip_to_mac: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# interface / MAC normalisation
# ---------------------------------------------------------------------------

IFACE_ALIASES = {
    "et": "Ethernet",
    "fa": "FastEthernet",
    "gi": "GigabitEthernet",
    "te": "TenGigabitEthernet",
    "tw": "TwoGigabitEthernet",
    "two": "TwoGigabitEthernet",
    "twe": "TwentyFiveGigE",
    "fo": "FortyGigabitEthernet",
    "hu": "HundredGigabitEthernet",
    "ap": "AppGigabitEthernet",
    "se": "Serial",
    "po": "Port-channel",
    "vl": "Vlan",
    "lo": "Loopback",
    "tu": "Tunnel",
    "mg": "MgmtEth",
    "mgmt": "mgmt",
}

IFACE_RANK = {
    "Ethernet": 0,
    "FastEthernet": 1,
    "GigabitEthernet": 2,
    "TwoGigabitEthernet": 3,
    "TenGigabitEthernet": 4,
    "TwentyFiveGigE": 5,
    "FortyGigabitEthernet": 6,
    "HundredGigabitEthernet": 7,
    "AppGigabitEthernet": 8,
    "Port-channel": 20,
    "Vlan": 30,
    "Loopback": 40,
    "Tunnel": 50,
}

# Full names (e.g. TwentyFiveGigE) must not be shortened by the 2-letter
# alias lookup.
for _name in IFACE_RANK:
    IFACE_ALIASES.setdefault(_name.lower(), _name)
del _name

MAC_ADDR = r"[0-9a-fA-F]{2}(?:[.\-:]?[0-9a-fA-F]{2}){5}"


def normalize_iface(name: str) -> str:
    """Turn 'Gi1/0/1' into 'GigabitEthernet1/0/1' so that the output of
    different commands can be merged on the same key."""
    text = (name or "").strip()
    text = text.split(",")[0].strip()
    match = re.match(r"^([A-Za-z][A-Za-z\-]*)\s*([\d/\.:]+)$", text)
    if not match:
        return text
    prefix, numbers = match.groups()
    key = prefix.lower()
    full = IFACE_ALIASES.get(key) or IFACE_ALIASES.get(key[:2], prefix)
    return full + numbers


def iface_sort_key(name: str):
    match = re.match(r"^([A-Za-z\-]+)([\d/\.:]*)$", name or "")
    if not match:
        return (99, (), name or "")
    prefix, numbers = match.groups()
    rank = IFACE_RANK.get(prefix, 60)
    digits = tuple(int(part) for part in re.findall(r"\d+", numbers))
    return (rank, digits, name)


def normalize_mac(value: str) -> str:
    digits = re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()
    if len(digits) < 12:
        return (value or "").upper()
    digits = digits[:12]
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def is_multicast_mac(mac: str) -> bool:
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(digits) < 2:
        return False
    try:
        first = int(digits[:2], 16)
    except ValueError:
        return False
    return bool(first & 0x01)


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------

STATUS_TOKENS = {
    "connected",
    "notconnect",
    "disabled",
    "err-disabled",
    "monitoring",
    "inactive",
    "suspended",
    "dormant",
    "down",
    "up",
    "sfpabsent",
    "xcvr",
    "faulty",
}

# Some platforms abbreviate the status column ("notconnec" on NX-OS,
# "err-disab" on a narrow terminal), so match by prefix as well.
_STATUS_PREFIXES = (
    "notconn",
    "disabl",
    "err-dis",
    "monitor",
    "inactive",
    "suspend",
    "dormant",
    "sfpabs",
    "lowerlayerdown",
)


def is_status_token(value: str) -> bool:
    token = (value or "").strip().lower()
    if token in STATUS_TOKENS:
        return True
    return any(token.startswith(prefix) for prefix in _STATUS_PREFIXES)


_IDLE_STATUSES = {
    "notconnect",
    "disabled",
    "down",
    "inactive",
    "sfpabsent",
    "err-disabled",
}


def _is_idle_status(value: str) -> bool:
    token = (value or "").strip().lower()
    if token in _IDLE_STATUSES:
        return True
    return any(token.startswith(prefix) for prefix in ("notconn", "err-dis", "sfpabs"))


def parse_hostname(version_text: str) -> str:
    match = re.search(r"^(\S+)\s+uptime is", version_text, re.M | re.I)
    return match.group(1).strip() if match else ""


_EXPLICIT_DUPLEX = {"a-full", "a-half", "full", "half"}
_SPEED_RE = re.compile(r"^(?:auto|a-\d+|\d+[GM]?)$", re.I)


def _looks_like_speed(value: str) -> bool:
    return bool(_SPEED_RE.match((value or "").strip().split(" ")[0]))


def _parse_status_line(parts: List[str]) -> Optional[tuple]:
    """Parse one row of 'show interfaces status'; None when it is not a row."""
    if len(parts) < 3:
        return None
    status_index = None
    for index, part in enumerate(parts):
        if index and is_status_token(part):
            status_index = index
            break
    if status_index is None:
        return None
    port = parts[0]
    if not re.match(r"^[A-Za-z]", port):
        return None
    description = " ".join(parts[1:status_index]).strip()
    status_value = parts[status_index].strip()
    rest = parts[status_index + 1 :]
    if " " in status_value:
        # A narrow NX-OS terminal separates columns by a single space, so the
        # status can be glued to the next column ('notconnec 1').  Split it
        # back apart instead of reporting 'notconnec 1' as the status.
        head, _, tail = status_value.partition(" ")
        if is_status_token(head):
            status_value = head
            rest = [tail.strip()] + rest
    # Variants with both a link and a protocol status column repeat the
    # status token; drop the extra one.
    while rest and is_status_token(rest[0]):
        rest = rest[1:]
    # A narrow column layout can glue the duplex/speed/type cells together
    # ("a-full a-1000 10/100/1000BaseTX"), so split such a cell again when it
    # starts with a duplex or speed value.
    expanded: List[str] = []
    for part in rest:
        words = part.split()
        first_word = words[0].lower() if words else ""
        if len(words) > 1 and (
            first_word in _EXPLICIT_DUPLEX
            or first_word == "auto"
            or _looks_like_speed(words[0])
        ):
            expanded.extend(words)
        else:
            expanded.append(part)
    rest = expanded
    if len(rest) < 2:
        return None

    second = rest[1].strip().lower()
    if len(rest) == 2 and second in ("auto", "full", "half"):
        # CBS/SG: Speed, Duplex  (only two trailing columns)
        vlan = ""
        speed = rest[0].strip()
        duplex = rest[1].strip()
        port_type = ""
    elif second in _EXPLICIT_DUPLEX or (
        second == "auto"
        and (len(rest) >= 4 or _looks_like_speed(rest[2]))
    ):
        # IOS: Vlan, Duplex, Speed, Type
        vlan = rest[0].strip()
        duplex = rest[1].strip()
        speed, _, type_tail = rest[2].strip().partition(" ")
        port_type = " ".join([type_tail] + rest[3:]).strip()
    else:
        # NX-OS / Nexus: Vlan, Speed, Type  (no Duplex column)
        vlan, duplex = rest[0].strip(), ""
        speed = rest[1].strip()
        port_type = " ".join(rest[2:]).strip()

    return port, {
        "description": description,
        "status": status_value,
        "vlan": vlan,
        "duplex": duplex,
        "speed": speed,
        "type": port_type,
    }


def parse_interface_status(text: str) -> Dict[str, dict]:
    """Parse 'show interfaces status'.

    IOS:   Port  Name  Status  Vlan  Duplex  Speed  Type
    NX-OS: Port  Name  Status  Vlan  Speed   Type      (no Duplex column)
    CBS/SG: Port  Name  Status  Speed  Duplex
    """
    result: Dict[str, dict] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        padded = re.split(r"\s{2,}", line.strip())
        candidates = [padded]
        # Some CLIs (and narrow terminals) separate columns with a single
        # space only, so try plain whitespace splitting as well.
        plain = line.strip().split()
        if plain != padded:
            candidates.append(plain)
        for parts in candidates:
            parsed = _parse_status_line(parts)
            if parsed:
                port, info = parsed
                result[normalize_iface(port)] = info
                break
    return result


def parse_ip_interface_brief(text: str) -> Dict[str, dict]:
    """Fallback interface list from 'show ip interface brief'.

    Used only when 'show interfaces status' is not understood, so that at
    least the interface names and up/down state are shown.
    """
    result: Dict[str, dict] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0]
        if not re.match(r"^[A-Za-z][A-Za-z\-]*[\d/\.:]+$", name):
            continue
        status = parts[-2].lower()
        if status not in ("up", "down", "deleted", "shutdown", "admin"):
            status = parts[-1].lower()
        result[normalize_iface(name)] = {
            "description": "",
            "status": status,
            "vlan": "",
            "duplex": "",
            "speed": "",
            "type": "",
        }
    return result


def parse_cdp_neighbors(text: str) -> Dict[str, dict]:
    result: Dict[str, dict] = {}
    blocks = re.split(r"\n\s*-{5,}\s*\n", text)
    for block in blocks:
        device = re.search(r"^Device ID:\s*(.+)$", block, re.M)
        if not device:
            continue
        local = re.search(r"^Interface:\s*([^,]+)", block, re.M)
        if not local:
            continue
        name = re.sub(r"\(.*\)\s*$", "", device.group(1).strip()).strip()
        ips = re.findall(r"IP address:\s*(\d{1,3}(?:\.\d{1,3}){3})", block)
        platform = re.search(r"^Platform:\s*([^,]+)", block, re.M)
        # Real IOS puts this on the same line as "Interface:":
        #   Interface: Gi0/1,  Port ID (outgoing port): Gi0/48
        # so do not anchor it to the beginning of the line.
        port = re.search(r"Port ID \(outgoing port\):\s*(.+)$", block, re.M)
        result[normalize_iface(local.group(1))] = {
            "neighbor_name": name,
            "neighbor_ip": ips[0] if ips else "",
            "neighbor_platform": platform.group(1).strip() if platform else "",
            "neighbor_port": port.group(1).strip() if port else "",
            "chassis_id": "",
        }
    return result


_LLDP_FIELD_RE = re.compile(
    r"^\s*(?:chassis id|port id|port description|system name|system description|"
    r"time remaining|system capabilities|enabled capabilities|"
    r"management addresses|auto negotiation|physical media capabilities|"
    r"media attachment unit type|vlan id|med information|med codes|"
    r"inventory information|capabilities|device type|network policies|"
    r"power requirements|location)\b",
    re.I,
)


def _lldp_description(block: str) -> str:
    lines = block.splitlines()
    for index, line in enumerate(lines):
        if line.strip().lower().startswith("system description"):
            if "not advertised" in line.lower():
                return ""
            value = line.split(":", 1)[1].strip() if ":" in line else ""
            if value:
                return value
            for following in lines[index + 1 :]:
                if not following.strip():
                    continue
                # 'System Description:' with nothing after it is followed by
                # the next LLDP field, not by a description.
                if _LLDP_FIELD_RE.match(following):
                    return ""
                return following.strip()
            return ""
    return ""


def parse_lldp_neighbors(text: str) -> Dict[str, dict]:
    result: Dict[str, dict] = {}
    blocks = re.split(r"\n\s*-{5,}\s*\n", text)
    for block in blocks:
        local = re.search(r"^Local Int(?:erface|f):\s*(\S+)", block, re.M)
        if not local:
            continue
        result[normalize_iface(local.group(1))] = _lldp_entry(block)
    return result


def _lldp_entry(block: str) -> dict:
    name = re.search(r"^System Name:\s*(.*)$", block, re.M | re.I)
    port = re.search(r"^Port id:\s*(.+)$", block, re.M | re.I)
    chassis = re.search(r"^Chassis id:\s*(.+)$", block, re.M | re.I)
    ip = re.search(
        r"^\s*IP(?:v4)?(?:\s+address)?:\s*(\d{1,3}(?:\.\d{1,3}){3})",
        block,
        re.M | re.I,
    )
    description = _lldp_description(block)
    platform = description.splitlines()[0][:90] if description else ""
    med = re.search(r"^\s*Device type:\s*(.+)$", block, re.M | re.I)
    med_type = med.group(1).strip() if med else ""
    return {
        "neighbor_name": name.group(1).strip() if name else "",
        "neighbor_ip": ip.group(1) if ip else "",
        "neighbor_platform": platform,
        "neighbor_port": port.group(1).strip() if port else "",
        "chassis_id": chassis.group(1).strip() if chassis else "",
        "med_type": med_type,
    }


def lldp_disabled(text: str) -> bool:
    """True when 'show lldp neighbors detail' reports that LLDP is off."""
    lowered = strip_ansi(text or "").lower()
    return (
        "lldp is not enabled" in lowered
        or "lldp is disabled" in lowered
        or "lldp not enabled" in lowered
    )


def parse_lldp_by_chassis(text: str) -> Dict[str, dict]:
    """LLDP neighbours keyed by chassis MAC, for output without 'Local Intf'.

    Some IOS versions leave the local interface out of
    ``show lldp neighbors detail``.  The port is then found later by matching
    the neighbour's chassis MAC against the switch's MAC address table.
    """
    result: Dict[str, dict] = {}
    for block in re.split(r"\n\s*-{5,}\s*\n", text):
        chassis = re.search(r"^Chassis id:\s*(\S+)", block, re.M | re.I)
        if not chassis:
            continue
        value = chassis.group(1)
        if not re.fullmatch(MAC_ADDR, value):
            continue  # a device name, not a MAC address
        entry = _lldp_entry(block)
        result.setdefault(normalize_mac(value), entry)
    return result


def parse_mac_table(text: str) -> Dict[str, List[dict]]:
    result: Dict[str, List[dict]] = {}
    pattern = re.compile(
        r"^\s*[*+Gg]?\s*(\d+)\s+(" + MAC_ADDR + r")\s+(\S+)\s+(.+)$", re.I
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        vlan, mac_text, entry_type, rest = match.groups()
        # IOS puts only the port last; NX-OS has age/Secure/NTFY columns in
        # between, so the last token is the port in both cases.
        tokens = rest.split()
        if not tokens:
            continue
        port = tokens[-1]
        port_low = port.lower()
        if port_low in ("cpu", "drop", "self", "router"):
            continue
        mac = normalize_mac(mac_text)
        if not mac or is_multicast_mac(mac):
            continue
        bucket = result.setdefault(normalize_iface(port), [])
        if any(item["mac"] == mac for item in bucket):
            continue
        bucket.append({"mac": mac, "vlan": vlan, "type": entry_type})
    return result


def parse_arp(text: str) -> Dict[str, tuple]:
    result: Dict[str, tuple] = {}
    pattern = re.compile(
        r"^\s*Internet\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+("
        + MAC_ADDR
        + r")\s+\S+\s+(\S+)",
        re.I | re.M,
    )
    for match in pattern.finditer(text):
        ip, mac_text, vlan = match.groups()
        result[normalize_mac(mac_text)] = (ip, vlan)
    # NX-OS / Arista style, which has no "Internet" keyword:
    #   10.0.0.7   00:01:02   0022.9058.c800   Vlan7
    nxos = re.compile(
        r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(" + MAC_ADDR + r")\s+(\S+)\s*$",
        re.I | re.M,
    )
    for match in nxos.finditer(text):
        ip, mac_text, vlan = match.groups()
        result.setdefault(normalize_mac(mac_text), (ip, vlan))
    return result


def _parse_vlan_list(text: str) -> Optional[set]:
    """Parse '1,10,20' or '1-5' into a set of VLAN ids.

    Returns ``None`` for 'ALL' (every VLAN allowed) and an empty set when the
    list is empty/unknown.
    """
    value = (text or "").strip()
    if not value or value.lower() in ("none", "--", "-"):
        return set()
    if value.lower() == "all":
        return None
    vlans = set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start, _, end = token.partition("-")
            start, end = start.strip(), end.strip()
            if start.isdigit() and end.isdigit():
                low, high = int(start), int(end)
                if 1 <= low <= high <= 4094:
                    vlans.update(range(low, high + 1))
        elif token.isdigit():
            vlan = int(token)
            if 1 <= vlan <= 4094:
                vlans.add(vlan)
    return vlans


def _first_vlan(text: str) -> Optional[int]:
    match = re.search(r"(\d{1,4})", text or "")
    if not match:
        return None
    vlan = int(match.group(1))
    return vlan if 1 <= vlan <= 4094 else None


def parse_switchport(text: str) -> Dict[str, dict]:
    """Parse 'show interfaces switchport' (IOS / IOS-XE / NX-OS).

    Returns one dict per interface with the configured and operational mode,
    the access/native/voice VLAN and the allowed trunk VLANs.  Unknown or
    unsupported output yields an empty dict so the caller can fall back to
    the older description/CDP heuristics.
    """
    result: Dict[str, dict] = {}
    blocks = re.split(r"(?m)^\s*Name:\s*", text or "")
    for block in blocks[1:]:
        lines = block.splitlines()
        if not lines:
            continue
        name = normalize_iface(lines[0].strip())
        if not name:
            continue
        body = "\n".join(lines[1:])

        def field(pattern: str) -> str:
            match = re.search(pattern, body, re.M | re.I)
            return match.group(1).strip() if match else ""

        switchport_text = field(r"^\s*Switchport:\s*(.+)$")
        allowed_text = field(r"^\s*Trunking VLANs (?:Enabled|Allowed):\s*(.+)$")
        result[name] = {
            "switchport": switchport_text.lower().startswith("enabled"),
            "mode_admin": field(r"^\s*Administrative Mode:\s*(.+)$"),
            "mode_oper": field(r"^\s*Operational Mode:\s*(.+)$"),
            "access_vlan": _first_vlan(
                field(r"^\s*Access Mode VLAN:\s*(.+)$")
            ),
            "native_vlan": _first_vlan(
                field(r"^\s*Trunking Native Mode VLAN:\s*(.+)$")
            ),
            "voice_vlan": _first_vlan(field(r"^\s*Voice VLAN:\s*(.+)$")),
            "allowed_text": allowed_text,
            "allowed_vlans": _parse_vlan_list(allowed_text),
        }
    return result


_TRUNK_HEADER_IOS = re.compile(
    r"^(\S+)\s+(on|off|auto|desirable|none)\s+(\S+)\s+"
    r"(trunking|not-trunking|not trunking)\s+(\d{1,4})\s*$",
    re.I,
)
_TRUNK_HEADER_NXOS = re.compile(
    r"^(\S+)\s+(\d{1,4})\s+(trunking|not-trunking|not trunking)\s+\S+\s*$",
    re.I,
)


def parse_trunk(text: str) -> Dict[str, dict]:
    """Parse 'show interfaces trunk' (IOS) / 'show interface trunk' (NX-OS).

    The command prints several tables that repeat the same port name; this
    parser merges them into one dict per interface.  Ports that are not
    trunking are kept with ``status='not-trunking'`` so callers can tell
    'known to be access' from 'unknown'.
    """
    result: Dict[str, dict] = {}
    section: Optional[str] = None
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        low = stripped.lower()
        if low.startswith("port ") and "vlans" not in low:
            section = None
            continue
        if "vlans allowed on trunk" in low:
            section = "allowed"
            continue
        if "vlans allowed and active" in low:
            section = "active"
            continue
        if "vlans in spanning tree forwarding state" in low:
            section = "forwarding"
            continue

        match = _TRUNK_HEADER_IOS.match(stripped)
        if match:
            interface, mode, encapsulation, status, native = match.groups()
            result[normalize_iface(interface)] = {
                "mode": mode.lower(),
                "encapsulation": encapsulation,
                "status": status.lower(),
                "native_vlan": int(native),
                "allowed_text": "",
                "allowed_vlans": None,
                "active_vlans": set(),
                "forwarding_vlans": set(),
            }
            continue
        match = _TRUNK_HEADER_NXOS.match(stripped)
        if match:
            interface, native, status = match.groups()
            result[normalize_iface(interface)] = {
                "mode": "",
                "encapsulation": "",
                "status": status.lower(),
                "native_vlan": int(native),
                "allowed_text": "",
                "allowed_vlans": None,
                "active_vlans": set(),
                "forwarding_vlans": set(),
            }
            continue

        if section and " " in stripped:
            interface, _, vlan_text = stripped.partition(" ")
            name = normalize_iface(interface)
            if not name:
                continue
            entry = result.setdefault(
                name,
                {
                    "mode": "",
                    "encapsulation": "",
                    "status": "",
                    "native_vlan": None,
                    "allowed_text": "",
                    "allowed_vlans": None,
                    "active_vlans": set(),
                    "forwarding_vlans": set(),
                },
            )
            vlans = _parse_vlan_list(vlan_text)
            if section == "allowed":
                entry["allowed_text"] = vlan_text.strip()
                entry["allowed_vlans"] = vlans
            elif section == "active":
                entry["active_vlans"] = vlans or set()
            elif section == "forwarding":
                entry["forwarding_vlans"] = vlans or set()
    return result


def _port_mode(switchport_info: Optional[dict],
               trunk_info: Optional[dict]) -> str:
    """Return 'trunk', 'access' or '' (unknown) from real CLI data.

    The operational value wins; the administrative value is only used when
    the switch did not report an operational mode (port down).
    """
    info = switchport_info or {}
    trunk = trunk_info or {}
    status = str(trunk.get("status", "") or "").lower()
    if status == "trunking":
        return "trunk"
    oper = str(info.get("mode_oper", "") or "").lower()
    admin = str(info.get("mode_admin", "") or "").lower()
    if "trunk" in oper or (not oper and "trunk" in admin):
        return "trunk"
    if "access" in oper or (not oper and "access" in admin):
        return "access"
    return ""


# ---------------------------------------------------------------------------
# result assembly
# ---------------------------------------------------------------------------

def _detail_text(hostname: str, host: str, name: str, status_info: dict,
                 neighbor: dict, protocol: str, mac_entries: List[dict],
                 arp: Dict[str, tuple], oui: Dict[str, str],
                 switchport_info: Optional[dict] = None,
                 trunk_info: Optional[dict] = None) -> str:
    mode = _port_mode(switchport_info, trunk_info)
    lines = [
        f"Switch      : {hostname} ({host})",
        f"Interface   : {name}",
        f"Description : {status_info.get('description', '')}",
        f"Status      : {status_info.get('status', '')}",
        f"VLAN        : {status_info.get('vlan', '')}",
        f"Duplex/Speed: {status_info.get('duplex', '')} / {status_info.get('speed', '')}",
        f"Port type   : {status_info.get('type', '')}",
        f"Port mode   : {mode or 'unknown'}",
        f"Detected by : {protocol or 'nothing learned'}",
    ]
    if switchport_info:
        if switchport_info.get("access_vlan"):
            lines.append(f"Access VLAN : {switchport_info['access_vlan']}")
        native = (trunk_info or {}).get("native_vlan") \
            or switchport_info.get("native_vlan")
        if native:
            lines.append(f"Native VLAN : {native}")
        allowed = (trunk_info or {}).get("allowed_text") \
            or switchport_info.get("allowed_text")
        if allowed:
            lines.append(f"Trunk VLANs : {allowed}")
    if trunk_info and trunk_info.get("active_vlans"):
        active = ", ".join(str(vlan) for vlan in sorted(trunk_info["active_vlans"]))
        lines.append(f"Active VLANs: {active}")
    if neighbor:
        lines.extend([
            f"Neighbour   : {neighbor.get('neighbor_name') or neighbor.get('chassis_id', '')}",
            f"Neighbour IP: {neighbor.get('neighbor_ip', '')}",
            f"Platform    : {neighbor.get('neighbor_platform', '')}",
            f"Remote port : {neighbor.get('neighbor_port', '')}",
        ])
    lines.append("")
    if mac_entries:
        lines.append(f"Learned MAC addresses ({len(mac_entries)}):")
        lines.append(f"  {'MAC':<19}{'IP':<17}{'VLAN':<7}{'TYPE':<12}VENDOR")
        for entry in mac_entries:
            mac = entry["mac"]
            ip, _vlan = arp.get(mac, ("", ""))
            vendor = lookup_vendor(mac, oui)
            lines.append(
                f"  {mac:<19}{ip:<17}{entry.get('vlan', ''):<7}"
                f"{entry.get('type', ''):<12}{vendor}"
            )
    else:
        lines.append("No MAC addresses learned on this port.")
    return "\n".join(lines)


def build_rows(hostname: str, host: str, status: Dict[str, dict],
               cdp: Dict[str, dict], lldp: Dict[str, dict],
               macs: Dict[str, List[dict]], arp: Dict[str, tuple],
               oui: Optional[Dict[str, str]] = None,
               lldp_by_chassis: Optional[Dict[str, dict]] = None,
               switchports: Optional[Dict[str, dict]] = None,
               trunks: Optional[Dict[str, dict]] = None) -> List[dict]:
    database = oui or {}
    chassis_neighbours = lldp_by_chassis or {}
    switchport_data = switchports or {}
    trunk_data = trunks or {}
    names = set(status) | set(cdp) | set(lldp) | set(macs)
    rows: List[dict] = []

    for name in sorted(names, key=iface_sort_key):
        status_info = status.get(name, {})
        switchport_info = switchport_data.get(name, {})
        trunk_info = trunk_data.get(name, {})
        mode = _port_mode(switchport_info, trunk_info)
        mac_entries = macs.get(name, [])
        neighbor = cdp.get(name)
        protocol = "CDP" if neighbor else ""
        if neighbor is None:
            neighbor = lldp.get(name)
            if neighbor is not None:
                protocol = "LLDP"
        if neighbor is None and chassis_neighbours:
            # LLDP without 'Local Intf': identify the port by the neighbour's
            # chassis MAC appearing in this port's MAC table entries.
            for entry in mac_entries:
                match = chassis_neighbours.get(entry["mac"])
                if match:
                    neighbor = match
                    protocol = "LLDP"
                    break

        ip_by_mac: Dict[str, str] = {}
        vendors: List[str] = []
        for entry in mac_entries:
            ip, _vlan = arp.get(entry["mac"], ("", ""))
            if ip:
                ip_by_mac[entry["mac"]] = ip
            vendor = lookup_vendor(entry["mac"], database)
            if vendor and vendor not in vendors:
                vendors.append(vendor)
        ips = list(ip_by_mac.values())

        if neighbor:
            display = (
                neighbor.get("neighbor_name")
                or neighbor.get("neighbor_platform")
                or (
                    "LLDP-MED " + neighbor["med_type"]
                    if neighbor.get("med_type")
                    else ""
                )
                or neighbor.get("chassis_id")
                or "Unknown neighbour"
            )
            neighbor_ip = neighbor.get("neighbor_ip", "")
            platform = neighbor.get("neighbor_platform", "")
            remote_port = neighbor.get("neighbor_port", "")
        else:
            neighbor_ip = ips[0] if ips else ""
            platform = ", ".join(vendors)
            remote_port = ""
            protocol = "MAC" if mac_entries else ""
            if len(mac_entries) > 3:
                display = f"Unmanaged switch / AP? ({len(mac_entries)} MACs)"
            elif vendors:
                display = f"{vendors[0]} device"
            elif mac_entries:
                display = "Unknown device"
            else:
                display = ""

        mac_text = ", ".join(
            entry["mac"] + (f" ({ip_by_mac[entry['mac']]})" if entry["mac"] in ip_by_mac else "")
            for entry in mac_entries
        )

        status_text = str(status_info.get("status", ""))
        idle = (
            _is_idle_status(status_text)
            and not neighbor
            and not mac_entries
        )

        vlan_text = status_info.get("vlan", "")
        if not vlan_text and mode == "access" and switchport_info.get("access_vlan"):
            vlan_text = str(switchport_info["access_vlan"])
        native_vlan = (
            trunk_info.get("native_vlan")
            or switchport_info.get("native_vlan")
        )

        rows.append({
            "switch": hostname,
            "interface": name,
            "description": status_info.get("description", ""),
            "status": status_text,
            "vlan": vlan_text,
            "mode": mode,
            "access_vlan": switchport_info.get("access_vlan") or "",
            "native_vlan": native_vlan or "",
            "speed": status_info.get("speed", ""),
            "neighbor": display,
            "ip": neighbor_ip,
            "platform": platform,
            "remote_port": remote_port,
            "macs": mac_text,
            "source": protocol,
            "_idle": idle,
            "_detail": _detail_text(
                hostname, host, name, status_info, neighbor, protocol,
                mac_entries, arp, database, switchport_info, trunk_info,
            ),
        })
    return rows


def build_mac_indexes(hostname: str, host: str, status: Dict[str, dict],
                      macs: Dict[str, List[dict]], arp: Dict[str, tuple],
                      cdp: Optional[Dict[str, dict]] = None,
                      lldp: Optional[Dict[str, dict]] = None,
                      switchports: Optional[Dict[str, dict]] = None,
                      trunks: Optional[Dict[str, dict]] = None
                      ) -> Tuple[Dict[str, List[dict]], Dict[str, str]]:
    """Index the MAC table by MAC address and the ARP table by IP.

    The camera scanner matches the MAC address it discovered on the LAN
    against ``mac_ports`` and gets every switch/port where that MAC was
    learned.  ``ip_to_mac`` is the fallback for routed VLANs: on an L3 switch
    the ARP table maps a camera IP to its MAC even when the scanner cannot
    reach the camera's subnet directly.

    Each entry also carries ``uplink`` (from the real trunk/switchport data
    when available, otherwise from the description/CDP heuristics), the port
    ``mode`` (access/trunk/unknown) and the access/native VLAN.
    """
    switchport_data = switchports or {}
    trunk_data = trunks or {}
    mac_ports: Dict[str, List[dict]] = {}
    uplink_by_port: Dict[str, bool] = {}
    for interface, entries in macs.items():
        info = status.get(interface, {})
        switchport_info = switchport_data.get(interface, {})
        trunk_info = trunk_data.get(interface, {})
        if interface not in uplink_by_port:
            uplink_by_port[interface] = _port_is_uplink(
                interface, info, cdp, lldp, switchport_info, trunk_info
            )
        uplink = uplink_by_port[interface]
        mode = _port_mode(switchport_info, trunk_info)
        native_vlan = (
            trunk_info.get("native_vlan")
            or switchport_info.get("native_vlan")
        )
        for entry in entries:
            mac_ports.setdefault(entry["mac"], []).append({
                "switch": hostname,
                "host": host,
                "interface": interface,
                "vlan": entry.get("vlan", ""),
                "type": entry.get("type", ""),
                "description": info.get("description", ""),
                "status": info.get("status", ""),
                "uplink": uplink,
                "mode": mode,
                "access_vlan": switchport_info.get("access_vlan") or "",
                "native_vlan": native_vlan or "",
            })
    ip_to_mac: Dict[str, str] = {}
    for mac, value in arp.items():
        ip = value[0] if value else ""
        if ip:
            ip_to_mac[ip] = mac
    return mac_ports, ip_to_mac


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------

BASE_COMMANDS = [
    "terminal length 0",
    "terminal width 512",
    "show version",
    "show interfaces status",
    "show interface status",
    "show interfaces switchport",
    "show interface switchport",
    "show interfaces trunk",
    "show interface trunk",
    "show ip interface brief",
    "show cdp neighbors detail",
    "show lldp neighbors detail",
    "show mac address-table",
    "show mac-address-table",
    "show ip arp",
    "show arp",
]


def _run(cfg: SwitchConfig, commands: List[str],
         cancel=None, log: Optional[Callable[[str], None]] = None
         ) -> Tuple[Dict[str, str], str]:
    log = log or (lambda message: None)
    try:
        transcript = run_commands(
            cfg.host,
            cfg.port,
            cfg.username,
            cfg.password,
            commands,
            cancel=cancel,
            log=log,
            timeout=max(120.0, cfg.timeout * 8),
        )
    except ExecCancelled as exc:
        raise ScanCancelled(str(exc)) from exc
    except ExecError as exc:
        raise ScanError(str(exc)) from exc
    outputs = split_transcript(transcript, commands)
    if "show version" in commands and not any(
        output.strip() for output in outputs.values()
    ):
        snippet = strip_ansi(transcript).strip()[:400]
        raise ScanError(
            "Connected, but no command output could be recognised. The switch "
            "prompt was probably not detected.\n\nFirst output received:\n"
            + (snippet or "(nothing)"),
            transcript=transcript,
        )
    return outputs, transcript


def scan_switch(cfg: SwitchConfig, cancel=None,
                log: Optional[Callable[[str], None]] = None,
                oui: Optional[Dict[str, str]] = None) -> ScanResult:
    log = log or (lambda message: None)
    database = oui or {}

    commands: List[str] = []
    if cfg.secret:
        commands.extend(["enable", cfg.secret])
    if cfg.enable_lldp:
        commands.extend(["configure terminal", "lldp run", "end"])
    commands.extend(BASE_COMMANDS)

    log(f"Connecting to {cfg.username}@{cfg.host}:{cfg.port}")
    outputs, transcript = _run(cfg, commands, cancel=cancel, log=log)

    version_text = outputs.get("show version", "")
    hostname = parse_hostname(version_text) or cfg.label or cfg.host

    status: Dict[str, dict] = {}
    # Some platforms only accept one of the two spellings; merge both.
    for command in ("show interfaces status", "show interface status"):
        for name, info in parse_interface_status(outputs.get(command, "")).items():
            status.setdefault(name, info)
    if not status:
        # Last-resort interface list: works on IOS, IOS-XE and NX-OS even when
        # 'show interfaces status' is spelled differently or unsupported.
        status = parse_ip_interface_brief(
            outputs.get("show ip interface brief", "")
        )
        if status:
            log(
                f"{hostname}: 'show interfaces status' was not understood; "
                "using 'show ip interface brief' instead"
            )
        else:
            log(f"{hostname}: no interface list could be parsed")

    switchports: Dict[str, dict] = {}
    for command in ("show interfaces switchport", "show interface switchport"):
        for name, info in parse_switchport(outputs.get(command, "")).items():
            switchports.setdefault(name, info)
    if switchports:
        log(f"{hostname}: switchport mode known for {len(switchports)} port(s)")
    else:
        log(
            f"{hostname}: 'show interfaces switchport' was not understood; "
            "using description/CDP heuristics for the port mode"
        )

    trunks: Dict[str, dict] = {}
    for command in ("show interfaces trunk", "show interface trunk"):
        for name, info in parse_trunk(outputs.get(command, "")).items():
            trunks.setdefault(name, info)
    if trunks:
        trunking = sum(
            1 for info in trunks.values() if info.get("status") == "trunking"
        )
        log(f"{hostname}: {trunking} trunking port(s) reported")

    cdp = parse_cdp_neighbors(outputs.get("show cdp neighbors detail", ""))
    if not cdp:
        log(f"{hostname}: no CDP neighbours found")
    lldp_text = outputs.get("show lldp neighbors detail", "")
    lldp = parse_lldp_neighbors(lldp_text)
    lldp_by_chassis = parse_lldp_by_chassis(lldp_text)
    if not lldp and not lldp_by_chassis and cfg.enable_lldp \
            and lldp_disabled(lldp_text):
        log("LLDP was enabled just now - waiting 12s for advertisements")
        time.sleep(12)
        try:
            extra, _ = _run(
                cfg,
                ["terminal length 0", "show lldp neighbors detail"],
                cancel=cancel,
                log=log,
            )
            lldp_text = extra.get("show lldp neighbors detail", "")
            lldp = parse_lldp_neighbors(lldp_text)
            lldp_by_chassis = parse_lldp_by_chassis(lldp_text)
        except ScanCancelled:
            raise
        except ScanError as exc:
            log(f"Could not re-read LLDP: {exc}")
    if not lldp and not lldp_by_chassis:
        log(f"{hostname}: no LLDP neighbours found")

    macs: Dict[str, List[dict]] = {}
    for command in ("show mac address-table", "show mac-address-table"):
        for port, entries in parse_mac_table(outputs.get(command, "")).items():
            bucket = macs.setdefault(port, [])
            for entry in entries:
                if not any(existing["mac"] == entry["mac"] for existing in bucket):
                    bucket.append(entry)
    log(f"{hostname}: {sum(len(value) for value in macs.values())} MAC entries learned")

    arp: Dict[str, tuple] = {}
    for command in ("show ip arp", "show arp"):
        arp.update(parse_arp(outputs.get(command, "")))

    sizes = ", ".join(
        f"{command.split(' ', 1)[-1]}={len(outputs.get(command, ''))}"
        for command in (
            "show version",
            "show interfaces status",
            "show interfaces switchport",
            "show interfaces trunk",
            "show ip interface brief",
            "show cdp neighbors detail",
            "show lldp neighbors detail",
            "show mac address-table",
            "show ip arp",
        )
    )
    log(f"{hostname}: output sizes (chars): {sizes}")
    log(
        f"{hostname}: parsed status={len(status)} cdp={len(cdp)} lldp={len(lldp)} "
        f"lldp-by-mac={len(lldp_by_chassis)} switchport={len(switchports)} "
        f"trunks={len(trunks)} "
        f"macs={sum(len(value) for value in macs.values())} arp={len(arp)}"
    )

    rows = build_rows(hostname, cfg.host, status, cdp, lldp, macs, arp, database,
                      lldp_by_chassis, switchports, trunks)
    mac_ports, ip_to_mac = build_mac_indexes(
        hostname, cfg.host, status, macs, arp, cdp, lldp,
        switchports, trunks,
    )
    if not rows:
        log(
            f"{hostname}: 0 rows. SSH worked, but the CLI output was not "
            "recognised. Check raw_<host>.txt next to the program."
        )
    return ScanResult(
        switch_name=hostname,
        host=cfg.host,
        rows=rows,
        raw=outputs,
        transcript=transcript,
        mac_ports=mac_ports,
        ip_to_mac=ip_to_mac,
    )
