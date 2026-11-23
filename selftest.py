"""Offline parser tests - no switch required.

Run:  python selftest.py
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import zipfile

from cameras import (
    Camera,
    _hikvision_details,
    _key_values,
    build_ip_port_index,
    cameras_from_switch_rows,
    classify_host,
    iter_targets,
    match_cameras,
    merge_cameras,
    normalize_mac as normalize_mac_camera,
    parse_arp_table,
    parse_targets,
    target_count,
)
from cisco import (
    _port_mode,
    build_mac_indexes,
    build_rows,
    lldp_disabled,
    normalize_iface,
    normalize_mac,
    parse_arp,
    parse_cdp_neighbors,
    parse_hostname,
    parse_interface_status,
    parse_ip_interface_brief,
    parse_lldp_by_chassis,
    parse_lldp_neighbors,
    parse_mac_table,
    parse_switchport,
    parse_trunk,
)
from hosts import (
    Host,
    _parse_dns_ptr,
    _parse_nbstat,
    classify_pc,
    match_hosts,
    names_from_switch_rows,
)
from oui import lookup_vendor
from prereq import looks_like_plink, ssh_status
from sshexec import (
    kex_preference_string,
    split_transcript,
    weak_crypto_problem,
)
from xlsx import write_xlsx

VERSION = """Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE SOFTWARE (fc1)
Copyright (c) 1986-2020 by Cisco Systems, Inc.

SW1 uptime is 3 weeks, 2 days, 4 hours, 5 minutes
System returned to ROM by power-on
"""

STATUS = """Port      Name               Status       Vlan       Duplex  Speed Type
Gi0/1     uplink-sw2         connected    trunk      a-full  a-1000 10/100/1000BaseTX
Gi0/2                        notconnect   1            auto   auto 10/100/1000BaseTX
Gi0/10    web-server-01      connected    10         a-full  a-1000 10/100/1000BaseTX
Gi0/24    core-uplink        connected    1          a-full  a-1000 10/100/1000BaseTX
Gi1/0/1                      notconnect   1            auto   auto 10/100/1000BaseTX
"""

SG_STATUS = """Port      Description    Status               Speed    Duplex
--------- -------------- -------------------- -------- ------
gi1                      Up                   1000M    Full
gi2       printer        Down                 100M     Half
"""

NX_STATUS = """Port          Name               Status    Vlan     Speed     Type
-----------------------------------------------------------------------------
Eth1/1        --                 connected 1        10G       10Gbase-SR
Eth1/2        --                 notconnec 1        auto      --
"""

CDP = """
-------------------------
Device ID: SW2.lab.local
Entry address(es):
  IP address: 10.0.0.2
Platform: cisco WS-C2960X-48FPD-L,  Capabilities: Switch IGMP
Interface: GigabitEthernet0/1,  Port ID (outgoing port): GigabitEthernet0/48
Holdtime : 145 sec

Version :
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4

advertisement version: 2
VTP Management Domain: 'LAB'
Native VLAN: 1
Duplex: full
Management address(es):
  IP address: 10.0.0.2
"""

LLDP = """
------------------------------------------------
Local Intf: Gi0/10
Chassis id: 5254.00aa.bbcc
Port id: 52:54:00:AA:BB:CC
Port Description: eth0
System Name: web-server-01

System Description:
Ubuntu 22.04.3 LTS Linux 5.15.0-91-generic
Time remaining: 98 seconds
System Capabilities: B
Enabled Capabilities: B
Management Addresses:
    IP: 10.0.0.50
Auto Negotiation - supported, enabled
Physical media capabilities:
    1000baseT(FD)
"""

LLDP_NO_LOCAL = """
------------------------------------------------
Chassis id: 88dc.968d.87c3
Port id: br-lan
Port Description: br-lan
System Name: EAP1300

System Description:
EnGenius EAP1300

Time remaining: 61 seconds
System Capabilities: W
Enabled Capabilities: W
Management Addresses:
    IP: 172.16.8.5
Vlan ID: - not advertised
"""

MAC_TABLE = """          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
   1    0022.9058.c800    DYNAMIC     Gi1/0/1
  10    0050.56aa.bbcc    DYNAMIC     Gi0/10
  10    0050.56aa.bbcc    DYNAMIC     Gi0/10
   1    0011.2233.4455    STATIC      Gi0/24
   1    ffff.ffff.ffff    STATIC      CPU
   1    0100.5e00.0001    STATIC      Gi0/24
Total Mac Addresses for this criterion: 6
"""

ARP = """Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.0.0.2               45   0022.9058.c800  ARPA   Vlan1
Internet  10.0.0.50               -   0050.56aa.bbcc  ARPA   Vlan10
Internet  10.0.0.99             120   Incomplete      ARPA
"""

IP_BRIEF = """Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/1     10.0.0.1        YES NVRAM  up                    up
GigabitEthernet0/2     unassigned      YES NVRAM  administratively down down
Vlan10                 10.0.0.250      YES NVRAM  up                    up
"""

TRANSCRIPT_COMMANDS = [
    "show version",
    "show interfaces status",
    "show mac address-table",
    "show ip arp",
]

TRANSCRIPT = (
    "SW1>terminal length 0\r\n"
    "SW1>\r\n"
    "SW1>show version\r\n"
    "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4\r\n"
    "SW1 uptime is 3 weeks, 2 days\r\n"
    "SW1>\r\n"
    "SW1>show interfaces status\r\n"
    "Port      Name               Status       Vlan       Duplex  Speed Type\r\n"
    "Gi0/1     uplink-sw2         connected    trunk      a-full  a-1000 10/100/1000BaseTX\r\n"
    "--More--\r\n"
    "Gi0/2                        notconnect   1            auto   auto 10/100/1000BaseTX\r\n"
    "\x1b[KSW1>\r\n"
    "SW1>show mac address-table\r\n"
    "\r\n"
    "          Mac Address Table\r\n"
    "   1    0022.9058.c800    DYNAMIC     Gi1/0/1\r\n"
    "SW1>\r\n"
    "SW1>show ip arp\r\n"
    "Internet  10.0.0.2   45   0022.9058.c800  ARPA   Vlan1\r\n"
    "SW1>\r\n"
)

failures = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  ok   {label}")
    else:
        failures.append(label)
        print(f"  FAIL {label} {detail}")


def main() -> int:
    print("normalisation")
    check("Gi0/1 -> GigabitEthernet0/1",
          normalize_iface("Gi0/1") == "GigabitEthernet0/1", normalize_iface("Gi0/1"))
    check("Fa0/3 -> FastEthernet0/3",
          normalize_iface("Fa0/3") == "FastEthernet0/3")
    check("Port-channel1 kept",
          normalize_iface("Port-channel1") == "Port-channel1")
    check("MAC dotted -> colons",
          normalize_mac("0022.9058.c800") == "00:22:90:58:C8:00",
          normalize_mac("0022.9058.c800"))

    print("show version")
    check("hostname parsed", parse_hostname(VERSION) == "SW1", parse_hostname(VERSION))

    print("show interfaces status")
    status = parse_interface_status(STATUS)
    check("five ports", len(status) == 5, str(len(status)))
    check("Gi0/1 description", status["GigabitEthernet0/1"]["description"] == "uplink-sw2")
    check("Gi0/1 vlan trunk", status["GigabitEthernet0/1"]["vlan"] == "trunk")
    check("Gi0/2 notconnect", status["GigabitEthernet0/2"]["status"] == "notconnect")
    check("Gi0/2 empty description", status["GigabitEthernet0/2"]["description"] == "")

    print("show interfaces status - CBS/SG layout (Speed, Duplex only)")
    sg = parse_interface_status(SG_STATUS)
    check("SG rows", len(sg) == 2, str(sg))
    check("SG speed", sg.get("GigabitEthernet1", {}).get("speed") == "1000M", str(sg))
    check("SG duplex", sg.get("GigabitEthernet1", {}).get("duplex") == "Full", str(sg))
    check("SG down", sg.get("GigabitEthernet2", {}).get("status") == "Down", str(sg))

    print("show interfaces status - NX-OS single-space columns")
    nx = parse_interface_status(NX_STATUS)
    check("NX rows", len(nx) == 2, str(nx))
    check("NX status", nx.get("Ethernet1/1", {}).get("status") == "connected", str(nx))
    check("NX speed", nx.get("Ethernet1/1", {}).get("speed") == "10G", str(nx))
    check("NX truncated status", nx.get("Ethernet1/2", {}).get("status") == "notconnec", str(nx))

    print("show interfaces status - glued duplex/speed/type columns")
    glued = parse_interface_status(
        "Port      Name               Status       Vlan       Duplex  Speed Type\n"
        "Gi1/0/13                     connected    1          a-full a-1000 10/100/1000BaseTX\n"
        "Gi1/0/4                      connected    1          a-full  a-100 10/100/1000BaseTX\n"
        "Gi1/0/34  UP-LINK-SW10       connected    trunk      a-full a-1000 10/100/1000BaseTX\n"
    )
    row13 = glued.get("GigabitEthernet1/0/13", {})
    check("glued vlan", row13.get("vlan") == "1", str(row13))
    check("glued duplex", row13.get("duplex") == "a-full", str(row13))
    check("glued speed", row13.get("speed") == "a-1000", str(row13))
    check("glued type", row13.get("type") == "10/100/1000BaseTX", str(row13))
    row4 = glued.get("GigabitEthernet1/0/4", {})
    check("two-space speed", row4.get("speed") == "a-100", str(row4))
    row34 = glued.get("GigabitEthernet1/0/34", {})
    check("glued description", row34.get("description") == "UP-LINK-SW10", str(row34))
    check("glued trunk vlan", row34.get("vlan") == "trunk", str(row34))

    print("show cdp neighbors detail")
    cdp = parse_cdp_neighbors(CDP)
    check("one neighbour", len(cdp) == 1, str(cdp))
    neighbor = cdp.get("GigabitEthernet0/1", {})
    check("CDP name", neighbor.get("neighbor_name") == "SW2.lab.local")
    check("CDP ip", neighbor.get("neighbor_ip") == "10.0.0.2")
    check("CDP platform", (neighbor.get("neighbor_platform") or "").startswith("cisco WS-C2960X"))
    check("CDP remote port", neighbor.get("neighbor_port") == "GigabitEthernet0/48")

    print("show lldp neighbors detail")
    lldp = parse_lldp_neighbors(LLDP)
    check("one neighbour", len(lldp) == 1, str(lldp))
    lldp_info = lldp.get("GigabitEthernet0/10", {})
    check("LLDP name", lldp_info.get("neighbor_name") == "web-server-01")
    check("LLDP ip", lldp_info.get("neighbor_ip") == "10.0.0.50")
    check("LLDP port", lldp_info.get("neighbor_port") == "52:54:00:AA:BB:CC")
    check("LLDP platform", (lldp_info.get("neighbor_platform") or "").startswith("Ubuntu"))

    print("show mac address-table")
    macs = parse_mac_table(MAC_TABLE)
    check("port count", len(macs) == 3, str(list(macs)))
    check("duplicate MAC removed", len(macs.get("GigabitEthernet0/10", [])) == 1)
    check("static MAC kept", len(macs.get("GigabitEthernet0/24", [])) == 1,
          str(macs.get("GigabitEthernet0/24")))
    check("multicast filtered",
          all(entry["mac"] != "01:00:5E:00:00:01" for entry in macs.get("GigabitEthernet0/24", [])))
    check("CPU port filtered", "CPU" not in macs)

    print("show ip arp")
    arp = parse_arp(ARP)
    check("two entries", len(arp) == 2, str(arp))
    check("web server ip", arp.get("00:50:56:AA:BB:CC") == ("10.0.0.50", "Vlan10"),
          str(arp.get("00:50:56:AA:BB:CC")))
    arp_colon = parse_arp("Internet  10.0.0.7   12   00:50:56:aa:bb:cc   ARPA   Vlan7\n")
    check("colon MAC in ARP", arp_colon.get("00:50:56:AA:BB:CC") == ("10.0.0.7", "Vlan7"),
          str(arp_colon))
    mac_colon = parse_mac_table("  11   00:50:56:aa:bb:cc   DYNAMIC   Gi0/7\n")
    check("colon MAC in MAC table",
          mac_colon.get("GigabitEthernet0/7", [{}])[0].get("mac") == "00:50:56:AA:BB:CC",
          str(mac_colon))

    print("show ip interface brief fallback")
    brief = parse_ip_interface_brief(IP_BRIEF)
    check("brief rows", len(brief) == 3, str(brief))
    check("brief up", brief.get("GigabitEthernet0/1", {}).get("status") == "up")
    check("brief admin down",
          brief.get("GigabitEthernet0/2", {}).get("status") == "down")
    check("brief SVI", "Vlan10" in brief, str(list(brief)))

    print("sshexec transcript split")
    parts = split_transcript(TRANSCRIPT, TRANSCRIPT_COMMANDS)
    check("four sections", set(parts) == set(TRANSCRIPT_COMMANDS), str(list(parts)))
    check("version output", "C2960X" in parts["show version"] and "uptime is" in parts["show version"])
    check("prompt lines removed", "SW1>" not in parts["show version"])
    check("no command echo in output", "show version" not in parts["show version"])
    check("status continues after --More--",
          "Gi0/1" in parts["show interfaces status"]
          and "Gi0/2" in parts["show interfaces status"])
    check("--More-- removed", "More" not in parts["show interfaces status"])
    check("ANSI stripped", "\x1b" not in parts["show interfaces status"])
    check("mac table split", "0022.9058.c800" in parts["show mac address-table"])
    check("arp split", "10.0.0.2" in parts["show ip arp"])
    check("unknown command is empty", split_transcript(TRANSCRIPT, ["reload"]).get("reload") == "")

    print("plink weak-crypto message (word-wrapped like PuTTY prints it)")
    # Exactly the wrapping seen in cisco_port_mapper.log: the break lands
    # after 'configured', not after 'warning'.
    weak_text = (
        "The first key-exchange algorithm supported by the server is\n"
        "diffie-hellman-group1-sha1, which is below the configured\n"
        "warning threshold.\n"
        "Connection abandoned.\n"
        "FATAL ERROR: Cannot confirm a weak crypto primitive in batch mode\n"
    )
    problem = weak_crypto_problem(weak_text)
    check("weak kex detected", problem == ("key-exchange algorithm",
                                           "diffie-hellman-group1-sha1"),
          str(problem))
    check("normal output is not weak crypto",
          weak_crypto_problem("SW1>show version\r\nCisco IOS\r\n") is None)
    # Fallback when the sentence wording differs but the abort line is there.
    fallback_text = (
        "Something changed: the server wants diffie-hellman-group1-sha1,\n"
        "which is below the configured threshold.\n"
        "FATAL ERROR: Cannot confirm a weak crypto primitive in batch mode\n"
    )
    check("weak kex fallback detected",
          weak_crypto_problem(fallback_text)
          == ("key-exchange algorithm", "diffie-hellman-group1-sha1"),
          str(weak_crypto_problem(fallback_text)))
    kex = kex_preference_string("dh-group1-sha1")
    entries = kex.split(",")
    check("WARN is last in KEX list", entries[-1] == "WARN", kex)
    check("weak kex is above WARN", entries[-2] == "dh-group1-sha1", kex)
    check("strong kex is preferred",
          entries.index("ecdh") < entries.index("dh-group1-sha1"), kex)

    print("build_rows")
    rows = build_rows("SW1", "10.0.0.1", status, cdp, lldp, macs, arp, oui=None)
    by_iface = {row["interface"]: row for row in rows}
    check("row count", len(rows) == 5, str(len(rows)))
    check("CDP row source", by_iface["GigabitEthernet0/1"]["source"] == "CDP")
    check("CDP row device", by_iface["GigabitEthernet0/1"]["neighbor"] == "SW2.lab.local")
    check("LLDP row source", by_iface["GigabitEthernet0/10"]["source"] == "LLDP")
    check("LLDP row device", by_iface["GigabitEthernet0/10"]["neighbor"] == "web-server-01")
    check("LLDP row ip", by_iface["GigabitEthernet0/10"]["ip"] == "10.0.0.50")
    check("MAC fallback source", by_iface["GigabitEthernet1/0/1"]["source"] == "MAC")
    check("MAC fallback ip", by_iface["GigabitEthernet1/0/1"]["ip"] == "10.0.0.2")
    check("idle port flagged", by_iface["GigabitEthernet0/2"]["_idle"] is True)
    check("unknown port labelled", "device" in by_iface["GigabitEthernet0/24"]["neighbor"].lower())
    check("detail text present", "Learned MAC" in by_iface["GigabitEthernet0/10"]["_detail"])

    print("LLDP without 'Local Intf' (matched by chassis MAC)")
    by_chassis = parse_lldp_by_chassis(LLDP_NO_LOCAL)
    check("chassis lldp parsed", "88:DC:96:8D:87:C3" in by_chassis, str(by_chassis))
    check("chassis lldp not in local map", parse_lldp_neighbors(LLDP_NO_LOCAL) == {})
    chassis_macs = {
        "GigabitEthernet1/0/20": [
            {"mac": "88:DC:96:8D:87:C3", "vlan": "1", "type": "DYNAMIC"}
        ]
    }
    chassis_status = {
        "GigabitEthernet1/0/20": {
            "description": "", "status": "connected", "vlan": "1",
            "duplex": "a-full", "speed": "a-1000", "type": "10/100/1000BaseTX",
        }
    }
    chassis_rows = build_rows(
        "SW1", "10.0.0.1", chassis_status, {}, {}, chassis_macs, {},
        oui=None, lldp_by_chassis=by_chassis,
    )
    check("chassis row count", len(chassis_rows) == 1, str(len(chassis_rows)))
    chassis_row = chassis_rows[0]
    check("chassis neighbor", chassis_row["neighbor"] == "EAP1300", str(chassis_row))
    check("chassis source", chassis_row["source"] == "LLDP", str(chassis_row))
    check("chassis ip", chassis_row["ip"] == "172.16.8.5", str(chassis_row))
    check("chassis platform", "EnGenius" in chassis_row["platform"], str(chassis_row))

    med_text = (
        "------------------------------------------------\n"
        "Chassis id: 3497.f69f.b319\n"
        "Port id: 3497.f69f.b319\n"
        "System Name - not advertised\n"
        "System Description - not advertised\n"
        "\n"
        "Time remaining: 3425 seconds\n"
        "Device type: Endpoint Class I\n"
    )
    med = parse_lldp_by_chassis(med_text).get("34:97:F6:9F:B3:19", {})
    check("MED platform empty", med.get("neighbor_platform") == "", str(med))
    check("MED type parsed", med.get("med_type") == "Endpoint Class I", str(med))
    check("lldp off detected", lldp_disabled("% LLDP is not enabled\n"))
    check("lldp neighbours are not 'off'", not lldp_disabled(LLDP_NO_LOCAL))

    print("camera targets")
    targets = parse_targets("10.0.0.0/30, 10.0.0.10-10.0.0.12; 192.168.1.5")
    check("target count", target_count(targets) == 6, str(target_count(targets)))
    check("single address", target_count(parse_targets("192.168.1.5")) == 1)
    shorthand = parse_targets("192.168.217.1-254")
    check("range shorthand count", target_count(shorthand) == 254,
          str(target_count(shorthand)))
    check("range shorthand first", next(iter_targets(shorthand)) == "192.168.217.1",
          str(next(iter_targets(shorthand))))
    check("range shorthand last",
          list(iter_targets(shorthand))[-1] == "192.168.217.254")
    wildcard = parse_targets("192.168.217.*")
    check("wildcard count", target_count(wildcard) == 254,
          str(target_count(wildcard)))
    annotated = parse_targets(
        "# camera VLANs\n10.1.1.1-3\n192.168.5.0/30 # vlan 5"
    )
    check("comments ignored", target_count(annotated) == 5,
          str(target_count(annotated)))
    multi = parse_targets(
        "192.168.217.1-192.168.217.254\n192.168.218.1-192.168.218.254"
    )
    check("multiple ranges", target_count(multi) == 508,
          str(target_count(multi)))
    try:
        parse_targets("not-an-ip")
    except ValueError:
        check("invalid target rejected", True)
    else:
        check("invalid target rejected", False)

    print("ARP table import")
    forti = (
        "Address           Age(min)  Hardware Addr     Interface\n"
        "172.16.12.10        5         3c:ef:8c:11:22:33  VLAN12\n"
        "172.16.12.11        4         3c:ef:8c:11:22:44  VLAN12\n"
        "255.255.255.255   0         ff:ff:ff:ff:ff:ff  root\n"
    )
    forti_arp = parse_arp_table(forti)
    check("forti arp count", len(forti_arp) == 2, str(forti_arp))
    check("forti arp mac",
          forti_arp.get("172.16.12.10") == "3C:EF:8C:11:22:33",
          str(forti_arp))
    cisco_arp_text = (
        "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
        "Internet  172.16.12.20             12   3cef.8c11.2255  ARPA   Vlan12\n"
    )
    cisco_arp = parse_arp_table(cisco_arp_text)
    check("cisco dotted arp",
          cisco_arp.get("172.16.12.20") == "3C:EF:8C:11:22:55", str(cisco_arp))
    windows_arp = parse_arp_table(
        "  172.16.12.30          3c-ef-8c-11-22-66     dynamic\n"
    )
    check("windows arp",
          windows_arp.get("172.16.12.30") == "3C:EF:8C:11:22:66",
          str(windows_arp))

    print("camera classification")
    hik_info = _hikvision_details(
        "<DeviceInfo><deviceName>Front Door</deviceName>"
        "<model>DS-2CD2143G2-I</model>"
        "<serialNumber>DS-2CD2143G2-123</serialNumber>"
        "<firmwareVersion>V5.7.3</firmwareVersion>"
        "<deviceType>IPCamera</deviceType></DeviceInfo>"
    )
    check("hikvision XML model", hik_info["model"] == "DS-2CD2143G2-I",
          str(hik_info))
    check("hikvision XML serial", hik_info["serial"] == "DS-2CD2143G2-123",
          str(hik_info))
    dahua_info = _key_values(
        "deviceType=IPC-HDW2231T\nserialNumber=7A03\n"
        "softwareVersion=2.800\nmachinename=Dahua"
    )
    check("dahua CGI devicetype", dahua_info["devicetype"] == "IPC-HDW2231T",
          str(dahua_info))
    check("dahua CGI serial", dahua_info["serialnumber"] == "7A03",
          str(dahua_info))
    hik_probe = {
        "open_ports": [80, 554, 8000],
        "http": [{
            "status": 200,
            "headers": {"server": "webs"},
            "body": "<html><title>Hikvision</title>NETSurveillance ...</html>",
            "title": "Hikvision",
            "port": 80,
            "tls": False,
        }],
        "rtsp": [{"server": "Hikvision RTSP Server", "realm": "IP Camera", "public": ""}],
        "onvif": {"detected": True, "port": 80, "manufacturer": "Hikvision",
                  "model": "DS-2CD2042WD", "firmware": "", "serial": "ABC123"},
    }
    hik = classify_host("10.0.0.50", "44:19:B6:01:02:03", hik_probe)
    check("hikvision is a camera", hik.is_camera)
    check("hikvision high confidence", hik.confidence == "High", hik.confidence)
    check("hikvision model from ONVIF", hik.model == "Hikvision DS-2CD2042WD", hik.model)
    check("hikvision rtsp evidence",
          any("RTSP" in item for item in hik.evidence), str(hik.evidence))
    check("hikvision MAC normalised",
          hik.mac == "44:19:B6:01:02:03", hik.mac)

    hik_vendor_probe = {
        "open_ports": [80, 554],
        "http": [],
        "rtsp": [],
        "onvif": None,
        "vendor": {
            "hikvision": {
                "matched": True, "port": 80, "status": 401,
                "model": "DS-2CD2143G2", "serial": "HIK123",
                "type": "IPCamera",
            }
        },
    }
    hik_vendor = classify_host("10.0.0.52", "44:19:B6:01:02:09", hik_vendor_probe)
    check("hikvision ISAPI detected", hik_vendor.vendor == "Hikvision",
          hik_vendor.vendor)
    check("hikvision ISAPI model", "DS-2CD2143G2" in hik_vendor.model,
          hik_vendor.model)
    check("hikvision ISAPI serial", hik_vendor.serial == "HIK123",
          hik_vendor.serial)
    check("hikvision ISAPI is a camera", hik_vendor.is_camera)
    check("hikvision ISAPI evidence",
          any("ISAPI" in item for item in hik_vendor.evidence),
          str(hik_vendor.evidence))

    dahua_vendor_probe = {
        "open_ports": [80, 37777],
        "http": [],
        "rtsp": [],
        "onvif": None,
        "vendor": {
            "dahua": {
                "matched": True, "port": 80, "status": 200,
                "model": "IPC-HDW2231T", "serial": "DH456",
                "type": "IPC-HDW2231T",
            }
        },
    }
    dahua_vendor = classify_host(
        "10.0.0.53", "3C:EF:8C:01:02:03", dahua_vendor_probe
    )
    check("dahua CGI detected", dahua_vendor.vendor == "Dahua",
          dahua_vendor.vendor)
    check("dahua CGI model", "IPC-HDW2231T" in dahua_vendor.model,
          dahua_vendor.model)
    check("dahua CGI serial", dahua_vendor.serial == "DH456",
          dahua_vendor.serial)
    check("dahua CGI is a camera", dahua_vendor.is_camera)
    check("dahua CGI evidence",
          any("Dahua CGI" in item for item in dahua_vendor.evidence),
          str(dahua_vendor.evidence))

    dahua_http_probe = {
        "open_ports": [80, 554],
        "http": [{
            "status": 200,
            "headers": {"server": "webs"},
            "body": "<html><title>Dahua</title>IPC-HDW2231T</html>",
            "title": "Dahua",
            "port": 80,
            "tls": False,
        }],
        "rtsp": [],
        "onvif": None,
    }
    dahua_http = classify_host(
        "10.0.0.54", "3C:EF:8C:01:02:04", dahua_http_probe
    )
    check("dahua model token detected", dahua_http.vendor == "Dahua",
          dahua_http.vendor)

    onvif_mac_probe = {
        "open_ports": [80],
        "http": [],
        "rtsp": [],
        "onvif": {
            "detected": True, "port": 80, "manufacturer": "Dahua",
            "model": "IPC-HDW2231T", "serial": "", "firmware": "",
            "mac": "3C:EF:8C:AA:BB:CC",
        },
    }
    routed_cam = classify_host("10.20.0.5", "", onvif_mac_probe)
    check("ONVIF MAC used when ARP missing",
          routed_cam.mac == "3C:EF:8C:AA:BB:CC", routed_cam.mac)
    check("ONVIF MAC source", routed_cam.source.startswith("ONVIF"),
          routed_cam.source)
    check("ONVIF MAC evidence",
          any("ONVIF" in item for item in routed_cam.evidence),
          str(routed_cam.evidence))
    onvif_rows = match_cameras(
        [routed_cam],
        {"3C:EF:8C:AA:BB:CC": [{
            "switch": "SW3", "interface": "GigabitEthernet0/7", "vlan": "20",
            "description": "cam-routed", "status": "connected",
        }]},
        {},
    )
    check("ONVIF MAC matches switch port",
          onvif_rows[0]["interface"] == "GigabitEthernet0/7",
          str(onvif_rows[0]))
    check("ONVIF MAC match label", "ONVIF" in onvif_rows[0]["match"],
          onvif_rows[0]["match"])

    printer_probe = {
        "open_ports": [80],
        "http": [{
            "status": 200,
            "headers": {"server": "HP-ChaiSOE"},
            "body": "<html><title>HP LaserJet</title>printer status</html>",
            "title": "HP LaserJet",
            "port": 80,
            "tls": False,
        }],
        "rtsp": [],
        "onvif": None,
    }
    printer = classify_host("10.0.0.60", "00:1B:78:00:00:01", printer_probe)
    check("printer is not a camera", not printer.is_camera, str(printer.score))

    print("camera MAC matching")
    mac_ports = {
        "44:19:B6:01:02:03": [
            {"switch": "SW2", "host": "10.0.0.2",
             "interface": "GigabitEthernet1/0/5", "vlan": "40",
             "description": "cam-lobby", "status": "connected"},
            {"switch": "SW1", "host": "10.0.0.1",
             "interface": "GigabitEthernet0/48", "vlan": "trunk",
             "description": "uplink-sw2", "status": "connected"},
        ],
    }
    # Make the uplink look like a trunk by learning many MACs on it.
    for index in range(12):
        mac_ports[f"00:11:22:33:44:{index:02X}"] = [{
            "switch": "SW1", "host": "10.0.0.1",
            "interface": "GigabitEthernet0/48", "vlan": "trunk",
            "description": "uplink-sw2", "status": "connected",
        }]
    camera = Camera(ip="10.0.0.50", mac="44:19:B6:01:02:03",
                    model="Hikvision", confidence="High", score=10, is_camera=True)
    rows = match_cameras([camera], mac_ports, {})
    check("one camera row", len(rows) == 1, str(len(rows)))
    check("access port chosen", rows[0]["interface"] == "GigabitEthernet1/0/5",
          str(rows[0]))
    check("access switch chosen", rows[0]["switch"] == "SW2", str(rows[0]))
    check("port description", rows[0]["port_desc"] == "cam-lobby")
    check("single-MAC access port is confirmed",
          rows[0]["port_status"] == "confirmed", str(rows[0]))
    check("match text", rows[0]["match"].startswith("Confirmed:"), rows[0]["match"])
    check("reason recorded", bool(rows[0]["port_reason"]), str(rows[0]))
    check("uplink mentioned in detail", "uplink" in rows[0]["_detail"].lower())

    shared_camera = Camera(
        ip="10.0.0.90", mac="00:11:22:33:44:00", model="?", confidence="Low", score=4
    )
    rows_shared = match_cameras([shared_camera], mac_ports, {})
    check("shared port not claimed",
          rows_shared[0]["interface"] == "", str(rows_shared[0]))
    check("shared port marked candidates",
          rows_shared[0]["port_status"] == "candidates", str(rows_shared[0]))
    check("shared port flagged",
          rows_shared[0]["match"].startswith("Candidates:"),
          rows_shared[0]["match"])
    check("shared port listed in candidates",
          len(rows_shared[0]["candidates"]) == 1,
          str(rows_shared[0]["candidates"]))

    multi_ports = {
        "44:19:B6:01:02:03": [
            {"switch": "SW2", "host": "10.0.0.2",
             "interface": "GigabitEthernet1/0/5", "vlan": "40",
             "description": "cam-lobby", "status": "connected"},
            {"switch": "SW3", "host": "10.0.0.3",
             "interface": "GigabitEthernet1/0/6", "vlan": "40",
             "description": "cam-lobby-2", "status": "connected"},
        ],
    }
    rows_multi = match_cameras([camera], multi_ports, {})
    check("two access ports not guessed",
          rows_multi[0]["interface"] == "", str(rows_multi[0]))
    check("two access ports marked candidates",
          rows_multi[0]["port_status"] == "candidates", str(rows_multi[0]))
    check("two access ports listed",
          len(rows_multi[0]["candidates"]) == 2,
          str(rows_multi[0]["candidates"]))

    busy_ports = {
        "44:19:B6:01:02:03": [{
            "switch": "SW4", "host": "10.0.0.4",
            "interface": "GigabitEthernet1/0/7", "vlan": "40",
            "description": "cam-busy", "status": "connected",
        }],
    }
    for index in range(2):
        busy_ports[f"00:AA:BB:CC:DD:{index:02X}"] = [{
            "switch": "SW4", "host": "10.0.0.4",
            "interface": "GigabitEthernet1/0/7", "vlan": "40",
            "description": "cam-busy", "status": "connected",
        }]
    rows_busy = match_cameras([camera], busy_ports, {})
    check("shared access port is probable",
          rows_busy[0]["port_status"] == "probable", str(rows_busy[0]))
    check("shared access port still claimed",
          rows_busy[0]["interface"] == "GigabitEthernet1/0/7",
          str(rows_busy[0]))

    unknown = Camera(ip="10.9.9.9", mac="", model="?", confidence="Low", score=4)
    rows_unknown = match_cameras([unknown], mac_ports, {})
    check("unknown MAC reported",
          rows_unknown[0]["match"].startswith("Unknown: MAC unknown"),
          rows_unknown[0]["match"])
    check("unknown row claims no port",
          rows_unknown[0]["interface"] == ""
          and rows_unknown[0]["port_status"] == "unknown",
          str(rows_unknown[0]))

    routed = Camera(ip="10.0.0.77", mac="", model="?", confidence="High", score=6)
    rows_routed = match_cameras(
        [routed], mac_ports, {"10.0.0.77": "44:19:B6:01:02:03"}
    )
    check("MAC from switch ARP used", routed.mac == "44:19:B6:01:02:03", routed.mac)
    check("routed camera mapped", rows_routed[0]["interface"] == "GigabitEthernet1/0/5",
          str(rows_routed[0]))

    print("cameras seen from the switch side")
    switch_rows = [{
        "switch": "SW1", "interface": "GigabitEthernet0/10",
        "neighbor": "HIKVISION-CAM", "platform": "Hikvision",
        "description": "cam-entrance", "remote_port": "eth0",
        "ip": "10.0.0.51", "macs": "44:19:B6:01:02:04", "source": "LLDP",
    }, {
        "switch": "SW1", "interface": "GigabitEthernet0/11",
        "neighbor": "web-server-01", "platform": "Ubuntu Linux",
        "description": "server", "remote_port": "eth0",
        "ip": "10.0.0.52", "macs": "00:50:56:AA:BB:CC", "source": "LLDP",
    }]
    from_switches = cameras_from_switch_rows(switch_rows)
    check("only camera neighbour kept", len(from_switches) == 1, str(len(from_switches)))
    check("switch-side camera ip", from_switches[0].ip == "10.0.0.51")
    check("switch-side camera mac", from_switches[0].mac == "44:19:B6:01:02:04")
    merged = merge_cameras([camera], from_switches)
    check("merge deduplicates different cameras", len(merged) == 2, str(len(merged)))
    merged_same = merge_cameras(
        [Camera(ip="10.0.0.50", mac="44:19:B6:01:02:03", model="", confidence="High")],
        [Camera(ip="10.0.0.50", mac="44:19:B6:01:02:03", vendor="Hikvision",
                model="HIKVISION-CAM", confidence="Switch side", score=5,
                source="switch (CDP/LLDP)")],
    )
    check("merge fills vendor", merged_same[0].vendor == "Hikvision")
    check("merge keeps one row", len(merged_same) == 1, str(len(merged_same)))

    check("Hikvision OUI known", lookup_vendor("44:19:B6:01:02:03") == "Hikvision",
          lookup_vendor("44:19:B6:01:02:03"))
    check("Dahua OUI known", lookup_vendor("3C:EF:8C:01:02:03") == "Dahua",
          lookup_vendor("3C:EF:8C:01:02:03"))
    mac_only_row = {
        "switch": "SW1", "interface": "GigabitEthernet0/12",
        "neighbor": "Hikvision device", "platform": "Hikvision",
        "description": "", "remote_port": "", "ip": "",
        "macs": "44:19:B6:01:02:03", "source": "MAC",
    }
    mac_only_cams = cameras_from_switch_rows([mac_only_row])
    check("camera found from MAC vendor", len(mac_only_cams) == 1, str(mac_only_cams))
    check("camera MAC from MAC table",
          mac_only_cams[0].mac == "44:19:B6:01:02:03", mac_only_cams[0].mac)

    ip_index = build_ip_port_index(switch_rows)
    check("IP index built", "10.0.0.51" in ip_index, str(ip_index))
    no_mac = Camera(ip="10.0.0.51", mac="", model="HIKVISION-CAM",
                    confidence="High", score=6)
    rows_by_ip = match_cameras([no_mac], {}, {}, ip_index)
    check("IP fallback finds port",
          rows_by_ip[0]["interface"] == "GigabitEthernet0/10", str(rows_by_ip[0]))
    check("IP fallback match text",
          rows_by_ip[0]["match"].startswith("Probable: IP matched"),
          rows_by_ip[0]["match"])
    check("IP fallback is probable",
          rows_by_ip[0]["port_status"] == "probable", str(rows_by_ip[0]))

    print("switch MAC index")
    index_macs, index_arp = build_mac_indexes(
        "SW1", "10.0.0.1", status, macs, arp
    )
    entry = index_macs.get("00:22:90:58:C8:00", [])
    check("MAC indexed", len(entry) == 1, str(index_macs))
    check("MAC indexed port", entry[0]["interface"] == "GigabitEthernet1/0/1", str(entry))
    check("IP indexed", index_arp.get("10.0.0.50") == "00:50:56:AA:BB:CC",
          str(index_arp))
    check("camera normalisation matches cisco",
          normalize_mac_camera("0022.9058.c800") == normalize_mac("0022.9058.c800"))

    print("uplink / trunk detection")
    uplink_status = {
        "GigabitEthernet0/1": {
            "description": "uplink-sw2", "status": "connected", "vlan": "trunk",
            "duplex": "a-full", "speed": "a-1000", "type": "10/100/1000BaseTX",
        },
        "GigabitEthernet0/10": {
            "description": "web-server-01", "status": "connected", "vlan": "10",
            "duplex": "a-full", "speed": "a-1000", "type": "10/100/1000BaseTX",
        },
    }
    uplink_macs = {
        "GigabitEthernet0/1": [
            {"mac": "00:22:90:58:C8:00", "vlan": "trunk", "type": "DYNAMIC"}
        ],
        "GigabitEthernet0/10": [
            {"mac": "00:50:56:AA:BB:CC", "vlan": "10", "type": "DYNAMIC"}
        ],
    }
    uplink_index, _ = build_mac_indexes(
        "SW1", "10.0.0.1", uplink_status, uplink_macs, {}, cdp, lldp
    )
    check("trunk port marked uplink",
          uplink_index["00:22:90:58:C8:00"][0]["uplink"] is True,
          str(uplink_index["00:22:90:58:C8:00"]))
    check("access port not uplink",
          uplink_index["00:50:56:AA:BB:CC"][0]["uplink"] is False,
          str(uplink_index["00:50:56:AA:BB:CC"]))

    cdp_only_status = {
        "GigabitEthernet0/1": {
            "description": "", "status": "connected", "vlan": "1",
        }
    }
    cdp_only_macs = {
        "GigabitEthernet0/1": [
            {"mac": "00:22:90:58:C8:00", "vlan": "1", "type": "DYNAMIC"}
        ]
    }
    cdp_index, _ = build_mac_indexes(
        "SW1", "10.0.0.1", cdp_only_status, cdp_only_macs, {}, cdp, {}
    )
    check("switch neighbour marked uplink",
          cdp_index["00:22:90:58:C8:00"][0]["uplink"] is True,
          str(cdp_index["00:22:90:58:C8:00"]))

    ip_uplink_rows = [
        {"switch": "SW1", "interface": "GigabitEthernet0/1", "vlan": "trunk",
         "description": "uplink-sw2", "platform": "", "ip": "10.0.0.9",
         "source": "CDP"},
        {"switch": "SW1", "interface": "GigabitEthernet0/10", "vlan": "10",
         "description": "cam-lobby", "platform": "Hikvision",
         "ip": "10.0.0.51", "source": "LLDP"},
    ]
    ip_uplink_index = build_ip_port_index(ip_uplink_rows)
    check("IP index marks trunk uplink",
          ip_uplink_index["10.0.0.9"][0]["uplink"] is True,
          str(ip_uplink_index["10.0.0.9"]))
    check("IP index keeps access port",
          ip_uplink_index["10.0.0.51"][0]["uplink"] is False,
          str(ip_uplink_index["10.0.0.51"]))

    print("real switchport / trunk parsing")
    switchport_ios = (
        "Name: Gi0/1\n"
        "Switchport: Enabled\n"
        "Administrative Mode: dynamic auto\n"
        "Operational Mode: static access\n"
        "Access Mode VLAN: 10 (CCTV)\n"
        "Trunking Native Mode VLAN: 1 (default)\n"
        "Voice VLAN: none\n"
        "Trunking VLANs Enabled: ALL\n"
        "\n"
        "Name: Gi0/14\n"
        "Switchport: Enabled\n"
        "Administrative Mode: trunk\n"
        "Operational Mode: trunk\n"
        "Access Mode VLAN: 1 (default)\n"
        "Trunking Native Mode VLAN: 20 (voice)\n"
        "Voice VLAN: none\n"
        "Trunking VLANs Enabled: 1-4094\n"
        "\n"
        "Name: Gi0/2\n"
        "Switchport: Disabled\n"
        "Administrative Mode: dynamic auto\n"
        "Operational Mode: down\n"
        "Access Mode VLAN: 1 (default)\n"
        "Trunking Native Mode VLAN: 1 (default)\n"
        "Voice VLAN: none\n"
    )
    switchports = parse_switchport(switchport_ios)
    check("switchport parsed all ports", len(switchports) == 3, str(switchports))
    check("switchport normalises names",
          "GigabitEthernet0/1" in switchports, str(switchports))
    access_info = switchports["GigabitEthernet0/1"]
    check("access operational mode",
          access_info["mode_oper"] == "static access", str(access_info))
    check("access vlan parsed", access_info["access_vlan"] == 10, str(access_info))
    check("voice vlan none", access_info["voice_vlan"] is None, str(access_info))
    trunk_info = switchports["GigabitEthernet0/14"]
    check("trunk admin mode", trunk_info["mode_admin"] == "trunk", str(trunk_info))
    check("trunk native vlan", trunk_info["native_vlan"] == 20, str(trunk_info))
    check("access switchport allows all vlans",
          access_info["allowed_vlans"] is None, str(access_info["allowed_text"]))
    check("disabled switchport",
          switchports["GigabitEthernet0/2"]["switchport"] is False,
          str(switchports["GigabitEthernet0/2"]))
    check("unsupported switchport output ignored",
          parse_switchport("% Invalid input detected at '^' marker.\n") == {})
    check("mode from switchport", _port_mode(access_info, {}) == "access")
    check("mode from trunk switchport", _port_mode(trunk_info, {}) == "trunk")

    trunk_ios = (
        "Port        Mode             Encapsulation  Status        Native vlan\n"
        "Gi0/14      on               802.1q         trunking      1\n"
        "Gi0/15      auto             802.1q         not-trunking  1\n"
        "\n"
        "Port        Vlans allowed on trunk\n"
        "Gi0/14      1-4094\n"
        "Gi0/15      1\n"
        "Po1         1,10\n"
        "\n"
        "Port        Vlans allowed and active in management domain\n"
        "Gi0/14      1,10,20\n"
        "Gi0/15      1\n"
        "\n"
        "Port        Vlans in spanning tree forwarding state and not pruned\n"
        "Gi0/14      1,10,20\n"
        "Gi0/15      1\n"
    )
    trunks = parse_trunk(trunk_ios)
    check("trunk parsed all ports", len(trunks) == 3, str(trunks))
    trunk = trunks["GigabitEthernet0/14"]
    check("trunk mode on", trunk["mode"] == "on", str(trunk))
    check("trunk encapsulation", trunk["encapsulation"] == "802.1q", str(trunk))
    check("trunk status", trunk["status"] == "trunking", str(trunk))
    check("trunk native", trunk["native_vlan"] == 1, str(trunk))
    check("trunk allowed text", trunk["allowed_text"] == "1-4094", str(trunk))
    check("trunk active vlans", trunk["active_vlans"] == {1, 10, 20}, str(trunk))
    check("non-trunking port kept",
          trunks["GigabitEthernet0/15"]["status"] == "not-trunking",
          str(trunks["GigabitEthernet0/15"]))
    check("port-channel listed in trunk table",
          trunks["Port-channel1"]["allowed_text"] == "1,10", str(trunks))

    trunk_nxos = (
        "Port          Native  Status        Port\n"
        "              Vlan                  Channel\n"
        "Eth1/1        1       trunking      --\n"
        "\n"
        "Port          Vlans Allowed on Trunk\n"
        "Eth1/1        1-3967\n"
    )
    nxos_trunks = parse_trunk(trunk_nxos)
    check("NX-OS trunk parsed",
          nxos_trunks["Ethernet1/1"]["status"] == "trunking", str(nxos_trunks))
    check("NX-OS trunk allowed",
          nxos_trunks["Ethernet1/1"]["allowed_text"] == "1-3967",
          str(nxos_trunks))

    real_status = {
        "GigabitEthernet0/1": {
            "description": "cam-lobby", "status": "connected", "vlan": "10",
            "duplex": "a-full", "speed": "a-1000", "type": "10/100/1000BaseTX",
        },
        # VLAN column says '1' and the description is neutral: only the real
        # trunk data can tell that this is an uplink.
        "GigabitEthernet0/14": {
            "description": "port-14", "status": "connected", "vlan": "1",
            "duplex": "a-full", "speed": "a-1000", "type": "10/100/1000BaseTX",
        },
        "GigabitEthernet0/16": {
            "description": "uplink-sw3", "status": "connected", "vlan": "1",
            "duplex": "a-full", "speed": "a-1000", "type": "10/100/1000BaseTX",
        },
    }
    real_macs = {
        "GigabitEthernet0/1": [
            {"mac": "44:19:B6:01:02:03", "vlan": "10", "type": "DYNAMIC"}
        ],
        "GigabitEthernet0/14": [
            {"mac": "44:19:B6:01:02:04", "vlan": "10", "type": "DYNAMIC"}
        ],
        "GigabitEthernet0/16": [
            {"mac": "44:19:B6:01:02:05", "vlan": "10", "type": "DYNAMIC"}
        ],
    }
    real_index, _ = build_mac_indexes(
        "SW1", "10.0.0.1", real_status, real_macs, {}, {}, {},
        switchports, trunks,
    )
    check("access port mode indexed",
          real_index["44:19:B6:01:02:03"][0]["mode"] == "access",
          str(real_index["44:19:B6:01:02:03"]))
    check("access vlan indexed",
          real_index["44:19:B6:01:02:03"][0]["access_vlan"] == 10,
          str(real_index["44:19:B6:01:02:03"]))
    check("access port not uplink",
          real_index["44:19:B6:01:02:03"][0]["uplink"] is False,
          str(real_index["44:19:B6:01:02:03"]))
    check("real trunk mode marked uplink",
          real_index["44:19:B6:01:02:04"][0]["uplink"] is True,
          str(real_index["44:19:B6:01:02:04"]))
    check("real trunk mode indexed",
          real_index["44:19:B6:01:02:04"][0]["mode"] == "trunk",
          str(real_index["44:19:B6:01:02:04"]))
    check("description fallback still marks uplink",
          real_index["44:19:B6:01:02:05"][0]["uplink"] is True,
          str(real_index["44:19:B6:01:02:05"]))

    real_rows = build_rows(
        "SW1", "10.0.0.1", real_status, {}, {}, real_macs, {},
        switchports=switchports, trunks=trunks,
    )
    real_by_name = {row["interface"]: row for row in real_rows}
    check("row carries real mode",
          real_by_name["GigabitEthernet0/14"]["mode"] == "trunk",
          str(real_by_name["GigabitEthernet0/14"]))
    check("row carries access vlan",
          real_by_name["GigabitEthernet0/1"]["access_vlan"] == 10,
          str(real_by_name["GigabitEthernet0/1"]))
    check("detail shows port mode",
          "Port mode   : trunk"
          in real_by_name["GigabitEthernet0/14"]["_detail"],
          real_by_name["GigabitEthernet0/14"]["_detail"][:300])

    real_cam = Camera(ip="10.0.0.60", mac="44:19:B6:01:02:03",
                      model="Hikvision", confidence="High", score=10,
                      is_camera=True)
    real_match = match_cameras([real_cam], real_index, {})
    check("real switchport access is confirmed",
          real_match[0]["port_status"] == "confirmed", str(real_match[0]))
    check("confirmed reason mentions access mode",
          "access mode" in real_match[0]["port_reason"],
          real_match[0]["port_reason"])

    real_trunk_cam = Camera(ip="10.0.0.61", mac="44:19:B6:01:02:04",
                            model="Hikvision", confidence="High", score=10,
                            is_camera=True)
    real_trunk_match = match_cameras([real_trunk_cam], real_index, {})
    check("real trunk-only port is candidates",
          real_trunk_match[0]["port_status"] == "candidates",
          str(real_trunk_match[0]))
    check("real trunk-only claims no port",
          real_trunk_match[0]["interface"] == "", str(real_trunk_match[0]))

    print("local-only rows")
    local_ports = {
        "44:19:B6:01:02:03": [{
            "switch": "SW2", "host": "10.0.0.2",
            "interface": "GigabitEthernet1/0/5", "vlan": "40",
            "description": "cam-lobby", "status": "connected",
        }],
    }
    local_cam = Camera(ip="10.0.0.50", mac="44:19:B6:01:02:03",
                       model="Hikvision", confidence="High", score=10,
                       is_camera=True)
    local_rows = match_cameras([local_cam], local_ports, {})
    check("access match is local", local_rows[0]["local"] is True,
          str(local_rows[0]))
    check("access match is not uplink-only",
          local_rows[0]["uplink_only"] is False, str(local_rows[0]))
    check("access match is confirmed",
          local_rows[0]["port_status"] == "confirmed", str(local_rows[0]))

    trunk_only_ports = {
        "44:19:B6:01:02:03": [{
            "switch": "SW1", "host": "10.0.0.1",
            "interface": "GigabitEthernet0/48", "vlan": "trunk",
            "description": "uplink-sw2", "status": "connected",
            "uplink": True,
        }],
    }
    trunk_cam = Camera(ip="10.0.0.50", mac="44:19:B6:01:02:03",
                       model="Hikvision", confidence="High", score=10,
                       is_camera=True)
    trunk_rows = match_cameras([trunk_cam], trunk_only_ports, {})
    check("trunk-only match is not local",
          trunk_rows[0]["local"] is False, str(trunk_rows[0]))
    check("trunk-only match flagged uplink-only",
          trunk_rows[0]["uplink_only"] is True, str(trunk_rows[0]))
    check("trunk-only match claims no port",
          trunk_rows[0]["interface"] == "", str(trunk_rows[0]))
    check("trunk-only match is candidates",
          trunk_rows[0]["port_status"] == "candidates", str(trunk_rows[0]))
    check("trunk-only match text", "uplink" in trunk_rows[0]["match"].lower(),
          trunk_rows[0]["match"])

    print("runtime prerequisites")
    check("plink signature accepted",
          looks_like_plink(b"MZ" + b"\x00" * 120_000))
    check("short download rejected", not looks_like_plink(b"MZ" + b"\x00" * 10))
    check("non-exe rejected", not looks_like_plink(b"PK" + b"\x00" * 120_000))
    ssh_info = ssh_status()
    check("ssh status has expected keys",
          set(ssh_info) == {"plink", "ssh", "ok", "description"}, str(ssh_info))
    check("ssh status ok matches paths",
          ssh_info["ok"] == bool(ssh_info["plink"] or ssh_info["ssh"]),
          str(ssh_info))

    print("PC / host discovery")
    # Synthetic NetBIOS node-status answer advertising the workstation name.
    qname = b"\x20CK" + b"CA" * 15 + b"\x00"
    rdata = bytes([1]) + b"MYPC" + b" " * 11 + b"\x00" + b"\x00\x00"
    nbstat_packet = (
        struct.pack(">HHHHHH", 0x1234, 0x8400, 0, 1, 0, 0)
        + qname
        + struct.pack(">HHIH", 0x0021, 0x0001, 0, len(rdata))
        + rdata
    )
    check("NetBIOS name parsed", _parse_nbstat(nbstat_packet) == "MYPC",
          _parse_nbstat(nbstat_packet))

    # Synthetic mDNS PTR answer for 10.0.0.5 -> desktop.local.
    owner = b"\x015\x010\x010\x0210\x07in-addr\x04arpa\x00"
    target = b"\x07desktop\x05local\x00"
    mdns_packet = (
        struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        + owner
        + struct.pack(">HHIH", 12, 1, 0, len(target))
        + target
    )
    check("mDNS PTR parsed", _parse_dns_ptr(mdns_packet) == "desktop.local",
          _parse_dns_ptr(mdns_packet))

    win_host = classify_pc(
        "10.0.0.20", "00:1A:2B:3C:4D:5E", "PC-FINANCE", "DNS",
        [135, 445, 3389],
    )
    check("Windows PC classified", win_host.os_hint == "Windows PC",
          win_host.os_hint)
    check("Windows PC high confidence", win_host.confidence == "High",
          win_host.confidence)
    check("Windows PC counted as computer", win_host.is_pc)
    check("hostname kept", win_host.hostname == "PC-FINANCE")
    check("ports text sorted", win_host.ports_text == "135, 445, 3389",
          win_host.ports_text)

    printer_host = classify_pc(
        "10.0.0.30", "00:11:22:33:44:55", "PRN-1", "NetBIOS", [631, 9100]
    )
    check("printer classified", printer_host.os_hint == "Printer",
          printer_host.os_hint)
    check("printer hidden by 'only computers'", not printer_host.is_pc)

    linux_host = classify_pc("10.0.0.40", "", "", "", [22])
    check("Linux host classified", linux_host.os_hint == "Linux host",
          linux_host.os_hint)
    check("no MAC -> port scan source", linux_host.source == "port scan",
          linux_host.source)

    host_mac_ports = {
        "00:1A:2B:3C:4D:5E": [{
            "switch": "SW1", "interface": "GigabitEthernet0/9", "vlan": "20",
            "description": "finance", "status": "connected",
        }],
    }
    host_rows = match_hosts([win_host], host_mac_ports, {})
    check("host matched to switch port",
          host_rows[0]["interface"] == "GigabitEthernet0/9", str(host_rows[0]))
    check("host match text",
          host_rows[0]["match"].startswith("Confirmed:"), host_rows[0]["match"])
    check("host match is confirmed",
          host_rows[0]["port_status"] == "confirmed", str(host_rows[0]))
    check("host row carries hostname", host_rows[0]["hostname"] == "PC-FINANCE")
    check("host row carries type", host_rows[0]["os_hint"] == "Windows PC")
    check("host row carries local flag", host_rows[0]["local"] is True,
          str(host_rows[0]))
    check("host row carries uplink flag",
          host_rows[0]["uplink_only"] is False, str(host_rows[0]))
    check("host detail names the device type",
          host_rows[0]["_detail"].startswith("Host"), host_rows[0]["_detail"][:20])

    routed_host = Host(ip="10.0.0.77", hostname="PC-REMOTE", os_hint="Windows PC",
                       confidence="High", score=5)
    routed_rows = match_hosts(
        [routed_host], host_mac_ports, {"10.0.0.77": "00:1A:2B:3C:4D:5E"}
    )
    check("routed host uses switch ARP MAC",
          routed_host.mac == "00:1A:2B:3C:4D:5E", routed_host.mac)
    check("routed host mapped",
          routed_rows[0]["interface"] == "GigabitEthernet0/9", str(routed_rows[0]))

    no_mac_host = Host(ip="10.0.0.88", hostname="?", confidence="Low")
    no_mac_rows = match_hosts([no_mac_host], host_mac_ports, {})
    check("host without MAC reported",
          no_mac_rows[0]["match"].startswith("Unknown: MAC unknown"),
          no_mac_rows[0]["match"])

    switch_names = names_from_switch_rows([
        {"ip": "10.0.0.20", "neighbor": "PC-FINANCE"},
        {"ip": "10.0.0.21", "neighbor": "not advertised"},
        {"ip": "", "neighbor": "PC-NO-IP"},
    ])
    check("name taken from switch neighbour",
          switch_names.get("10.0.0.20") == "PC-FINANCE", str(switch_names))
    check("placeholder neighbour ignored", "10.0.0.21" not in switch_names,
          str(switch_names))
    check("row without IP ignored", len(switch_names) == 1, str(switch_names))

    print("search / status columns")
    from app import PORT_STATUS_FILTERS, _row_matches_search

    search_row = {
        "ip": "172.16.40.15",
        "mac": "44:19:B6:01:02:03",
        "macs": "44:19:B6:01:02:03 (172.16.40.15), AA:BB:CC:DD:EE:FF",
        "port_status_label": "Confirmed",
        "interface": "GigabitEthernet1/0/15",
    }
    search_columns = [
        ("ip", "IP", 0), ("mac", "MAC", 0), ("macs", "MACs", 0),
        ("interface", "Interface", 0),
    ]
    check("exact IP search matches",
          _row_matches_search(search_row, "172.16.40.15", search_columns))
    check("partial IP does not exact-match",
          not _row_matches_search(search_row, "172.16.40.1", search_columns))
    check("exact MAC search normalises separators",
          _row_matches_search(search_row, "44-19-b6-01-02-03", search_columns))
    check("dotted MAC search normalises separators",
          _row_matches_search(search_row, "4419.b601.0203", search_columns))
    check("unknown exact MAC does not match",
          not _row_matches_search(
              search_row, "44:19:B6:99:99:99", search_columns
          ))
    check("text search still uses substring",
          _row_matches_search(search_row, "gigabit", search_columns))
    check("status filter values",
          PORT_STATUS_FILTERS == (
              "All", "Confirmed", "Probable", "Candidates", "Unknown"
          ),
          str(PORT_STATUS_FILTERS))
    check("matched row carries a status label",
          real_match[0]["port_status_label"] == "Confirmed",
          str(real_match[0].get("port_status_label")))

    print("xlsx export")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "test.xlsx")
        write_xlsx(
            path,
            [
                ("Ports", ["Switch", "Port", "VLAN"], [
                    ["SW1", "Gi0/1", 10],
                    ["SW2", "Gi0/2", ""],
                ]),
                ("Cameras", ["IP", "MAC"],
                 [["10.0.0.5", "AA:BB:CC:DD:EE:FF"]]),
                ("Ports", ["A"], [["duplicate name"]]),
            ],
        )
        check("xlsx file created", os.path.getsize(path) > 0)
        with zipfile.ZipFile(path) as archive:
            parts = set(archive.namelist())
            sheet1 = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
            workbook = archive.read("xl/workbook.xml").decode("utf-8")
        required = {
            "[Content_Types].xml", "_rels/.rels", "xl/workbook.xml",
            "xl/_rels/workbook.xml.rels", "xl/styles.xml",
            "xl/worksheets/sheet1.xml", "xl/worksheets/sheet2.xml",
            "xl/worksheets/sheet3.xml",
        }
        check("xlsx package parts", required <= parts, str(sorted(parts)))
        check("xlsx header written", ">Switch<" in sheet1, sheet1[:200])
        check("xlsx text cell written", "Gi0/1" in sheet1)
        check("xlsx numeric cell written", "<v>10</v>" in sheet1)
        check("xlsx auto filter range",
              'autoFilter ref="A1:C3"' in sheet1, sheet1[-200:])
        check("xlsx duplicate sheet renamed",
              "Ports (2)" in workbook, workbook)

    print("real fixture regression")
    from regression import run_regression

    report = run_regression(os.path.dirname(os.path.abspath(__file__)))
    if not report["fixtures"]:
        # Raw transcripts are not committed to the repository.  Without
        # fixtures there is nothing to replay; the parser tests above still
        # cover the same code paths, so this is not a failure.
        print("  (no raw_*.txt fixtures present - replay skipped)")
    else:
        # Fixtures are live captures and get re-scanned; some switches may
        # be unreachable on any given run and are reported as SKIPPED.
        check("regression fixtures found",
              report["fixtures"] > 0, str(report["fixtures"]))
        check("regression fixtures parsed",
              report["parsed"] > 0, str(report["parsed"]))
        check("regression invariants",
              not report["violations"], str(report["violations"][:3]))
        check("regression errors",
              not report["errors"], str(report["errors"][:3]))
        check("regression workbook",
              not report["workbook_problems"],
              str(report["workbook_problems"][:3]))
        totals = report["totals"]
        check("regression summary adds up",
              totals["confirmed"] + totals["probable"]
              + totals["candidates"] + totals["unknown"] == totals["total"],
              str(totals))
        check("regression rows matched", totals["matched"] > 0, str(totals))

    print()
    if failures:
        print(f"{len(failures)} test(s) FAILED: {', '.join(failures)}")
        return 1
    print("All tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
