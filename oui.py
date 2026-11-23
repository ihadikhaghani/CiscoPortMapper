"""MAC vendor lookup: small built-in table + optional IEEE oui.csv.

Drop the IEEE file (https://standards-oui.ieee.org/oui/oui.csv) next to
the program as ``oui.csv`` to get the complete vendor database.
"""

from __future__ import annotations

import csv
import os
import re
from typing import Dict, Optional

# Small, curated set of well known OUIs.  The full IEEE list can be added
# with oui.csv (see load_oui_database).
BUILTIN_OUI: Dict[str, str] = {
    # Cisco
    "00000c": "Cisco",
    "000142": "Cisco",
    "000163": "Cisco",
    "0001c7": "Cisco",
    "0004dd": "Cisco",
    "000585": "Cisco",
    "000b60": "Cisco",
    "000d28": "Cisco",
    "0011bb": "Cisco",
    "001a30": "Cisco",
    "001b0c": "Cisco",
    "001bd4": "Cisco",
    "001e13": "Cisco",
    "002155": "Cisco",
    "0023eb": "Cisco",
    "0026cb": "Cisco",
    "0050f2": "Microsoft",       # also used by Cisco phones occasionally
    "1cdf0f": "Cisco",
    "2c542d": "Cisco",
    "3c0e23": "Cisco",
    "58971e": "Cisco",
    "6c416a": "Cisco",
    "70dbf9": "Cisco",
    "887556": "Cisco",
    "a43d78": "Cisco",
    "b0aa77": "Cisco",
    "c067af": "Cisco",
    "d072dc": "Cisco",
    "e8b748": "Cisco",
    "f02929": "Cisco",
    # Virtualisation
    "005056": "VMware",
    "000c29": "VMware",
    "001c14": "VMware",
    "000569": "VMware",
    "080027": "VirtualBox",
    "0a0027": "VirtualBox",
    "525400": "QEMU/KVM",
    "00155d": "Microsoft Hyper-V",
    "0017f2": "Apple",
    # Microsoft
    "000d3a": "Microsoft",
    "0017fa": "Microsoft",
    "7c1e52": "Microsoft",
    # Intel
    "0002b3": "Intel",
    "001b21": "Intel",
    "0024d7": "Intel",
    "3c970e": "Intel",
    # Dell
    "001aa0": "Dell",
    "00219b": "Dell",
    "0024e8": "Dell",
    "f8bc12": "Dell",
    # HP / Aruba
    "001b78": "HP",
    "3cd92b": "HP",
    "000b86": "Aruba",
    "001a1e": "Aruba",
    "24dec6": "Aruba",
    # Apple
    "001cb3": "Apple",
    "002436": "Apple",
    "3c0754": "Apple",
    "6c709f": "Apple",
    # Samsung / Huawei / H3C
    "0012fb": "Samsung",
    "5c0a5b": "Samsung",
    "00e0fc": "Huawei",
    "001882": "Huawei",
    "00259e": "Huawei",
    "002389": "H3C",
    # Juniper / Fortinet / Palo Alto
    "0010db": "Juniper",
    "001bc0": "Juniper",
    "00090f": "Fortinet",
    "001b17": "Palo Alto",
    # Consumer / SMB network gear
    "001d0f": "TP-Link",
    "14cc20": "TP-Link",
    "50c7bf": "TP-Link",
    "000d88": "D-Link",
    "00179a": "D-Link",
    "000fb5": "Netgear",
    "0024b2": "Netgear",
    "000c42": "MikroTik",
    "4c5e0c": "MikroTik",
    "64d154": "MikroTik",
    # Cameras / video surveillance (verified IEEE registrations).
    # Having these built in means the Cameras tab can recognise camera MACs
    # on the switch even without a full oui.csv.
    "4419b6": "Hikvision",
    "4cbd8f": "Hikvision",
    "bcad28": "Hikvision",
    "54c415": "Hikvision",
    "b4a382": "Hikvision",
    "e0ca3c": "Hikvision",
    "8ce748": "Hikvision",
    "3cef8c": "Dahua",
    "9002a9": "Dahua",
    "e0508b": "Dahua",
    "3ce36b": "Dahua",
    "4c11bf": "Dahua",
    "08eded": "Dahua",
    "a0bd1d": "Dahua",
    "14a78b": "Dahua",
    "38af29": "Dahua",
    "00408c": "Axis",
    "0002d1": "Vivotek",
    "48ea63": "Uniview",
    "ec71db": "Reolink",
    "000918": "Samsung Techwin",
    "e43022": "Hanwha",
    "000f7c": "ACTi",
    "001a07": "Arecont",
    "0003c5": "Mobotix",
    # Servers / SBC / printers
    "001132": "Synology",
    "ac1f6b": "Supermicro",
    "b827eb": "Raspberry Pi",
    "dca632": "Raspberry Pi",
    "e45f01": "Raspberry Pi",
    "00e04c": "Realtek",
    "001bfc": "ASUS",
}


def _key(mac: str) -> str:
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    return digits[:6].lower() if len(digits) >= 6 else ""


def lookup_vendor(mac: str, database: Optional[Dict[str, str]] = None) -> str:
    db = database if database is not None else BUILTIN_OUI
    return db.get(_key(mac), "")


def load_oui_database(csv_path: Optional[str] = None) -> Dict[str, str]:
    database = dict(BUILTIN_OUI)
    if not csv_path or not os.path.exists(csv_path):
        return database
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as handle:
            for row in csv.reader(handle):
                if len(row) < 3:
                    continue
                key = row[1].strip().lower()
                if re.fullmatch(r"[0-9a-f]{6}", key):
                    vendor = row[2].strip()
                    if vendor:
                        database[key] = vendor
    except OSError:
        pass
    return database
