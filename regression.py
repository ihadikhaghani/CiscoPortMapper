"""Offline regression over the saved ``raw_*.txt`` switch transcripts.

The GUI writes every scan to ``raw_<host>.txt``.  This module replays those
files through exactly the same parsers and matching code as the application,
so parser or confidence changes can be checked without a real switch.

Run:  python regression.py

Exit code 0 means every complete fixture parsed and no invariant failed.
Incomplete transcripts (a scan that aborted before any command output) are
reported as skipped, not as failures.
"""

from __future__ import annotations

import glob
import os
import re
import tempfile
import xml.etree.ElementTree as ET
import zipfile

from cameras import PORT_STATUS_LABELS, Camera, match_cameras, summarize
from cisco import (
    build_mac_indexes,
    parse_arp,
    parse_cdp_neighbors,
    parse_hostname,
    parse_interface_status,
    parse_lldp_by_chassis,
    parse_lldp_neighbors,
    parse_mac_table,
    parse_switchport,
    parse_trunk,
)
from xlsx import write_xlsx

SECTION = re.compile(r"^===== (.+?) \((\d+) chars\) =====$", re.M)
SWITCH_HEADER = re.compile(r"^Switch:\s*(.*?)\s*\((\S+)\)", re.M)
MAX_REPLAY_DEVICES = 500
KNOWN_STATUSES = set(PORT_STATUS_LABELS)


def load_fixture(path: str) -> dict:
    """Read a saved raw transcript and return its header and command outputs."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    header = SWITCH_HEADER.search(text)
    switch_name = header.group(1).strip() if header else ""
    host = header.group(2).strip() if header else ""
    if not host:
        match = re.search(r"raw_([^\\/]+)\.txt$", path)
        host = match.group(1) if match else ""

    outputs: dict[str, str] = {}
    sections = list(SECTION.finditer(text))
    for index, match in enumerate(sections):
        command = match.group(1).strip()
        start = match.end()
        end = sections[index + 1].start() if index + 1 < len(sections) else len(text)
        if command == "FULL SSH TRANSCRIPT":
            continue
        outputs[command] = text[start:end].strip("\n")
    return {
        "path": path,
        "switch": switch_name,
        "host": host,
        "outputs": outputs,
    }


def replay_fixture(path: str) -> dict:
    """Parse one fixture the same way :func:`cisco.scan_switch` does."""
    fixture = load_fixture(path)
    outputs = fixture["outputs"]
    host = fixture["host"]
    name = fixture["switch"]

    status: dict[str, dict] = {}
    for command in ("show interfaces status", "show interface status"):
        status.update(parse_interface_status(outputs.get(command, "")))

    switchports: dict[str, dict] = {}
    for command in ("show interfaces switchport", "show interface switchport"):
        switchports.update(parse_switchport(outputs.get(command, "")))

    trunks: dict[str, dict] = {}
    for command in ("show interfaces trunk", "show interface trunk"):
        trunks.update(parse_trunk(outputs.get(command, "")))

    cdp = parse_cdp_neighbors(outputs.get("show cdp neighbors detail", ""))
    lldp_text = outputs.get("show lldp neighbors detail", "")
    lldp = parse_lldp_neighbors(lldp_text)
    lldp_by_chassis = parse_lldp_by_chassis(lldp_text)

    macs: dict[str, list] = {}
    for command in ("show mac address-table", "show mac-address-table"):
        for port, entries in parse_mac_table(outputs.get(command, "")).items():
            bucket = macs.setdefault(port, [])
            for entry in entries:
                if not any(
                    existing["mac"] == entry["mac"] for existing in bucket
                ):
                    bucket.append(entry)

    arp: dict[str, tuple] = {}
    for command in ("show ip arp", "show arp"):
        arp.update(parse_arp(outputs.get(command, "")))

    hostname = parse_hostname(outputs.get("show version", "")) or name or host
    mac_ports, ip_to_mac = build_mac_indexes(
        hostname, host, status, macs, arp, cdp, lldp, switchports, trunks
    )

    devices = [
        Camera(
            ip=f"172.16.40.{index + 1}",
            mac=mac,
            model="regression",
            confidence="High",
            score=1,
        )
        for index, mac in enumerate(list(mac_ports)[:MAX_REPLAY_DEVICES])
    ]
    match_rows = match_cameras(devices, mac_ports, ip_to_mac)
    counts = summarize(match_rows)

    parsed = bool(status or macs or cdp or lldp)
    return {
        "path": path,
        "switch": hostname,
        "host": host,
        "parsed": parsed,
        "sections": len(outputs),
        "ports": len(status),
        "switchports": len(switchports),
        "trunks": len(trunks),
        "cdp": len(cdp),
        "lldp": len(lldp),
        "macs": sum(len(entries) for entries in macs.values()),
        "arp": len(arp),
        "index": len(mac_ports),
        "match_rows": match_rows,
        "counts": counts,
        "violations": check_invariants(match_rows, mac_ports),
    }


def check_invariants(rows: list[dict], mac_ports: dict) -> list[str]:
    """Return a list of human-readable problems (empty means healthy)."""
    problems: list[str] = []
    confirmed_claims: dict[tuple[str, str], str] = {}
    for row in rows:
        mac = row.get("mac", "")
        status = row.get("port_status", "")
        claimed = bool(row.get("switch") and row.get("interface"))
        label = row.get("port_status_label", "")

        if status not in KNOWN_STATUSES:
            problems.append(f"{mac}: unknown status {status!r}")
            continue
        if label != PORT_STATUS_LABELS[status]:
            problems.append(f"{mac}: label {label!r} != {status!r}")
        if not str(row.get("match", "")).startswith(label + ":"):
            problems.append(f"{mac}: match text is not prefixed by {label!r}")
        if not row.get("port_reason"):
            problems.append(f"{mac}: missing port_reason")

        if status in ("candidates", "unknown") and claimed:
            problems.append(
                f"{mac}: {status} row claims {row['switch']} {row['interface']}"
            )
        if status in ("confirmed", "probable") and not claimed:
            problems.append(f"{mac}: {status} row has no switch port")
        if status == "candidates" and not row.get("candidates"):
            problems.append(f"{mac}: candidates status without candidate list")

        if status == "confirmed":
            key = (str(row.get("switch")), str(row.get("interface")))
            if key in confirmed_claims:
                problems.append(
                    f"{mac}: confirmed port {key} already claimed by "
                    f"{confirmed_claims[key]}"
                )
            else:
                confirmed_claims[key] = mac

        entries = mac_ports.get(mac, [])
        if bool(row.get("uplink_only")) and any(
            not entry.get("uplink") for entry in entries
        ):
            problems.append(f"{mac}: marked uplink_only but has an access entry")
    return problems


def check_workbook(match_rows: list[dict]) -> list[str]:
    """Write a representative workbook and verify the package can be read."""
    problems: list[str] = []
    headers = ["Switch", "Port", "Device IP", "MAC", "Status", "Reason"]
    values = [
        [
            row.get("switch", ""),
            row.get("interface", ""),
            row.get("ip", ""),
            row.get("mac", ""),
            row.get("port_status_label", ""),
            row.get("port_reason", ""),
        ]
        for row in match_rows
    ]
    try:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "regression.xlsx")
            write_xlsx(path, [("Matches", headers, values)])
            with zipfile.ZipFile(path) as archive:
                if archive.testzip() is not None:
                    problems.append("xlsx zip integrity check failed")
                for part in archive.namelist():
                    if part.endswith(".xml") or part.endswith(".rels"):
                        try:
                            ET.fromstring(archive.read(part))
                        except ET.ParseError as exc:
                            problems.append(f"{part}: {exc}")
    except Exception as exc:  # noqa: BLE001 - regression must not crash
        problems.append(f"{type(exc).__name__}: {exc}")
    return problems


def _empty_result(path: str) -> dict:
    return {
        "path": path,
        "switch": "?",
        "host": "",
        "parsed": False,
        "sections": 0,
        "ports": 0,
        "switchports": 0,
        "trunks": 0,
        "cdp": 0,
        "lldp": 0,
        "macs": 0,
        "arp": 0,
        "index": 0,
        "match_rows": [],
        "counts": {},
        "violations": [],
    }


def run_regression(directory: str | None = None,
                   pattern: str = "raw_*.txt") -> dict:
    """Replay every fixture in ``directory`` and return a report dict."""
    directory = directory or os.path.dirname(os.path.abspath(__file__))
    paths = sorted(glob.glob(os.path.join(directory, pattern)))
    results = []
    errors: list[tuple[str, str]] = []
    # No fixtures is not a failure: the repository intentionally ships
    # without real switch transcripts (they contain production network data).
    for path in paths:
        try:
            results.append(replay_fixture(path))
        except Exception as exc:  # noqa: BLE001 - keep the report running
            errors.append((path, f"{type(exc).__name__}: {exc}"))
            results.append(_empty_result(path))

    parsed = [result for result in results if result["parsed"]]
    skipped = [result for result in results if not result["parsed"]]
    violations = [
        (result["path"], problem)
        for result in results
        for problem in result["violations"]
    ]
    totals = {
        key: sum(result["counts"].get(key, 0) for result in parsed)
        for key in (
            "total", "matched", "confirmed", "probable",
            "candidates", "unknown", "unknown_mac", "missing",
        )
    }
    workbook_problems = check_workbook(
        [row for result in parsed for row in result["match_rows"]]
    )
    return {
        "fixtures": len(results),
        "parsed": len(parsed),
        "skipped": len(skipped),
        "results": results,
        "totals": totals,
        "violations": violations,
        "errors": errors,
        "workbook_problems": workbook_problems,
    }


def main() -> int:
    report = run_regression()
    if not report["results"]:
        print("No raw_*.txt fixtures found - replay skipped.")
        print("Add real switch transcripts to enable fixture replay.")
    for result in report["results"]:
        name = os.path.basename(result["path"])
        if not result["parsed"]:
            print(f"{name:<22} SKIPPED (no command output)")
            continue
        counts = result["counts"]
        print(
            f"{name:<22} {result['switch']:<12} "
            f"ports={result['ports']:>3} swport={result['switchports']:>3} "
            f"trunk={result['trunks']:>2} cdp={result['cdp']:>2} "
            f"lldp={result['lldp']:>2} macs={result['macs']:>4} "
            f"arp={result['arp']:>3} | matched={counts['matched']:>3} "
            f"confirmed={counts['confirmed']:>3} "
            f"probable={counts['probable']:>3} "
            f"candidates={counts['candidates']:>3} "
            f"unknown={counts['unknown']:>3}"
        )

    totals = report["totals"]
    print(
        f"\nfixtures={report['fixtures']} parsed={report['parsed']} "
        f"skipped={report['skipped']}"
    )
    print(
        "totals: "
        + " ".join(f"{key}={value}" for key, value in totals.items())
    )
    for path, problem in report["violations"]:
        print(f"VIOLATION {os.path.basename(path)}: {problem}")
    for path, problem in report["errors"]:
        print(f"ERROR {os.path.basename(str(path))}: {problem}")
    for problem in report["workbook_problems"]:
        print(f"WORKBOOK PROBLEM: {problem}")

    failed = bool(
        report["violations"]
        or report["errors"]
        or report["workbook_problems"]
    )
    print("\nREGRESSION " + ("FAILED" if failed else "OK"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
