"""Command-line diagnostics for Cisco Port Mapper.

This runs exactly the same SSH layer as the GUI, but prints everything to the
console and saves a report file, so a connection / login / parsing problem is
visible instead of staying hidden behind an empty table.

Usage (run from the folder that contains app.py):

    python diagnose.py 192.168.1.10 admin
    python diagnose.py 192.168.1.10 admin --secret ENABLEPASS
    python diagnose.py 192.168.1.10 admin --password MYPASS --no-rows
    python diagnose.py 192.168.1.10 admin --commands "show version"
    python diagnose.py 192.168.1.10 admin --raw

The report is written to diagnose_<host>.txt next to this file.
"""

from __future__ import annotations

import argparse
import getpass
import os
import subprocess
import sys
import traceback

from cisco import BASE_COMMANDS, ScanError, SwitchConfig, scan_switch
from sshexec import (
    CREATE_NO_WINDOW,
    describe_backend,
    find_plink,
    find_ssh,
    split_transcript,
)


def client_versions() -> list[str]:
    lines = [f"Python      : {sys.version.split()[0]} ({sys.executable})"]
    lines.append(f"SSH backend : {describe_backend()}")

    plink = find_plink()
    if plink:
        try:
            done = subprocess.run(
                [plink, "-V"],
                capture_output=True,
                timeout=10,
                creationflags=CREATE_NO_WINDOW,
            )
            text = (done.stdout or b"") + (done.stderr or b"")
            version = text.decode("utf-8", "replace").strip().replace("\r", " ")
            lines.append(f"plink       : {plink}")
            lines.append(f"plink -V    : {version}")
        except Exception as exc:  # noqa: BLE001 - diagnostics
            lines.append(f"plink       : {plink} (could not run -V: {exc})")
    else:
        lines.append("plink       : NOT FOUND")

    ssh = find_ssh()
    lines.append(f"ssh.exe     : {ssh or 'NOT FOUND'}")
    return lines


def visible(text: str) -> str:
    """Make control characters visible without hiding the real text."""
    out = []
    for char in text:
        if char == "\r":
            out.append("\\r")
        elif char == "\n":
            out.append("\\n\n")
        elif char == "\t":
            out.append("\\t")
        elif ord(char) < 32 or ord(char) == 127:
            out.append(f"<{ord(char):02X}>")
        else:
            out.append(char)
    return "".join(out)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:  # noqa: BLE001 - older/redirected streams
            pass

    parser = argparse.ArgumentParser(description="Diagnose a Cisco SSH scan.")
    parser.add_argument("host", help="switch IP or hostname")
    parser.add_argument("username", help="SSH username")
    parser.add_argument("--password", default=None,
                        help="SSH password (prompted when omitted)")
    parser.add_argument("--secret", default="", help="enable secret")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="per-connection timeout in seconds (default 15)")
    parser.add_argument("--lldp", action="store_true",
                        help="also run 'configure terminal / lldp run'")
    parser.add_argument("--commands", nargs="*", default=None,
                        help="custom command list (default: the app's list)")
    parser.add_argument("--no-rows", action="store_true",
                        help="stop after the raw SSH transcript")
    parser.add_argument("--raw", action="store_true",
                        help="print the whole transcript, not just the beginning")
    args = parser.parse_args()

    password = args.password
    if password is None:
        try:
            password = getpass.getpass("SSH password (empty for key/agent): ")
        except Exception:  # noqa: BLE001 - no console available
            password = input("SSH password (empty for key/agent): ")

    report: list[str] = []
    report.append("=== Cisco Port Mapper diagnosis ===")
    report.append(f"Target: {args.username}@{args.host}:{args.port}")
    report.append("")
    report.extend(client_versions())
    report.append("")

    cfg = SwitchConfig(
        host=args.host,
        username=args.username,
        password=password,
        secret=args.secret,
        port=args.port,
        enable_lldp=args.lldp,
        timeout=int(args.timeout),
    )

    def log(message: str) -> None:
        line = f"  log: {message}"
        print(line)
        report.append(line)

    print("\n".join(report))
    report.append("")

    try:
        result = scan_switch(cfg, log=log)
    except ScanError as exc:
        print(f"\nSCAN FAILED: {exc}")
        report.append(f"SCAN FAILED: {exc}")
        report.append("")
        report.append("--- Python traceback (for the developer) ---")
        report.append(traceback.format_exc())
        _save(args.host, report)
        return 2
    except Exception as exc:  # noqa: BLE001 - diagnostics
        print(f"\nUNEXPECTED ERROR: {exc.__class__.__name__}: {exc}")
        report.append(f"UNEXPECTED ERROR: {exc.__class__.__name__}: {exc}")
        report.append("")
        report.append(traceback.format_exc())
        _save(args.host, report)
        return 3

    transcript = result.transcript or ""
    report.append(f"Transcript length: {len(transcript)} characters")
    report.append("")
    report.append("--- RAW TRANSCRIPT (control characters made visible) ---")
    report.append(visible(transcript))
    report.append("")

    print(f"\nTranscript length: {len(transcript)} characters")
    if not transcript.strip():
        print("!! The SSH client returned NOTHING.")
        report.append("The SSH client returned NOTHING.")
        _save(args.host, report)
        return 4

    commands = args.commands if args.commands else list(BASE_COMMANDS)
    sections = split_transcript(transcript, commands)
    report.append("--- OUTPUT RECOGNISED PER COMMAND ---")
    for command in commands:
        body = sections.get(command, "")
        report.append(f"{command:<32} {len(body):>6} chars")
    missing = [c for c in commands if not sections.get(c, "").strip()]
    if missing:
        report.append("")
        report.append("NO OUTPUT RECOGNISED FOR: " + ", ".join(missing))
    report.append("")

    print("\n--- OUTLINE OF THE TRANSCRIPT ---")
    shown = transcript if args.raw else transcript[:4000]
    print(visible(shown))
    if not args.raw and len(transcript) > 4000:
        print(f"... ({len(transcript) - 4000} more characters in the report file)")

    if args.no_rows:
        _save(args.host, report)
        return 0

    report.append("--- PARSED RESULT ---")
    report.append(f"Switch name: {result.switch_name}")
    report.append(f"Rows       : {len(result.rows)}")
    for row in result.rows:
        report.append(
            f"{row.get('interface', ''):<28} "
            f"status={row.get('status', ''):<12} "
            f"src={row.get('source', ''):<4} "
            f"device={row.get('neighbor', '')!r} "
            f"ip={row.get('ip', '')} "
            f"macs={row.get('macs', '')}"
        )

    print(f"\nSwitch name: {result.switch_name}")
    print(f"Rows       : {len(result.rows)}")
    for row in result.rows:
        print(
            f"  {row.get('interface', ''):<28} "
            f"{row.get('status', ''):<12} "
            f"{row.get('source', ''):<4} "
            f"{row.get('neighbor', '')!r:<34} {row.get('ip', '')}"
        )

    path = _save(args.host, report)
    print(f"\nReport saved to: {path}")
    return 0


def _save(host: str, report: list[str]) -> str:
    safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in host)
    path = os.path.abspath(f"diagnose_{safe}.txt")
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(report) + "\n")
    except OSError as exc:
        print(f"Could not write {path}: {exc}")
    return path


if __name__ == "__main__":
    sys.exit(main())
