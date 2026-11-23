"""Runtime prerequisites for Cisco Port Mapper.

The application itself only needs the Python standard library.  The one
external piece it needs to talk to switches is an SSH client:

* ``plink.exe`` from PuTTY - supports password login (recommended), or
* the Windows OpenSSH Client (``ssh.exe``) - key / ssh-agent login only.

On a fresh Windows PC neither may be present.  :func:`download_plink`
fetches the official PuTTY build into the program folder (no administrator
rights required), and :func:`install_openssh_client` can enable the Windows
optional feature when the program is running as administrator.
"""

from __future__ import annotations

import os
import ssl
import subprocess
import sys
import urllib.request
from typing import Callable, Optional

USER_AGENT = "CiscoPortMapper/1.0 (+https://www.putty.org/)"
MIN_PLINK_BYTES = 100_000
MAX_PLINK_BYTES = 8_000_000

# Official PuTTY download server (the.earth.li is the mirror linked from
# putty.org).  The 64-bit build is tried first, then the 32-bit build for
# older Windows installations.
PLINK_URLS = (
    "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe",
    "https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe",
)

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class PrereqError(Exception):
    """A prerequisite could not be installed."""


def program_dir() -> str:
    """Folder of the script, or of the exe when frozen by PyInstaller."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def ssh_status() -> dict:
    """Describe the SSH client that the scanner would use right now."""
    from sshexec import describe_backend, find_plink, find_ssh

    plink = find_plink()
    ssh = find_ssh()
    return {
        "plink": plink,
        "ssh": ssh,
        "ok": bool(plink or ssh),
        "description": describe_backend(),
    }


def looks_like_plink(data: bytes) -> bool:
    """Cheap sanity check for a downloaded Windows executable."""
    return (
        isinstance(data, (bytes, bytearray))
        and len(data) >= MIN_PLINK_BYTES
        and bytes(data[:2]) == b"MZ"
    )


def download_plink(
    dest_dir: Optional[str] = None,
    log: Optional[Callable[[str], None]] = None,
    timeout: float = 90.0,
) -> str:
    """Download the official ``plink.exe`` next to the program.

    Returns the path of the saved file.  Raises :class:`PrereqError` with a
    readable message when every mirror fails.
    """
    log = log or (lambda message: None)
    dest_dir = dest_dir or program_dir()
    target = os.path.join(dest_dir, "plink.exe")
    errors: list[str] = []
    context = ssl.create_default_context()

    for url in PLINK_URLS:
        try:
            log(f"Downloading {url}")
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(
                request, timeout=timeout, context=context
            ) as response:
                data = response.read(MAX_PLINK_BYTES + 1)
            if len(data) > MAX_PLINK_BYTES:
                raise PrereqError("the downloaded file is unexpectedly large")
            if not looks_like_plink(data):
                raise PrereqError(
                    "the server did not return a Windows executable "
                    f"({len(data)} bytes)"
                )
            part = target + ".part"
            with open(part, "wb") as handle:
                handle.write(data)
            os.replace(part, target)
            try:
                os.chmod(target, 0o755)
            except OSError:
                pass
            log(f"Saved {target} ({len(data):,} bytes)")
            return target
        except Exception as exc:  # noqa: BLE001 - try the next mirror
            errors.append(f"{url}\n  {exc}")
            log(f"Download failed: {exc}")

    raise PrereqError(
        "Could not download plink.exe automatically.\n\n"
        "Check the internet connection / proxy, then try again, or download "
        "plink.exe manually from putty.org and put it next to this program.\n\n"
        + "\n".join(errors)
    )


def is_admin() -> bool:
    """True when the current process can change Windows optional features."""
    if os.name != "nt":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - best effort
        return False


def install_openssh_client(
    log: Optional[Callable[[str], None]] = None,
) -> str:
    """Enable the Windows 'OpenSSH Client' optional feature.

    This needs administrator rights.  It is a fallback for machines where
    downloading plink.exe is not allowed.
    """
    log = log or (lambda message: None)
    if os.name != "nt":
        raise PrereqError("The OpenSSH Client installer is only available on Windows.")
    if not is_admin():
        raise PrereqError(
            "Installing the Windows OpenSSH Client needs Administrator rights.\n\n"
            "Close Cisco Port Mapper, right-click it and choose "
            "'Run as administrator', then open Setup again.\n\n"
            "Or use 'Download plink.exe' instead - it does not need admin "
            "rights and supports password login."
        )

    command = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0",
    ]
    log("Running: " + " ".join(command))
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=600,
        creationflags=CREATE_NO_WINDOW,
    )
    output = ((completed.stdout or "") + (completed.stderr or "")).strip()
    if output:
        log(output)
    if completed.returncode != 0:
        raise PrereqError(
            "Windows could not install the OpenSSH Client.\n\n"
            + (output[-1500:] or "No details were returned.")
        )

    from sshexec import find_ssh

    if not find_ssh():
        raise PrereqError(
            "The Windows command finished, but ssh.exe was not found yet.\n\n"
            "Restart Windows (or sign out and in) and press Re-check."
        )
    return "OpenSSH Client installed. ssh.exe is now available."


def main(argv: Optional[list[str]] = None) -> int:
    """Small command-line helper, also usable from setup.bat."""
    import argparse

    parser = argparse.ArgumentParser(description="Cisco Port Mapper prerequisites")
    parser.add_argument("--check", action="store_true", help="show SSH client status")
    parser.add_argument(
        "--install-plink", action="store_true", help="download plink.exe"
    )
    parser.add_argument(
        "--install-openssh",
        action="store_true",
        help="enable the Windows OpenSSH Client (admin)",
    )
    args = parser.parse_args(argv)

    if args.install_plink:
        try:
            path = download_plink(log=print)
        except PrereqError as exc:
            print(exc)
            return 1
        print(f"plink.exe installed: {path}")
        return 0

    if args.install_openssh:
        try:
            print(install_openssh_client(log=print))
        except PrereqError as exc:
            print(exc)
            return 1
        return 0

    status = ssh_status()
    print(status["description"])
    if status["plink"]:
        print(f"plink.exe : {status['plink']}")
    if status["ssh"]:
        print(f"ssh.exe   : {status['ssh']}")
    print("Ready." if status["ok"] else "No SSH client found.")
    return 0 if status["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
