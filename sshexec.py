"""Run CLI commands on a device through plink.exe (PuTTY) or Windows ssh.exe.

No third-party Python packages are required.  plink supports password
authentication; the built-in OpenSSH client only supports key/agent
authentication in a non-interactive session.

The commands are piped to the SSH client over stdin in a single interactive
session; the client's transcript is then split per command.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
from typing import Callable, Dict, List, Optional, Sequence

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

ANSI_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1b\[[0-9;?]*[A-Za-z]"
    r"|\x1b[()][A-Z0-9]"
    r"|\x1b[=>]"
)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


class ExecError(Exception):
    """The external SSH client failed."""


class ExecCancelled(ExecError):
    """The user cancelled the scan."""


def strip_ansi(text: str) -> str:
    return CONTROL_RE.sub("", ANSI_RE.sub("", text))


# ---------------------------------------------------------------------------
# locating the SSH clients
# ---------------------------------------------------------------------------

_PLINK_PATHS = (
    "plink.exe",
    os.path.join("C:\\", "Program Files", "PuTTY", "plink.exe"),
    os.path.join("C:\\", "Program Files (x86)", "PuTTY", "plink.exe"),
)

_SSH_PATHS = (
    os.path.join("C:\\", "Windows", "System32", "OpenSSH", "ssh.exe"),
)


def _program_dir() -> str:
    """Folder of the script, or of the exe when frozen by PyInstaller."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def find_plink() -> Optional[str]:
    local = os.path.join(_program_dir(), "plink.exe")
    if os.path.exists(local):
        return local
    found = shutil.which("plink")
    if found:
        return found
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    candidates = list(_PLINK_PATHS)
    if local_appdata:
        candidates.append(os.path.join(local_appdata, "Programs", "PuTTY", "plink.exe"))
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def find_ssh() -> Optional[str]:
    found = shutil.which("ssh")
    if found:
        return found
    for path in _SSH_PATHS:
        if os.path.exists(path):
            return path
    return None


def describe_backend() -> str:
    plink = find_plink()
    ssh = find_ssh()
    if plink:
        return f"plink.exe ({plink})"
    if ssh:
        return f"ssh.exe ({ssh}) - key/agent login only, no password"
    return (
        "none found - put plink.exe next to this program, or install the "
        "Windows OpenSSH client (Settings > Apps > Optional features)"
    )


# ---------------------------------------------------------------------------
# running one batch of commands
# ---------------------------------------------------------------------------

def _script_bytes(commands: Sequence[str]) -> bytes:
    """Commands for the interactive shell, plus 'exit' so the session ends.

    A single ``\\n`` is used on purpose: a PTY can turn ``\\r\\n`` into two
    line endings, which would send an empty line to the ``enable`` password
    prompt and break authentication.

    The leading blank line is consumed by devices that greet with
    'Press RETURN to get started!'; on any other device it is just an empty
    line at the prompt and is ignored.
    """
    lines = [""] + list(commands) + ["exit"]
    return ("\n".join(lines) + "\n").encode("utf-8", "replace")


# ---------------------------------------------------------------------------
# weak SSH algorithms (old Cisco switches)
# ---------------------------------------------------------------------------

# PuTTY refuses to use algorithms below its 'warn below here' line when it is
# running in batch mode (-batch), which is how this program drives it.  Many
# old Cisco switches only offer 'diffie-hellman-group1-sha1', so plink aborts
# with "the first key-exchange algorithm supported by the server is ... which
# is below the configured warning threshold".
#
# There is no command-line switch for this, but plink can load a saved session
# from the registry, so a private session is written that contains only the
# KEX preference list with the weak algorithm placed above 'WARN'.
#
# The session must NOT contain a HostName: with '-load', a host name stored in
# the session makes plink treat the 'host' argument as part of the remote
# command.  Nothing else is stored, so the session cannot affect other PuTTY
# behaviour.
PUTTY_SESSION_NAME = "CiscoPortMapper"

_PUTTY_SESSION_KEY = r"Software\SimonTatham\PuTTY\Sessions"

# Names from PuTTY's kexnames[] table.  plink silently ignores names it does
# not know, so newer entries are harmless on older PuTTY builds.
_KEX_PREFERENCES = (
    "mlkem-curve25519",
    "mlkem-nist",
    "ntru-curve25519",
    "ecdh",
    "dh-group15-sha512",
    "dh-group16-sha512",
    "dh-group17-sha512",
    "dh-group18-sha512",
    "dh-gex-sha1",
    "dh-group14-sha1",
    "rsa",
    "dh-group1-sha1",
)

# Algorithm name as reported by plink -> name used in PuTTY's KEX setting.
_KEX_ALGORITHM_TO_PREFERENCE = {
    "diffie-hellman-group1-sha1": "dh-group1-sha1",
    "diffie-hellman-group14-sha1": "dh-group14-sha1",
    "diffie-hellman-group14-sha256": "dh-group14-sha1",
    "diffie-hellman-group15-sha512": "dh-group15-sha512",
    "diffie-hellman-group16-sha512": "dh-group16-sha512",
    "diffie-hellman-group17-sha512": "dh-group17-sha512",
    "diffie-hellman-group18-sha512": "dh-group18-sha512",
    "diffie-hellman-group-exchange-sha1": "dh-gex-sha1",
    "diffie-hellman-group-exchange-sha256": "dh-gex-sha1",
    "rsa1024-sha1": "rsa",
    "rsa2048-sha256": "rsa",
    "curve25519-sha256": "ecdh",
    "curve25519-sha256@libssh.org": "ecdh",
    "ecdh-sha2-nistp256": "ecdh",
    "ecdh-sha2-nistp384": "ecdh",
    "ecdh-sha2-nistp521": "ecdh",
}

# plink hard-wraps this message at 60 columns, so a line break can appear
# between ANY two words (for example "... below the configured" / "warning
# threshold").  Every gap is therefore \s+, never a literal space.
_WEAK_CRYPTO_RE = re.compile(
    r"the\s+first\s+(?P<kind>[a-z][a-z -]*?)\s+supported\s+by\s+the\s+"
    r"server\s+is\s+(?P<algorithm>[A-Za-z0-9@._+-]+)\s*,?\s*"
    r"which\s+is\s+below\s+the\s+configured\s+warning\s+threshold",
    re.IGNORECASE,
)

# PuTTY configuration page that holds each kind of algorithm.
_WEAK_CRYPTO_PAGES = {
    "key-exchange algorithm": "Connection > SSH > Kex",
    "host key type": "Connection > SSH > Host keys",
    "client-to-server cipher": "Connection > SSH > Ciphers",
    "server-to-client cipher": "Connection > SSH > Ciphers",
}


def weak_crypto_problem(text: str) -> Optional[tuple]:
    """Return ``(kind, algorithm)`` when plink refused a weak algorithm.

    For example ``("key-exchange algorithm", "diffie-hellman-group1-sha1")``.
    """
    cleaned = strip_ansi(text or "")
    match = _WEAK_CRYPTO_RE.search(cleaned)
    if match:
        kind = " ".join(match.group("kind").split()).lower()
        return kind, match.group("algorithm")

    # Safety net: if PuTTY changes the wording or the wrapping is unusual,
    # the batch-mode abort line still tells us it was a weak primitive.
    lowered = cleaned.lower()
    if "below the configured" in lowered and (
        "key-exchange" in lowered or "weak crypto" in lowered
    ):
        for name in sorted(
            _KEX_ALGORITHM_TO_PREFERENCE, key=len, reverse=True
        ):
            if name in lowered:
                return "key-exchange algorithm", name
    return None


def _write_putty_session(session: str, values: Dict[str, str]) -> bool:
    """Create/update one PuTTY saved session in HKCU; False on any failure."""
    if os.name != "nt":
        return False
    try:
        import winreg
    except ImportError:  # pragma: no cover - non-Windows
        return False

    path = _PUTTY_SESSION_KEY + "\\" + session
    access = (
        winreg.KEY_SET_VALUE
        | winreg.KEY_QUERY_VALUE
        | winreg.KEY_CREATE_SUB_KEY
    )
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, access)
        try:
            for name, value in values.items():
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
            for name, value in values.items():
                if winreg.QueryValueEx(key, name)[0] != value:
                    return False
        finally:
            winreg.CloseKey(key)
    except OSError:
        return False
    return True


def kex_preference_string(weak_preference: str) -> str:
    """PuTTY KEX list with ``weak_preference`` last but above 'WARN'.

    'WARN' must stay at the very end: PuTTY only flags algorithms that appear
    after it, so the weak algorithm is accepted while every stronger one is
    still tried first.
    """
    order = [name for name in _KEX_PREFERENCES if name != weak_preference]
    order.append(weak_preference)
    order.append("WARN")
    return ",".join(order)


def allow_weak_kex(algorithm: str,
                   session: str = PUTTY_SESSION_NAME) -> str:
    """Make plink accept a weak key-exchange algorithm via a saved session.

    Returns the session name when the registry entry was written, else ''.
    """
    preference = _KEX_ALGORITHM_TO_PREFERENCE.get((algorithm or "").lower(), "")
    if not preference:
        return ""
    if _write_putty_session(
        session, {"KEX": kex_preference_string(preference)}
    ):
        return session
    return ""


def _error_excerpt(text: str, lines: int = 10, limit: int = 800) -> str:
    """First few meaningful lines of a client error, for dialogs and logs."""
    cleaned = strip_ansi(text or "").replace("\r", "\n")
    parts = [line.strip() for line in cleaned.split("\n") if line.strip()]
    return "\n".join(parts[:lines])[:limit]


def _weak_crypto_message(kind: str, algorithm: str, text: str,
                         session: str) -> str:
    page = _WEAK_CRYPTO_PAGES.get(kind, "Connection > SSH")
    lines = [
        f"This switch only supports a weak SSH {kind} ({algorithm}), which",
        "plink.exe refuses to use in batch mode.",
        "",
        "plink said:",
        _error_excerpt(text),
        "",
    ]
    if kind == "key-exchange algorithm":
        if session:
            lines.append(
                "Cisco Port Mapper added a private PuTTY session "
                f"('{session}') that allows this algorithm, but plink still "
                "refused it, so PuTTY is probably not reading its settings "
                "from the Windows registry."
            )
        else:
            lines.append(
                "Cisco Port Mapper could not change the PuTTY setting for "
                "this algorithm automatically."
            )
    else:
        lines.append(
            "Only the key-exchange list can be changed automatically, so this "
            "algorithm has to be allowed in PuTTY's settings."
        )
    lines += [
        "",
        "Do this once in PuTTY:",
        "  1. Open PuTTY and load 'Default Settings'.",
        f"  2. Go to {page}.",
        "  3. Select the line 'Warn below here' and press 'Down' until it is",
        "     the last entry in the list.",
        "  4. Go back to Session and press 'Save'.",
        "Then scan this switch again.",
    ]
    return "\n".join(lines)


def _plink_command(path: str, host: str, port: int, username: str,
                   password: str, batch: bool = True, hostkey: str = "",
                   verbose: bool = False, session: str = "") -> List[str]:
    # -t asks for a pseudo-terminal so IOS echoes prompts/commands, which is
    # what split_transcript relies on.  The commands are piped on stdin
    # (interactive shell) instead of -m, because classic IOS rejects SSH
    # 'exec' requests.
    command = [path]
    if session:
        # '-load' must come before the options below, otherwise the values
        # stored in the session would overwrite them.
        command += ["-load", session]
    command += ["-ssh", "-t", "-P", str(port), "-l", username]
    if batch:
        # Never sit on an interactive question.  A missing host key is
        # detected from the output and handled through -hostkey instead.
        command.append("-batch")
    if hostkey:
        command += ["-hostkey", hostkey]
    if verbose:
        command.append("-v")
    if password:
        command += ["-pw", password]
    command.append(host)
    return command


def _ssh_command(path: str, host: str, port: int, username: str) -> List[str]:
    return [
        path,
        "-tt",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=15",
        "-o", "ServerAliveInterval=15",
        "-o", "LogLevel=ERROR",
        "-p", str(port),
        f"{username}@{host}",
    ]


def _kill_on_cancel(proc: subprocess.Popen, cancel: Optional[threading.Event],
                    stop: threading.Event) -> None:
    while not stop.wait(0.2):
        if cancel is not None and cancel.is_set():
            try:
                proc.kill()
            except OSError:
                pass
            return


def _execute(command: Sequence[str], stdin_data: bytes, timeout: float,
             cancel: Optional[threading.Event], backend: str) -> str:
    """Run one SSH client process and return its combined output."""
    proc = subprocess.Popen(
        list(command),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        creationflags=CREATE_NO_WINDOW,
    )
    stop = threading.Event()
    watcher = threading.Thread(
        target=_kill_on_cancel, args=(proc, cancel, stop), daemon=True
    )
    watcher.start()
    try:
        raw, _ = proc.communicate(input=stdin_data, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        # Keep whatever the device already printed: it usually shows whether
        # the login worked and where it got stuck (for example '--More--').
        partial = exc.stdout or b""
        if isinstance(partial, str):
            partial = partial.encode("utf-8", "replace")
        try:
            proc.kill()
            rest, _ = proc.communicate(timeout=5)
            partial += rest or b""
        except Exception:  # noqa: BLE001 - best effort only
            pass
        snippet = (partial or b"").decode("utf-8", "replace").strip()
        raise ExecError(
            f"{backend} timed out after {int(timeout)}s. If the device asked "
            "'--More--', paging could not be disabled.\n\n"
            "Output received so far:\n"
            + (snippet[-1500:] if snippet else "(nothing)")
        )
    finally:
        stop.set()

    if cancel is not None and cancel.is_set():
        raise ExecCancelled("Scan cancelled by user")
    return (raw or b"").decode("utf-8", "replace")


def _host_key_missing(text: str) -> bool:
    lowered = text.lower()
    if "host key" not in lowered:
        return False
    return (
        "not cached" in lowered
        or "not in the cache" in lowered
        or "no host key" in lowered
        or "host key for this server was not found" in lowered
        or "unknown host key" in lowered
    )


def _host_key_changed(text: str) -> bool:
    lowered = text.lower()
    if "host key" not in lowered:
        return False
    return (
        "does not match" in lowered
        or "has changed" in lowered
        or "key changed" in lowered
        or "different host key" in lowered
    )


# host:port -> fingerprint of the key we already trusted this run
_HOST_FINGERPRINTS: Dict[tuple, str] = {}

_FINGERPRINT_PATTERNS = (
    re.compile(r"(SHA256:[A-Za-z0-9+/]{20,}={0,2})"),
    re.compile(r"(MD5:(?:[0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2})"),
    re.compile(
        r"((?:ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp\d+)"
        r"\s+\d+\s+(?:[0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2})"
    ),
)


def _host_key_fingerprint(text: str) -> str:
    """Pull the switch's host key fingerprint out of plink's output.

    plink prints it both in the interactive prompt and in verbose (-v) logs,
    which lets us reconnect with '-hostkey' and avoid the interactive prompt
    entirely (that prompt does not read from a piped stdin).
    """
    for pattern in _FINGERPRINT_PATTERNS:
        match = pattern.search(text or "")
        if match:
            return match.group(1)
    return ""


def run_commands(host: str, port: int, username: str, password: str,
                 commands: Sequence[str],
                 cancel: Optional[threading.Event] = None,
                 log: Optional[Callable[[str], None]] = None,
                 timeout: float = 180.0) -> str:
    """Run `commands` on the device and return the raw terminal transcript."""
    log = log or (lambda message: None)
    plink = find_plink()
    ssh = find_ssh()

    if plink and (password or not ssh):
        backend, client = "plink", plink
    elif ssh:
        backend, client = "ssh", ssh
    elif plink:
        backend, client = "plink", plink
    else:
        raise ExecError(
            "No SSH client found. Put plink.exe (PuTTY) next to this program, or "
            "install the Windows OpenSSH client."
        )

    log(f"Using {backend}: {client}")
    script_bytes = _script_bytes(commands)
    if backend == "plink":
        cache_key = (host.lower(), int(port))

        def plink_attempt(session: str = "") -> str:
            """Connect once, trusting an unknown/changed host key if needed."""
            hostkey = _HOST_FINGERPRINTS.get(cache_key, "")
            command = _plink_command(
                client, host, port, username, password,
                hostkey=hostkey, session=session,
            )
            output = _execute(command, script_bytes, timeout, cancel, backend)

            if not (_host_key_missing(output) or _host_key_changed(output)):
                return output

            if _host_key_changed(output):
                log("WARNING: this switch's SSH host key changed since the last scan.")
                _HOST_FINGERPRINTS.pop(cache_key, None)

            fingerprint = _host_key_fingerprint(output)
            if not fingerprint:
                # '-v' prints the key fingerprint before aborting on the
                # unknown key.  It never prompts, so it cannot hang.
                log("Reading this switch's SSH host key...")
                probe = _execute(
                    _plink_command(
                        client, host, port, username, password,
                        verbose=True, session=session,
                    ),
                    b"exit\n",
                    min(30.0, timeout),
                    cancel,
                    backend,
                )
                fingerprint = _host_key_fingerprint(probe)

            if not fingerprint:
                # Never fall back to plink's interactive prompt: with piped
                # stdin / no console it waits forever instead of reading 'y'.
                raise ExecError(
                    "plink refused this switch's SSH host key and its "
                    "fingerprint could not be read automatically.\n\n"
                    "Open a Command Prompt and run this once, then answer 'y':\n"
                    f"  {os.path.basename(client)} -ssh {username}@{host}\n\n"
                    "After that, scanning works normally."
                )

            _HOST_FINGERPRINTS[cache_key] = fingerprint
            log(f"Trusting this switch's host key: {fingerprint}")
            output = _execute(
                _plink_command(
                    client, host, port, username, password,
                    hostkey=fingerprint, session=session,
                ),
                script_bytes, timeout, cancel, backend,
            )
            if "unknown option" in output.lower():
                raise ExecError(
                    "This plink.exe is too old to use '-hostkey'. Please "
                    "update PuTTY (putty.org) or run plink once manually and "
                    "answer 'y' to cache the key."
                )
            return output

        text = plink_attempt()

        # An old switch may only offer a key-exchange algorithm that PuTTY
        # considers weak.  Retry once through a session that allows it.
        problem = weak_crypto_problem(text)
        if problem:
            kind, algorithm = problem
            log(
                f"This switch only offers a weak SSH {kind} ({algorithm}) - "
                "preparing a PuTTY setting that allows it..."
            )
            session = ""
            if kind == "key-exchange algorithm":
                session = allow_weak_kex(algorithm)
            if not session:
                log("Could not create the PuTTY setting; see the error below")
            else:
                log(f"Retrying with the PuTTY session '{session}'")
                text = plink_attempt(session)
                problem = weak_crypto_problem(text)
                if not problem and "unable to load" in text.lower():
                    raise ExecError(
                        f"plink could not load the PuTTY session '{session}' "
                        "that Cisco Port Mapper created.\n\n"
                        + _error_excerpt(text)
                    )
            if problem:
                raise ExecError(
                    _weak_crypto_message(problem[0], problem[1], text, session)
                )
    else:
        if password:
            log(
                "Note: ssh.exe cannot send a password non-interactively; "
                "it will use your SSH key or ssh-agent."
            )
        command = _ssh_command(client, host, port, username)
        text = _execute(command, script_bytes, timeout, cancel, backend)

    lowered = text.lower()

    if _host_key_missing(text):
        raise ExecError(
            "plink could not read this switch's SSH host key automatically.\n\n"
            "Open a Command Prompt and run this once, then answer 'y':\n"
            f"  {os.path.basename(client)} -ssh {username}@{host}\n\n"
            "After that, scanning works normally."
        )
    if _host_key_changed(text):
        raise ExecError(
            "The switch's SSH host key changed, so the connection was refused "
            "for safety. If the switch was reinstalled or upgraded this is "
            "normal: run plink once, answer 'y' to store the new key, then scan "
            "again."
        )
    if "permission denied" in lowered or "access denied" in lowered:
        if backend == "ssh":
            raise ExecError(
                "SSH authentication failed. ssh.exe needs an SSH key or "
                "ssh-agent (no password support); install PuTTY/plink.exe for "
                "password login."
            )
        raise ExecError("SSH authentication failed - check username/password")
    if "unable to authenticate" in lowered or "authentication failed" in lowered:
        raise ExecError("SSH authentication failed - check username/password")
    for marker in (
        "connection refused",
        "connection timed out",
        "no route to host",
        "unable to open connection",
        "unable to negotiate",
        "no matching key exchange method",
        "no matching host key type",
        "network error",
        "fatal error",
    ):
        if marker in lowered:
            raise ExecError(_error_excerpt(text))

    if not text.strip():
        raise ExecError(f"{backend} returned no output.")
    return text


# ---------------------------------------------------------------------------
# transcript -> per command output
# ---------------------------------------------------------------------------

_PROMPT_LINE_RE = re.compile(r"^[A-Za-z0-9_.:/\-()\[\]]+\s*[>#]\s*(.*)$")
_MORE_RE = re.compile(r"^(?:<+\s*)?-*\s*more\s*-*(?:\s*>+)?$", re.I)


def split_transcript(transcript: str, commands: Sequence[str]) -> Dict[str, str]:
    """Split an interactive transcript into {command: output}.

    Works with any prompt that ends in '>' or '#'; the command is recognised
    because the device echoes '<prompt><command>' before its output.
    """
    wanted: Dict[str, str] = {}
    for command in commands:
        wanted.setdefault(command.strip(), command)

    sections: Dict[str, str] = {command: "" for command in commands}
    current: Optional[str] = None
    buffer: List[str] = []

    text = transcript.replace("\r\n", "\n").replace("\r", "\n")
    for raw_line in text.split("\n"):
        line = strip_ansi(raw_line)
        stripped = line.strip()
        match = _PROMPT_LINE_RE.match(stripped)
        matched: Optional[str] = None
        if match:
            remainder = match.group(1).strip()
            if remainder in wanted:
                matched = wanted[remainder]
        if matched is None:
            # Fallback for prompts the regex does not know (for example a
            # prompt containing '~' or '+').  A '<prompt>#<command>' or
            # '<prompt>><command>' line still ends the previous section.
            for separator in ("#", ">"):
                index = stripped.rfind(separator)
                if index >= 0:
                    remainder = stripped[index + 1:].strip()
                    if remainder in wanted:
                        matched = wanted[remainder]
                        break
        if matched is not None:
            if current is not None:
                sections[current] = "\n".join(buffer).strip("\n")
            current = matched
            buffer = []
            continue
        if match:
            # Any other prompt line (including a bare prompt or the echo of a
            # command we did not ask for) is not part of the output.
            continue
        if _MORE_RE.match(stripped):
            continue
        if current is not None:
            buffer.append(line.rstrip())

    if current is not None:
        sections[current] = "\n".join(buffer).strip("\n")

    return {command: output.strip("\n") for command, output in sections.items()}
