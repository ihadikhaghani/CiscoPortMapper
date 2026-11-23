"""Cisco Port Mapper - Windows GUI.

Connects to Cisco switches over SSH (no SNMP) and lists, for every
interface, which device is connected (CDP / LLDP / MAC table + ARP).
"""

from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import sys
import threading
import time
import tkinter as tk
import uuid
from tkinter import filedialog, messagebox, ttk

try:
    from cameras import (
        CameraCancelled,
        build_ip_port_index,
        cameras_from_switch_rows,
        default_targets_text,
        discover_cameras,
        match_cameras,
        merge_cameras,
        normalize_mac,
        parse_arp_table,
        parse_targets,
        summarize,
        target_count,
    )
    from cisco import ScanCancelled, SwitchConfig, scan_switch
    from hosts import (
        HostCancelled,
        discover_hosts,
        match_hosts,
        names_from_switch_rows,
    )
    from oui import load_oui_database
    from prereq import (
        PrereqError,
        download_plink,
        install_openssh_client,
        is_admin,
        ssh_status,
    )
    from sshexec import describe_backend
    from xlsx import write_xlsx
except Exception as exc:  # broken install
    IMPORT_ERROR = exc
else:
    IMPORT_ERROR = None

APP_TITLE = "Cisco Port Mapper"
APP_SUBTITLE = "Switch ports, cameras and PCs over SSH - no SNMP, no agents"

# ---------------------------------------------------------------- theme ----
FONT = "Segoe UI"
MONO_FONT = "Consolas"

COLOR_BG = "#eef2f7"
COLOR_CARD = "#ffffff"
COLOR_HEADER = "#0d2338"
COLOR_HEADER_SOFT = "#173a5c"
COLOR_ACCENT = "#1f6feb"
COLOR_ACCENT_DARK = "#1657bd"
COLOR_TEXT = "#1b2733"
COLOR_MUTED = "#5d6b7a"
COLOR_BORDER = "#d5dde8"
COLOR_STRIPE = "#f5f8fc"
COLOR_SELECT = "#d9e8ff"
COLOR_OK = "#146c43"
COLOR_WARN = "#a35a00"
COLOR_BANNER_BG = "#fff4d6"
COLOR_BANNER_TEXT = "#6d4300"

COLUMNS = [
    ("switch", "Switch", 120),
    ("interface", "Interface", 150),
    ("description", "Description", 130),
    ("status", "Status", 85),
    ("vlan", "VLAN", 55),
    ("mode", "Mode", 70),
    ("speed", "Speed", 70),
    ("neighbor", "Connected device", 210),
    ("ip", "IP", 115),
    ("platform", "Platform", 160),
    ("remote_port", "Remote port", 130),
    ("macs", "MAC addresses", 190),
    ("source", "Source", 65),
]
CAM_COLUMNS = [
    ("ip", "Camera IP", 115),
    ("mac", "MAC", 140),
    ("vendor", "Vendor", 110),
    ("model", "Name / model", 190),
    ("confidence", "Confidence", 85),
    ("ports", "Open ports", 105),
    ("switch", "Switch", 115),
    ("interface", "Switch port", 145),
    ("port_status_label", "Port status", 95),
    ("vlan", "VLAN", 50),
    ("port_desc", "Port description", 130),
    ("match", "Match", 175),
    ("evidence", "Evidence", 230),
    ("port_reason", "Port reason", 320),
]
HOST_COLUMNS = [
    ("ip", "IP", 115),
    ("mac", "MAC", 140),
    ("model", "Hostname", 190),
    ("vendor", "Vendor", 120),
    ("os_hint", "Type", 110),
    ("confidence", "Confidence", 85),
    ("ports", "Open ports", 120),
    ("switch", "Switch", 115),
    ("interface", "Switch port", 145),
    ("port_status_label", "Port status", 95),
    ("vlan", "VLAN", 50),
    ("port_desc", "Port description", 130),
    ("match", "Match", 175),
    ("evidence", "Evidence", 230),
    ("port_reason", "Port reason", 320),
]

PORT_STATUS_FILTERS = ("All", "Confirmed", "Probable", "Candidates", "Unknown")
_IP_QUERY = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAC_QUERY = re.compile(
    r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"
    r"|^(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$"
    r"|^[0-9A-Fa-f]{12}$"
)


def _row_matches_search(row: dict, needle: str, columns) -> bool:
    """Match a search box value against one result row.

    A full IP or MAC address is compared exactly so that a partial MAC never
    matches by accident; anything else is a normal substring search over the
    visible columns.
    """
    text = (needle or "").strip()
    if not text:
        return True
    if _IP_QUERY.match(text):
        if str(row.get("ip", "")).strip() == text:
            return True
        return f"({text})" in str(row.get("macs", "") or "")
    if _MAC_QUERY.match(text):
        target = normalize_mac(text)
        values = []
        mac = str(row.get("mac", "") or "").strip()
        if mac:
            values.append(mac)
        for part in str(row.get("macs", "") or "").split(","):
            token = part.strip().split(" ")[0]
            if token:
                values.append(token)
        return any(normalize_mac(value) == target for value in values)
    haystack = " ".join(str(row.get(key, "")) for key, _, _ in columns).lower()
    return text.lower() in haystack


def app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def encode_secret(value: str) -> str:
    if not value:
        return ""
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def decode_secret(value: str) -> str:
    if not value:
        return ""
    try:
        return base64.b64decode(value.encode("ascii")).decode("utf-8")
    except Exception:
        return value


def enable_dpi_awareness() -> None:
    """Ask Windows to render the UI sharply on high-DPI screens."""
    if os.name != "nt":
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # older Windows
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:  # best effort only
        pass


class SetupDialog(tk.Toplevel):
    """Install the one external runtime piece: an SSH client."""

    def __init__(self, app: "App", auto_download: bool = False):
        super().__init__(app)
        self.app = app
        self.title("Runtime setup - SSH client")
        self.transient(app)
        self.resizable(False, False)
        self.configure(background=COLOR_BG)
        self.result = None
        self._busy = False

        wrap = ttk.Frame(self, padding=16)
        wrap.pack(fill="both", expand=True)

        ttk.Label(
            wrap,
            text="SSH client",
            font=(FONT, 13, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            wrap,
            text=(
                "Cisco Port Mapper talks to the switches through an SSH client. "
                "The application itself needs no Python packages."
            ),
            wraplength=560,
            justify="left",
        ).pack(anchor="w", pady=(2, 10))

        self.status_var = tk.StringVar(value="")
        status_card = ttk.Frame(wrap, style="Card.TFrame", padding=12)
        status_card.pack(fill="x")
        ttk.Label(
            status_card, textvariable=self.status_var, style="Card.TLabel",
            wraplength=540, justify="left",
        ).pack(anchor="w")

        ttk.Label(
            wrap,
            text=(
                "Option 1 - recommended: download the official plink.exe from "
                "PuTTY. It supports password login and needs no administrator "
                "rights."
            ),
            wraplength=560,
            justify="left",
        ).pack(anchor="w", pady=(14, 4))
        self.btn_plink = ttk.Button(
            wrap,
            text="Download plink.exe automatically",
            style="Accent.TButton",
            command=self.start_download,
        )
        self.btn_plink.pack(anchor="w")

        ttk.Label(
            wrap,
            text=(
                "Option 2 - fallback: enable the built-in Windows OpenSSH "
                "Client. It only supports key/ssh-agent login and needs "
                "Administrator rights."
            ),
            wraplength=560,
            justify="left",
        ).pack(anchor="w", pady=(14, 4))
        self.btn_openssh = ttk.Button(
            wrap,
            text="Install Windows OpenSSH Client",
            command=self.start_openssh,
        )
        self.btn_openssh.pack(anchor="w")

        self.log_text = tk.Text(
            wrap,
            height=7,
            width=72,
            wrap="word",
            state="disabled",
            background="#ffffff",
            foreground=COLOR_TEXT,
            relief="flat",
            font=(MONO_FONT, 9),
            padx=8,
            pady=6,
            highlightthickness=1,
            highlightbackground=COLOR_BORDER,
        )
        self.log_text.pack(fill="both", expand=True, pady=(14, 0))

        buttons = ttk.Frame(wrap)
        buttons.pack(fill="x", pady=(12, 0))
        self.btn_recheck = ttk.Button(
            buttons, text="Re-check", command=self.refresh_status
        )
        self.btn_recheck.pack(side="left")
        ttk.Button(buttons, text="Close", command=self.destroy).pack(side="right")

        self.bind("<Escape>", lambda event: self.destroy())
        self.refresh_status()
        self.grab_set()
        self.focus_force()
        if auto_download:
            self.after(250, self.start_download)

    # -- helpers --------------------------------------------------------
    def _append(self, message: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message.rstrip() + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _post(self, message: str) -> None:
        """Thread-safe log append."""
        self.after(0, lambda: self._append(message))

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for button in (self.btn_plink, self.btn_openssh, self.btn_recheck):
            button.configure(state=state)

    def refresh_status(self) -> None:
        status = ssh_status()
        lines = []
        if status["plink"]:
            lines.append(f"plink.exe : {status['plink']}")
        if status["ssh"]:
            lines.append(f"ssh.exe   : {status['ssh']}")
        if status["ok"]:
            lines.append("Ready: the switch scanner can connect.")
        else:
            lines.append("No SSH client found yet.")
        if os.name == "nt":
            lines.append(
                "Administrator rights: " + ("yes" if is_admin() else "no")
            )
        self.status_var.set("\n".join(lines))
        self.app.update_ssh_badge()

    def _run(self, action) -> None:
        if self._busy:
            return
        self._set_busy(True)
        self._append("Working...")

        def worker() -> None:
            try:
                message = action(self._post)
            except PrereqError as exc:
                self.after(0, lambda exc=exc: self._finish(False, str(exc)))
            except Exception as exc:  # noqa: BLE001 - show it to the user
                self.after(0, lambda exc=exc: self._finish(
                    False, f"Unexpected error: {exc}"
                ))
            else:
                self.after(0, lambda message=message: self._finish(True, message))

        threading.Thread(target=worker, daemon=True).start()

    def _finish(self, ok: bool, message: str) -> None:
        self._set_busy(False)
        self._append(("OK: " if ok else "FAILED: ") + message)
        self.refresh_status()
        if ok:
            messagebox.showinfo(APP_TITLE, message, parent=self)
        else:
            messagebox.showerror(APP_TITLE, message, parent=self)

    def start_download(self) -> None:
        self._run(
            lambda log: "plink.exe is ready:\n" + download_plink(log=log)
        )

    def start_openssh(self) -> None:
        self._run(lambda log: install_openssh_client(log=log))


class SwitchDialog(tk.Toplevel):
    """Add / edit one switch entry."""

    def __init__(self, parent, cfg: SwitchConfig | None = None):
        super().__init__(parent)
        self.title("Edit switch" if cfg else "Add switch")
        self.transient(parent)
        self.resizable(False, False)
        self.result = None
        self.cfg = cfg

        frame = ttk.Frame(self, padding=12)
        frame.pack(fill="both", expand=True)

        self.vars = {}
        self.hidden_entries = []
        row = 0

        def add_field(label: str, key: str, value: str, show: str = "") -> None:
            nonlocal row
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=4)
            var = tk.StringVar(value=value)
            entry = ttk.Entry(frame, textvariable=var, width=36, show=show)
            entry.grid(row=row, column=1, sticky="we", padx=(10, 0), pady=4)
            self.vars[key] = var
            if show:
                self.hidden_entries.append(entry)
            row += 1

        add_field("Name (optional)", "label", cfg.label if cfg else "")
        add_field("Host / IP", "host", cfg.host if cfg else "")
        add_field("SSH port", "port", str(cfg.port if cfg else 22))
        add_field("Username", "username", cfg.username if cfg else "")
        add_field("Password", "password", cfg.password if cfg else "", show="*")
        add_field("Enable secret (optional)", "secret", cfg.secret if cfg else "", show="*")

        show_var = tk.BooleanVar(value=False)

        def toggle_show() -> None:
            char = "" if show_var.get() else "*"
            for entry in self.hidden_entries:
                entry.configure(show=char)

        ttk.Checkbutton(frame, text="Show passwords", variable=show_var,
                        command=toggle_show).grid(row=row, column=1, sticky="w", padx=(10, 0))
        row += 1

        self.lldp_var = tk.BooleanVar(value=cfg.enable_lldp if cfg else False)
        ttk.Checkbutton(
            frame,
            text="Enable LLDP on the switch if it is disabled (changes device config)",
            variable=self.lldp_var,
        ).grid(row=row, column=0, columnspan=2, sticky="w", pady=(6, 0))
        row += 1

        buttons = ttk.Frame(frame)
        buttons.grid(row=row, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="Save", command=self.save).pack(side="left", padx=4)
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="left")

        self.bind("<Return>", lambda event: self.save())
        self.bind("<Escape>", lambda event: self.destroy())
        self.wait_visibility()
        self.grab_set()
        self.focus_force()

    def save(self) -> None:
        host = self.vars["host"].get().strip()
        username = self.vars["username"].get().strip()
        if not host:
            messagebox.showerror("Missing host", "Enter the switch IP address or hostname.", parent=self)
            return
        try:
            port = int(self.vars["port"].get().strip() or "22")
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid port", "SSH port must be a number between 1 and 65535.", parent=self)
            return
        self.result = SwitchConfig(
            rid=self.cfg.rid if self.cfg else uuid.uuid4().hex,
            host=host,
            username=username,
            password=self.vars["password"].get(),
            secret=self.vars["secret"].get(),
            port=port,
            label=self.vars["label"].get().strip(),
            enable_lldp=bool(self.lldp_var.get()),
        )
        self.destroy()


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(1040, 620)

        self.base_dir = app_dir()
        self.log_path = os.path.join(self.base_dir, "cisco_port_mapper.log")
        try:
            with open(self.log_path, "w", encoding="utf-8") as handle:
                handle.write(
                    f"Cisco Port Mapper log - {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
        except OSError:
            self.log_path = ""
        self.switches: list[SwitchConfig] = []
        self.all_rows: list[dict] = []
        self.row_by_iid: dict[str, dict] = {}
        self.oui_db = load_oui_database(os.path.join(self.base_dir, "oui.csv"))

        # Camera discovery state.  The switch MAC tables are kept per switch
        # so re-scanning one switch replaces only that switch's data.
        self.discovered_cameras: list = []
        self.cameras: list = []
        self.camera_rows: list[dict] = []
        self.cam_row_by_iid: dict[str, dict] = {}
        self.mac_ports_by_switch: dict[str, dict] = {}
        self.ip_mac_by_switch: dict[str, dict] = {}
        self.manual_ip_mac: dict[str, str] = {}
        self.camera_errors: list[tuple[str, str]] = []

        # PC / endpoint discovery state (same switch MAC tables as cameras).
        self.discovered_hosts: list = []
        self.hosts: list = []
        self.host_rows: list[dict] = []
        self.host_row_by_iid: dict[str, dict] = {}
        self.host_errors: list[tuple[str, str]] = []

        self.scanning = False
        self.cancel_event = threading.Event()
        self.queue: queue.Queue = queue.Queue()
        self.errors: list[tuple[str, str]] = []

        self.sort_key = None
        self.sort_reverse = False

        self._build_ui()
        self.load_inventory()
        self.append_log(f"SSH client: {describe_backend()}")
        self.update_ssh_badge()

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(600, self.startup_prereq_check)

    # ------------------------------------------------------------------ UI
    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            for theme in ("vista", "winnative", "clam"):
                if theme in style.theme_names():
                    style.theme_use(theme)
                    break

        style.configure(".", font=(FONT, 9))
        style.configure("TFrame", background=COLOR_BG)
        style.configure("TLabel", background=COLOR_BG, foreground=COLOR_TEXT)
        style.configure("TCheckbutton", background=COLOR_BG, foreground=COLOR_TEXT)
        style.map("TCheckbutton", background=[("active", COLOR_BG)])

        style.configure("Card.TFrame", background=COLOR_CARD, relief="flat")
        style.configure("Card.TLabel", background=COLOR_CARD, foreground=COLOR_TEXT)
        style.configure(
            "CardTitle.TLabel",
            background=COLOR_CARD,
            foreground=COLOR_TEXT,
            font=(FONT, 10, "bold"),
        )
        style.configure(
            "CardHint.TLabel",
            background=COLOR_CARD,
            foreground=COLOR_MUTED,
            font=(FONT, 8),
        )
        style.configure(
            "Card.TCheckbutton", background=COLOR_CARD, foreground=COLOR_TEXT
        )
        style.map("Card.TCheckbutton", background=[("active", COLOR_CARD)])

        style.configure(
            "TButton",
            font=(FONT, 9),
            padding=(11, 5),
            background=COLOR_CARD,
            foreground=COLOR_TEXT,
            bordercolor=COLOR_BORDER,
            lightcolor=COLOR_CARD,
            darkcolor=COLOR_CARD,
            relief="flat",
        )
        style.map(
            "TButton",
            background=[("active", "#e7eef8"), ("pressed", "#d8e4f4")],
            foreground=[("disabled", "#a6b0bb")],
            bordercolor=[("active", COLOR_ACCENT)],
        )
        style.configure(
            "Accent.TButton",
            background=COLOR_ACCENT,
            foreground="#ffffff",
            bordercolor=COLOR_ACCENT,
            lightcolor=COLOR_ACCENT,
            darkcolor=COLOR_ACCENT,
            font=(FONT, 9, "bold"),
        )
        style.map(
            "Accent.TButton",
            background=[("active", COLOR_ACCENT_DARK), ("pressed", "#12468f")],
            foreground=[("disabled", "#d6e3f7")],
        )
        style.configure(
            "Header.TButton",
            background=COLOR_HEADER_SOFT,
            foreground="#ffffff",
            bordercolor=COLOR_HEADER_SOFT,
            lightcolor=COLOR_HEADER_SOFT,
            darkcolor=COLOR_HEADER_SOFT,
        )
        style.map(
            "Header.TButton",
            background=[("active", "#245580"), ("pressed", "#102c46")],
            foreground=[("active", "#ffffff")],
        )

        style.configure(
            "TEntry",
            fieldbackground="#ffffff",
            foreground=COLOR_TEXT,
            bordercolor=COLOR_BORDER,
            lightcolor=COLOR_BORDER,
            darkcolor=COLOR_BORDER,
            padding=(6, 4),
        )
        style.map("TEntry", bordercolor=[("focus", COLOR_ACCENT)])

        style.configure(
            "Treeview",
            background="#ffffff",
            fieldbackground="#ffffff",
            foreground=COLOR_TEXT,
            rowheight=26,
            font=(FONT, 9),
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background="#e9eff7",
            foreground="#33465c",
            font=(FONT, 9, "bold"),
            relief="flat",
            padding=(7, 6),
        )
        style.map("Treeview.Heading", background=[("active", "#dce7f5")])
        style.map(
            "Treeview",
            background=[("selected", COLOR_SELECT)],
            foreground=[("selected", COLOR_TEXT)],
        )

        style.configure("TNotebook", background=COLOR_BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background="#e2e9f3",
            foreground=COLOR_MUTED,
            padding=(16, 7),
            font=(FONT, 9, "bold"),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", COLOR_CARD), ("active", "#edf3fb")],
            foreground=[("selected", COLOR_ACCENT)],
        )

        style.configure(
            "TProgressbar",
            background=COLOR_ACCENT,
            troughcolor="#dde5f0",
            bordercolor=COLOR_BORDER,
            lightcolor=COLOR_ACCENT,
            darkcolor=COLOR_ACCENT,
        )
        style.configure("TSeparator", background=COLOR_BORDER)
        style.configure("TPanedwindow", background=COLOR_BG, sashwidth=6)

    def center_window(self, width: int, height: int) -> None:
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        width = min(width, max(900, screen_w - 60))
        height = min(height, max(600, screen_h - 100))
        x = max(0, (screen_w - width) // 2)
        y = max(0, (screen_h - height) // 2 - 20)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _build_ui(self) -> None:
        self.configure(background=COLOR_BG)
        self._configure_styles()
        self.center_window(1380, 840)

        # ---- dark header -------------------------------------------------
        self.header = tk.Frame(self, background=COLOR_HEADER)
        self.header.pack(fill="x")
        header_inner = tk.Frame(
            self.header, background=COLOR_HEADER, padx=18, pady=12
        )
        header_inner.pack(fill="x")

        title_wrap = tk.Frame(header_inner, background=COLOR_HEADER)
        title_wrap.pack(side="left")
        tk.Label(
            title_wrap,
            text=APP_TITLE,
            background=COLOR_HEADER,
            foreground="#ffffff",
            font=(FONT, 16, "bold"),
        ).pack(anchor="w")
        tk.Label(
            title_wrap,
            text=APP_SUBTITLE,
            background=COLOR_HEADER,
            foreground="#9fb8d6",
            font=(FONT, 9),
        ).pack(anchor="w", pady=(2, 0))

        header_right = tk.Frame(header_inner, background=COLOR_HEADER)
        header_right.pack(side="right")
        self.ssh_badge_var = tk.StringVar(value="Checking SSH client...")
        self.ssh_badge = tk.Label(
            header_right,
            textvariable=self.ssh_badge_var,
            background=COLOR_HEADER_SOFT,
            foreground="#dbe9ff",
            font=(FONT, 9, "bold"),
            padx=12,
            pady=6,
        )
        self.ssh_badge.pack(side="left", padx=(0, 8))
        ttk.Button(
            header_right,
            text="Setup...",
            style="Header.TButton",
            command=self.open_setup_dialog,
        ).pack(side="left")

        # ---- prerequisite banner (only when no SSH client is found) ------
        self.banner = tk.Frame(self, background=COLOR_BANNER_BG)
        banner_inner = tk.Frame(
            self.banner, background=COLOR_BANNER_BG, padx=18, pady=8
        )
        banner_inner.pack(fill="x")
        tk.Label(
            banner_inner,
            text="!",
            background="#f2c14e",
            foreground="#4a2c00",
            font=(FONT, 11, "bold"),
            width=2,
        ).pack(side="left")
        self.banner_var = tk.StringVar(
            value=(
                "No SSH client found. Set it up once and this PC can reach "
                "your switches."
            )
        )
        tk.Label(
            banner_inner,
            textvariable=self.banner_var,
            background=COLOR_BANNER_BG,
            foreground=COLOR_BANNER_TEXT,
            font=(FONT, 9),
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            banner_inner,
            text="Set up now",
            style="Accent.TButton",
            command=lambda: self.open_setup_dialog(auto_download=True),
        ).pack(side="right")
        ttk.Button(
            banner_inner,
            text="Re-check",
            command=self.update_ssh_badge,
        ).pack(side="right", padx=(0, 8))

        # ---- toolbar -----------------------------------------------------
        toolbar = ttk.Frame(self, style="Card.TFrame", padding=(14, 10))
        toolbar.pack(fill="x", padx=14, pady=(12, 8))

        self.btn_add = ttk.Button(
            toolbar,
            text="Add switch",
            style="Accent.TButton",
            command=self.add_switch,
        )
        self.btn_edit = ttk.Button(toolbar, text="Edit", command=self.edit_switch)
        self.btn_remove = ttk.Button(
            toolbar, text="Remove", command=self.remove_switch
        )
        self.btn_scan_sel = ttk.Button(
            toolbar, text="Scan selected", command=self.scan_selected
        )
        self.btn_scan_all = ttk.Button(
            toolbar, text="Scan all", command=self.scan_all
        )
        self.btn_stop = ttk.Button(
            toolbar, text="Stop", command=self.stop_scan, state="disabled"
        )
        self.btn_export = ttk.Button(
            toolbar, text="Export CSV", command=self.export_csv
        )
        self.btn_export_xlsx = ttk.Button(
            toolbar, text="Export Excel", command=self.export_ports_excel
        )

        for button in (
            self.btn_add, self.btn_edit, self.btn_remove, self.btn_scan_sel,
            self.btn_scan_all, self.btn_stop, self.btn_export,
            self.btn_export_xlsx,
        ):
            button.pack(side="left", padx=(0, 5))

        ttk.Separator(toolbar, orient="vertical").pack(
            side="left", fill="y", padx=10
        )

        ttk.Label(toolbar, text="Filter", style="Card.TLabel").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *args: self.refresh_rows())
        filter_entry = ttk.Entry(toolbar, textvariable=self.filter_var, width=20)
        filter_entry.pack(side="left", padx=(6, 12))

        self.show_down_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            toolbar,
            text="Show disconnected ports",
            variable=self.show_down_var,
            command=self.refresh_rows,
            style="Card.TCheckbutton",
        ).pack(side="left")

        # ---- body --------------------------------------------------------
        body = ttk.Frame(self, padding=(14, 0, 14, 0))
        body.pack(fill="both", expand=True)

        paned = ttk.PanedWindow(body, orient="horizontal")
        paned.pack(fill="both", expand=True)

        left = ttk.Frame(paned, style="Card.TFrame", padding=12)
        paned.add(left, weight=0)

        left_head = ttk.Frame(left, style="Card.TFrame")
        left_head.pack(fill="x", pady=(0, 8))
        ttk.Label(
            left_head, text="Switches", style="CardTitle.TLabel"
        ).pack(side="left")
        ttk.Label(
            left_head, text="double-click to edit", style="CardHint.TLabel"
        ).pack(side="right")

        switch_wrap = ttk.Frame(left, style="Card.TFrame")
        switch_wrap.pack(fill="both", expand=True)
        self.tree_switches = ttk.Treeview(
            switch_wrap,
            columns=("name", "host"),
            show="headings",
            selectmode="extended",
        )
        self.tree_switches.heading("name", text="Name")
        self.tree_switches.heading("host", text="Host")
        self.tree_switches.column("name", width=130, anchor="w")
        self.tree_switches.column("host", width=120, anchor="w")
        scroll_left = ttk.Scrollbar(
            switch_wrap, orient="vertical", command=self.tree_switches.yview
        )
        self.tree_switches.configure(yscrollcommand=scroll_left.set)
        self.tree_switches.pack(side="left", fill="both", expand=True)
        scroll_left.pack(side="right", fill="y")
        self.tree_switches.bind("<Double-1>", lambda event: self.edit_switch())

        right = ttk.Frame(paned)
        paned.add(right, weight=1)

        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill="both", expand=True)

        # ---- ports -------------------------------------------------------
        ports_tab = ttk.Frame(self.notebook, padding=(10, 10, 10, 6))
        self.notebook.add(ports_tab, text="Ports")

        self.tree_ports = ttk.Treeview(
            ports_tab, columns=[key for key, _, _ in COLUMNS], show="headings",
        )
        for key, title, width in COLUMNS:
            self.tree_ports.heading(
                key, text=title, command=lambda k=key: self.sort_rows(k)
            )
            self.tree_ports.column(key, width=width, anchor="w", stretch=False)
        self.tree_ports.tag_configure("idle", foreground="#8a97a5")
        self.tree_ports.tag_configure("guess", foreground=COLOR_WARN)
        self.tree_ports.tag_configure("neighbor", foreground=COLOR_OK)
        self.tree_ports.tag_configure("stripe", background=COLOR_STRIPE)

        ports_y = ttk.Scrollbar(
            ports_tab, orient="vertical", command=self.tree_ports.yview
        )
        ports_x = ttk.Scrollbar(
            ports_tab, orient="horizontal", command=self.tree_ports.xview
        )
        self.tree_ports.configure(
            yscrollcommand=ports_y.set, xscrollcommand=ports_x.set
        )
        self.tree_ports.grid(row=0, column=0, sticky="nsew")
        ports_y.grid(row=0, column=1, sticky="ns")
        ports_x.grid(row=1, column=0, sticky="we")
        ports_tab.rowconfigure(0, weight=1)
        ports_tab.columnconfigure(0, weight=1)

        self.tree_ports.bind("<Double-1>", self.show_detail)
        self.tree_ports.bind("<Control-c>", self.copy_selected)

        # ---- cameras -----------------------------------------------------
        cam_tab = ttk.Frame(self.notebook, padding=(10, 10, 10, 6))
        self.notebook.add(cam_tab, text="Cameras")

        cam_input = ttk.Frame(cam_tab)
        cam_input.grid(row=0, column=0, columnspan=2, sticky="we")
        ttk.Label(
            cam_input,
            text=(
                "Subnets / ranges (one per line, e.g. "
                "192.168.217.1-192.168.217.254):"
            ),
        ).grid(row=0, column=0, sticky="w")
        self.cam_targets_text = tk.Text(
            cam_input,
            height=3,
            width=60,
            wrap="word",
            undo=True,
            background="#ffffff",
            foreground=COLOR_TEXT,
            relief="flat",
            font=(MONO_FONT, 9),
            padx=8,
            pady=6,
            highlightthickness=1,
            highlightbackground=COLOR_BORDER,
            highlightcolor=COLOR_ACCENT,
        )
        self.cam_targets_text.grid(row=1, column=0, sticky="we", pady=(4, 0))
        self.cam_targets_text.insert("1.0", default_targets_text())
        cam_input_scroll = ttk.Scrollbar(
            cam_input, orient="vertical", command=self.cam_targets_text.yview
        )
        cam_input_scroll.grid(row=1, column=1, sticky="ns", pady=(4, 0))
        self.cam_targets_text.configure(yscrollcommand=cam_input_scroll.set)
        self.cam_targets_text.bind("<KeyRelease>", self.update_camera_target_count)
        self.cam_targets_text.bind(
            "<<Paste>>",
            lambda event: self.after(1, self.update_camera_target_count),
        )
        cam_input.columnconfigure(0, weight=1)

        cam_top = ttk.Frame(cam_tab, padding=(0, 8))
        cam_top.grid(row=1, column=0, columnspan=2, sticky="we")

        self.btn_cam_scan = ttk.Button(
            cam_top,
            text="Discover cameras",
            style="Accent.TButton",
            command=self.start_camera_scan,
        )
        self.btn_cam_scan.pack(side="left", padx=(0, 5))
        self.btn_cam_match = ttk.Button(
            cam_top, text="Match only", command=self.match_only
        )
        self.btn_cam_match.pack(side="left", padx=(0, 5))
        self.btn_cam_export = ttk.Button(
            cam_top, text="Export CSV", command=self.export_cameras
        )
        self.btn_cam_export.pack(side="left")
        self.btn_cam_xlsx = ttk.Button(
            cam_top, text="Export Excel", command=self.export_cameras_excel
        )
        self.btn_cam_xlsx.pack(side="left", padx=(5, 0))
        self.btn_cam_arp = ttk.Button(
            cam_top, text="Load ARP table...", command=self.load_arp_table
        )
        self.btn_cam_arp.pack(side="left", padx=(5, 0))
        self.cam_count_var = tk.StringVar(value="")
        ttk.Label(cam_top, textvariable=self.cam_count_var).pack(
            side="left", padx=(10, 0)
        )

        cam_opts = ttk.Frame(cam_tab)
        cam_opts.grid(row=2, column=0, columnspan=2, sticky="we", pady=(0, 8))

        self.cam_rescan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            cam_opts,
            text="Re-scan switches before matching",
            variable=self.cam_rescan_var,
        ).pack(side="left")
        self.cam_all_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            cam_opts,
            text="Show non-camera devices too",
            variable=self.cam_all_var,
        ).pack(side="left", padx=(12, 0))
        self.local_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            cam_opts,
            text="Only devices on the scanned switch (hide uplink/trunk devices)",
            variable=self.local_only_var,
            command=self.on_local_only_toggle,
        ).pack(side="left", padx=(12, 0))

        ttk.Label(cam_opts, text="Filter:").pack(side="left", padx=(16, 0))
        self.cam_filter_var = tk.StringVar()
        self.cam_filter_var.trace_add(
            "write", lambda *args: self.refresh_camera_rows()
        )
        ttk.Entry(cam_opts, textvariable=self.cam_filter_var, width=20).pack(
            side="left", padx=(4, 0)
        )
        ttk.Label(cam_opts, text="(IP/MAC = exact)").pack(
            side="left", padx=(6, 0)
        )

        ttk.Label(cam_opts, text="Port status:").pack(side="left", padx=(12, 0))
        self.cam_status_filter_var = tk.StringVar(value=PORT_STATUS_FILTERS[0])
        cam_status_box = ttk.Combobox(
            cam_opts,
            textvariable=self.cam_status_filter_var,
            values=list(PORT_STATUS_FILTERS),
            state="readonly",
            width=11,
        )
        cam_status_box.pack(side="left", padx=(4, 0))
        cam_status_box.bind(
            "<<ComboboxSelected>>", lambda *args: self.refresh_camera_rows()
        )

        self.tree_cameras = ttk.Treeview(
            cam_tab, columns=[key for key, _, _ in CAM_COLUMNS], show="headings"
        )
        for key, title, width in CAM_COLUMNS:
            self.tree_cameras.heading(key, text=title)
            self.tree_cameras.column(key, width=width, anchor="w", stretch=False)
        self.tree_cameras.tag_configure("matched", foreground=COLOR_OK)
        self.tree_cameras.tag_configure("candidate", foreground=COLOR_WARN)
        self.tree_cameras.tag_configure("unknown", foreground=COLOR_MUTED)
        self.tree_cameras.tag_configure("unmatched", foreground=COLOR_WARN)
        self.tree_cameras.tag_configure("switchside", foreground="#3b5bdb")
        self.tree_cameras.tag_configure("stripe", background=COLOR_STRIPE)

        cam_y = ttk.Scrollbar(
            cam_tab, orient="vertical", command=self.tree_cameras.yview
        )
        cam_x = ttk.Scrollbar(
            cam_tab, orient="horizontal", command=self.tree_cameras.xview
        )
        self.tree_cameras.configure(
            yscrollcommand=cam_y.set, xscrollcommand=cam_x.set
        )
        self.tree_cameras.grid(row=3, column=0, sticky="nsew")
        cam_y.grid(row=3, column=1, sticky="ns")
        cam_x.grid(row=4, column=0, sticky="we")
        cam_tab.rowconfigure(3, weight=1)
        cam_tab.columnconfigure(0, weight=1)
        self.tree_cameras.bind("<Double-1>", self.show_camera_detail)
        self.tree_cameras.bind("<Control-c>", self.copy_camera_selected)

        self.camera_status_var = tk.StringVar(
            value="Enter a subnet and press 'Discover cameras'."
        )
        ttk.Label(
            cam_tab, textvariable=self.camera_status_var, foreground=COLOR_MUTED
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self.update_camera_target_count()

        # ---- PCs / hosts -------------------------------------------------
        host_tab = ttk.Frame(self.notebook, padding=(10, 10, 10, 6))
        self.notebook.add(host_tab, text="PCs / Hosts")

        host_input = ttk.Frame(host_tab)
        host_input.grid(row=0, column=0, columnspan=2, sticky="we")
        ttk.Label(
            host_input,
            text=(
                "Subnets / ranges (one per line, e.g. "
                "192.168.217.1-192.168.217.254):"
            ),
        ).grid(row=0, column=0, sticky="w")
        self.host_targets_text = tk.Text(
            host_input,
            height=3,
            width=60,
            wrap="word",
            undo=True,
            background="#ffffff",
            foreground=COLOR_TEXT,
            relief="flat",
            font=(MONO_FONT, 9),
            padx=8,
            pady=6,
            highlightthickness=1,
            highlightbackground=COLOR_BORDER,
            highlightcolor=COLOR_ACCENT,
        )
        self.host_targets_text.grid(row=1, column=0, sticky="we", pady=(4, 0))
        self.host_targets_text.insert("1.0", default_targets_text())
        host_input_scroll = ttk.Scrollbar(
            host_input, orient="vertical", command=self.host_targets_text.yview
        )
        host_input_scroll.grid(row=1, column=1, sticky="ns", pady=(4, 0))
        self.host_targets_text.configure(yscrollcommand=host_input_scroll.set)
        self.host_targets_text.bind("<KeyRelease>", self.update_host_target_count)
        self.host_targets_text.bind(
            "<<Paste>>",
            lambda event: self.after(1, self.update_host_target_count),
        )
        host_input.columnconfigure(0, weight=1)

        host_top = ttk.Frame(host_tab, padding=(0, 8))
        host_top.grid(row=1, column=0, columnspan=2, sticky="we")
        self.btn_host_scan = ttk.Button(
            host_top,
            text="Discover hosts",
            style="Accent.TButton",
            command=self.start_host_scan,
        )
        self.btn_host_scan.pack(side="left", padx=(0, 5))
        self.btn_host_match = ttk.Button(
            host_top, text="Match only", command=self.match_hosts_only
        )
        self.btn_host_match.pack(side="left", padx=(0, 5))
        self.btn_host_export = ttk.Button(
            host_top, text="Export CSV", command=self.export_hosts
        )
        self.btn_host_export.pack(side="left")
        self.btn_host_xlsx = ttk.Button(
            host_top, text="Export Excel", command=self.export_hosts_excel
        )
        self.btn_host_xlsx.pack(side="left", padx=(5, 0))
        self.btn_host_arp = ttk.Button(
            host_top, text="Load ARP table...", command=self.load_arp_table
        )
        self.btn_host_arp.pack(side="left", padx=(5, 0))
        self.host_count_var = tk.StringVar(value="")
        ttk.Label(host_top, textvariable=self.host_count_var).pack(
            side="left", padx=(10, 0)
        )

        host_opts = ttk.Frame(host_tab)
        host_opts.grid(row=2, column=0, columnspan=2, sticky="we", pady=(0, 8))
        self.host_rescan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            host_opts,
            text="Re-scan switches before matching",
            variable=self.host_rescan_var,
        ).pack(side="left")
        self.host_names_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            host_opts,
            text="Resolve names (DNS / NetBIOS / mDNS)",
            variable=self.host_names_var,
        ).pack(side="left", padx=(12, 0))
        self.host_pc_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            host_opts,
            text="Only computers (hide printers/phones)",
            variable=self.host_pc_only_var,
        ).pack(side="left", padx=(12, 0))
        ttk.Checkbutton(
            host_opts,
            text="Only devices on the scanned switch (hide uplink/trunk devices)",
            variable=self.local_only_var,
            command=self.on_local_only_toggle,
        ).pack(side="left", padx=(12, 0))

        ttk.Label(host_opts, text="Filter:").pack(side="left", padx=(16, 0))
        self.host_filter_var = tk.StringVar()
        self.host_filter_var.trace_add(
            "write", lambda *args: self.refresh_host_rows()
        )
        ttk.Entry(host_opts, textvariable=self.host_filter_var, width=20).pack(
            side="left", padx=(4, 0)
        )
        ttk.Label(host_opts, text="(IP/MAC = exact)").pack(
            side="left", padx=(6, 0)
        )

        ttk.Label(host_opts, text="Port status:").pack(side="left", padx=(12, 0))
        self.host_status_filter_var = tk.StringVar(value=PORT_STATUS_FILTERS[0])
        host_status_box = ttk.Combobox(
            host_opts,
            textvariable=self.host_status_filter_var,
            values=list(PORT_STATUS_FILTERS),
            state="readonly",
            width=11,
        )
        host_status_box.pack(side="left", padx=(4, 0))
        host_status_box.bind(
            "<<ComboboxSelected>>", lambda *args: self.refresh_host_rows()
        )

        self.tree_hosts = ttk.Treeview(
            host_tab, columns=[key for key, _, _ in HOST_COLUMNS], show="headings"
        )
        for key, title, width in HOST_COLUMNS:
            self.tree_hosts.heading(key, text=title)
            self.tree_hosts.column(key, width=width, anchor="w", stretch=False)
        self.tree_hosts.tag_configure("matched", foreground=COLOR_OK)
        self.tree_hosts.tag_configure("candidate", foreground=COLOR_WARN)
        self.tree_hosts.tag_configure("unknown", foreground=COLOR_MUTED)
        self.tree_hosts.tag_configure("unmatched", foreground=COLOR_WARN)
        self.tree_hosts.tag_configure("stripe", background=COLOR_STRIPE)

        host_y = ttk.Scrollbar(
            host_tab, orient="vertical", command=self.tree_hosts.yview
        )
        host_x = ttk.Scrollbar(
            host_tab, orient="horizontal", command=self.tree_hosts.xview
        )
        self.tree_hosts.configure(
            yscrollcommand=host_y.set, xscrollcommand=host_x.set
        )
        self.tree_hosts.grid(row=3, column=0, sticky="nsew")
        host_y.grid(row=3, column=1, sticky="ns")
        host_x.grid(row=4, column=0, sticky="we")
        host_tab.rowconfigure(3, weight=1)
        host_tab.columnconfigure(0, weight=1)
        self.tree_hosts.bind("<Double-1>", self.show_host_detail)
        self.tree_hosts.bind("<Control-c>", self.copy_host_selected)

        self.host_status_var = tk.StringVar(
            value="Enter a subnet and press 'Discover hosts'."
        )
        ttk.Label(
            host_tab, textvariable=self.host_status_var, foreground=COLOR_MUTED
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self.update_host_target_count()

        # ---- log ---------------------------------------------------------
        log_tab = ttk.Frame(self.notebook, padding=(10, 10, 10, 6))
        self.notebook.add(log_tab, text="Log")
        self.log_text = tk.Text(
            log_tab,
            wrap="word",
            height=10,
            state="disabled",
            background="#0f1b29",
            foreground="#d7e3f2",
            relief="flat",
            font=(MONO_FONT, 9),
            padx=10,
            pady=8,
            insertbackground="#d7e3f2",
        )
        log_scroll = ttk.Scrollbar(
            log_tab, orient="vertical", command=self.log_text.yview
        )
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll.grid(row=0, column=1, sticky="ns")
        log_tab.rowconfigure(0, weight=1)
        log_tab.columnconfigure(0, weight=1)

        # ---- status bar ---------------------------------------------------
        status = ttk.Frame(self, style="Card.TFrame", padding=(14, 7))
        status.pack(fill="x", padx=14, pady=(8, 12))
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(
            status, textvariable=self.status_var, style="Card.TLabel"
        ).pack(side="left")
        self.count_var = tk.StringVar(value="0 ports")
        ttk.Label(
            status, textvariable=self.count_var, style="CardHint.TLabel"
        ).pack(side="right", padx=(10, 0))
        self.progress = ttk.Progressbar(status, length=190, mode="determinate")
        self.progress.pack(side="right", padx=8)

    # ----------------------------------------------------------- SSH setup
    def update_ssh_badge(self) -> None:
        """Refresh the header badge and the amber prerequisite banner."""
        status = ssh_status()
        if status["plink"]:
            self.ssh_badge_var.set("SSH ready - plink.exe")
            self.ssh_badge.configure(
                background="#14532d", foreground="#c9f2d9"
            )
        elif status["ssh"]:
            self.ssh_badge_var.set("SSH ready - ssh.exe (keys only)")
            self.ssh_badge.configure(
                background="#14532d", foreground="#c9f2d9"
            )
        else:
            self.ssh_badge_var.set("SSH client missing")
            self.ssh_badge.configure(
                background="#7f1d1d", foreground="#ffd9d9"
            )
        if status["ok"]:
            self.banner.pack_forget()
        else:
            self.banner.pack(fill="x", after=self.header)

    def open_setup_dialog(self, auto_download: bool = False) -> None:
        existing = getattr(self, "_setup_dialog", None)
        if existing is not None and existing.winfo_exists():
            existing.lift()
            existing.focus_force()
            if auto_download:
                existing.start_download()
            return
        dialog = SetupDialog(self, auto_download=auto_download)
        self._setup_dialog = dialog

    def startup_prereq_check(self) -> None:
        """On a fresh PC offer to install the SSH client right away."""
        self.update_ssh_badge()
        if ssh_status()["ok"]:
            return
        if messagebox.askyesno(
            APP_TITLE,
            "This PC has no SSH client yet, so Cisco Port Mapper cannot "
            "connect to the switches.\n\n"
            "Download the official plink.exe (PuTTY) now?\n"
            "It is saved next to the program and needs no administrator "
            "rights.",
            parent=self,
        ):
            self.open_setup_dialog(auto_download=True)

    def ensure_ssh(self) -> bool:
        """True when a client exists; otherwise offer the setup window."""
        if ssh_status()["ok"]:
            return True
        if messagebox.askyesno(
            APP_TITLE,
            "No SSH client was found, so the switches cannot be scanned.\n\n"
            "Open the setup window and download plink.exe now?",
            parent=self,
        ):
            self.open_setup_dialog(auto_download=True)
        return False

    def on_local_only_toggle(self) -> None:
        self.refresh_camera_rows()
        self.refresh_host_rows()

    # ----------------------------------------------------------- inventory
    def inventory_path(self) -> str:
        return os.path.join(self.base_dir, "inventory.json")

    def load_inventory(self) -> None:
        path = self.inventory_path()
        if not os.path.exists(path):
            self.refresh_switches()
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception as exc:
            messagebox.showwarning(APP_TITLE, f"Could not read {path}:\n{exc}")
            self.refresh_switches()
            return
        self.switches = []
        for item in data.get("switches", []):
            host = str(item.get("host", "")).strip()
            if not host:
                continue
            try:
                port = int(item.get("port", 22) or 22)
            except (TypeError, ValueError):
                port = 22
            self.switches.append(
                SwitchConfig(
                    rid=str(item.get("rid") or uuid.uuid4().hex),
                    label=str(item.get("label", "")),
                    host=host,
                    port=port,
                    username=str(item.get("username", "")),
                    password=decode_secret(str(item.get("password", ""))),
                    secret=decode_secret(str(item.get("secret", ""))),
                    enable_lldp=bool(item.get("enable_lldp", False)),
                )
            )
        self.refresh_switches()

    def save_inventory(self) -> None:
        data = {
            "switches": [
                {
                    "rid": cfg.rid,
                    "label": cfg.label,
                    "host": cfg.host,
                    "port": cfg.port,
                    "username": cfg.username,
                    "password": encode_secret(cfg.password),
                    "secret": encode_secret(cfg.secret),
                    "enable_lldp": cfg.enable_lldp,
                }
                for cfg in self.switches
            ]
        }
        try:
            with open(self.inventory_path(), "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not save {self.inventory_path()}:\n{exc}")

    def refresh_switches(self) -> None:
        self.tree_switches.delete(*self.tree_switches.get_children())
        for cfg in self.switches:
            name = cfg.label or cfg.host
            self.tree_switches.insert(
                "", "end", iid=cfg.rid, values=(name, f"{cfg.host}:{cfg.port}")
            )

    def selected_switches(self) -> list[SwitchConfig]:
        chosen = set(self.tree_switches.selection())
        return [cfg for cfg in self.switches if cfg.rid in chosen]

    def add_switch(self) -> None:
        dialog = SwitchDialog(self)
        self.wait_window(dialog)
        if dialog.result:
            self.switches.append(dialog.result)
            self.save_inventory()
            self.refresh_switches()
            self.tree_switches.selection_set(dialog.result.rid)

    def edit_switch(self) -> None:
        selected = self.selected_switches()
        if len(selected) != 1:
            messagebox.showinfo(APP_TITLE, "Select exactly one switch to edit.")
            return
        dialog = SwitchDialog(self, selected[0])
        self.wait_window(dialog)
        if dialog.result:
            index = next(
                i for i, cfg in enumerate(self.switches) if cfg.rid == selected[0].rid
            )
            self.switches[index] = dialog.result
            self.save_inventory()
            self.refresh_switches()
            self.tree_switches.selection_set(dialog.result.rid)

    def remove_switch(self) -> None:
        selected = self.selected_switches()
        if not selected:
            return
        if not messagebox.askyesno(APP_TITLE, f"Remove {len(selected)} switch(es) from the list?"):
            return
        remove = {cfg.rid for cfg in selected}
        self.switches = [cfg for cfg in self.switches if cfg.rid not in remove]
        self.save_inventory()
        self.refresh_switches()

    # --------------------------------------------------------------- scanning
    def scan_selected(self) -> None:
        targets = self.selected_switches()
        if not targets:
            messagebox.showinfo(APP_TITLE, "Select one or more switches first.")
            return
        self.start_scan(targets)

    def scan_all(self) -> None:
        if not self.switches:
            messagebox.showinfo(APP_TITLE, "Add a switch first.")
            return
        self.start_scan(list(self.switches))

    def start_scan(self, targets: list[SwitchConfig]) -> None:
        if self.scanning:
            return
        if not self.ensure_ssh():
            return
        self.scanning = True
        self.cancel_event = threading.Event()
        self.errors = []
        self._set_scan_state(True)

        self.all_rows = []
        self.mac_ports_by_switch.clear()
        self.ip_mac_by_switch.clear()
        self.refresh_rows()
        self.progress.configure(maximum=len(targets), value=0)
        self.status_var.set(f"Scanning {len(targets)} switch(es)...")
        self.append_log(f"Starting scan of {len(targets)} switch(es)")

        worker = threading.Thread(target=self._worker, args=(targets,), daemon=True)
        worker.start()
        self.after(120, self.poll_queue)

    def _worker(self, targets: list[SwitchConfig]) -> None:
        ok = 0
        for index, cfg in enumerate(targets, start=1):
            if self.cancel_event.is_set():
                self.queue.put(("log", "Scan cancelled"))
                break
            self.queue.put(("status", f"Scanning {cfg.host} ({index}/{len(targets)})..."))
            try:
                result = scan_switch(
                    cfg,
                    cancel=self.cancel_event,
                    log=self.thread_log,
                    oui=self.oui_db,
                )
            except ScanCancelled:
                self.queue.put(("log", f"Cancelled while scanning {cfg.host}"))
                break
            except Exception as exc:
                detail = str(exc) or exc.__class__.__name__
                transcript = getattr(exc, "transcript", "")
                if transcript:
                    self.save_raw_text(cfg.host, transcript)
                self.queue.put(("error", (cfg.host, detail)))
                self.queue.put(("log", f"ERROR {cfg.host}: {detail}"))
            else:
                self.save_raw_transcript(result)
                self.queue.put(("result", result))
                ok += 1
                self.queue.put(
                    ("log", f"{result.switch_name}: {len(result.rows)} interface(s) collected")
                )
            finally:
                self.queue.put(("tick", index))
        self.queue.put(("finish", ok))

    def thread_log(self, message: str) -> None:
        self.queue.put(("log", message))

    def save_raw_transcript(self, result) -> None:
        """Write the raw SSH output so a failed parse can be investigated."""
        self.save_raw_text(
            result.host, result.transcript, result.raw, result.switch_name
        )

    def save_raw_text(self, host: str, transcript: str,
                      raw: dict | None = None, switch_name: str = "") -> None:
        if not transcript:
            return
        safe = "".join(
            char if char.isalnum() or char in ".-_" else "_" for char in host
        )
        path = os.path.join(self.base_dir, f"raw_{safe}.txt")
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(f"Switch: {switch_name or '?'} ({host})\n")
                for command, body in (raw or {}).items():
                    handle.write(
                        f"\n===== {command} ({len(body)} chars) =====\n{body}\n"
                    )
                handle.write("\n===== FULL SSH TRANSCRIPT =====\n")
                handle.write(transcript)
        except OSError as exc:
            self.queue.put(("log", f"Could not save raw output: {exc}"))
        else:
            self.queue.put(("log", f"Raw switch output saved to {path}"))

    def poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "log":
                    self.append_log(payload)
                elif kind == "status":
                    self.status_var.set(payload)
                elif kind == "result":
                    self.ingest_scan_result(payload)
                elif kind == "rows":
                    self.all_rows.extend(payload)
                    self.refresh_rows()
                elif kind == "error":
                    self.errors.append(payload)
                elif kind == "tick":
                    self.progress.configure(value=payload)
                elif kind == "cameras":
                    self.discovered_cameras = list(payload)
                    self.cameras = list(payload)
                elif kind == "hosts":
                    self.discovered_hosts = list(payload)
                    self.hosts = list(payload)
                elif kind in ("cam_progress", "host_progress"):
                    done, total = payload
                    self.progress.configure(maximum=max(1, total), value=done)
                elif kind == "camera_error":
                    self.camera_errors.append(payload)
                elif kind == "host_error":
                    self.host_errors.append(payload)
                elif kind == "cam_done":
                    self.finish_camera_scan(payload)
                elif kind == "host_done":
                    self.finish_host_scan(payload)
                elif kind == "finish":
                    self.finish_scan(payload)
        except queue.Empty:
            pass
        if self.scanning:
            self.after(120, self.poll_queue)

    def finish_scan(self, ok: int) -> None:
        self.scanning = False
        self._set_scan_state(False)
        message = (
            f"Scan finished: {ok} switch(es) OK, {len(self.errors)} failed, "
            f"{len(self.all_rows)} interface row(s)."
        )
        self.status_var.set(message)
        self.append_log(message)
        for host, detail in self.errors:
            self.append_log(f"FAILED {host}: {detail}")

        if self.all_rows:
            self.rebuild_camera_match()
            if self.discovered_hosts:
                self.rebuild_host_match()

        if self.errors and ok == 0:
            detail = "\n\n".join(f"{host}:\n{msg}" for host, msg in self.errors)
            messagebox.showerror(
                APP_TITLE,
                "The scan failed for every switch:\n\n" + detail[:2500],
            )
        elif ok and not self.all_rows:
            messagebox.showwarning(
                APP_TITLE,
                "The SSH connection worked, but no interfaces were recognised.\n\n"
                "The raw switch output was saved next to the program as "
                "raw_<switch-ip>.txt - please send me that file.\n\n"
                "Most common causes:\n"
                "  - the switch asked '--More--' because paging was not disabled\n"
                "    (set the 'Enable secret' field so 'terminal length 0' works)\n"
                "  - the switch CLI or prompt format is not the usual IOS one\n\n"
                "You can also run this in the program folder:\n"
                "  python diagnose.py <switch-ip> <username>",
            )

    def stop_scan(self) -> None:
        if self.scanning:
            self.cancel_event.set()
            self.status_var.set("Stopping...")

    def _set_scan_state(self, running: bool) -> None:
        state = "disabled" if running else "normal"
        for button in (
            self.btn_add, self.btn_edit, self.btn_remove,
            self.btn_scan_sel, self.btn_scan_all,
            self.btn_cam_scan, self.btn_cam_match, self.btn_cam_export,
            self.btn_host_scan, self.btn_host_match, self.btn_host_export,
        ):
            button.configure(state=state)
        self.btn_stop.configure(state="normal" if running else "disabled")

    # ------------------------------------------------------------- cameras
    def ingest_scan_result(self, result) -> None:
        """Store rows and the MAC index of one scanned switch."""
        self.all_rows.extend(result.rows)
        self.refresh_rows()
        key = getattr(result, "host", "") or getattr(result, "switch_name", "")
        self.mac_ports_by_switch[key] = getattr(result, "mac_ports", {}) or {}
        self.ip_mac_by_switch[key] = getattr(result, "ip_to_mac", {}) or {}
        self.rebuild_camera_match()
        if self.discovered_hosts:
            self.rebuild_host_match()

    def combined_mac_ports(self) -> dict:
        merged: dict = {}
        for table in self.mac_ports_by_switch.values():
            for mac, entries in table.items():
                merged.setdefault(mac, []).extend(entries)
        return merged

    def combined_ip_mac(self) -> dict:
        merged: dict = {}
        for table in self.ip_mac_by_switch.values():
            merged.update(table)
        merged.update(self.manual_ip_mac)
        return merged

    def rebuild_camera_match(self) -> None:
        switch_cameras = cameras_from_switch_rows(self.all_rows, self.oui_db)
        self.cameras = merge_cameras(self.discovered_cameras, switch_cameras)
        self.camera_rows = match_cameras(
            self.cameras,
            self.combined_mac_ports(),
            self.combined_ip_mac(),
            build_ip_port_index(self.all_rows),
        )
        self.refresh_camera_rows()

    def camera_targets_value(self) -> str:
        """Current contents of the multi-line range box."""
        return self.cam_targets_text.get("1.0", "end")

    def update_camera_target_count(self, event=None) -> None:
        """Show how many addresses the current range text expands to."""
        try:
            ranges = parse_targets(self.camera_targets_value())
            total = target_count(ranges)
        except ValueError:
            self.cam_count_var.set("Invalid range")
            return
        if total <= 0:
            self.cam_count_var.set("No address")
            return
        count = len(ranges)
        label = "range" if count == 1 else "ranges"
        self.cam_count_var.set(f"{total} address(es) in {count} {label}")

    def load_arp_table(self) -> None:
        """Import an ARP table from the L3 device (FortiGate/Cisco/etc.)."""
        path = filedialog.askopenfilename(
            title="Load ARP table",
            filetypes=[
                ("Text / log / CSV", "*.txt *.log *.csv"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                text = handle.read()
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not read the file:\n\n{exc}")
            return
        table = parse_arp_table(text)
        if not table:
            messagebox.showerror(
                APP_TITLE,
                "No IP/MAC pairs were found in this file.\n\n"
                "Expected lines with an IPv4 address and a MAC address, e.g.\n"
                "172.16.12.10  5  3c:ef:8c:11:22:33  VLAN12",
            )
            return
        self.manual_ip_mac.update(table)
        self.rebuild_camera_match()
        if self.discovered_hosts:
            self.rebuild_host_match()
        name = os.path.basename(path)
        self.append_log(f"Loaded {len(table)} ARP entr(ies) from {name}")
        self.camera_status_var.set(
            f"Loaded {len(table)} ARP entries from {name}. "
            "Existing cameras were re-matched; press 'Match only' to refresh."
        )

    def start_camera_scan(self) -> None:
        if self.scanning:
            return
        try:
            ranges = parse_targets(self.camera_targets_value())
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        total = target_count(ranges)
        if total == 0:
            messagebox.showerror(APP_TITLE, "The range contains no usable IPv4 address.")
            return
        if total > 2048 and not messagebox.askyesno(
            APP_TITLE,
            f"This will probe {total} addresses. It can take several minutes "
            "and may be noticed by network monitoring.\n\nContinue?",
        ):
            return

        switch_targets: list[SwitchConfig] = []
        if self.cam_rescan_var.get() and self.switches:
            switch_targets = list(self.selected_switches()) or list(self.switches)
        if switch_targets and not self.ensure_ssh():
            return

        self.scanning = True
        self.cancel_event = threading.Event()
        self.errors = []
        self.camera_errors = []
        self._set_scan_state(True)

        if switch_targets:
            self.all_rows = []
            self.mac_ports_by_switch.clear()
            self.ip_mac_by_switch.clear()
            self.refresh_rows()
        self.discovered_cameras = []
        self.cameras = []
        self.camera_rows = []
        self.refresh_camera_rows()

        self.progress.configure(maximum=max(1, total), value=0)
        self.status_var.set(f"Discovering cameras in {total} address(es)...")
        self.camera_status_var.set(
            f"Scanning {total} address(es)"
            + (f" and {len(switch_targets)} switch(es)..." if switch_targets else "...")
        )
        self.append_log(
            f"Camera discovery started: {total} address(es), "
            f"{len(switch_targets)} switch(es) to scan"
        )

        include_all = bool(self.cam_all_var.get())
        worker = threading.Thread(
            target=self._camera_worker,
            args=(ranges, switch_targets, include_all),
            daemon=True,
        )
        worker.start()
        self.after(120, self.poll_queue)

    def _camera_worker(self, ranges, switch_targets: list[SwitchConfig],
                       include_all: bool) -> None:
        try:
            cameras = discover_cameras(
                ranges,
                cancel=self.cancel_event,
                log=self.thread_log,
                progress=lambda done, total: self.queue.put(
                    ("cam_progress", (done, total))
                ),
                oui=self.oui_db,
                include_all=include_all,
            )
        except CameraCancelled:
            self.queue.put(("log", "Camera discovery cancelled"))
            self.queue.put(("cam_done", {"cancelled": True}))
            return
        except Exception as exc:
            detail = str(exc) or exc.__class__.__name__
            self.queue.put(("camera_error", ("camera discovery", detail)))
            self.queue.put(("log", f"ERROR camera discovery: {detail}"))
            self.queue.put(("cam_done", {"error": detail}))
            return

        self.queue.put(("cameras", cameras))
        self.queue.put(
            ("status", f"{len(cameras)} camera row(s); scanning switches...")
        )

        ok = 0
        for index, cfg in enumerate(switch_targets, start=1):
            if self.cancel_event.is_set():
                self.queue.put(("log", "Switch scan cancelled"))
                break
            self.queue.put(
                ("status", f"Scanning switch {cfg.host} ({index}/{len(switch_targets)})...")
            )
            self.queue.put(("cam_progress", (0, len(switch_targets))))
            try:
                result = scan_switch(
                    cfg,
                    cancel=self.cancel_event,
                    log=self.thread_log,
                    oui=self.oui_db,
                )
            except ScanCancelled:
                self.queue.put(("log", f"Cancelled while scanning {cfg.host}"))
                break
            except Exception as exc:
                detail = str(exc) or exc.__class__.__name__
                transcript = getattr(exc, "transcript", "")
                if transcript:
                    self.save_raw_text(cfg.host, transcript)
                self.queue.put(("error", (cfg.host, detail)))
                self.queue.put(("log", f"ERROR {cfg.host}: {detail}"))
            else:
                self.save_raw_transcript(result)
                self.queue.put(("result", result))
                ok += 1
                self.queue.put(
                    ("log", f"{result.switch_name}: {len(result.rows)} interface(s) collected")
                )
            finally:
                self.queue.put(("cam_progress", (index, len(switch_targets))))

        self.queue.put(
            (
                "cam_done",
                {
                    "cameras": len(cameras),
                    "switches_ok": ok,
                    "switch_total": len(switch_targets),
                },
            )
        )

    def finish_camera_scan(self, info: dict) -> None:
        self.scanning = False
        self._set_scan_state(False)
        if info.get("cancelled"):
            self.status_var.set("Camera discovery cancelled")
            self.camera_status_var.set("Cancelled.")
            return
        if info.get("error"):
            self.status_var.set("Camera discovery failed")
            self.camera_status_var.set("Failed: " + info["error"])
            self.progress.configure(value=0)
            messagebox.showerror(
                APP_TITLE, "Camera discovery failed:\n\n" + info["error"][:1500]
            )
            return

        self.rebuild_camera_match()
        counts = summarize(self.camera_rows)
        camera_count = sum(1 for camera in self.cameras if camera.is_camera)
        summary = (
            f"{camera_count} camera-like device(s), "
            f"{counts['matched']} mapped to a switch port"
        )
        if counts["unknown_mac"]:
            summary += f", {counts['unknown_mac']} with unknown MAC"
        if counts["missing"]:
            summary += f", {counts['missing']} not found on scanned switches"
        if counts["candidates"]:
            summary += f", {counts['candidates']} with candidate ports"
        if counts["unknown"]:
            summary += f", {counts['unknown']} unknown"
        self.camera_status_var.set(summary)
        self.status_var.set("Camera scan finished: " + summary)
        self.append_log("Camera scan finished: " + summary)
        for host, detail in self.camera_errors:
            self.append_log(f"CAMERA FAILED {host}: {detail}")
        for host, detail in self.errors:
            self.append_log(f"SWITCH FAILED {host}: {detail}")

        if counts["unknown_mac"]:
            self.append_log(
                "Tip: a camera without a MAC is behind a router. Run the scan "
                "from a PC in the camera VLAN, or scan an L3 switch so its ARP "
                "table can supply the MAC address."
            )
        if counts["unknown_mac"] and counts["matched"] == 0:
            messagebox.showwarning(
                APP_TITLE,
                "The cameras were found, but their MAC addresses could not be "
                "resolved, so no switch port could be identified.\n\n"
                "ARP only works inside the subnet of this PC. Run the scanner "
                "from a PC/port in the camera VLAN, or use a switch with an L3 "
                "interface (SVI) so its ARP table maps the camera IP to a MAC.\n\n"
                "Details are in the Cameras tab and the Log tab.",
            )

    def match_only(self) -> None:
        if not self.discovered_cameras:
            messagebox.showinfo(
                APP_TITLE,
                "No cameras discovered yet. Press 'Discover cameras' first.",
            )
            return
        if not self.mac_ports_by_switch:
            messagebox.showinfo(
                APP_TITLE,
                "No switch MAC tables are loaded yet.\n\n"
                "Scan the switches (Ports tab) first, or tick "
                "'Re-scan switches before matching' and run the camera scan.",
            )
            return
        self.rebuild_camera_match()
        counts = summarize(self.camera_rows)
        self.camera_status_var.set(
            f"{counts['total']} camera row(s), {counts['matched']} mapped to a switch port"
        )

    def visible_camera_rows(self) -> list[dict]:
        """Rows that pass the search box, the status filter and local-only."""
        needle = self.cam_filter_var.get().strip()
        local_only = bool(self.local_only_var.get())
        status = self.cam_status_filter_var.get()
        rows = []
        for row in self.camera_rows:
            if local_only and not row.get("local"):
                continue
            if status != "All" and row.get("port_status_label") != status:
                continue
            if not _row_matches_search(row, needle, CAM_COLUMNS):
                continue
            rows.append(row)
        return rows

    def refresh_camera_rows(self) -> None:
        self.tree_cameras.delete(*self.tree_cameras.get_children())
        self.cam_row_by_iid.clear()
        rows = self.visible_camera_rows()

        for index, row in enumerate(rows):
            tags = ["stripe"] if index % 2 else []
            status = row.get("port_status")
            if row.get("confidence") == "Switch side":
                tags.append("switchside")
            elif status in ("confirmed", "probable"):
                tags.append("matched")
            elif status == "candidates":
                tags.append("candidate")
            else:
                tags.append("unknown")
            iid = str(index)
            self.cam_row_by_iid[iid] = row
            self.tree_cameras.insert(
                "",
                "end",
                iid=iid,
                values=[row.get(key, "") for key, _, _ in CAM_COLUMNS],
                tags=tuple(tags),
            )
        filtered = (
            self.cam_filter_var.get().strip()
            or self.local_only_var.get()
            or self.cam_status_filter_var.get() != "All"
        )
        if filtered:
            suffix = " (only devices on this switch)" if self.local_only_var.get() else ""
            self.camera_status_var.set(
                f"{len(rows)} shown / {len(self.camera_rows)} camera row(s){suffix}"
            )

    def _copy_row(self, tree, mapping, columns) -> str:
        selected = tree.selection()
        if not selected:
            return "break"
        row = mapping.get(selected[0])
        if row:
            self.clipboard_clear()
            self.clipboard_append(
                "\t".join(str(row.get(key, "")) for key, _, _ in columns)
            )
        return "break"

    def _detail_window(self, title: str, body: str) -> None:
        """Open a themed read-only window with monospaced detail text."""
        window = tk.Toplevel(self)
        window.title(title)
        window.geometry("720x560")
        window.minsize(480, 320)
        window.configure(background=COLOR_BG)
        window.transient(self)

        header = tk.Frame(window, background=COLOR_HEADER, padx=14, pady=10)
        header.pack(fill="x")
        tk.Label(
            header,
            text=title,
            background=COLOR_HEADER,
            foreground="#ffffff",
            font=(FONT, 11, "bold"),
        ).pack(anchor="w")

        wrap = ttk.Frame(window, padding=10)
        wrap.pack(fill="both", expand=True)
        text = tk.Text(
            wrap,
            wrap="word",
            background="#ffffff",
            foreground=COLOR_TEXT,
            relief="flat",
            font=(MONO_FONT, 9),
            padx=10,
            pady=8,
            highlightthickness=1,
            highlightbackground=COLOR_BORDER,
        )
        scroll = ttk.Scrollbar(wrap, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        text.insert("1.0", body)
        text.configure(state="disabled")
        window.bind("<Escape>", lambda event: window.destroy())

    def _show_detail(self, tree, mapping) -> None:
        selected = tree.selection()
        if not selected:
            return
        row = mapping.get(selected[0])
        if not row:
            return
        self._detail_window(
            f"{row.get('ip', '')} - {row.get('model', '')}",
            row.get("_detail", ""),
        )

    def copy_camera_selected(self, event=None) -> str:
        return self._copy_row(self.tree_cameras, self.cam_row_by_iid, CAM_COLUMNS)

    def show_camera_detail(self, event=None) -> None:
        self._show_detail(self.tree_cameras, self.cam_row_by_iid)

    def copy_host_selected(self, event=None) -> str:
        return self._copy_row(self.tree_hosts, self.host_row_by_iid, HOST_COLUMNS)

    def show_host_detail(self, event=None) -> None:
        self._show_detail(self.tree_hosts, self.host_row_by_iid)

    def _export_excel(self, rows, columns, title: str,
                      initialfile: str, sheet_name: str) -> None:
        """Write one table to an .xlsx workbook with the visible columns."""
        if not rows:
            messagebox.showinfo(
                APP_TITLE,
                "There are no rows to export with the current filter.",
            )
            return
        path = filedialog.asksaveasfilename(
            title=title,
            defaultextension=".xlsx",
            initialfile=initialfile,
            filetypes=[("Excel workbook", "*.xlsx"), ("All files", "*.*")],
        )
        if not path:
            return
        headers = [column_title for _, column_title, _ in columns]
        values = [
            [row.get(key, "") for key, _, _ in columns]
            for row in rows
        ]
        try:
            write_xlsx(path, [(sheet_name, headers, values)])
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Could not write {path}:\n{exc}")
            return
        messagebox.showinfo(
            APP_TITLE, f"Exported {len(rows)} row(s) to:\n{path}"
        )

    def export_cameras(self) -> None:
        rows = self.visible_camera_rows()
        if not rows:
            messagebox.showinfo(
                APP_TITLE,
                "There are no camera rows to export with the current filter.",
            )
            return
        path = filedialog.asksaveasfilename(
            title="Export camera map",
            defaultextension=".csv",
            initialfile="camera_map.csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle)
                writer.writerow([title for _, title, _ in CAM_COLUMNS])
                for row in rows:
                    writer.writerow([row.get(key, "") for key, _, _ in CAM_COLUMNS])
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not write {path}:\n{exc}")
            return
        messagebox.showinfo(
            APP_TITLE, f"Exported {len(rows)} camera row(s) to:\n{path}"
        )

    def export_cameras_excel(self) -> None:
        self._export_excel(
            self.visible_camera_rows(),
            CAM_COLUMNS,
            "Export camera map (Excel)",
            "camera_map.xlsx",
            "Cameras",
        )

    # ---------------------------------------------------------- PCs / hosts
    def rebuild_host_match(self) -> None:
        """Match every discovered host MAC to the switch MAC tables."""
        switch_names = names_from_switch_rows(self.all_rows)
        for host in self.discovered_hosts:
            if not host.hostname and host.ip in switch_names:
                host.hostname = switch_names[host.ip]
                note = "name from switch CDP/LLDP"
                if note not in host.evidence:
                    host.evidence.append(note)
        self.hosts = list(self.discovered_hosts)
        self.host_rows = match_hosts(
            self.hosts,
            self.combined_mac_ports(),
            self.combined_ip_mac(),
            build_ip_port_index(self.all_rows),
        )
        self.refresh_host_rows()

    def host_targets_value(self) -> str:
        """Current contents of the host range box."""
        return self.host_targets_text.get("1.0", "end")

    def update_host_target_count(self, event=None) -> None:
        """Show how many addresses the host range text expands to."""
        try:
            ranges = parse_targets(self.host_targets_value())
            total = target_count(ranges)
        except ValueError:
            self.host_count_var.set("Invalid range")
            return
        if total <= 0:
            self.host_count_var.set("No address")
            return
        count = len(ranges)
        label = "range" if count == 1 else "ranges"
        self.host_count_var.set(f"{total} address(es) in {count} {label}")

    def start_host_scan(self) -> None:
        if self.scanning:
            return
        try:
            ranges = parse_targets(self.host_targets_value())
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        total = target_count(ranges)
        if total == 0:
            messagebox.showerror(APP_TITLE, "The range contains no usable IPv4 address.")
            return
        if total > 2048 and not messagebox.askyesno(
            APP_TITLE,
            f"This will check {total} addresses. It can take several minutes "
            "and may be noticed by network monitoring.\n\nContinue?",
        ):
            return

        switch_targets: list[SwitchConfig] = []
        if self.host_rescan_var.get() and self.switches:
            switch_targets = list(self.selected_switches()) or list(self.switches)
        if switch_targets and not self.ensure_ssh():
            return

        self.scanning = True
        self.cancel_event = threading.Event()
        self.errors = []
        self.host_errors = []
        self._set_scan_state(True)

        if switch_targets:
            self.all_rows = []
            self.mac_ports_by_switch.clear()
            self.ip_mac_by_switch.clear()
            self.refresh_rows()
        self.discovered_hosts = []
        self.hosts = []
        self.host_rows = []
        self.refresh_host_rows()

        self.progress.configure(maximum=max(1, total), value=0)
        self.status_var.set(f"Discovering hosts in {total} address(es)...")
        self.host_status_var.set(
            f"Scanning {total} address(es)"
            + (f" and {len(switch_targets)} switch(es)..." if switch_targets else "...")
        )
        self.append_log(
            f"Host discovery started: {total} address(es), "
            f"{len(switch_targets)} switch(es) to scan"
        )

        worker = threading.Thread(
            target=self._host_worker,
            args=(
                ranges,
                switch_targets,
                not self.host_pc_only_var.get(),
                bool(self.host_names_var.get()),
            ),
            daemon=True,
        )
        worker.start()
        self.after(120, self.poll_queue)

    def _host_worker(self, ranges, switch_targets: list[SwitchConfig],
                     include_all: bool, resolve_names: bool) -> None:
        try:
            hosts = discover_hosts(
                ranges,
                cancel=self.cancel_event,
                log=self.thread_log,
                progress=lambda done, total: self.queue.put(
                    ("host_progress", (done, total))
                ),
                oui=self.oui_db,
                include_all=include_all,
                resolve_names=resolve_names,
            )
        except HostCancelled:
            self.queue.put(("log", "Host discovery cancelled"))
            self.queue.put(("host_done", {"cancelled": True}))
            return
        except Exception as exc:
            detail = str(exc) or exc.__class__.__name__
            self.queue.put(("host_error", ("host discovery", detail)))
            self.queue.put(("log", f"ERROR host discovery: {detail}"))
            self.queue.put(("host_done", {"error": detail}))
            return

        self.queue.put(("hosts", hosts))
        self.queue.put(("status", f"{len(hosts)} host row(s); scanning switches..."))

        ok = 0
        for index, cfg in enumerate(switch_targets, start=1):
            if self.cancel_event.is_set():
                self.queue.put(("log", "Switch scan cancelled"))
                break
            self.queue.put(
                ("status", f"Scanning switch {cfg.host} ({index}/{len(switch_targets)})...")
            )
            self.queue.put(("host_progress", (0, len(switch_targets))))
            try:
                result = scan_switch(
                    cfg,
                    cancel=self.cancel_event,
                    log=self.thread_log,
                    oui=self.oui_db,
                )
            except ScanCancelled:
                self.queue.put(("log", f"Cancelled while scanning {cfg.host}"))
                break
            except Exception as exc:
                detail = str(exc) or exc.__class__.__name__
                transcript = getattr(exc, "transcript", "")
                if transcript:
                    self.save_raw_text(cfg.host, transcript)
                self.queue.put(("error", (cfg.host, detail)))
                self.queue.put(("log", f"ERROR {cfg.host}: {detail}"))
            else:
                self.save_raw_transcript(result)
                self.queue.put(("result", result))
                ok += 1
                self.queue.put(
                    ("log", f"{result.switch_name}: {len(result.rows)} interface(s) collected")
                )
            finally:
                self.queue.put(("host_progress", (index, len(switch_targets))))

        self.queue.put(
            (
                "host_done",
                {
                    "hosts": len(hosts),
                    "switches_ok": ok,
                    "switch_total": len(switch_targets),
                },
            )
        )

    def finish_host_scan(self, info: dict) -> None:
        self.scanning = False
        self._set_scan_state(False)
        if info.get("cancelled"):
            self.status_var.set("Host discovery cancelled")
            self.host_status_var.set("Cancelled.")
            return
        if info.get("error"):
            self.status_var.set("Host discovery failed")
            self.host_status_var.set("Failed: " + info["error"])
            self.progress.configure(value=0)
            messagebox.showerror(
                APP_TITLE, "Host discovery failed:\n\n" + info["error"][:1500]
            )
            return

        self.rebuild_host_match()
        counts = summarize(self.host_rows)
        computer_count = sum(1 for host in self.hosts if host.is_pc)
        summary = (
            f"{computer_count} computer(s), "
            f"{counts['matched']} mapped to a switch port"
        )
        if counts["unknown_mac"]:
            summary += f", {counts['unknown_mac']} with unknown MAC"
        if counts["missing"]:
            summary += f", {counts['missing']} not found on scanned switches"
        if counts["candidates"]:
            summary += f", {counts['candidates']} with candidate ports"
        if counts["unknown"]:
            summary += f", {counts['unknown']} unknown"
        self.host_status_var.set(summary)
        self.status_var.set("Host scan finished: " + summary)
        self.append_log("Host scan finished: " + summary)
        for host, detail in self.host_errors:
            self.append_log(f"HOST FAILED {host}: {detail}")
        for host, detail in self.errors:
            self.append_log(f"SWITCH FAILED {host}: {detail}")

        if counts["unknown_mac"]:
            self.append_log(
                "Tip: a host without a MAC is behind a router. Load the ARP "
                "table of the L3 device with 'Load ARP table...' or scan from "
                "a PC inside that VLAN."
            )
        if counts["unknown_mac"] and counts["matched"] == 0:
            messagebox.showwarning(
                APP_TITLE,
                "The hosts were found, but their MAC addresses could not be "
                "resolved, so no switch port could be identified.\n\n"
                "ARP only works inside the subnet of this PC. Load the FortiGate "
                "ARP table with 'Load ARP table...', run the scanner from a PC "
                "inside that VLAN, or scan an L3 switch.\n\n"
                "Details are in the PCs / Hosts tab and the Log tab.",
            )

    def match_hosts_only(self) -> None:
        if not self.discovered_hosts:
            messagebox.showinfo(
                APP_TITLE,
                "No hosts discovered yet. Press 'Discover hosts' first.",
            )
            return
        if not self.mac_ports_by_switch:
            messagebox.showinfo(
                APP_TITLE,
                "No switch MAC tables are loaded yet.\n\n"
                "Scan the switches (Ports tab) first, or tick "
                "'Re-scan switches before matching' and run the host scan.",
            )
            return
        self.rebuild_host_match()
        counts = summarize(self.host_rows)
        self.host_status_var.set(
            f"{counts['total']} host row(s), {counts['matched']} mapped to a switch port"
        )

    def visible_host_rows(self) -> list[dict]:
        """Rows that pass the search box, the status filter and local-only."""
        needle = self.host_filter_var.get().strip()
        local_only = bool(self.local_only_var.get())
        status = self.host_status_filter_var.get()
        rows = []
        for row in self.host_rows:
            if local_only and not row.get("local"):
                continue
            if status != "All" and row.get("port_status_label") != status:
                continue
            if not _row_matches_search(row, needle, HOST_COLUMNS):
                continue
            rows.append(row)
        return rows

    def refresh_host_rows(self) -> None:
        self.tree_hosts.delete(*self.tree_hosts.get_children())
        self.host_row_by_iid.clear()
        rows = self.visible_host_rows()

        for index, row in enumerate(rows):
            tags = ["stripe"] if index % 2 else []
            status = row.get("port_status")
            if status in ("confirmed", "probable"):
                tags.append("matched")
            elif status == "candidates":
                tags.append("candidate")
            else:
                tags.append("unknown")
            iid = str(index)
            self.host_row_by_iid[iid] = row
            self.tree_hosts.insert(
                "",
                "end",
                iid=iid,
                values=[row.get(key, "") for key, _, _ in HOST_COLUMNS],
                tags=tuple(tags),
            )
        filtered = (
            self.host_filter_var.get().strip()
            or self.local_only_var.get()
            or self.host_status_filter_var.get() != "All"
        )
        if filtered:
            suffix = " (only devices on this switch)" if self.local_only_var.get() else ""
            self.host_status_var.set(
                f"{len(rows)} shown / {len(self.host_rows)} host row(s){suffix}"
            )

    def export_hosts(self) -> None:
        rows = self.visible_host_rows()
        if not rows:
            messagebox.showinfo(
                APP_TITLE,
                "There are no host rows to export with the current filter.",
            )
            return
        path = filedialog.asksaveasfilename(
            title="Export PC / host map",
            defaultextension=".csv",
            initialfile="pc_map.csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle)
                writer.writerow([title for _, title, _ in HOST_COLUMNS])
                for row in rows:
                    writer.writerow([row.get(key, "") for key, _, _ in HOST_COLUMNS])
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not write {path}:\n{exc}")
            return
        messagebox.showinfo(
            APP_TITLE, f"Exported {len(rows)} host row(s) to:\n{path}"
        )

    def export_hosts_excel(self) -> None:
        self._export_excel(
            self.visible_host_rows(),
            HOST_COLUMNS,
            "Export PC / host map (Excel)",
            "pc_map.xlsx",
            "PCs",
        )

    # ------------------------------------------------------------- results
    def refresh_rows(self) -> None:
        self.tree_ports.delete(*self.tree_ports.get_children())
        self.row_by_iid.clear()

        needle = self.filter_var.get().strip()
        show_down = self.show_down_var.get()

        rows = []
        for row in self.all_rows:
            if not show_down and row.get("_idle"):
                continue
            if not _row_matches_search(row, needle, COLUMNS):
                continue
            rows.append(row)

        if self.sort_key:
            rows.sort(
                key=lambda item: str(item.get(self.sort_key, "")).lower(),
                reverse=self.sort_reverse,
            )

        for key, title, _width in COLUMNS:
            if key == self.sort_key:
                title += " \u25B2" if not self.sort_reverse else " \u25BC"
            self.tree_ports.heading(key, text=title)

        for index, row in enumerate(rows):
            tags = ["stripe"] if index % 2 else []
            if row.get("_idle"):
                tags.append("idle")
            else:
                source = row.get("source")
                if source in ("CDP", "LLDP"):
                    tags.append("neighbor")
                elif source == "MAC":
                    tags.append("guess")
            iid = str(index)
            self.row_by_iid[iid] = row
            self.tree_ports.insert(
                "", "end", iid=iid,
                values=[row.get(key, "") for key, _, _ in COLUMNS],
                tags=tuple(tags),
            )

        self.count_var.set(
            f"{len(rows)} shown / {len(self.all_rows)} ports"
            if needle or not show_down
            else f"{len(self.all_rows)} ports"
        )

    def sort_rows(self, key: str) -> None:
        if self.sort_key == key:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_key = key
            self.sort_reverse = False
        self.refresh_rows()

    def copy_selected(self, event=None) -> str:
        selected = self.tree_ports.selection()
        if not selected:
            return "break"
        row = self.row_by_iid.get(selected[0])
        if row:
            self.clipboard_clear()
            self.clipboard_append("\t".join(str(row.get(key, "")) for key, _, _ in COLUMNS))
        return "break"

    def show_detail(self, event=None) -> None:
        selected = self.tree_ports.selection()
        if not selected:
            return
        row = self.row_by_iid.get(selected[0])
        if not row:
            return
        self._detail_window(
            f"{row.get('switch')} - {row.get('interface')}",
            row.get("_detail", ""),
        )

    def export_csv(self) -> None:
        selected_ids = self.tree_ports.get_children()
        rows = [self.row_by_iid[iid] for iid in selected_ids if iid in self.row_by_iid]
        if not rows:
            messagebox.showinfo(APP_TITLE, "There is nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Export port map",
            defaultextension=".csv",
            initialfile="port_map.csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle)
                writer.writerow([title for _, title, _ in COLUMNS])
                for row in rows:
                    writer.writerow([row.get(key, "") for key, _, _ in COLUMNS])
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not write {path}:\n{exc}")
            return
        messagebox.showinfo(APP_TITLE, f"Exported {len(rows)} row(s) to:\n{path}")

    def export_ports_excel(self) -> None:
        visible_ids = self.tree_ports.get_children()
        rows = [
            self.row_by_iid[iid]
            for iid in visible_ids
            if iid in self.row_by_iid
        ]
        self._export_excel(
            rows,
            COLUMNS,
            "Export port map (Excel)",
            "port_map.xlsx",
            "Ports",
        )

    # ---------------------------------------------------------------- misc
    def append_log(self, message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{stamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as handle:
                    handle.write(f"[{stamp}] {message}\n")
            except OSError:
                self.log_path = ""

    def on_close(self) -> None:
        if self.scanning:
            self.cancel_event.set()
        self.destroy()


def main() -> None:
    enable_dpi_awareness()
    if IMPORT_ERROR is not None:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            APP_TITLE,
            "A required program file is missing or broken.\n\n"
            "Keep app.py, cisco.py, oui.py, sshexec.py and prereq.py in the "
            "same folder.\n\n"
            f"Details: {IMPORT_ERROR}",
        )
        root.destroy()
        return
    App().mainloop()


if __name__ == "__main__":
    main()
