from __future__ import annotations

import configparser
import ctypes
import os
import re
import shutil
import subprocess
import sys
import threading
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from tkinter import messagebox
import tkinter as tk
from tkinter import ttk
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

APP_TITLE = "R6Fixer"
DEFAULT_REFRESH_RATE = 144
CLOUDFLARE_DNS_IPV4 = ("1.1.1.1", "1.0.0.1")
CLOUDFLARE_DNS_IPV6 = ("2606:4700:4700::1111", "2606:4700:4700::1001")
ID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
EMBEDDED_GAMESETTINGS_TEMPLATE = """
[DISPLAY]
FPSLimit=(Active Monitor Refresh Rate - 2)
NVReflex=2
NVReflexIndicator=0

[DISPLAY_SETTINGS]
VSync=0
MaxGPUBufferedFrame=1

[QUALITY]
OverallQualityLevelName=Custom

[CUSTOM_QUALITY]
AntiAliasing=2
Atmospheric=-1
Geometry=5
Lighting=0
Shadow=1
Sharpness=10
Texture=0
VFX=0
TextureFiltering=4
Reflection=0
AO=1
LensEffects=0
DOF=0
AdaptiveRenderScalingTargetFPS=(Active Monitor Refresh Rate / 5)
RenderScalingFactor=15
DLSSPerfQual=0
FSR2PerfQual=0
FSRPerfQual=0
TextureStreaming=0
TextureVRAMLimit=5
TemporalUpscalerMode=0
Upscaler=0
""".strip()


@dataclass(frozen=True)
class IdSourceSpec:
    label: str
    path: Path
    kind: str  # "dir" or "file"
    trim_prefix: str = ""


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    try:
        if getattr(sys, "frozen", False):
            params = subprocess.list2cmdline(sys.argv[1:])
        else:
            script_path = str(Path(sys.argv[0]).resolve())
            params = subprocess.list2cmdline([script_path, *sys.argv[1:]])

        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            None,
            1,
        )
        return result > 32
    except Exception:
        return False


def ensure_admin_or_relaunch() -> bool:
    if is_admin():
        return True

    if relaunch_as_admin():
        return False

    try:
        ctypes.windll.user32.MessageBoxW(
            0,
            "R6Fixer requires Administrator privileges. Please relaunch as Administrator.",
            APP_TITLE,
            0x10,
        )
    except Exception:
        pass

    return False


def get_active_network_adapters() -> list[dict[str, str]]:
    script = (
        "$adapters = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true -and "
        "$_.InterfaceDescription -notmatch 'Hyper-V|VMware|VirtualBox|Loopback|Bluetooth|TAP|TUN|VPN|Npcap' }; "
        "if (-not $adapters) { "
        "$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Status -eq 'Up' -and ($_.Name -match 'Wi[- ]?Fi|Ethernet') } "
        "}; "
        "$adapters | ForEach-Object { \"$($_.Name)|$($_.NdisPhysicalMedium)\" }"
    )

    ok, output = run_command(["powershell", "-NoProfile", "-Command", script], timeout=35)
    if not ok:
        return []

    adapters: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in output.splitlines():
        row = line.strip()
        if not row:
            continue
        if row.lower().startswith(("name", "----")):
            continue

        if "|" in row:
            name, medium = row.split("|", 1)
        else:
            name, medium = row, "Unknown"

        name = name.strip()
        medium = medium.strip() or "Unknown"
        if name in seen:
            continue

        seen.add(name)
        adapters.append({"alias": name, "medium": medium})

    return adapters


def get_adapter_metric(mode: str, medium: str, alias: str) -> int:
    signal = f"{medium} {alias}".lower()
    is_wifi = any(marker in signal for marker in ("802_11", "wireless", "wi-fi", "wifi", "wlan"))

    if mode == "throughput":
        return 25 if is_wifi else 15
    return 20 if is_wifi else 10


def apply_adapter_network_settings(
    adapters: list[dict[str, str]],
    mode: str,
) -> tuple[int, int, list[str]]:
    success = 0
    total = 0
    logs: list[str] = []

    for adapter in adapters:
        alias = adapter["alias"]
        medium = adapter.get("medium", "Unknown")
        metric = get_adapter_metric(mode, medium, alias)
        escaped_alias = alias.replace("'", "''")

        dns_script = (
            "$ErrorActionPreference='Stop';"
            f"$alias='{escaped_alias}';"
            "Set-DnsClientServerAddress "
            "-InterfaceAlias $alias "
            f"-ServerAddresses @('{CLOUDFLARE_DNS_IPV4[0]}','{CLOUDFLARE_DNS_IPV4[1]}') "
            "-AddressFamily IPv4;"
            "try { Set-DnsClientServerAddress -InterfaceAlias $alias -AddressFamily IPv6 "
            "-ServerAddresses @('"
            + CLOUDFLARE_DNS_IPV6[0]
            + "','"
            + CLOUDFLARE_DNS_IPV6[1]
            + "') -ErrorAction Stop } catch { }"
        )
        total += 1
        ok_dns, out_dns = run_command(
            ["powershell", "-NoProfile", "-Command", dns_script],
            timeout=35,
        )
        if ok_dns:
            success += 1
        else:
            logs.append(f"DNS command failed on {alias}")
        if out_dns:
            logs.append(out_dns)

        metric_script = (
            "$ErrorActionPreference='Stop';"
            f"$alias='{escaped_alias}';"
            f"$metric={metric};"
            "Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 "
            "-AutomaticMetric Disabled -InterfaceMetric $metric;"
            "try { Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv6 "
            "-AutomaticMetric Disabled -InterfaceMetric $metric -ErrorAction Stop } catch { };"
            "try { Set-DnsClient -InterfaceAlias $alias -RegisterThisConnectionsAddress $true "
            "-UseSuffixWhenRegistering $false -ErrorAction Stop } catch { }"
        )
        total += 1
        ok_metric, out_metric = run_command(
            ["powershell", "-NoProfile", "-Command", metric_script],
            timeout=40,
        )
        if ok_metric:
            success += 1
        else:
            logs.append(f"Metric/registration command failed on {alias}")
        if out_metric:
            logs.append(out_metric)

        power_script = (
            f"$alias='{escaped_alias}';"
            "if (Get-Command Disable-NetAdapterPowerManagement -ErrorAction SilentlyContinue) {"
            "  try { Disable-NetAdapterPowerManagement -Name $alias -NoRestart -ErrorAction Stop } catch { }"
            "}"
        )
        total += 1
        ok_power, out_power = run_command(
            ["powershell", "-NoProfile", "-Command", power_script],
            timeout=35,
        )
        if ok_power:
            success += 1
        else:
            logs.append(f"Power-management tuning failed on {alias}")
        if out_power:
            logs.append(out_power)

        if ok_dns:
            logs.append(
                f"{alias}: DNS {CLOUDFLARE_DNS_IPV4[0]}/{CLOUDFLARE_DNS_IPV4[1]}, metric {metric}"
            )

    flush_ok, flush_output = run_command(["ipconfig", "/flushdns"], timeout=20)
    if flush_output:
        logs.append(flush_output)
    if not flush_ok:
        logs.append("DNS cache flush failed")

    clear_ok, clear_output = run_command(
        ["powershell", "-NoProfile", "-Command", "Clear-DnsClientCache"],
        timeout=20,
    )
    total += 1
    if clear_ok:
        success += 1
    if clear_output:
        logs.append(clear_output)

    return success, total, logs


def get_source_specs() -> list[IdSourceSpec]:
    home = Path.home()
    local_app_data = Path(os.path.expandvars(r"%LOCALAPPDATA%"))

    return [
        IdSourceSpec(
            label="Documents profile folders",
            path=home / "Documents" / "My Games" / "Rainbow Six - Siege",
            kind="dir",
        ),
        IdSourceSpec(
            label="Ubisoft launcher spool",
            path=local_app_data / "Ubisoft Game Launcher" / "spool",
            kind="dir",
        ),
        IdSourceSpec(
            label="Ubisoft cache club",
            path=local_app_data / "Ubisoft Game Launcher" / "cache" / "club",
            kind="file",
        ),
        IdSourceSpec(
            label="Ubisoft cache ownership",
            path=local_app_data / "Ubisoft Game Launcher" / "cache" / "ownership",
            kind="file",
        ),
        IdSourceSpec(
            label="Ubisoft cache settings",
            path=local_app_data / "Ubisoft Game Launcher" / "cache" / "settings",
            kind="file",
        ),
        IdSourceSpec(
            label="Ubisoft savegames",
            path=Path(r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\savegames"),
            kind="dir",
        ),
        IdSourceSpec(
            label="Ubisoft statistics cache",
            path=Path(r"C:\ProgramData\Ubisoft\Ubisoft Game Launcher\cache\statistics"),
            kind="file",
            trim_prefix="gear",
        ),
        IdSourceSpec(
            label="Ubisoft game stats cache",
            path=Path(r"C:\ProgramData\Ubisoft\Ubisoft Game Launcher\cache\game_stats"),
            kind="file",
        ),
    ]


def normalize_candidate_id(raw: str, trim_prefix: str = "") -> str | None:
    candidate = raw.strip()
    if trim_prefix and candidate.lower().startswith(trim_prefix.lower()):
        candidate = candidate[len(trim_prefix) :]

    if ID_PATTERN.fullmatch(candidate):
        return candidate
    return None


def candidate_ids_from_name(name: str, trim_prefix: str = "") -> set[str]:
    raw_candidates = {name, Path(name).stem}
    parsed: set[str] = set()

    for raw in raw_candidates:
        parsed_id = normalize_candidate_id(raw, trim_prefix=trim_prefix)
        if parsed_id:
            parsed.add(parsed_id)

    return parsed


def collect_user_ids() -> dict[str, list[str]]:
    collected: dict[str, list[str]] = {}

    for spec in get_source_specs():
        if not spec.path.exists() or not spec.path.is_dir():
            continue

        try:
            for child in spec.path.iterdir():
                if spec.kind == "dir" and not child.is_dir():
                    continue
                if spec.kind == "file" and not child.is_file():
                    continue

                candidates = candidate_ids_from_name(child.name, trim_prefix=spec.trim_prefix)
                for user_id in candidates:
                    collected.setdefault(user_id, []).append(f"{spec.label}: {child.name}")
        except PermissionError:
            continue

    return collected


def clear_directory_contents(path: Path) -> tuple[int, int]:
    if not path.exists() or not path.is_dir():
        return 0, 0

    removed_files = 0
    removed_dirs = 0

    for child in list(path.iterdir()):
        try:
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=False)
                removed_dirs += 1
            else:
                child.unlink(missing_ok=True)
                removed_files += 1
        except (PermissionError, OSError):
            continue

    return removed_files, removed_dirs


def run_command(command: list[str], timeout: int = 60) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)

    output = "\n".join(
        piece for piece in [completed.stdout.strip(), completed.stderr.strip()] if piece
    )
    return completed.returncode == 0, output


def detect_refresh_rate(default_rate: int = DEFAULT_REFRESH_RATE) -> int:
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            "$rates = Get-CimInstance Win32_VideoController | "
            "ForEach-Object { $_.CurrentRefreshRate }; "
            "$rates | Where-Object { $_ -gt 0 } | "
            "Sort-Object -Descending | Select-Object -First 1"
        ),
    ]

    ok, output = run_command(cmd, timeout=20)
    if not ok:
        return default_rate

    for line in output.splitlines():
        value = line.strip()
        if value.isdigit() and int(value) > 0:
            return int(value)

    return default_rate


def resolve_template_value(value: str, refresh_rate: int) -> str:
    cleaned = value.strip().lower()

    if cleaned == "(active monitor refresh rate - 2)":
        return str(max(refresh_rate - 2, 30))
    if cleaned == "(active monitor refresh rate / 5)":
        return str(max(refresh_rate // 5, 30))

    return value.strip()


def load_template_config(template_path: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.optionxform = str

    if template_path.exists():
        with template_path.open("r", encoding="utf-8") as handle:
            cfg.read_file(handle)
    else:
        # Embedded fallback ensures executable builds still have optimization values.
        cfg.read_string(EMBEDDED_GAMESETTINGS_TEMPLATE)

    return cfg


def load_target_config(target_path: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.optionxform = str

    if target_path.exists():
        with target_path.open("r", encoding="utf-8") as handle:
            cfg.read_file(handle)

    return cfg


def write_target_config(target_path: Path, cfg: configparser.ConfigParser) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("w", encoding="utf-8", newline="\n") as handle:
        cfg.write(handle, space_around_delimiters=False)


def gather_gamesettings_paths(user_ids: list[str]) -> list[Path]:
    docs_root = Path.home() / "Documents" / "My Games" / "Rainbow Six - Siege"
    seen: set[Path] = set()

    for user_id in user_ids:
        target = docs_root / user_id / "GameSettings.ini"
        if target.exists():
            seen.add(target)

    if docs_root.exists():
        for user_folder in docs_root.iterdir():
            if not user_folder.is_dir():
                continue
            target = user_folder / "GameSettings.ini"
            if target.exists():
                seen.add(target)

    return sorted(seen)


def apply_template_to_gamesettings(
    template_path: Path,
    target_files: list[Path],
    refresh_rate: int,
) -> tuple[int, list[str]]:
    template_cfg = load_template_config(template_path)
    updated = 0
    details: list[str] = []

    for target in target_files:
        target_cfg = load_target_config(target)

        for section in template_cfg.sections():
            if not target_cfg.has_section(section):
                target_cfg.add_section(section)

            for key, value in template_cfg.items(section):
                resolved = resolve_template_value(value, refresh_rate)
                target_cfg.set(section, key, resolved)

        backup_path = target.with_suffix(target.suffix + ".bak")
        if target.exists() and not backup_path.exists():
            shutil.copy2(target, backup_path)

        write_target_config(target, target_cfg)
        updated += 1
        details.append(str(target))

    return updated, details


def cleanup_user_artifacts(user_id: str) -> tuple[list[str], list[str]]:
    removed_items: list[str] = []
    skipped_items: list[str] = []

    for spec in get_source_specs():
        if not spec.path.exists() or not spec.path.is_dir():
            continue

        if spec.kind == "dir":
            target_dir = spec.path / user_id
            if target_dir.exists() and target_dir.is_dir():
                try:
                    shutil.rmtree(target_dir, ignore_errors=False)
                    removed_items.append(str(target_dir))
                except (PermissionError, OSError):
                    skipped_items.append(str(target_dir))
            continue

        for child in spec.path.iterdir():
            if not child.is_file():
                continue

            candidates = candidate_ids_from_name(child.name, trim_prefix=spec.trim_prefix)
            if user_id in candidates:
                try:
                    child.unlink(missing_ok=True)
                    removed_items.append(str(child))
                except (PermissionError, OSError):
                    skipped_items.append(str(child))

    docs_profile = Path.home() / "Documents" / "My Games" / "Rainbow Six - Siege" / user_id
    if docs_profile.exists() and docs_profile.is_dir():
        try:
            shutil.rmtree(docs_profile, ignore_errors=False)
            removed_items.append(str(docs_profile))
        except (PermissionError, OSError):
            skipped_items.append(str(docs_profile))

    return removed_items, skipped_items


def find_r6_executables() -> list[Path]:
    roots = [
        Path(os.path.expandvars(r"%ProgramFiles(x86)%\Ubisoft\Ubisoft Game Launcher\games")),
        Path(os.path.expandvars(r"%ProgramFiles%\Ubisoft\Ubisoft Game Launcher\games")),
        Path(os.path.expandvars(r"%ProgramFiles(x86)%\Steam\steamapps\common")),
        Path(os.path.expandvars(r"%ProgramFiles%\Steam\steamapps\common")),
    ]

    matches: set[Path] = set()
    for root in roots:
        if not root.exists() or not root.is_dir():
            continue

        try:
            for candidate in root.rglob("RainbowSix*.exe"):
                name = candidate.name.lower()
                if name in {"rainbowsix.exe", "rainbowsix_vulkan.exe"}:
                    matches.add(candidate)
        except PermissionError:
            continue

    return sorted(matches)


def check_ban_status(user_id: str, timeout: int = 10) -> str:
    def classify_statscc_profile_status(page_text: str) -> str:
        normalized = " ".join(page_text.lower().split())

        if "rank reset due to ban" in normalized:
            return "Banned"

        section_match = re.search(r"ubisoft bans(.{0,240})", normalized)
        if section_match:
            section = section_match.group(1)
            if "no ban" in section or "none" in section:
                return "Not banned"

            reason_markers = (
                "cheating",
                "toxic",
                "abusive",
                "grief",
                "exploit",
                "fraud",
                "battleye",
            )
            if any(marker in section for marker in reason_markers):
                return "Banned"

            if re.search(r"\b\d+\s+(minute|hour|day|week|month|year)s?\s+ago\b", section):
                return "Banned"

        if any(
            marker in normalized
            for marker in ("battleye banned", "permanently banned", "temporarily banned")
        ):
            return "Banned"

        # If the profile loaded and no ban notice is present, treat as not banned.
        profile_markers = ("last played", "current season", "max ranks", "username history")
        if any(marker in normalized for marker in profile_markers):
            return "Not banned"

        return "Unknown"

    urls = [
        f"https://stats.cc/siege/-/{user_id}",
        f"https://stats.cc/siege/{user_id}",
        f"https://stats.cc/siege/player/{user_id}",
    ]

    for url in urls:
        request = Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                body = response.read(250000).decode("utf-8", errors="ignore").lower()
        except (HTTPError, URLError, TimeoutError):
            continue

        status = classify_statscc_profile_status(body)
        if status in {"Banned", "Not banned"}:
            return status

    return "Unavailable"


def open_driver_update_helpers(gpu_report: str) -> list[str]:
    launched: list[str] = []

    try:
        os.startfile("ms-settings:windowsupdate")
        launched.append("Windows Update")
    except OSError:
        pass

    report_lower = gpu_report.lower()
    if "nvidia" in report_lower:
        webbrowser.open("https://www.nvidia.com/en-us/geforce/geforce-experience/")
        launched.append("NVIDIA GeForce Experience")
    if "amd" in report_lower or "radeon" in report_lower:
        webbrowser.open("https://www.amd.com/en/support")
        launched.append("AMD Driver Support")
    if "intel" in report_lower:
        webbrowser.open("https://www.intel.com/content/www/us/en/download-center/home.html")
        launched.append("Intel Driver Support Assistant")

    return launched


def get_gpu_driver_report() -> str:
    ok, report = run_command(["wmic", "path", "win32_VideoController", "get", "Name,DriverVersion"])
    if ok and report.strip() and "No Instance" not in report:
        return report.strip()

    ps_command = (
        "Get-CimInstance Win32_VideoController | "
        "Select-Object Name,DriverVersion | Format-Table -HideTableHeaders"
    )
    ok_ps, report_ps = run_command(
        ["powershell", "-NoProfile", "-Command", ps_command],
        timeout=25,
    )
    if ok_ps and report_ps.strip():
        return report_ps.strip()

    fallback = report_ps.strip() if report_ps.strip() else report.strip()
    if fallback:
        return fallback
    return "Unable to query GPU driver information"


class R6FixerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1240x820")
        self.root.minsize(1060, 700)

        self.user_sources: dict[str, list[str]] = {}
        self.ban_status: dict[str, str] = {}
        self.network_mode = tk.StringVar(value="latency")

        self._configure_styles()
        self._build_ui()
        self.run_async("Refreshing discovered users", self.refresh_users)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        for theme in ("vista", "clam", "default"):
            try:
                style.theme_use(theme)
                break
            except tk.TclError:
                continue

        style.configure("Title.TLabel", font=("Segoe UI Semibold", 16))
        style.configure("Subtitle.TLabel", font=("Segoe UI", 10))
        style.configure("SectionHeader.TLabel", font=("Segoe UI Semibold", 11))
        style.configure("Hint.TLabel", font=("Segoe UI", 9))
        style.configure("Action.TButton", padding=(10, 6))
        style.configure("Section.TLabelframe.Label", font=("Segoe UI Semibold", 10))

    def _set_pane_position(self, pane: ttk.Panedwindow, index: int, position: int) -> None:
        try:
            pane.sashpos(index, position)
        except tk.TclError:
            pass

    def _create_scrollable_frame(self, parent: ttk.Frame) -> ttk.Frame:
        wrapper = ttk.Frame(parent)
        wrapper.pack(fill="both", expand=True)

        canvas = tk.Canvas(wrapper, highlightthickness=0, borderwidth=0, bg="#f5f7fb")
        scrollbar = ttk.Scrollbar(wrapper, orient="vertical", command=canvas.yview)
        content = ttk.Frame(canvas, padding=(0, 0, 8, 0))

        window_id = canvas.create_window((0, 0), window=content, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        def sync_scroll_region(_event: tk.Event) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def sync_content_width(event: tk.Event) -> None:
            canvas.itemconfigure(window_id, width=event.width)

        content.bind("<Configure>", sync_scroll_region)
        canvas.bind("<Configure>", sync_content_width)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return content

    def _add_action_block(
        self,
        parent: ttk.Frame,
        row: int,
        button_text: str,
        description: str,
        command,
    ) -> int:
        ttk.Button(parent, text=button_text, style="Action.TButton", command=command).grid(
            row=row,
            column=0,
            sticky="ew",
            pady=(0, 2),
        )
        ttk.Label(
            parent,
            text=description,
            style="Hint.TLabel",
            wraplength=560,
            justify="left",
        ).grid(row=row + 1, column=0, sticky="w", pady=(0, 10))
        return row + 2

    def _set_readonly_text(self, widget: tk.Text, content: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        if content:
            widget.insert("end", content)
        widget.configure(state="disabled")

    def _on_user_select(self, _event=None) -> None:
        selected = self.user_tree.selection()
        if not selected:
            self._set_readonly_text(
                self.source_text,
                "Select a user to view all locations where this ID was found.",
            )
            return

        user_id = selected[0]
        sources = sorted(self.user_sources.get(user_id, []))
        if not sources:
            self._set_readonly_text(self.source_text, f"{user_id}\n\nNo source entries recorded.")
            return

        lines = [f"{index + 1}. {value}" for index, value in enumerate(sources)]
        details = (
            f"{user_id}\n\nLocated in {len(sources)} location(s):\n"
            + "\n".join(lines)
        )
        self._set_readonly_text(self.source_text, details)

    def _build_ui(self) -> None:
        container = ttk.Frame(self.root, padding=12)
        container.pack(fill="both", expand=True)

        ttk.Label(container, text="R6Fixer Control Center", style="Title.TLabel").pack(
            anchor="w", pady=(0, 4)
        )

        description = (
            "R6Fixer can discover Ubisoft user IDs, clean cached data, apply optimized "
            "GameSettings values, and run Windows performance/network actions."
        )
        ttk.Label(
            container,
            text=description,
            style="Subtitle.TLabel",
            wraplength=1200,
            justify="left",
        ).pack(
            fill="x", pady=(0, 10)
        )

        split = ttk.Panedwindow(container, orient=tk.HORIZONTAL)
        split.pack(fill="both", expand=True)

        left = ttk.Frame(split, padding=8)
        right = ttk.Frame(split, padding=8)
        split.add(left, weight=1)
        split.add(right, weight=2)

        self.root.after(120, lambda: self._set_pane_position(split, 0, 380))

        self._build_users_panel(left)
        self._build_actions_panel(right)

    def _build_users_panel(self, parent: ttk.Frame) -> None:
        header = ttk.Frame(parent)
        header.pack(fill="x")

        ttk.Label(header, text="Discovered Ubisoft Users", style="SectionHeader.TLabel").pack(
            side="left",
            anchor="w",
        )
        self.user_count_var = tk.StringVar(value="0 user(s)")
        ttk.Label(header, textvariable=self.user_count_var, style="Hint.TLabel").pack(
            side="right",
            anchor="e",
        )

        columns = ("user_id", "locations", "ban")
        self.user_tree = ttk.Treeview(parent, columns=columns, show="headings", height=13)
        self.user_tree.heading("user_id", text="User ID")
        self.user_tree.heading("locations", text="Sources")
        self.user_tree.heading("ban", text="Ban Status")
        self.user_tree.column("user_id", width=280)
        self.user_tree.column("locations", width=70, anchor="center")
        self.user_tree.column("ban", width=95, anchor="center")
        self.user_tree.bind("<<TreeviewSelect>>", self._on_user_select)

        table_frame = ttk.Frame(parent)
        table_frame.pack(fill="both", expand=True, pady=(8, 8))

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.user_tree.yview)
        self.user_tree.configure(yscrollcommand=scroll.set)

        self.user_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        button_row = ttk.Frame(parent)
        button_row.pack(fill="x", pady=(2, 8))
        button_row.columnconfigure(0, weight=1)
        button_row.columnconfigure(1, weight=1)

        ttk.Button(
            button_row,
            text="Refresh Users",
            style="Action.TButton",
            command=lambda: self.run_async("Refreshing discovered users", self.refresh_users),
        ).grid(row=0, column=0, sticky="ew", padx=(0, 4), pady=(0, 4))

        ttk.Button(
            button_row,
            text="Check Ban Status",
            style="Action.TButton",
            command=self.start_check_bans,
        ).grid(row=0, column=1, sticky="ew", padx=(4, 0), pady=(0, 4))

        ttk.Button(
            button_row,
            text="Clean Selected Users",
            style="Action.TButton",
            command=self.prompt_cleanup_selected,
        ).grid(row=1, column=0, sticky="ew", padx=(0, 4))

        ttk.Button(
            button_row,
            text="Clean Banned Users",
            style="Action.TButton",
            command=self.prompt_cleanup_banned,
        ).grid(row=1, column=1, sticky="ew", padx=(4, 0))

        ttk.Label(parent, text="Selected User Sources", style="SectionHeader.TLabel").pack(
            anchor="w", pady=(2, 4)
        )

        source_frame = ttk.Frame(parent)
        source_frame.pack(fill="both", expand=False)

        self.source_text = tk.Text(
            source_frame,
            height=8,
            wrap="word",
            relief="solid",
            borderwidth=1,
            bg="#f8fafc",
        )
        source_scroll = ttk.Scrollbar(source_frame, orient="vertical", command=self.source_text.yview)
        self.source_text.configure(yscrollcommand=source_scroll.set)

        self.source_text.pack(side="left", fill="both", expand=True)
        source_scroll.pack(side="right", fill="y")
        self._set_readonly_text(
            self.source_text,
            "Select a user to view all locations where this ID was found.",
        )

    def _build_actions_panel(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Optimization Actions", style="SectionHeader.TLabel").pack(anchor="w")

        actions_host = ttk.Frame(parent)
        actions_host.pack(fill="both", expand=True, pady=(8, 8))
        actions = self._create_scrollable_frame(actions_host)

        profile_section = ttk.LabelFrame(
            actions,
            text="Profile Optimization",
            style="Section.TLabelframe",
            padding=10,
        )
        profile_section.pack(fill="x", pady=(0, 8))
        profile_section.columnconfigure(0, weight=1)
        self._add_action_block(
            profile_section,
            0,
            "Apply GameSettings To All Profiles",
            "Uses the project GameSettings.ini template and writes optimized keys to all detected profiles.",
            lambda: self.run_async("Applying GameSettings template", self.apply_gamesettings_to_all),
        )

        cleanup_section = ttk.LabelFrame(
            actions,
            text="Cache Cleanup",
            style="Section.TLabelframe",
            padding=10,
        )
        cleanup_section.pack(fill="x", pady=(0, 8))
        cleanup_section.columnconfigure(0, weight=1)
        row = 0
        row = self._add_action_block(
            cleanup_section,
            row,
            "Clear Rainbow Six Shader Cache",
            "Clears %LOCALAPPDATA%/Ubisoft/Rainbow Six - Siege cache files.",
            lambda: self.run_async("Clearing Rainbow Six shader cache", self.clear_r6_shader_cache),
        )
        row = self._add_action_block(
            cleanup_section,
            row,
            "Clear Ubisoft Launcher Cache",
            "Clears ProgramData Ubisoft launcher cache contents.",
            lambda: self.run_async("Clearing Ubisoft launcher cache", self.clear_ubisoft_cache),
        )
        self._add_action_block(
            cleanup_section,
            row,
            "Clear DirectX Shader Cache",
            "Removes D3D, NVIDIA, and AMD shader caches from LocalAppData where available.",
            lambda: self.run_async("Clearing DirectX shader caches", self.clear_directx_shader_cache),
        )

        network_section = ttk.LabelFrame(
            actions,
            text="Network Tuning",
            style="Section.TLabelframe",
            padding=10,
        )
        network_section.pack(fill="x", pady=(0, 8))
        network_section.columnconfigure(0, weight=1)

        ttk.Label(
            network_section,
            text="Choose a network profile:",
            style="Hint.TLabel",
        ).grid(row=0, column=0, sticky="w", pady=(0, 4))

        mode_row = ttk.Frame(network_section)
        mode_row.grid(row=1, column=0, sticky="w", pady=(0, 6))
        ttk.Radiobutton(
            mode_row,
            text="Latency + Stability",
            variable=self.network_mode,
            value="latency",
        ).pack(side="left", padx=(0, 8))
        ttk.Radiobutton(
            mode_row,
            text="Throughput + Downloads",
            variable=self.network_mode,
            value="throughput",
        ).pack(side="left")

        self._add_action_block(
            network_section,
            2,
            "Apply Network Optimizations",
            (
                "Runs global TCP tuning and applies Cloudflare DNS (1.1.1.1 / 1.0.0.1) "
                "to active Ethernet and Wi-Fi adapters."
            ),
            lambda: self.run_async("Applying network optimizations", self.apply_network_optimizations),
        )

        system_section = ttk.LabelFrame(
            actions,
            text="System Tweaks",
            style="Section.TLabelframe",
            padding=10,
        )
        system_section.pack(fill="x", pady=(0, 8))
        system_section.columnconfigure(0, weight=1)
        row = 0
        row = self._add_action_block(
            system_section,
            row,
            "Set High Performance Power Plan",
            "Sets Ultimate or High Performance and disables sleep/hibernate timeouts.",
            lambda: self.run_async("Setting high performance power plan", self.set_power_plan),
        )
        row = self._add_action_block(
            system_section,
            row,
            "Disable Fullscreen Optimizations",
            "Adds AppCompat flags for detected RainbowSix executables.",
            lambda: self.run_async(
                "Disabling fullscreen optimizations", self.disable_fullscreen_optimizations
            ),
        )
        self._add_action_block(
            system_section,
            row,
            "Check Graphics Driver Updates",
            "Collects current GPU driver versions and opens relevant update helpers.",
            lambda: self.run_async("Checking graphics driver updates", self.check_driver_updates),
        )

        one_click_section = ttk.LabelFrame(
            actions,
            text="One-Click",
            style="Section.TLabelframe",
            padding=10,
        )
        one_click_section.pack(fill="x", pady=(0, 4))
        one_click_section.columnconfigure(0, weight=1)
        self._add_action_block(
            one_click_section,
            0,
            "Run Full Optimization",
            "Runs profile update, cache cleanup, network tuning, and system tweaks in one flow.",
            lambda: self.run_async("Running full optimization", self.run_full_optimization),
        )

        ttk.Label(parent, text="Action Log", style="SectionHeader.TLabel").pack(anchor="w", pady=(4, 4))

        self.log_text = tk.Text(parent, height=9, wrap="word", relief="solid", borderwidth=1, bg="#f8fafc")
        self.log_text.pack(fill="both", expand=False)
        self.log_text.configure(state="disabled")

        startup_note = "Administrator mode active. System and network adapter tuning are enabled."
        self.log(startup_note)

    def log(self, message: str) -> None:
        def write() -> None:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", message.strip() + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

        self.root.after(0, write)

    def run_async(self, title: str, func) -> None:
        def worker() -> None:
            self.log(f"[{title}] started")
            try:
                result = func()
                if isinstance(result, str) and result:
                    self.log(f"[{title}] {result}")
                else:
                    self.log(f"[{title}] done")
            except Exception as exc:
                self.log(f"[{title}] failed: {exc}")

        threading.Thread(target=worker, daemon=True).start()

    def refresh_users(self) -> str:
        self.user_sources = collect_user_ids()
        self.ban_status = {
            user_id: status for user_id, status in self.ban_status.items() if user_id in self.user_sources
        }

        def repaint() -> None:
            previous_selection = set(self.user_tree.selection())
            self.user_tree.delete(*self.user_tree.get_children())
            for user_id in sorted(self.user_sources):
                locations = len(self.user_sources[user_id])
                status = self.ban_status.get(user_id, "Unknown")
                self.user_tree.insert("", "end", iid=user_id, values=(user_id, locations, status))

            self.user_count_var.set(f"{len(self.user_sources)} user(s)")

            valid_selection = [
                user_id for user_id in previous_selection if user_id in self.user_sources
            ]
            if valid_selection:
                self.user_tree.selection_set(valid_selection)
            elif self.user_tree.get_children():
                self.user_tree.selection_set(self.user_tree.get_children()[0])

            self._on_user_select()

        self.root.after(0, repaint)
        return f"Found {len(self.user_sources)} unique Ubisoft user IDs"

    def selected_user_ids(self) -> list[str]:
        selected = self.user_tree.selection()
        if selected:
            return list(selected)
        return sorted(self.user_sources.keys())

    def start_check_bans(self) -> None:
        user_ids = self.selected_user_ids()
        self.run_async("Checking ban status", lambda: self.check_bans(user_ids))

    def check_bans(self, user_ids: list[str]) -> str:
        if not user_ids:
            return "No users available to check"

        for user_id in user_ids:
            status = check_ban_status(user_id)
            self.ban_status[user_id] = status
            self.log(f"Ban check {user_id}: {status}")

        self.root.after(0, self._repaint_ban_status)
        return f"Checked ban status for {len(user_ids)} user(s)"

    def _repaint_ban_status(self) -> None:
        for user_id in self.user_tree.get_children():
            values = list(self.user_tree.item(user_id, "values"))
            if not values:
                continue
            values[2] = self.ban_status.get(user_id, "Unknown")
            self.user_tree.item(user_id, values=values)

    def prompt_cleanup_selected(self) -> None:
        user_ids = self.selected_user_ids()
        if not user_ids:
            messagebox.showinfo(APP_TITLE, "No users selected.")
            return

        answer = messagebox.askyesno(
            APP_TITLE,
            f"Delete all discovered local data for {len(user_ids)} selected user(s)?",
        )
        if not answer:
            return

        self.run_async("Cleaning selected users", lambda: self.cleanup_selected_users(user_ids))

    def prompt_cleanup_banned(self) -> None:
        banned_ids = [
            user_id
            for user_id in sorted(self.user_sources)
            if self.ban_status.get(user_id) == "Banned"
        ]

        if not banned_ids:
            messagebox.showinfo(APP_TITLE, "No banned users are currently detected.")
            return

        answer = messagebox.askyesno(
            APP_TITLE,
            f"Delete local data for {len(banned_ids)} banned user(s)?",
        )
        if not answer:
            return

        self.run_async("Cleaning banned users", lambda: self.cleanup_selected_users(banned_ids))

    def cleanup_selected_users(self, user_ids: list[str]) -> str:
        total_removed = 0
        total_skipped = 0

        for user_id in user_ids:
            removed, skipped = cleanup_user_artifacts(user_id)
            total_removed += len(removed)
            total_skipped += len(skipped)
            self.log(
                f"Cleaned {user_id}: removed {len(removed)} item(s), skipped {len(skipped)} item(s)"
            )

        self.refresh_users()
        return (
            f"Removed {total_removed} file/folder item(s), skipped {total_skipped} item(s) "
            f"across {len(user_ids)} user(s)"
        )

    def apply_gamesettings_to_all(self) -> str:
        template = Path(__file__).resolve().parent / "GameSettings.ini"
        using_embedded_template = not template.exists()
        user_ids = sorted(self.user_sources.keys())
        targets = gather_gamesettings_paths(user_ids)

        if not targets:
            return "No GameSettings.ini files were found"

        refresh_rate = detect_refresh_rate()
        updated, details = apply_template_to_gamesettings(template, targets, refresh_rate)

        for path in details:
            self.log(f"Updated: {path}")

        source_label = "embedded defaults" if using_embedded_template else "project GameSettings.ini"
        return (
            f"Applied template to {updated} file(s) using refresh rate {refresh_rate} Hz "
            f"(source: {source_label})"
        )

    def clear_r6_shader_cache(self) -> str:
        target = Path(os.path.expandvars(r"%LOCALAPPDATA%\Ubisoft\Rainbow Six - Siege"))
        files, dirs = clear_directory_contents(target)
        return f"Removed {files} files and {dirs} folders from {target}"

    def clear_ubisoft_cache(self) -> str:
        target = Path(r"C:\ProgramData\Ubisoft\Ubisoft Game Launcher\cache")
        files, dirs = clear_directory_contents(target)
        return f"Removed {files} files and {dirs} folders from {target}"

    def clear_directx_shader_cache(self) -> str:
        local = Path(os.path.expandvars(r"%LOCALAPPDATA%"))
        targets = [
            local / "D3DSCache",
            local / "NVIDIA" / "DXCache",
            local / "NVIDIA" / "GLCache",
            local / "AMD" / "DxCache",
            local / "AMD" / "GLCache",
        ]

        total_files = 0
        total_dirs = 0
        for target in targets:
            files, dirs = clear_directory_contents(target)
            total_files += files
            total_dirs += dirs

        return f"Removed {total_files} files and {total_dirs} folders across DirectX shader caches"

    def apply_network_optimizations(self) -> str:
        if not is_admin():
            return "Admin rights are required for network tweaks. Relaunch as Administrator."

        adapters = get_active_network_adapters()
        if not adapters:
            return "No active physical Ethernet/Wi-Fi adapters were detected"

        adapter_summaries = [f"{item['alias']} ({item.get('medium', 'Unknown')})" for item in adapters]
        self.log("Active network adapters: " + ", ".join(adapter_summaries))

        mode = self.network_mode.get()
        common_commands = [
            ["netsh", "int", "tcp", "set", "heuristics", "disabled"],
            ["netsh", "int", "tcp", "set", "global", "rss=enabled"],
            ["netsh", "int", "tcp", "set", "global", "rsc=disabled"],
            ["netsh", "int", "tcp", "set", "global", "timestamps=disabled"],
            ["netsh", "int", "tcp", "set", "global", "nonsackrttresiliency=disabled"],
            ["netsh", "int", "ip", "set", "global", "taskoffload=enabled"],
        ]

        if mode == "throughput":
            mode_commands = [
                ["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"],
                ["netsh", "int", "tcp", "set", "global", "ecncapability=enabled"],
                [
                    "netsh",
                    "int",
                    "tcp",
                    "set",
                    "supplemental",
                    "internet",
                    "congestionprovider=ctcp",
                ],
            ]
            mode_name = "Throughput + Downloads"
        else:
            mode_commands = [
                ["netsh", "int", "tcp", "set", "global", "autotuninglevel=highlyrestricted"],
                ["netsh", "int", "tcp", "set", "global", "ecncapability=disabled"],
                [
                    "netsh",
                    "int",
                    "tcp",
                    "set",
                    "supplemental",
                    "internet",
                    "congestionprovider=cubic",
                ],
            ]
            mode_name = "Latency + Stability"

        commands = common_commands + mode_commands

        success = 0
        for cmd in commands:
            ok, output = run_command(cmd)
            if ok:
                success += 1
            else:
                self.log(f"Command failed: {' '.join(cmd)}")
            if output:
                self.log(output)

        adapter_success, adapter_total, adapter_logs = apply_adapter_network_settings(adapters, mode)
        for item in adapter_logs:
            self.log(item)

        return (
            f"Applied {success}/{len(commands)} network commands for mode: {mode_name}; "
            f"adapter tuning applied in {adapter_success}/{adapter_total} operations"
        )

    def set_power_plan(self) -> str:
        if not is_admin():
            return "Admin rights are required for power plan changes. Relaunch as Administrator."

        selected = False
        for plan_guid in [
            "e9a42b02-d5df-448d-aa00-03f14749eb61",  # Ultimate Performance
            "381b4222-f694-41f0-9685-ff5bb260df2e",  # High Performance
        ]:
            ok, output = run_command(["powercfg", "/S", plan_guid])
            if ok:
                selected = True
                break
            if output:
                self.log(output)

        timeout_cmds = [
            ["powercfg", "/X", "monitor-timeout-ac", "0"],
            ["powercfg", "/X", "monitor-timeout-dc", "0"],
            ["powercfg", "/X", "standby-timeout-ac", "0"],
            ["powercfg", "/X", "standby-timeout-dc", "0"],
            ["powercfg", "/X", "hibernate-timeout-ac", "0"],
            ["powercfg", "/X", "hibernate-timeout-dc", "0"],
        ]

        success = 0
        for cmd in timeout_cmds:
            ok, output = run_command(cmd)
            if ok:
                success += 1
            if output:
                self.log(output)

        if selected:
            return f"Power plan set and {success}/{len(timeout_cmds)} timeout commands applied"
        return "Could not set High/Ultimate Performance power plan"

    def disable_fullscreen_optimizations(self) -> str:
        executables = find_r6_executables()
        if not executables:
            return "No RainbowSix executable was found in common launcher directories"

        success = 0
        for exe in executables:
            cmd = [
                "reg",
                "add",
                r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
                "/v",
                str(exe),
                "/t",
                "REG_SZ",
                "/d",
                "~ DISABLEDXMAXIMIZEDWINDOWEDMODE HIGHDPIAWARE",
                "/f",
            ]
            ok, output = run_command(cmd)
            if ok:
                success += 1
            if output:
                self.log(output)

        return f"Applied fullscreen optimization flags to {success}/{len(executables)} executable(s)"

    def check_driver_updates(self) -> str:
        report = get_gpu_driver_report()

        if report:
            self.log("Current GPU drivers:\n" + report)

        launched = open_driver_update_helpers(report)
        if launched:
            return "Opened update helpers: " + ", ".join(launched)
        return "Could not open update helpers automatically"

    def run_full_optimization(self) -> str:
        steps = [
            self.refresh_users,
            self.apply_gamesettings_to_all,
            self.clear_r6_shader_cache,
            self.clear_ubisoft_cache,
            self.clear_directx_shader_cache,
            self.apply_network_optimizations,
            self.set_power_plan,
            self.disable_fullscreen_optimizations,
        ]

        summaries: list[str] = []
        for step in steps:
            try:
                summary = step()
            except Exception as exc:
                summary = f"{step.__name__} failed: {exc}"
            summaries.append(summary)
            self.log(summary)

        return "Full optimization finished"


def main() -> None:
    if not ensure_admin_or_relaunch():
        return

    root = tk.Tk()
    app = R6FixerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
