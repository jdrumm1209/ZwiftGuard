"""Default configuration and user-config loading."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

# Standard Bluetooth SIG 16-bit service UUIDs used by Zwift-compatible equipment.
FITNESS_SERVICES = {
    "1826": "Fitness Machine (FTMS - smart trainer control)",
    "1818": "Cycling Power",
    "1816": "Cycling Speed and Cadence",
    "180d": "Heart Rate",
    "1814": "Running Speed and Cadence",
}

DEFAULTS: dict[str, Any] = {
    # BLE devices whose advertised name matches this regex are tracked even if
    # they do not advertise a standard fitness service.
    "watch_name_regex": (
        r"kickr|wahoo|tickr|tacx|neo\b|flux|elite\b|direto|suito|justo|kura|drivo|"
        r"rampa|saris|hammer|magnus|h3\b|stages|assioma|favero|vector|rally|quarq|"
        r"4iiii|powertap|polar|hrm|garmin|coospo|magene|jetblack|volt|zwift (hub|ride|click|cog|play)|"
        r"wattbike|keiser|schwinn|bkool|zycle|domyos|concept2|pm5|echelon|inride"
    ),
    # Bluetooth SIG company identifiers considered consistent with a brand name.
    # Extend from https://www.bluetooth.com/specifications/assigned-numbers/
    # Only brands listed here are checked, so wrong/missing entries never
    # produce false alerts for other equipment.
    "brand_company_ids": {
        "garmin": [135],          # 0x0087 Garmin International
        "polar": [107],           # 0x006B Polar Electro Oy
    },
    # Substrings (case-insensitive) of process names/paths that indicate sensor
    # emulators or BLE/ANT re-broadcasting bridges running on this machine.
    # A bridge is not automatically cheating, but it is a man-in-the-middle
    # point between the equipment and Zwift, which this tool exists to flag.
    "process_blocklist": [
        "simulant",        # SimulANT+ (ANT+ device simulator)
        "antsim",
        "fortiusant",      # FortiusANT trainer bridge
        "gymnasticon",     # bike-to-BLE bridge
        "qdomyos",         # QZ bridge (desktop builds)
        "ftms-sim",
        "ftmssim",
        "ble-sim",
        "blesim",
        "powermeter-sim",
        "virtualtrainer",
    ],
    # Zwift-owned domains; any hosts-file override of these is a redirect of
    # game traffic and gets flagged.
    "zwift_domains": ["zwift.com", "zwiftpower.com", "cdn.zwift.com", "us-or-rly101.zwift.com"],
    "zwift_process_names": ["zwiftapp", "zwift"],
    # Path to the live Zwift session log ("" = auto: ~/Documents/Zwift/Logs/Log.txt)
    "zwift_log_path": "",
    # Seconds after the first fitness device is seen before the session
    # baseline locks. After lock, any *new* fitness device is a WARN and any
    # identity change on an existing device is an ALERT.
    "baseline_lock_seconds": 120,
    # Sustained RSSI deviation (dB) from a device's early-session average that
    # triggers a signal-anomaly warning (device moved / replaced / relayed).
    "rssi_jump_db": 25,
    "rssi_min_samples": 10,
    # Polling intervals (seconds)
    "process_poll_interval": 10,
    "network_poll_interval": 8,
    "zwift_log_poll_interval": 2,
    # Live web dashboard (bound to 127.0.0.1 only)
    "dashboard_port": 8377,
    # ANT+ manufacturer IDs (FIT profile) used to name ANT sensors from the
    # "[ANT] dID <id> MFG <n> Model <m>" lines in Zwift's log. Extend freely.
    "ant_manufacturer_ids": {
        "1": "Garmin", "6": "SRM", "7": "Quarq", "9": "Saris", "15": "Dynastream",
        "32": "Wahoo Fitness", "40": "Concept2", "41": "Shimano", "51": "4iiii",
        "63": "Specialized", "67": "BKOOL", "69": "Stages Cycling", "73": "Wattbike",
        "81": "Bontrager", "83": "Scosche", "86": "Elite", "89": "Tacx",
        "107": "Kinetic", "263": "Favero Electronics",
    },
    # Seconds without BLE advertisements before equipment is considered
    # disconnected (R18 dropout/reconnect events, dashboard offline state).
    "equipment_timeout_s": 45,
    # Live power feed: attach (read-only) to the trainer/power meter's free
    # BLE Cycling Power slot for an independent watts/cadence witness. Only
    # devices that are actively advertising are ever contacted.
    "live_power_monitor": True,
    # Auto-fill rider power bests + estimated FTP from Zwift's local ride
    # cache (Documents/Zwift/cp). Explicit rider_profile values win.
    "auto_profile_from_zwift": True,
    # Power-integrity rule thresholds (R14-R17)
    "power_rules": {
        "profile_tolerance_pct": 15,   # R14: % above own best before alerting
        "sticky_seconds": 30,          # R15: frozen-value duration
        "sticky_min_watts": 100,
        "zero_cadence_seconds": 10,    # R16
        "smooth_window_s": 120,        # R17
        "smooth_min_watts": 180,
        "smooth_stdev_w": 2.0,
    },
    # One-time HTTPS lookup of public IP + city/timezone at session start
    # (ipapi.co) so the dashboard can show origin IP and location-local time.
    "public_ip_lookup": True,
    # Rider identity and power profile shown on the dashboard. Fill this in
    # (or leave city/country/timezone empty to use the IP-detected location).
    "rider_profile": {
        "name": "",
        "zwift_id": "",
        "category": "",
        "weight_kg": 0,
        "ftp_w": 0,
        "power_bests_w": {"5s": 0, "1m": 0, "5m": 0, "20m": 0},
        "city": "",
        "country": "",
        "timezone": "",
    },
    # Where session reports are written
    "report_dir": "reports",
    # Trusted-equipment registry created by --register
    "baseline_file": "baseline.json",
}


def load_config(path: str | None) -> dict[str, Any]:
    cfg = copy.deepcopy(DEFAULTS)
    if path:
        user = json.loads(Path(path).read_text(encoding="utf-8"))
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    return cfg


def write_default_config(path: str) -> None:
    Path(path).write_text(json.dumps(DEFAULTS, indent=2), encoding="utf-8")


def _documents_dir() -> Path:
    """Real Documents folder — respects OneDrive/folder redirection."""
    try:
        import winreg
        with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as key:
            value, _ = winreg.QueryValueEx(key, "Personal")
        return Path(os.path.expandvars(value))
    except OSError:
        return Path(os.path.expanduser("~")) / "Documents"


def default_zwift_log_path() -> str:
    return str(_documents_dir() / "Zwift" / "Logs" / "Log.txt")
