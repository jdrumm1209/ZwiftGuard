# Copyright (c) 2026 Jason Drummond. All rights reserved.
# Proprietary software: see the "Proprietary License" file in this
# repository. No use, copying, or redistribution without written consent.
"""Public IP / location lookup and local IP discovery.

The public lookup asks ipapi.co once per session (HTTPS, no key needed) for
the rider's public IP, city/country, timezone, and ISP so the dashboard can
show where the connection originates and the local date/time at that
location. Disable with "public_ip_lookup": false in the config.
"""

from __future__ import annotations

import json
import socket
import urllib.request
from typing import Optional


def lookup_public_ip(timeout: float = 8.0) -> Optional[dict]:
    req = urllib.request.Request(
        "https://ipapi.co/json/",
        headers={"User-Agent": "zwiftguard (+https://github.com/jdrumm1209/ZwiftGuard)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except Exception:
        return None
    if not isinstance(data, dict) or data.get("error"):
        return None
    return {
        "public_ip": data.get("ip", ""),
        "city": data.get("city", ""),
        "region": data.get("region", ""),
        "country": data.get("country_name", ""),
        "timezone": data.get("timezone", ""),
        "org": data.get("org", ""),
    }


def local_ip() -> str:
    """LAN IP of the default route interface (no packets are sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return ""
