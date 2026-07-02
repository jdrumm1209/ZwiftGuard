"""Core data models: device fingerprints and hash-chained integrity events."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

SEV_INFO = "INFO"
SEV_WARN = "WARN"
SEV_ALERT = "ALERT"


def now_ts() -> float:
    return time.time()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class DeviceFingerprint:
    """Identity of a piece of equipment as observed on one transport.

    source is one of:
      "ble"     - seen advertising over Bluetooth LE (address = MAC)
      "ant"     - reported in the Zwift log as an ANT+ device (address = device ID)
      "network" - a LAN device Zwift holds a TCP connection to (address = IP)
    """

    source: str
    address: str
    name: str = ""
    company_ids: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    mac: str = ""  # for network devices: MAC resolved from the ARP table
    first_seen: float = field(default_factory=now_ts)
    last_seen: float = field(default_factory=now_ts)
    rssi_last: Optional[int] = None
    rssi_baseline: Optional[float] = None  # rolling average established early on
    _rssi_samples: int = 0

    def identity_key(self) -> str:
        """Stable key for 'the same physical device'."""
        return f"{self.source}:{self.address.upper()}"

    def identity_hash(self) -> str:
        """Hash over the fields that should never change for real hardware."""
        stable = {
            "source": self.source,
            "address": self.address.upper(),
            "name": self.name,
            "company_ids": sorted(self.company_ids),
            "services": sorted(self.services),
            "mac": self.mac.upper(),
        }
        return sha256_hex(json.dumps(stable, sort_keys=True).encode())[:16]

    def update_rssi(self, rssi: Optional[int]) -> None:
        if rssi is None:
            return
        self.rssi_last = rssi
        # Build the baseline from the first ~20 samples, then freeze it.
        if self._rssi_samples < 20:
            if self.rssi_baseline is None:
                self.rssi_baseline = float(rssi)
            else:
                self.rssi_baseline += (rssi - self.rssi_baseline) / (self._rssi_samples + 1)
            self._rssi_samples += 1

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("_rssi_samples", None)
        d["identity_hash"] = self.identity_hash()
        return d


@dataclass
class IntegrityEvent:
    """One entry in the tamper-evident event log.

    Events form a hash chain: each event's hash covers its own content plus
    the hash of the previous event, so a report file cannot be edited after
    the fact without breaking verification (see cli.py --verify-report).
    """

    ts: float
    severity: str
    rule: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""

    def compute_hash(self) -> str:
        body = {
            "ts": self.ts,
            "severity": self.severity,
            "rule": self.rule,
            "message": self.message,
            "evidence": self.evidence,
            "prev_hash": self.prev_hash,
        }
        return sha256_hex(json.dumps(body, sort_keys=True, default=str).encode())

    def seal(self, prev_hash: str) -> None:
        self.prev_hash = prev_hash
        self.hash = self.compute_hash()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def verify_chain(events: list[dict[str, Any]], genesis: str) -> tuple[bool, int]:
    """Re-derive the hash chain of a saved report. Returns (ok, first_bad_index)."""
    prev = genesis
    for i, e in enumerate(events):
        ev = IntegrityEvent(
            ts=e["ts"], severity=e["severity"], rule=e["rule"],
            message=e["message"], evidence=e.get("evidence", {}),
        )
        ev.prev_hash = prev
        if e.get("prev_hash") != prev or ev.compute_hash() != e.get("hash"):
            return False, i
        prev = e["hash"]
    return True, -1
