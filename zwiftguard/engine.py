"""Integrity engine: device inventory, baseline, detection rules, event chain.

All monitors feed observations into this engine. The engine owns the device
inventory, applies the detection rules, and appends findings to a
hash-chained event log that becomes the session report.

Rules
  R01 identity-change   same device name reappears on a different BLE address mid-session
  R02 clone             two live BLE addresses advertising the same name at once
  R03 local-emulator    a "sensor" is advertising FROM this PC's own Bluetooth adapter
  R04 brand-mismatch    advertised brand name inconsistent with manufacturer company ID
  R05 rssi-anomaly      sustained signal-strength jump vs. the device's own baseline
  R06 blocked-process   known emulator / bridge software running
  R07 loopback-bridge   Zwift holds a TCP connection to another process on this PC
  R08 hosts-redirect    Zwift domains redirected in the hosts file
  R09 ghost-pairing     Zwift paired with a device never observed on the air
  R10 ant-id-change     ANT+ device ID for a role changed mid-session
  R11 post-lock-device  a new fitness device appeared after the baseline locked
  R12 registry-mismatch device name matches registered equipment but identity differs
  R13 arp-change        MAC behind a direct-connect trainer's IP changed mid-session
"""

from __future__ import annotations

import json
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from .models import DeviceFingerprint, IntegrityEvent, SEV_ALERT, SEV_INFO, SEV_WARN, now_ts, sha256_hex

_ANSI = {"INFO": "\x1b[36m", "WARN": "\x1b[33m", "ALERT": "\x1b[31;1m", "OK": "\x1b[32m", "END": "\x1b[0m"}


def _norm_name(name: str) -> str:
    """Normalize an advertised name for comparison (case, trailing digits kept)."""
    return re.sub(r"\s+", " ", (name or "").strip().lower())


class IntegrityEngine:
    def __init__(self, config: dict[str, Any], quiet: bool = False):
        self.cfg = config
        self.quiet = quiet
        self.session_id = uuid.uuid4().hex
        self.genesis = sha256_hex(f"zwiftguard-genesis-{self.session_id}".encode())
        self.started = now_ts()

        self.devices: dict[str, DeviceFingerprint] = {}
        self.events: list[IntegrityEvent] = []
        self._last_hash = self.genesis

        self.baseline_locked = False
        self._first_device_ts: Optional[float] = None

        # name -> set of addresses currently believed live (for clone/identity rules)
        self._name_addresses: dict[str, set[str]] = {}
        # Zwift-log state
        self._ant_role_ids: dict[str, str] = {}      # role ("PWR","HR","FEC") -> device id
        self._zwift_paired_names: set[str] = set()
        # network state
        self._ip_macs: dict[str, str] = {}
        # registered (trusted) equipment loaded from baseline.json
        self.registry: dict[str, dict[str, Any]] = {}

        self._local_adapter_macs: set[str] = set()
        self._flagged: set[str] = set()  # dedupe key -> already reported

    # ------------------------------------------------------------------ events

    def emit(self, severity: str, rule: str, message: str, evidence: dict[str, Any] | None = None,
             dedupe: str | None = None) -> None:
        if dedupe:
            key = f"{rule}:{dedupe}"
            if key in self._flagged:
                return
            self._flagged.add(key)
        ev = IntegrityEvent(ts=now_ts(), severity=severity, rule=rule,
                            message=message, evidence=evidence or {})
        ev.seal(self._last_hash)
        self._last_hash = ev.hash
        self.events.append(ev)
        if not self.quiet:
            color = _ANSI.get(severity, "")
            stamp = time.strftime("%H:%M:%S", time.localtime(ev.ts))
            print(f"{stamp} {color}[{severity:5s}]{_ANSI['END']} {rule:18s} {message}")
            sys.stdout.flush()

    # ---------------------------------------------------------------- registry

    def load_registry(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        data = json.loads(p.read_text(encoding="utf-8"))
        self.registry = {d["name_norm"]: d for d in data.get("devices", [])}
        self.emit(SEV_INFO, "registry", f"Loaded trusted-equipment registry with {len(self.registry)} device(s)",
                  {"path": str(p)})

    def save_registry(self, path: str) -> None:
        devices = []
        for fp in self.devices.values():
            devices.append({
                "name_norm": _norm_name(fp.name) or fp.identity_key(),
                "name": fp.name,
                "source": fp.source,
                "address": fp.address.upper(),
                "mac": fp.mac.upper(),
                "company_ids": sorted(fp.company_ids),
                "services": sorted(fp.services),
                "identity_hash": fp.identity_hash(),
            })
        Path(path).write_text(json.dumps({"created": now_ts(), "devices": devices}, indent=2),
                              encoding="utf-8")

    def set_local_adapter_macs(self, macs: set[str]) -> None:
        self._local_adapter_macs = {m.upper() for m in macs}

    # ------------------------------------------------------------ observations

    def observe_ble(self, address: str, name: str, rssi: Optional[int],
                    company_ids: list[int], services: list[str]) -> None:
        address = address.upper()
        key = f"ble:{address}"
        fp = self.devices.get(key)
        is_new = fp is None
        if is_new:
            fp = DeviceFingerprint(source="ble", address=address, name=name or "",
                                   company_ids=sorted(set(company_ids)),
                                   services=sorted(set(services)))
            self.devices[key] = fp
            self._on_new_device(fp)
        else:
            fp.last_seen = now_ts()
            if name and not fp.name:
                fp.name = name
            for cid in company_ids:
                if cid not in fp.company_ids:
                    fp.company_ids = sorted(set(fp.company_ids) | {cid})
            for s in services:
                if s not in fp.services:
                    fp.services = sorted(set(fp.services) | {s})
        fp.update_rssi(rssi)

        nn = _norm_name(fp.name)
        if nn:
            addrs = self._name_addresses.setdefault(nn, set())
            addrs.add(address)
            self._rule_clone_and_identity(nn, fp)

        self._rule_local_emulator(fp)
        self._rule_brand_mismatch(fp)
        self._rule_rssi(fp)
        self._rule_registry(fp)

    def observe_zwift_pairing(self, kind: str, name: str, ident: str, raw_line: str) -> None:
        """Called by the Zwift log tailer. kind: 'ant' | 'ble' | 'generic'."""
        nn = _norm_name(name)
        if kind == "ant" and ident:
            role = name or "device"
            prev = self._ant_role_ids.get(role)
            if prev is not None and prev != ident:
                self.emit(SEV_ALERT, "R10-ant-id-change",
                          f"ANT+ {role} device ID changed mid-session: {prev} -> {ident}",
                          {"role": role, "previous_id": prev, "new_id": ident, "log_line": raw_line})
            self._ant_role_ids[role] = ident
            key = f"ant:{ident}"
            if key not in self.devices:
                fp = DeviceFingerprint(source="ant", address=str(ident), name=role)
                self.devices[key] = fp
                self._on_new_device(fp)
        if nn:
            self._zwift_paired_names.add(nn)
        self.emit(SEV_INFO, "zwift-pairing",
                  f"Zwift log: paired {kind} device '{name}'" + (f" id={ident}" if ident else ""),
                  {"log_line": raw_line}, dedupe=f"{kind}:{name}:{ident}")
        # R09: Zwift paired with something we never saw advertising.
        if kind == "ble" and nn and not self._seen_on_air(nn):
            self.emit(SEV_WARN, "R09-ghost-pairing",
                      f"Zwift paired with BLE device '{name}' that was never observed advertising "
                      f"on this machine's radio (bridged via Companion app, another adapter, or emulated)",
                      {"name": name, "log_line": raw_line}, dedupe=nn)

    def observe_network_peer(self, ip: str, port: int, mac: str, is_loopback: bool,
                             peer_process: str | None = None) -> None:
        if is_loopback:
            self.emit(SEV_ALERT, "R07-loopback-bridge",
                      f"Zwift has a TCP connection to another program on this PC "
                      f"(127.0.0.1:{port}{', process: ' + peer_process if peer_process else ''}). "
                      f"A local bridge/proxy is sitting between the equipment and Zwift.",
                      {"ip": ip, "port": port, "peer_process": peer_process},
                      dedupe=f"{ip}:{port}:{peer_process}")
            return
        key = f"network:{ip}"
        fp = self.devices.get(key)
        if fp is None:
            fp = DeviceFingerprint(source="network", address=ip, mac=mac or "", name=f"LAN device {ip}")
            self.devices[key] = fp
            self._on_new_device(fp)
        else:
            fp.last_seen = now_ts()
        prev_mac = self._ip_macs.get(ip)
        if mac:
            if prev_mac and prev_mac != mac.upper():
                self.emit(SEV_ALERT, "R13-arp-change",
                          f"MAC address behind direct-connect device {ip} changed: "
                          f"{prev_mac} -> {mac.upper()} (device swapped or ARP spoofing)",
                          {"ip": ip, "previous_mac": prev_mac, "new_mac": mac.upper()})
            self._ip_macs[ip] = mac.upper()
            if not fp.mac:
                fp.mac = mac.upper()

    def observe_blocked_process(self, pid: int, name: str, exe: str, pattern: str) -> None:
        self.emit(SEV_ALERT, "R06-blocked-process",
                  f"Sensor emulator / bridge software running: {name} (pid {pid}, matched '{pattern}')",
                  {"pid": pid, "name": name, "exe": exe, "pattern": pattern},
                  dedupe=f"{name}:{pid}")

    def observe_hosts_redirect(self, line: str, domain: str) -> None:
        self.emit(SEV_ALERT, "R08-hosts-redirect",
                  f"Zwift domain '{domain}' is redirected in the Windows hosts file: {line.strip()}",
                  {"hosts_line": line.strip(), "domain": domain}, dedupe=domain)

    # ----------------------------------------------------------------- rules

    def _on_new_device(self, fp: DeviceFingerprint) -> None:
        ids = f" companyIDs={fp.company_ids}" if fp.company_ids else ""
        svc = f" services={fp.services}" if fp.services else ""
        self.emit(SEV_INFO, "inventory",
                  f"Discovered {fp.source.upper()} device '{fp.name or '(no name)'}' "
                  f"addr={fp.address}{ids}{svc} fingerprint={fp.identity_hash()}",
                  {"fingerprint": fp.to_dict()})
        if self._first_device_ts is None and fp.source in ("ble", "ant"):
            self._first_device_ts = now_ts()
        if self.baseline_locked and fp.source in ("ble", "ant"):
            self.emit(SEV_WARN, "R11-post-lock-device",
                      f"New {fp.source.upper()} fitness device '{fp.name or fp.address}' appeared "
                      f"after the session baseline locked",
                      {"fingerprint": fp.to_dict()}, dedupe=fp.identity_key())

    def _seen_on_air(self, name_norm: str) -> bool:
        for fp in self.devices.values():
            if fp.source == "ble" and _norm_name(fp.name) == name_norm:
                return True
        # Loose match: Zwift often logs a truncated or prefixed form of the name.
        for fp in self.devices.values():
            if fp.source == "ble" and fp.name and (
                    name_norm in _norm_name(fp.name) or _norm_name(fp.name) in name_norm):
                return True
        return False

    def _rule_clone_and_identity(self, name_norm: str, fp: DeviceFingerprint) -> None:
        addrs = self._name_addresses.get(name_norm, set())
        if len(addrs) < 2:
            return
        stale_cutoff = now_ts() - 30
        live = {a for a in addrs
                if (d := self.devices.get(f"ble:{a}")) and d.last_seen >= stale_cutoff}
        if len(live) >= 2:
            self.emit(SEV_ALERT, "R02-clone",
                      f"Two devices are advertising the same name '{fp.name}' simultaneously: "
                      f"{sorted(live)} — one of them is likely an impersonator",
                      {"name": fp.name, "addresses": sorted(live)},
                      dedupe=f"{name_norm}:{':'.join(sorted(live))}")
        elif fp.address in addrs and len(addrs) >= 2:
            others = sorted(addrs - {fp.address})
            self.emit(SEV_ALERT, "R01-identity-change",
                      f"Device '{fp.name}' reappeared with a different Bluetooth address: "
                      f"previously {others}, now {fp.address}. Real hardware keeps its address "
                      f"within a session; a spoofer replacing the device would not.",
                      {"name": fp.name, "previous_addresses": others, "current_address": fp.address},
                      dedupe=f"{name_norm}:{fp.address}")

    def _rule_local_emulator(self, fp: DeviceFingerprint) -> None:
        if fp.address in self._local_adapter_macs:
            self.emit(SEV_ALERT, "R03-local-emulator",
                      f"'{fp.name or fp.address}' is advertising from THIS PC's own Bluetooth "
                      f"adapter ({fp.address}) — a software sensor emulator is running locally.",
                      {"fingerprint": fp.to_dict()}, dedupe=fp.address)

    def _rule_brand_mismatch(self, fp: DeviceFingerprint) -> None:
        if not fp.name or not fp.company_ids:
            return
        nn = _norm_name(fp.name)
        for brand, allowed in self.cfg.get("brand_company_ids", {}).items():
            if brand in nn and not any(cid in allowed for cid in fp.company_ids):
                self.emit(SEV_WARN, "R04-brand-mismatch",
                          f"'{fp.name}' claims brand '{brand}' but its manufacturer data carries "
                          f"company ID(s) {fp.company_ids}, expected {allowed}. "
                          f"Possible impersonation of a known sensor.",
                          {"fingerprint": fp.to_dict(), "expected_company_ids": allowed},
                          dedupe=fp.address)

    def _rule_rssi(self, fp: DeviceFingerprint) -> None:
        if fp.rssi_baseline is None or fp.rssi_last is None:
            return
        if fp._rssi_samples < self.cfg.get("rssi_min_samples", 10):
            return
        jump = abs(fp.rssi_last - fp.rssi_baseline)
        if jump >= self.cfg.get("rssi_jump_db", 25):
            self.emit(SEV_WARN, "R05-rssi-anomaly",
                      f"Signal strength of '{fp.name or fp.address}' jumped {jump:.0f} dB from its "
                      f"session baseline ({fp.rssi_baseline:.0f} -> {fp.rssi_last} dBm) — device "
                      f"moved, was swapped, or is being relayed.",
                      {"address": fp.address, "baseline": fp.rssi_baseline, "current": fp.rssi_last},
                      dedupe=f"{fp.address}:{int(jump // 10)}")

    def _rule_registry(self, fp: DeviceFingerprint) -> None:
        if not self.registry or not fp.name:
            return
        nn = _norm_name(fp.name)
        reg = self.registry.get(nn)
        if reg is None:
            return
        if reg["source"] == fp.source and reg["address"] != fp.address.upper():
            self.emit(SEV_ALERT, "R12-registry-mismatch",
                      f"'{fp.name}' matches registered equipment but its address differs: "
                      f"registered {reg['address']}, observed {fp.address}. "
                      f"This is not the registered physical device.",
                      {"registered": reg, "observed": fp.to_dict()}, dedupe=fp.address)

    # ------------------------------------------------------------------ ticks

    def tick(self) -> None:
        """Periodic housekeeping: baseline locking."""
        if (not self.baseline_locked and self._first_device_ts is not None
                and now_ts() - self._first_device_ts >= self.cfg.get("baseline_lock_seconds", 120)):
            self.baseline_locked = True
            names = [f"'{d.name or d.address}'" for d in self.devices.values()
                     if d.source in ("ble", "ant")]
            self.emit(SEV_INFO, "baseline-lock",
                      f"Session baseline locked with {len(names)} fitness device(s): {', '.join(names)}. "
                      f"Identity changes from here on are integrity violations.")

    # ----------------------------------------------------------------- report

    def build_report(self) -> dict[str, Any]:
        counts = {SEV_INFO: 0, SEV_WARN: 0, SEV_ALERT: 0}
        rules_hit: dict[str, int] = {}
        for e in self.events:
            counts[e.severity] = counts.get(e.severity, 0) + 1
            if e.rule.startswith("R"):
                rules_hit[e.rule] = rules_hit.get(e.rule, 0) + 1
        verdict = "CLEAN"
        if counts[SEV_ALERT]:
            verdict = "INTEGRITY VIOLATIONS DETECTED"
        elif counts[SEV_WARN]:
            verdict = "SUSPICIOUS ACTIVITY - REVIEW WARNINGS"
        return {
            "tool": "zwiftguard",
            "session_id": self.session_id,
            "genesis_hash": self.genesis,
            "started": self.started,
            "ended": now_ts(),
            "verdict": verdict,
            "severity_counts": counts,
            "rules_triggered": rules_hit,
            "devices": [fp.to_dict() for fp in self.devices.values()],
            "events": [e.to_dict() for e in self.events],
            "final_hash": self._last_hash,
        }

    def write_report(self, report_dir: str) -> str:
        d = Path(report_dir)
        d.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(self.started))
        path = d / f"session_{stamp}.json"
        path.write_text(json.dumps(self.build_report(), indent=2, default=str), encoding="utf-8")
        return str(path)
