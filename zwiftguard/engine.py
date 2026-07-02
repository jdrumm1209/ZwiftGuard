# Copyright (c) 2026 Jason Drummond. All rights reserved.
# Proprietary software: see the "Proprietary License" file in this
# repository. No use, copying, or redistribution without written consent.
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
  R14 profile-power     sustained power exceeds the rider's own best-power curve
  R15 sticky-watts      power value frozen for an extended period under load
  R16 zero-cadence      sustained power with the cranks not turning
  R17 robot-smooth      power variance impossibly low for a human (ERG caveat)
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
        self._ant_role_ids: dict[str, str] = {}      # role/channel -> device id
        self._ant_ids: set[str] = set()              # all ANT+ device IDs seen
        self._tnp_name: str = ""                     # direct-connect trainer name
        self._ghost_pending: dict[str, tuple[str, str, float]] = {}  # nn -> (name, line, ts)
        self._offline: set[str] = set()              # device keys currently off the air
        self._zwift_paired_names: set[str] = set()
        # network state
        self._ip_macs: dict[str, str] = {}
        self.zwift_servers: dict[str, list[int]] = {}   # public endpoint ip -> ports
        self.zwift_running: bool = False
        self.zwift_process_list: list[str] = []
        # rider identity / location shown on the dashboard
        self.rider: dict[str, Any] = dict(config.get("rider_profile") or {})
        self.location: dict[str, Any] = {}
        self.local_ips: list[str] = []
        self.known_device_names: list[str] = []
        # live power feed state (see observe_power)
        self.power_source: str = ""
        self.power_connected: bool = False
        self._pw: dict[int, list] = {}        # second -> [sum, count]
        self._pw_last: Optional[int] = None   # last instantaneous watts
        self._pw_cadence: Optional[int] = None
        self._pw_bests: dict[str, int] = {}   # session bests per window label
        self._pw_freeze_start: Optional[float] = None
        self._pw_freeze_val: Optional[int] = None
        self._pw_zerocad_start: Optional[float] = None
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
            if severity == SEV_ALERT:
                try:
                    import winsound
                    winsound.MessageBeep(winsound.MB_ICONHAND)
                except Exception:
                    pass

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
            if key in self._offline:
                self._offline.discard(key)
                gap = now_ts() - fp.last_seen
                self.emit(SEV_WARN if self.baseline_locked else SEV_INFO, "R18-reconnect",
                          f"'{fp.name or fp.address}' is back on the air after {gap:.0f}s offline"
                          + (" mid-session — identity rules re-checked" if self.baseline_locked else ""),
                          {"address": fp.address, "offline_seconds": round(gap)},
                          dedupe=f"{key}:{int(fp.last_seen)}")
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

    def observe_ant_ident(self, ident: str, mfg: int, model: int, raw_line: str) -> None:
        """'[ANT] dID <id> MFG <n> Model <m>' — name the ANT+ sensor properly."""
        self._ant_ids.add(ident)
        mfg_name = self.cfg.get("ant_manufacturer_ids", {}).get(str(mfg), f"MFG {mfg}")
        label = f"{mfg_name} ANT+ sensor (model {model})"
        key = f"ant:{ident}"
        fp = self.devices.get(key)
        if fp is None:
            fp = DeviceFingerprint(source="ant", address=str(ident), name=label)
            self.devices[key] = fp
            self._on_new_device(fp)
        else:
            fp.last_seen = now_ts()
            if fp.name in ("", "device") or fp.name.startswith("channel "):
                fp.name = label
                self.emit(SEV_INFO, "zwift-pairing",
                          f"ANT+ device {ident} identified: {label}",
                          {"log_line": raw_line}, dedupe=f"antid:{ident}")

    def observe_equipment_status(self, name: str, status: str, raw_line: str) -> None:
        """Zwift-reported link-state change (disconnect / unpair / TCP close)."""
        sev = SEV_WARN if (self.baseline_locked and status.startswith("disconnect")) else SEV_INFO
        self.emit(sev, "R18-connection",
                  f"Equipment link change: '{name}' {status}"
                  + (" mid-session" if self.baseline_locked else ""),
                  {"name": name, "status": status, "log_line": raw_line},
                  dedupe=f"{name}:{status}:{int(now_ts() / 60)}")

    def observe_zwift_pairing(self, kind: str, name: str, ident: str, raw_line: str,
                              role: str = "") -> None:
        """Called by the Zwift log tailer. kind: 'ant' | 'ble' | 'tnp' | 'generic'."""
        nn = _norm_name(name)
        if kind == "tnp":
            # Direct-connect (Wahoo TNP over LAN) trainer: give the anonymous
            # LAN fingerprint(s) their real name.
            self._tnp_name = name
            for fp in self.devices.values():
                if fp.source == "network" and fp.name.startswith("LAN device"):
                    fp.name = f"{name} (Direct Connect)"
            self.emit(SEV_INFO, "zwift-pairing",
                      f"Zwift log: direct-connect trainer '{name}' (Wahoo TNP over LAN)",
                      {"log_line": raw_line}, dedupe=f"tnp:{nn}")
            if nn:
                self._zwift_paired_names.add(nn)
            return
        if kind == "ant" and ident:
            role = name or "device"
            if role.isdigit():
                role = f"channel {role}"
            self._ant_ids.add(ident)
            # R10 only applies when the role/channel is known: several distinct
            # ANT sensors legitimately appear under the anonymous "device" role.
            if role != "device":
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
        # A [BLE]-tagged pairing whose name embeds a known ANT id names that
        # ANT sensor (e.g. 'HR Strap 43692' -> ant:43692), role included.
        if kind in ("ble", "generic") and name:
            for aid in re.findall(r"\d{3,10}", name):
                fp = self.devices.get(f"ant:{aid}")
                if fp is not None and (fp.name in ("", "device", name) or fp.name.startswith("channel ")
                                       or "ANT+ sensor" in fp.name):
                    fp.name = name + (f" ({role})" if role else "")
        self.emit(SEV_INFO, "zwift-pairing",
                  f"Zwift log: paired {kind} device '{name}'"
                  + (f" role={role}" if role else "") + (f" id={ident}" if ident else ""),
                  {"log_line": raw_line}, dedupe=f"{kind}:{name}:{ident}")
        # R09 candidate: Zwift paired with something we never saw advertising.
        # Evaluation is deferred ~10s (see tick) because log lines for the
        # same device can arrive in any order: Zwift's device manager logs
        # ANT+ sensors under the [BLE] tag with the ANT ID embedded in the
        # name ("HR Strap 43692"), and those are on ANT, not BLE.
        if kind == "ble" and nn and nn not in self._ghost_pending:
            self._ghost_pending[nn] = (name, raw_line, now_ts())

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
        port_tag = f"tcp:{port}"
        fp = self.devices.get(key)
        if fp is None:
            name = (f"{self._tnp_name} (Direct Connect)" if self._tnp_name
                    else f"LAN device {ip}")
            fp = DeviceFingerprint(source="network", address=ip, mac=mac or "",
                                   name=name, services=[port_tag])
            self.devices[key] = fp
            self._on_new_device(fp)
        else:
            fp.last_seen = now_ts()
            if port_tag not in fp.services:
                fp.services = sorted(set(fp.services) | {port_tag})
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

    def observe_zwift_server(self, ip: str, port: int) -> None:
        ports = self.zwift_servers.setdefault(ip, [])
        if port not in ports:
            ports.append(port)
        self.emit(SEV_INFO, "net-monitor", f"Zwift server endpoint: {ip}:{port}",
                  {"ip": ip, "port": port}, dedupe=f"srv:{ip}")

    def set_zwift_running(self, names: list[str]) -> None:
        self.zwift_running = bool(names)
        self.zwift_process_list = names

    def set_location(self, info: dict[str, Any]) -> None:
        self.location = info
        where = ", ".join(x for x in (info.get("city"), info.get("country")) if x)
        self.emit(SEV_INFO, "net-monitor",
                  f"Connection origin: public IP {info.get('public_ip')} ({where}, "
                  f"{info.get('timezone')}, ISP: {info.get('org')})",
                  dict(info), dedupe="geo")

    def set_local_ips(self, ips: list[str]) -> None:
        self.local_ips = [ip for ip in ips if ip]

    def set_player_id(self, player_id: str, raw_line: str) -> None:
        self.rider["player_id"] = player_id
        self.emit(SEV_INFO, "zwift-log", f"Zwift player ID from game log: {player_id}",
                  {"log_line": raw_line}, dedupe=f"pid:{player_id}")

    def set_known_devices(self, names: list[str]) -> None:
        self.known_device_names = names
        if names:
            self.emit(SEV_INFO, "zwift-local",
                      f"Loaded Zwift's historical device list ({len(names)} sensors ever paired)")

    def apply_local_profile(self, info: Optional[dict[str, Any]]) -> None:
        """Fill rider power profile from Zwift's local ride cache (config wins)."""
        if not info:
            return
        pb = self.rider.get("power_bests_w") or {}
        if not any(pb.get(k) for k in ("5s", "1m", "5m", "20m")):
            self.rider["power_bests_w"] = dict(info["bests_w"])
            self.rider["bests_source"] = f"Zwift ride cache ({info['rides_scanned']} rides, all-time)"
        if not self.rider.get("ftp_w") and info.get("ftp_estimate_w"):
            self.rider["ftp_w"] = info["ftp_estimate_w"]
            self.rider["ftp_estimated"] = True
        b = self.rider.get("power_bests_w", {})
        self.emit(SEV_INFO, "zwift-local",
                  f"Rider power profile from Zwift's local ride cache "
                  f"({info['rides_scanned']} rides): 5s {b.get('5s', '?')}W / 1m {b.get('1m', '?')}W / "
                  f"5m {b.get('5m', '?')}W / 20m {b.get('20m', '?')}W"
                  + (f", FTP~{self.rider['ftp_w']}W (est.)" if self.rider.get("ftp_estimated") else ""),
                  {"cp": info})

    # ------------------------------------------------------------- live power

    POWER_WINDOWS = {"5s": 5, "1m": 60, "5m": 300, "20m": 1200}

    def set_power_source(self, name: str, connected: bool) -> None:
        self.power_source = name
        self.power_connected = connected

    def _rolling_avg(self, now: float, span: int) -> Optional[float]:
        sec = int(now)
        total = cnt = buckets = 0
        for s in range(sec - span + 1, sec + 1):
            b = self._pw.get(s)
            if b:
                total += b[0]
                cnt += b[1]
                buckets += 1
        if cnt == 0 or buckets < max(1, int(span * 0.8)):  # need 80% coverage
            return None
        return total / cnt

    def observe_power(self, watts: int, cadence: Optional[int]) -> None:
        now = now_ts()
        sec = int(now)
        b = self._pw.setdefault(sec, [0, 0])
        b[0] += watts
        b[1] += 1
        self._pw_last = watts
        if cadence is not None:
            self._pw_cadence = cadence
        if len(self._pw) > 1400:
            cut = sec - 1300
            for k in [k for k in self._pw if k < cut]:
                del self._pw[k]
        pr = self.cfg.get("power_rules", {})
        profile = self.rider.get("power_bests_w") or {}
        tol = 1 + pr.get("profile_tolerance_pct", 15) / 100.0
        for label, span in self.POWER_WINDOWS.items():
            avg = self._rolling_avg(now, span)
            if avg is None:
                continue
            if avg > self._pw_bests.get(label, 0):
                self._pw_bests[label] = round(avg)
            ref = profile.get(label) or 0
            if ref and avg > ref * tol:
                self.emit(SEV_ALERT, "R14-profile-power",
                          f"Rider produced {avg:.0f} W over {label} — {avg / ref * 100 - 100:.0f}% above "
                          f"their own all-time {label} best of {ref} W. Inconsistent with the rider "
                          f"profile; review this session's power source.",
                          {"window": label, "session_avg_w": round(avg), "profile_best_w": ref},
                          dedupe=f"R14:{label}")
        self._rule_sticky(now, watts, pr)
        self._rule_zero_cadence(now, watts, cadence, pr)
        self._rule_smoothness(now, sec, pr)

    def _rule_sticky(self, now: float, watts: int, pr: dict) -> None:
        min_w = pr.get("sticky_min_watts", 100)
        hold = pr.get("sticky_seconds", 30)
        if watts >= min_w and self._pw_freeze_val is not None and abs(watts - self._pw_freeze_val) <= 1:
            if self._pw_freeze_start and now - self._pw_freeze_start >= hold:
                self.emit(SEV_WARN, "R15-sticky-watts",
                          f"Power value frozen at {watts} W for {now - self._pw_freeze_start:.0f}s — "
                          f"real pedaling fluctuates; a frozen value is the classic 'sticky watts' signature.",
                          {"watts": watts, "seconds": round(now - self._pw_freeze_start)},
                          dedupe=f"R15:{int(self._pw_freeze_start)}")
        else:
            self._pw_freeze_val = watts if watts >= min_w else None
            self._pw_freeze_start = now if watts >= min_w else None

    def _rule_zero_cadence(self, now: float, watts: int, cadence: Optional[int], pr: dict) -> None:
        if cadence == 0 and watts >= pr.get("sticky_min_watts", 100):
            if self._pw_zerocad_start is None:
                self._pw_zerocad_start = now
            elif now - self._pw_zerocad_start >= pr.get("zero_cadence_seconds", 10):
                self.emit(SEV_ALERT, "R16-zero-cadence",
                          f"{watts} W sustained with the cranks not turning for "
                          f"{now - self._pw_zerocad_start:.0f}s — physically impossible; "
                          f"the power data is not coming from the pedals.",
                          {"watts": watts, "seconds": round(now - self._pw_zerocad_start)},
                          dedupe=f"R16:{int(self._pw_zerocad_start)}")
        else:
            self._pw_zerocad_start = None

    def _rule_smoothness(self, now: float, sec: int, pr: dict) -> None:
        if sec % 30 != 0 or self._pw.get(sec, [0, 0])[1] != 1:
            return  # evaluate once per 30s
        span = pr.get("smooth_window_s", 120)
        vals = [b[0] / b[1] for s in range(sec - span + 1, sec + 1)
                if (b := self._pw.get(s)) and b[1]]
        if len(vals) < span * 0.8:
            return
        mean = sum(vals) / len(vals)
        if mean < pr.get("smooth_min_watts", 180):
            return
        var = sum((v - mean) ** 2 for v in vals) / len(vals)
        if var ** 0.5 < pr.get("smooth_stdev_w", 2.0):
            self.emit(SEV_WARN, "R17-robot-smooth",
                      f"Power over the last {span}s averages {mean:.0f} W with a standard deviation "
                      f"of only {var ** 0.5:.1f} W — implausibly smooth for human pedaling. "
                      f"(Note: ERG mode legitimately reduces variance; treat as a review flag.)",
                      {"mean_w": round(mean), "stdev_w": round(var ** 0.5, 2), "window_s": span},
                      dedupe=f"R17:{sec // 600}")

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
        if fp.source == "ble" and fp.name and self.known_device_names:
            nn = _norm_name(fp.name)
            known = any(nn in _norm_name(k) or _norm_name(k) in nn
                        for k in self.known_device_names)
            if not known:
                self.emit(SEV_INFO, "first-time-device",
                          f"'{fp.name}' is not in Zwift's historical device list — "
                          f"first-time equipment on this install",
                          {"name": fp.name}, dedupe=fp.address)
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
        """Housekeeping: baseline lock, deferred R09, BLE dropout sweep."""
        timeout = self.cfg.get("equipment_timeout_s", 45)
        for key, fp in self.devices.items():
            if fp.source != "ble" or key in self._offline:
                continue
            gap = now_ts() - fp.last_seen
            if gap > timeout:
                self._offline.add(key)
                self.emit(SEV_WARN if self.baseline_locked else SEV_INFO, "R18-dropout",
                          f"Signal from '{fp.name or fp.address}' lost — no advertisements for "
                          f"{gap:.0f}s (powered off, out of range, or now exclusively connected)"
                          + (" mid-session" if self.baseline_locked else ""),
                          {"address": fp.address, "gap_seconds": round(gap)},
                          dedupe=f"{key}:{int(fp.last_seen)}")
        for nn in list(self._ghost_pending):
            name, raw_line, ts = self._ghost_pending[nn]
            if any(aid in name for aid in self._ant_ids) or self._seen_on_air(nn):
                del self._ghost_pending[nn]        # resolved: ANT+ device or seen on air
            elif now_ts() - ts >= 10:
                del self._ghost_pending[nn]
                self.emit(SEV_WARN, "R09-ghost-pairing",
                          f"Zwift paired with BLE device '{name}' that was never observed "
                          f"advertising on this machine's radio (bridged via Companion app, "
                          f"another adapter, or emulated)",
                          {"name": name, "log_line": raw_line}, dedupe=nn)
        if (not self.baseline_locked and self._first_device_ts is not None
                and now_ts() - self._first_device_ts >= self.cfg.get("baseline_lock_seconds", 120)):
            self.baseline_locked = True
            names = [f"'{d.name or d.address}'" for d in self.devices.values()
                     if d.source in ("ble", "ant")]
            self.emit(SEV_INFO, "baseline-lock",
                      f"Session baseline locked with {len(names)} fitness device(s): {', '.join(names)}. "
                      f"Identity changes from here on are integrity violations.")

    # -------------------------------------------------------------- dashboard

    def state_snapshot(self) -> dict[str, Any]:
        """Thread-safe-enough snapshot of live state for the web dashboard."""
        counts = {SEV_INFO: 0, SEV_WARN: 0, SEV_ALERT: 0}
        for e in self.events:
            counts[e.severity] = counts.get(e.severity, 0) + 1
        verdict = "CLEAN"
        if counts[SEV_ALERT]:
            verdict = "INTEGRITY VIOLATIONS DETECTED"
        elif counts[SEV_WARN]:
            verdict = "SUSPICIOUS - REVIEW WARNINGS"

        # Per-device status: worst severity of any warning/alert that mentions it.
        flagged: list[tuple[str, str]] = []
        for e in list(self.events):
            if e.severity in (SEV_WARN, SEV_ALERT):
                blob = (json.dumps(e.evidence, default=str) + e.message).upper()
                flagged.append((e.severity, blob))
        devices = []
        for fp in list(self.devices.values()):
            status = "ok"
            # word-boundary match so ANT id "43692" does not hit "43692120"
            ident_re = re.compile(r"(?<![0-9A-Z])" + re.escape(fp.address.upper()) + r"(?![0-9A-Z])")
            name_up = fp.name.upper() if fp.name else None
            for sev, blob in flagged:
                if ident_re.search(blob) or (name_up and name_up in blob):
                    if sev == SEV_ALERT:
                        status = "alert"
                        break
                    status = "warn"
            d = fp.to_dict()
            d["status"] = status
            d["online"] = (fp.source != "ble"
                           or now_ts() - fp.last_seen <= self.cfg.get("equipment_timeout_s", 45))
            devices.append(d)

        return {
            "session_id": self.session_id,
            "started": self.started,
            "now": now_ts(),
            "verdict": verdict,
            "severity_counts": counts,
            "baseline_locked": self.baseline_locked,
            "zwift_running": self.zwift_running,
            "zwift_processes": list(self.zwift_process_list),
            "zwift_servers": {ip: list(ports) for ip, ports in self.zwift_servers.items()},
            "local_adapter_macs": sorted(self._local_adapter_macs),
            "local_ips": list(self.local_ips),
            "rider": dict(self.rider),
            "location": dict(self.location),
            "power": self._power_snapshot(),
            "devices": devices,
            "events": [e.to_dict() for e in list(self.events)[-200:]],
        }

    def _power_snapshot(self) -> dict[str, Any]:
        now = now_ts()
        sec = int(now)
        avg3 = self._rolling_avg(now, 3)
        weight = self.rider.get("weight_kg") or 0
        history = []
        span = 900
        for s in range(sec - span + 1, sec + 1, 5):   # one point per 5s
            pts = [b[0] / b[1] for x in range(s, min(s + 5, sec + 1))
                   if (b := self._pw.get(x)) and b[1]]
            if pts:
                history.append([s - sec, round(sum(pts) / len(pts))])
        return {
            "connected": self.power_connected,
            "source": self.power_source,
            "watts": self._pw_last,
            "avg3s": round(avg3) if avg3 is not None else None,
            "cadence": self._pw_cadence,
            "wkg": round(avg3 / weight, 2) if (avg3 is not None and weight) else None,
            "session_bests": dict(self._pw_bests),
            "profile_bests": dict(self.rider.get("power_bests_w") or {}),
            "history": history,
        }

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
            "zwift_servers": {ip: list(ports) for ip, ports in self.zwift_servers.items()},
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
