"""Network monitor.

Watches the TCP connections held by the Zwift process itself:

  - Loopback peers (127.0.0.1): another program on this PC is inserted
    between the equipment/network and Zwift (proxy or bridge) -> ALERT,
    unless the peer is another Zwift component (launcher etc.).
  - Private LAN peers: direct-connect trainers (e.g. KICKR Direct Connect,
    Zwift Hub over WiFi). The peer's MAC address is resolved from the ARP
    table and fingerprinted; if the MAC behind that IP changes mid-session
    the engine raises R13 (device swapped or ARP spoofing).
  - Public peers: Zwift's own servers; counted but not fingerprinted.

Also checks the Windows hosts file for redirected Zwift domains (a classic
way to route game traffic through a tampering proxy).
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import subprocess
from typing import Any, Optional

import psutil

from .engine import IntegrityEngine

_ARP_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})\s", re.MULTILINE)
_HOSTS_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                           "System32", "drivers", "etc", "hosts")


def read_arp_table() -> dict[str, str]:
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return {}
    return {ip: mac.replace("-", ":").upper() for ip, mac in _ARP_RE.findall(out)}


class NetworkMonitor:
    def __init__(self, engine: IntegrityEngine, config: dict[str, Any]):
        self.engine = engine
        self.cfg = config
        self._zwift_names = [n.lower() for n in config.get("zwift_process_names", [])]
        self._zwift_seen = False
        self._public_peer_count = 0
        self._lan_present: set[str] = set()
        self._lan_ever: set[str] = set()

    # ------------------------------------------------------------- helpers

    def _zwift_procs(self) -> list[psutil.Process]:
        procs = []
        me = os.getpid()
        for p in psutil.process_iter(["pid", "name"]):
            try:
                name = (p.info["name"] or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            # "zwiftguard" itself contains "zwift"; also skip the PyInstaller
            # bootloader parent, which is a second zwiftguard.exe process.
            if "zwiftguard" in name:
                continue
            if p.info["pid"] != me and any(z in name for z in self._zwift_names):
                procs.append(p)
        return procs

    def _peer_process_name(self, ip: str, port: int) -> Optional[str]:
        """Which local process owns the other end of a loopback connection?"""
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.laddr and c.laddr.ip in ("127.0.0.1", "::1") and c.laddr.port == port and c.pid:
                    try:
                        return psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        return None
        except (psutil.AccessDenied, PermissionError):
            return None
        return None

    def _check_hosts_file(self) -> None:
        try:
            with open(_HOSTS_PATH, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    for domain in self.cfg.get("zwift_domains", []):
                        if domain.lower() in stripped.lower():
                            self.engine.observe_hosts_redirect(line, domain)
        except OSError:
            pass

    def _poll_connections(self) -> None:
        procs = self._zwift_procs()
        self.engine.set_zwift_running([p.info["name"] for p in procs])
        if procs and not self._zwift_seen:
            self._zwift_seen = True
            self.engine.emit("INFO", "net-monitor",
                             f"Zwift process detected: {', '.join(p.info['name'] for p in procs)}")
        elif not procs and self._zwift_seen:
            self._zwift_seen = False
            self.engine.emit("INFO", "net-monitor", "Zwift process exited")

        arp = None  # lazy: only read the ARP table if a LAN peer shows up
        current_lan: set[str] = set()
        for p in procs:
            try:
                conns = p.net_connections(kind="inet")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            for c in conns:
                if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
                    continue
                ip_s = c.raddr.ip
                try:
                    ip = ipaddress.ip_address(ip_s)
                except ValueError:
                    continue
                if ip.is_loopback:
                    peer = self._peer_process_name(ip_s, c.raddr.port)
                    if peer and any(z in peer.lower() for z in self._zwift_names):
                        self.engine.emit("INFO", "net-monitor",
                                         f"Zwift internal loopback connection to {peer} (expected)",
                                         dedupe=f"loop:{peer}")
                    else:
                        self.engine.observe_network_peer(ip_s, c.raddr.port, mac="",
                                                         is_loopback=True, peer_process=peer)
                elif ip.is_private:
                    current_lan.add(ip_s)
                    if arp is None:
                        arp = read_arp_table()
                    self.engine.observe_network_peer(ip_s, c.raddr.port,
                                                     mac=arp.get(ip_s, ""), is_loopback=False)
                else:
                    self._public_peer_count += 1
                    self.engine.observe_zwift_server(ip_s, c.raddr.port)

        # Direct-connect trainer link-state transitions (only while Zwift is
        # up, so its normal exit does not spam disconnect events).
        if procs:
            for ip_s in self._lan_present - current_lan:
                fp = self.engine.devices.get(f"network:{ip_s}")
                self.engine.observe_equipment_status(fp.name if fp else ip_s,
                                                     "TCP link closed", "")
            for ip_s in current_lan - self._lan_present:
                if ip_s in self._lan_ever:
                    fp = self.engine.devices.get(f"network:{ip_s}")
                    self.engine.observe_equipment_status(fp.name if fp else ip_s,
                                                         "TCP link re-established", "")
            self._lan_present = current_lan
            self._lan_ever |= current_lan
        else:
            self._lan_present = set()

    # ----------------------------------------------------------------- run

    async def run(self, stop: asyncio.Event) -> None:
        interval = self.cfg.get("network_poll_interval", 8)
        self.engine.emit("INFO", "net-monitor", "Network watch running (Zwift connections + hosts file)")
        await asyncio.to_thread(self._check_hosts_file)
        hosts_check_counter = 0
        while not stop.is_set():
            try:
                await asyncio.to_thread(self._poll_connections)
                hosts_check_counter += 1
                if hosts_check_counter >= 8:  # re-check hosts file occasionally
                    hosts_check_counter = 0
                    await asyncio.to_thread(self._check_hosts_file)
            except Exception as e:
                self.engine.emit("WARN", "net-monitor", f"Network scan error: {e}")
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
