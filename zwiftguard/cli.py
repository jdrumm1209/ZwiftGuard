"""ZwiftGuard command-line interface.

Usage examples:
  python -m zwiftguard                      # monitor until Ctrl+C, write report
  python -m zwiftguard --duration 3600      # monitor one hour
  python -m zwiftguard --register 60        # scan 60s and save trusted equipment
  python -m zwiftguard --scan-only 30       # 30s inventory scan, no session report
  python -m zwiftguard --verify-report reports/session_x.json
  python -m zwiftguard --write-config zwiftguard.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
from pathlib import Path

from .ble_monitor import BleMonitor
from .config import load_config, write_default_config
from .engine import IntegrityEngine
from .models import verify_chain
from .net_monitor import NetworkMonitor
from .proc_monitor import ProcessMonitor
from .zwift_log import ZwiftLogMonitor

BANNER = r"""
 ZwiftGuard - equipment integrity monitor
 Fingerprints the trainers / HR monitors / power meters feeding Zwift and
 flags identity changes and man-in-the-middle bridges during the session.
"""


def _enable_ansi() -> None:
    if os.name == "nt":
        os.system("")  # enables VT processing in classic conhost
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


async def run_session(cfg: dict, duration: float | None, register_path: str | None,
                      disable: set[str], open_browser: bool = True) -> int:
    engine = IntegrityEngine(cfg)
    if not register_path:
        engine.load_registry(cfg.get("baseline_file", "baseline.json"))

    dashboard = None
    if "dash" not in disable:
        from .dashboard import Dashboard
        try:
            dashboard = Dashboard(engine, cfg.get("dashboard_port", 8377))
            url = dashboard.start()
            engine.emit("INFO", "dashboard", f"Live dashboard: {url}")
            if open_browser and not register_path:
                import webbrowser
                webbrowser.open(url)
        except OSError as e:
            dashboard = None
            engine.emit("WARN", "dashboard", f"Dashboard unavailable: {e}")

    stop = asyncio.Event()

    def _request_stop(*_a) -> None:
        stop.set()

    try:
        signal.signal(signal.SIGINT, _request_stop)
        signal.signal(signal.SIGTERM, _request_stop)
    except (ValueError, OSError):
        pass

    from . import geo
    engine.set_local_ips([geo.local_ip()])

    async def geo_task() -> None:
        if cfg.get("public_ip_lookup", True):
            info = await asyncio.to_thread(geo.lookup_public_ip)
            if info:
                engine.set_location(info)

    monitors = [geo_task()]
    if "ble" not in disable:
        monitors.append(BleMonitor(engine, cfg).run(stop))
    if "log" not in disable:
        monitors.append(ZwiftLogMonitor(engine, cfg).run(stop))
    if "proc" not in disable:
        monitors.append(ProcessMonitor(engine, cfg).run(stop))
    if "net" not in disable:
        monitors.append(NetworkMonitor(engine, cfg).run(stop))

    async def ticker() -> None:
        while not stop.is_set():
            engine.tick()
            try:
                await asyncio.wait_for(stop.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass

    async def timer() -> None:
        if duration:
            try:
                await asyncio.wait_for(stop.wait(), timeout=duration)
            except asyncio.TimeoutError:
                stop.set()

    tasks = [asyncio.create_task(c) for c in monitors]
    tasks += [asyncio.create_task(ticker()), asyncio.create_task(timer())]

    # Windows: signal handlers only fire while the loop wakes up, so poll.
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=0.5)
        except asyncio.TimeoutError:
            pass
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    if dashboard:
        dashboard.stop()

    if register_path:
        engine.save_registry(register_path)
        print(f"\nTrusted-equipment registry saved: {register_path}")
        for fp in engine.devices.values():
            print(f"  {fp.source:8s} {fp.address:20s} {fp.name or '(no name)'}  "
                  f"fingerprint={fp.identity_hash()}")
        return 0

    report = engine.build_report()
    path = engine.write_report(cfg.get("report_dir", "reports"))
    c = report["severity_counts"]
    print("\n" + "=" * 70)
    print(f" Session verdict : {report['verdict']}")
    print(f" Devices seen    : {len(report['devices'])}")
    print(f" Events          : {c.get('INFO', 0)} info / {c.get('WARN', 0)} warn / {c.get('ALERT', 0)} alert")
    if report["rules_triggered"]:
        print(f" Rules triggered : {', '.join(sorted(report['rules_triggered']))}")
    print(f" Report          : {path}")
    print(f" Final chain hash: {report['final_hash'][:32]}...")
    print("=" * 70)
    return 2 if c.get("ALERT") else (1 if c.get("WARN") else 0)


def cmd_verify(path: str) -> int:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    ok, bad = verify_chain(data.get("events", []), data.get("genesis_hash", ""))
    if ok and data.get("events") and data["events"][-1]["hash"] == data.get("final_hash"):
        print(f"OK: report intact, {len(data['events'])} events, "
              f"chain ends at {data['final_hash'][:32]}...")
        return 0
    if ok:
        print("TAMPERED: final_hash does not match last event")
    else:
        print(f"TAMPERED: hash chain breaks at event index {bad}")
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="zwiftguard", description=BANNER,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", help="path to a JSON config file")
    parser.add_argument("--duration", type=float, default=None,
                        help="stop after N seconds (default: run until Ctrl+C)")
    parser.add_argument("--scan-only", type=float, metavar="SECONDS",
                        help="short inventory scan; equivalent to --duration N")
    parser.add_argument("--register", type=float, metavar="SECONDS",
                        help="scan for N seconds and save the observed equipment as the "
                             "trusted registry (baseline.json)")
    parser.add_argument("--disable", action="append", default=[],
                        choices=["ble", "log", "proc", "net", "dash"],
                        help="turn off a monitor or the dashboard (repeatable)")
    parser.add_argument("--no-browser", action="store_true",
                        help="do not auto-open the dashboard in a browser")
    parser.add_argument("--dashboard-port", type=int,
                        help="dashboard port (default 8377, 127.0.0.1 only)")
    parser.add_argument("--zwift-log", help="override path to Zwift's Log.txt")
    parser.add_argument("--report-dir", help="directory for session reports")
    parser.add_argument("--verify-report", metavar="REPORT_JSON",
                        help="verify the tamper-evident hash chain of a saved report")
    parser.add_argument("--write-config", metavar="PATH",
                        help="write the default config to PATH and exit")
    args = parser.parse_args(argv)

    if args.write_config:
        write_default_config(args.write_config)
        print(f"Default config written to {args.write_config}")
        return 0
    if args.verify_report:
        return cmd_verify(args.verify_report)

    cfg = load_config(args.config)
    if args.zwift_log:
        cfg["zwift_log_path"] = args.zwift_log
    if args.report_dir:
        cfg["report_dir"] = args.report_dir
    if args.dashboard_port:
        cfg["dashboard_port"] = args.dashboard_port

    duration = args.duration
    register_path = None
    if args.register:
        duration = args.register
        register_path = cfg.get("baseline_file", "baseline.json")
    elif args.scan_only:
        duration = args.scan_only

    _enable_ansi()
    print(BANNER)
    if duration:
        print(f" Running for {duration:.0f} seconds...\n")
    else:
        print(" Running until Ctrl+C...\n")
    return asyncio.run(run_session(cfg, duration, register_path, set(args.disable),
                                   open_browser=not args.no_browser))


if __name__ == "__main__":
    sys.exit(main())
