"""Rule-engine tests using synthetic observations (no hardware required).

Run:  python -m tests.test_engine
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zwiftguard.config import load_config
from zwiftguard.engine import IntegrityEngine
from zwiftguard.models import verify_chain

PASS = 0
FAIL = 0


def check(label: str, cond: bool) -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok    {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")


def make_engine() -> IntegrityEngine:
    cfg = load_config(None)
    cfg["rssi_min_samples"] = 3
    return IntegrityEngine(cfg, quiet=True)


def rules_fired(e: IntegrityEngine) -> set[str]:
    return {ev.rule for ev in e.events}


def test_clone_detection() -> None:
    print("clone / identity change (R01, R02)")
    e = make_engine()
    for _ in range(3):
        e.observe_ble("AA:BB:CC:00:00:01", "KICKR CORE 1234", -60, [], ["1818", "1826"])
    # A second, different address starts advertising the same name at once.
    e.observe_ble("DE:AD:BE:EF:00:02", "KICKR CORE 1234", -55, [], ["1818", "1826"])
    check("simultaneous same-name devices raise R02-clone", "R02-clone" in rules_fired(e))


def test_identity_change() -> None:
    e = make_engine()
    e.observe_ble("AA:BB:CC:00:00:01", "TICKR 9F21", -58, [], ["180d"])
    # Simulate original going stale, then the name reappearing on a new address.
    e.devices["ble:AA:BB:CC:00:00:01"].last_seen -= 120
    e.observe_ble("11:22:33:44:55:66", "TICKR 9F21", -58, [], ["180d"])
    check("name on new address after old one went stale raises R01", "R01-identity-change" in rules_fired(e))


def test_local_emulator() -> None:
    print("local emulator (R03)")
    e = make_engine()
    e.set_local_adapter_macs({"F0:0D:CA:FE:00:01"})
    e.observe_ble("F0:0D:CA:FE:00:01", "KICKR SIM", -30, [], ["1826"])
    check("advertising from local adapter raises R03", "R03-local-emulator" in rules_fired(e))


def test_brand_mismatch() -> None:
    print("brand mismatch (R04)")
    e = make_engine()
    e.observe_ble("AA:00:00:00:00:10", "Garmin HRM-Dual", -62, [0x1234], ["180d"])
    check("garmin name with foreign company ID raises R04", "R04-brand-mismatch" in rules_fired(e))
    e2 = make_engine()
    e2.observe_ble("AA:00:00:00:00:11", "Garmin HRM-Dual", -62, [135], ["180d"])
    check("garmin name with Garmin company ID stays clean", "R04-brand-mismatch" not in rules_fired(e2))


def test_rssi_anomaly() -> None:
    print("RSSI anomaly (R05)")
    e = make_engine()
    for _ in range(5):
        e.observe_ble("AA:00:00:00:00:20", "ASSIOMA 77", -50, [], ["1818"])
    e.observe_ble("AA:00:00:00:00:20", "ASSIOMA 77", -90, [], ["1818"])
    check("40 dB jump raises R05", "R05-rssi-anomaly" in rules_fired(e))


def test_ant_id_change() -> None:
    print("ANT+ ID change (R10) + ghost pairing (R09)")
    e = make_engine()
    e.observe_zwift_pairing("ant", "PWR", "12345", "[10:00:01] ANT : device 12345 PWR")
    e.observe_zwift_pairing("ant", "PWR", "54321", "[10:31:07] ANT : device 54321 PWR")
    check("ANT power ID swap mid-session raises R10", "R10-ant-id-change" in rules_fired(e))
    # anonymous "device" role: multiple distinct ANT ids are normal, no R10
    e2 = make_engine()
    e2.observe_zwift_pairing("ant", "", "1141667", "[ANT] dID 1141667 MFG 32 Model 1")
    e2.observe_zwift_pairing("ant", "", "8170156", "[ANT] dID 8170156 MFG 1 Model 4130")
    check("multiple anonymous ANT ids do not raise R10", "R10-ant-id-change" not in rules_fired(e2))


def _age_ghosts(e, secs=11):
    for nn, (n, r, t) in list(e._ghost_pending.items()):
        e._ghost_pending[nn] = (n, r, t - secs)


def test_ghost_pairing() -> None:
    e = make_engine()
    e.observe_zwift_pairing("ble", "Phantom Trainer", "", "[10:00:01] BLE : Connecting to Phantom Trainer")
    _age_ghosts(e)
    e.tick()
    check("Zwift pairing never seen on air raises R09", "R09-ghost-pairing" in rules_fired(e))
    e2 = make_engine()
    e2.observe_ble("AA:00:00:00:00:30", "Real Trainer 99", -60, [], ["1826"])
    e2.observe_zwift_pairing("ble", "Real Trainer 99", "", "[10:00:01] BLE : Connecting to Real Trainer 99")
    _age_ghosts(e2)
    e2.tick()
    check("Zwift pairing that matches an on-air device stays clean", "R09-ghost-pairing" not in rules_fired(e2))
    # ANT+ device logged under Zwift's [BLE] tag with the ANT ID in the name
    # (even when the log lines arrive in the "wrong" order)
    e3 = make_engine()
    e3.observe_zwift_pairing("ble", "HR Strap 43692", "", '[BLE] Device: "HR Strap 43692" ... connected')
    e3.observe_zwift_pairing("ant", "1", "43692", "[ANT_IMPORTANT] Pairing deviceID 43692 to channel 1")
    _age_ghosts(e3)
    e3.tick()
    check("ANT+ sensor aliased under [BLE] tag does not raise R09", "R09-ghost-pairing" not in rules_fired(e3))


def test_tnp_direct_connect() -> None:
    print("direct-connect trainer naming (TNP)")
    e = make_engine()
    e.observe_network_peer("192.168.8.147", 36866, mac="B4:6F:2D:00:25:E1", is_loopback=False)
    e.observe_zwift_pairing("tnp", "Wahoo KICKR 6BA3", "", 'CreateWFTNPDevice for "Wahoo KICKR 6BA3"')
    fp = e.devices["network:192.168.8.147"]
    check("existing LAN device renamed to direct-connect trainer",
          fp.name == "Wahoo KICKR 6BA3 (Direct Connect)")
    check("tcp port recorded on LAN fingerprint", "tcp:36866" in fp.services)


def test_post_lock_and_baseline() -> None:
    print("baseline lock (R11)")
    e = make_engine()
    e.cfg["baseline_lock_seconds"] = 0
    e.observe_ble("AA:00:00:00:00:40", "NEO 2T 555", -55, [], ["1826"])
    e.tick()  # locks immediately with 0-second window
    check("baseline locks", e.baseline_locked)
    e.observe_ble("BB:00:00:00:00:41", "Late Joiner HRM", -70, [], ["180d"])
    check("new device after lock raises R11", "R11-post-lock-device" in rules_fired(e))


def test_loopback_and_arp() -> None:
    print("network rules (R07, R13)")
    e = make_engine()
    e.observe_network_peer("127.0.0.1", 36866, mac="", is_loopback=True, peer_process="evil-bridge.exe")
    check("loopback peer raises R07", "R07-loopback-bridge" in rules_fired(e))
    e2 = make_engine()
    e2.observe_network_peer("192.168.1.50", 36866, mac="AA:BB:CC:DD:EE:01", is_loopback=False)
    e2.observe_network_peer("192.168.1.50", 36866, mac="AA:BB:CC:DD:EE:02", is_loopback=False)
    check("MAC change behind trainer IP raises R13", "R13-arp-change" in rules_fired(e2))


def test_registry_mismatch() -> None:
    print("registry (R12)")
    e = make_engine()
    e.registry = {"kickr core 1234": {
        "name_norm": "kickr core 1234", "name": "KICKR CORE 1234", "source": "ble",
        "address": "AA:BB:CC:00:00:01", "mac": "", "company_ids": [], "services": ["1818"],
        "identity_hash": "x"}}
    e.observe_ble("66:77:88:99:AA:BB", "KICKR CORE 1234", -60, [], ["1818"])
    check("registered name on unknown address raises R12", "R12-registry-mismatch" in rules_fired(e))


def test_hash_chain() -> None:
    print("tamper-evident event chain")
    e = make_engine()
    e.observe_ble("AA:00:00:00:00:50", "Chain Test", -60, [], ["180d"])
    e.observe_zwift_pairing("ant", "HR", "999", "line")
    report = e.build_report()
    ok, _ = verify_chain(report["events"], report["genesis_hash"])
    check("untouched chain verifies", ok)
    report["events"][0]["message"] = "edited after the fact"
    ok2, idx = verify_chain(report["events"], report["genesis_hash"])
    check("edited event breaks the chain at index 0", not ok2 and idx == 0)


def test_zwift_log_parser() -> None:
    print("zwift log line parsing")
    from zwiftguard.zwift_log import _PATTERNS
    # First five lines are verbatim from a real 2026 PC-client Log.txt.
    samples = [
        ("[15:18:50] INFO LEVEL: [BLE] Device selected for role (device: HR Strap 43692, role: HR)",
         "ble", "HR Strap 43692"),
        ('[15:18:50] [BLE] Device: "HR Strap 43692" has new connection status: connected',
         "ble", "HR Strap 43692"),
        ('[15:18:56] INFO LEVEL: [BLE] WFTNPDeviceManager::Pairing device "Wahoo KICKR 6BA3 93"',
         "ble", "Wahoo KICKR 6BA3 93"),
        ('[15:18:49] CreateWFTNPDevice for "Wahoo KICKR 6BA3"',
         "tnp", "Wahoo KICKR 6BA3"),
        ("[15:18:50] [ANT_IMPORTANT] Pairing deviceID 43692 to channel 1, mfg network 0, ant network 0",
         "ant", None),
        ('[15:18:56] INFO LEVEL: [BLE] WFTNPDeviceManager: connecting to LAN device "Wahoo KICKR 6BA3"',
         "tnp", "Wahoo KICKR 6BA3"),
        ("[15:18:50] [ANT] dID 1141667 MFG 32 Model 1", "ant", None),
        ("[15:22:12] DEBUG LEVEL: POWER SOURCE: Interval Stats: device = Wahoo KICKR 6BA3 93, count = 64",
         "generic", "Wahoo KICKR 6BA3 93"),
        # noise lines that must NOT match anything
        ("[15:18:50] [ANT] Setting Channel ID for chan 1 (device 43692120)...", None, None),
        ("[15:18:31] ERROR LEVEL: [LOADER] Unable to load texture file Sky : milkyway.tga", None, None),
        # broad fallbacks for other client versions
        ("[10:01:22] ANT  : Registered device 51423 as PWR", "ant", None),
        ("[10:01:25] BLE : Connecting to KICKR CORE 4C21", "ble", "KICKR CORE 4C21"),
        ("[10:01:30] Paired POWER device: Wahoo KICKR 1234", "generic", "Wahoo KICKR 1234"),
    ]
    for line, expected_kind, expected_name in samples:
        matched = name = None
        for kind, pat in _PATTERNS:
            m = pat.search(line)
            if m:
                matched = kind
                name = (m.groupdict().get("name") or "").strip()
                break
        ok = matched == expected_kind and (expected_name is None or name == expected_name)
        check(f"parses: {line[11:64]}", ok)


def test_state_snapshot() -> None:
    print("dashboard state snapshot")
    import json as _json
    e = make_engine()
    e.observe_ble("AA:BB:CC:00:00:01", "KICKR CORE 1234", -60, [], ["1818", "1826"])
    e.observe_ble("DE:AD:BE:EF:00:02", "KICKR CORE 1234", -55, [], ["1818", "1826"])  # clone alert
    e.observe_zwift_server("54.201.10.5", 443)
    e.set_zwift_running(["ZwiftApp.exe"])
    snap = e.state_snapshot()
    _json.dumps(snap)  # must be JSON-serializable
    check("snapshot serializes to JSON", True)
    check("snapshot records zwift server endpoint", "54.201.10.5" in snap["zwift_servers"])
    check("snapshot reflects zwift running", snap["zwift_running"])
    statuses = {d["address"]: d["status"] for d in snap["devices"]}
    check("cloned device is marked alert in snapshot",
          statuses.get("DE:AD:BE:EF:00:02") == "alert" or statuses.get("AA:BB:CC:00:00:01") == "alert")


def test_dashboard_server() -> None:
    print("dashboard http server")
    import urllib.request
    from zwiftguard.dashboard import Dashboard
    e = make_engine()
    e.observe_ble("AA:BB:CC:00:00:01", "KICKR CORE 1234", -60, [], ["1826"])
    dash = Dashboard(e, port=0)  # ephemeral port
    url = dash.start()
    try:
        html = urllib.request.urlopen(url, timeout=5).read().decode("utf-8")
        check("serves dashboard page", "ZwiftGuard" in html and "Equipment" in html)
        import json as _json
        state = _json.loads(urllib.request.urlopen(url + "state", timeout=5).read())
        check("serves /state JSON with devices", len(state["devices"]) == 1)
    finally:
        dash.stop()


def main() -> int:
    for fn in [test_clone_detection, test_identity_change, test_local_emulator,
               test_brand_mismatch, test_rssi_anomaly, test_ant_id_change,
               test_ghost_pairing, test_post_lock_and_baseline, test_loopback_and_arp,
               test_registry_mismatch, test_hash_chain, test_zwift_log_parser,
               test_tnp_direct_connect, test_state_snapshot, test_dashboard_server]:
        fn()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
