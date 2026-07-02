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


def test_ghost_pairing() -> None:
    e = make_engine()
    e.observe_zwift_pairing("ble", "Phantom Trainer", "", "[10:00:01] BLE : Connecting to Phantom Trainer")
    check("Zwift pairing never seen on air raises R09", "R09-ghost-pairing" in rules_fired(e))
    e2 = make_engine()
    e2.observe_ble("AA:00:00:00:00:30", "Real Trainer 99", -60, [], ["1826"])
    e2.observe_zwift_pairing("ble", "Real Trainer 99", "", "[10:00:01] BLE : Connecting to Real Trainer 99")
    check("Zwift pairing that matches an on-air device stays clean", "R09-ghost-pairing" not in rules_fired(e2))


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
    samples = [
        ("[10:01:22] ANT  : Registered device 51423 as PWR", "ant"),
        ("[10:01:25] BLE : Connecting to KICKR CORE 4C21", "ble"),
        ("[10:01:30] Paired POWER device: Wahoo KICKR 1234", "generic"),
    ]
    for line, expected_kind in samples:
        matched = None
        for kind, pat in _PATTERNS:
            if pat.search(line):
                matched = kind
                break
        check(f"parses: {line[:50]}", matched == expected_kind)


def main() -> int:
    for fn in [test_clone_detection, test_identity_change, test_local_emulator,
               test_brand_mismatch, test_rssi_anomaly, test_ant_id_change,
               test_ghost_pairing, test_post_lock_and_baseline, test_loopback_and_arp,
               test_registry_mismatch, test_hash_chain, test_zwift_log_parser]:
        fn()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
