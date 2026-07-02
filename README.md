# ZwiftGuard

A passive equipment-integrity monitor that runs alongside Zwift on Windows.
It fingerprints the smart trainers, heart-rate monitors, and power meters
feeding data into Zwift — Bluetooth MAC address, advertised name,
manufacturer company IDs, advertised services, ANT+ device IDs, and (for
direct-connect trainers) IP and MAC — then watches for anything changing or
inserting itself between the equipment and the game during a session.

It is **detection support, not proof**: alerts identify sessions and devices
that deserve human review. It never connects to the sensors and never touches
the Zwift client, so it cannot disturb a ride.

## What it watches

| Monitor | What it sees | How |
|---|---|---|
| BLE radio | Every fitness device advertising nearby: MAC, name, RSSI, manufacturer data, services (FTMS `0x1826`, Cycling Power `0x1818`, Heart Rate `0x180D`, CSC `0x1816`, RSC `0x1814`) | Passive advertisement scan via `bleak` / WinRT |
| Zwift log | Which devices *Zwift itself* paired with (ANT+ device IDs, BLE sensor names) | Tails `~/Documents/Zwift/Logs/Log.txt` |
| Processes | Known sensor emulators and BLE/ANT re-broadcast bridges | `psutil` process scan against a configurable blocklist |
| Network | Zwift's own TCP peers: loopback proxies, direct-connect trainers on the LAN (IP + ARP-resolved MAC), hosts-file redirects of Zwift domains | `psutil` per-process connections + ARP table |

## Detection rules

| Rule | Severity | Meaning |
|---|---|---|
| R01 identity-change | ALERT | A device name reappeared on a different Bluetooth address mid-session |
| R02 clone | ALERT | Two addresses advertising the same device name simultaneously |
| R03 local-emulator | ALERT | A "sensor" is advertising from this PC's own Bluetooth adapter — software emulator |
| R04 brand-mismatch | WARN | Advertised brand name inconsistent with the Bluetooth manufacturer company ID |
| R05 rssi-anomaly | WARN | Sustained signal-strength jump vs. the device's own session baseline |
| R06 blocked-process | ALERT | Known emulator/bridge software running |
| R07 loopback-bridge | ALERT | Zwift holds a TCP connection to another program on the same PC (MITM bridge/proxy) |
| R08 hosts-redirect | ALERT | Zwift domains redirected in the Windows hosts file |
| R09 ghost-pairing | WARN | Zwift paired with a BLE device never observed on the air (bridged or emulated elsewhere) |
| R10 ant-id-change | ALERT | The ANT+ device ID for a role (power/HR/FE-C) changed mid-ride |
| R11 post-lock-device | WARN | A new fitness device appeared after the session baseline locked |
| R12 registry-mismatch | ALERT | A registered device name showed up with a different identity than the trusted registry |
| R13 arp-change | ALERT | The MAC behind a direct-connect trainer's IP changed mid-session |

Every event is appended to a **hash-chained log** (each event's SHA-256 covers
the previous event's hash), so a session report cannot be edited afterward
without breaking verification.

## Installation

**Option A — standalone EXE (no Python required).**
Download `zwiftguard.exe` from the
[Releases page](https://github.com/jdrumm1209/3.-Zwift/releases), then run it
from a terminal (PowerShell or Windows Terminal):

```powershell
.\zwiftguard.exe --register 60     # once, with your sensors awake
.\zwiftguard.exe                   # alongside every Zwift session
```

**Option B — pip install (Python 3.10+).**

```powershell
pip install git+https://github.com/jdrumm1209/3.-Zwift.git
zwiftguard --register 60
```

**Option C — from a clone (development).**

```powershell
git clone https://github.com/jdrumm1209/3.-Zwift.git
cd 3.-Zwift
pip install -e .
```

Requires Windows 10/11 with Bluetooth. Reports, `baseline.json`, and config
files are written to the directory you run it from.

## Usage

```powershell
# Register your real equipment once (with sensors awake and advertising):
python -m zwiftguard --register 60

# Then run alongside every Zwift session (start before pairing, Ctrl+C after):
python -m zwiftguard

# Other commands
python -m zwiftguard --scan-only 30                    # quick inventory scan
python -m zwiftguard --duration 3600                   # timed session
python -m zwiftguard --verify-report reports\session_20260701_145101.json
python -m zwiftguard --write-config zwiftguard.json    # emit editable config
python -m zwiftguard --config zwiftguard.json          # run with custom config
python -m zwiftguard --disable net --disable proc      # BLE + log only
```

Exit codes: `0` clean, `1` warnings, `2` alerts (or tampered report for
`--verify-report`) — usable from scripts and race-organizer tooling.

Reports land in `reports/session_*.json` with the full device inventory
(fingerprints included) and the sealed event chain.

## Configuration

`python -m zwiftguard --write-config zwiftguard.json` emits the defaults.
Notable keys:

- `watch_name_regex` — device names tracked even without a standard fitness
  service in the advertisement (KICKR, Tacx NEO, Assioma, TICKR, …).
- `brand_company_ids` — maps a brand substring to legitimate Bluetooth SIG
  company identifiers (used by R04). Ships with Garmin (`0x0087`) and Polar
  (`0x006B`); extend from the
  [Bluetooth assigned numbers](https://www.bluetooth.com/specifications/assigned-numbers/)
  list. Only brands listed here are checked, so an incomplete table never
  causes false alerts.
- `process_blocklist` — substrings of emulator/bridge process names (R06).
- `baseline_lock_seconds` — how long after the first sensor appears before
  the session baseline locks (default 120 s).
- `rssi_jump_db` — RSSI deviation threshold for R05 (default 25 dB).

## Testing

```powershell
python -m tests.test_engine
```

19 synthetic-observation tests cover every rule plus hash-chain tamper
detection and the Zwift log parser — no hardware needed.

## Honest limitations

- **Connected BLE devices may stop advertising.** Identity is captured during
  the pairing window and from devices that keep a second advertising set
  alive (most modern trainers do; HRMs vary). Start ZwiftGuard *before*
  pairing in Zwift.
- **ANT+ is only visible through Zwift's log.** The USB dongle is held
  exclusively by Zwift; sniffing the air would need a second dongle. Device-ID
  changes are still caught (R10) because Zwift logs them.
- **Zwift's log format is undocumented** and changes between releases. The
  parser patterns in `zwiftguard/zwift_log.py` are broad and every match
  stores the raw line as evidence, but expect to tune them occasionally.
- **Zwift Companion bridging** moves sensor traffic to the phone. ZwiftGuard
  flags it as R09 (pairing never seen on the local radio) rather than
  fingerprinting the phone-side sensor.
- **A sophisticated attacker who controls the firmware of a real trainer**
  presents a perfect identity. No external monitor can rule that out; this
  tool raises the bar so the cheap attacks (emulators, bridges, device swaps,
  proxies) leave evidence.
