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
| R14 profile-power | ALERT | Sustained power exceeds the rider's own all-time best curve by the configured tolerance |
| R15 sticky-watts | WARN | Power value frozen under load — the classic "sticky watts" signature |
| R16 zero-cadence | ALERT | Sustained power with the cranks not turning — data is not coming from the pedals |
| R17 robot-smooth | WARN | Power variance implausibly low for human pedaling (ERG mode noted as a caveat) |
| R18 dropout/reconnect | INFO/WARN | Equipment disconnected or reconnected — BLE advertisements stopping, Zwift-reported unpair/disconnect, or a direct-connect TCP link closing. WARN when it happens mid-session (after baseline lock) |

ANT+ sensors are named from Zwift's log: the manufacturer/model identification
lines (`dID … MFG … Model …`, mapped via `ant_manufacturer_ids` in the config)
and role-pairing lines give entries like *"HR Strap 43692 (HR)"* or
*"Wahoo Fitness ANT+ sensor (model 1)"* instead of bare device IDs. Devices
that stop advertising mid-session show as dimmed/offline on the dashboard
until they return.

Every event is appended to a **hash-chained log** (each event's SHA-256 covers
the previous event's hash), so a session report cannot be edited afterward
without breaking verification.

## How you are notified

When ZwiftGuard starts, it opens a **live dashboard** in your browser at
`http://127.0.0.1:8377` (local-only, nothing is exposed to the network). The
dashboard shows the full data path from each piece of equipment to Zwift's
servers:

```
EQUIPMENT                      THIS PC                    ZWIFT CLOUD
┌──────────────────┐  → power · cadence  ┌────────────┐  → ride telemetry ┌──────────────┐
│ Wahoo KICKR      │ ═══════════════════▶│ Zwift app  │═══════════════════▶│ server IPs   │
│ BLE · MAC ED:4F… │ ◀───────────────────│ BT adapter │◀───────────────────│ : ports      │
│ fingerprint 7d9… │  ← resistance (ERG) │ MAC 04:68… │  ← world state     └──────────────┘
└──────────────────┘                     └────────────┘
```

Each device node shows its transport (BLE MAC / ANT+ ID / LAN IP + MAC),
identity fingerprint, manufacturer IDs, live signal strength, and exactly
what it sends and receives, and is colored **green** (verified/unchanged),
**amber** (suspicious — review), or **red, pulsing** (integrity violation).
A live event feed runs underneath.

## Rider power monitor

ZwiftGuard maintains an independent, live view of the rider's output:

- **Real power profile, auto-loaded.** Zwift keeps a per-ride critical-power
  cache on disk (`Documents/Zwift/cp/`). At startup ZwiftGuard decodes every
  ride file and derives the rider's genuine all-time 5 s / 1 min / 5 min /
  20 min bests plus an estimated FTP (95% of the 20-min best). Explicit
  `rider_profile` config values always win; weight and category cannot be
  read locally and stay manual.
- **Live power feed.** The trainer/power meter's standard BLE Cycling Power
  service is subscribed read-only for live watts and cadence — a second
  witness, independent of the connection Zwift uses. Only devices that are
  *actively advertising* are ever contacted, so a sensor Zwift holds
  exclusively over BLE is never touched (trainers on ANT+/Direct Connect,
  and modern multi-connection trainers, keep a free advertising slot).
  Disable with `"live_power_monitor": false` or `--disable power`.
- **Physiological plausibility rules** (R14–R17) compare the live feed with
  the rider's own history: sustained output above their all-time curve,
  frozen "sticky" watts, power with stationary cranks, and robotically
  smooth output all raise events. Thresholds live under `power_rules` in
  the config.
- The **Live rider data** dashboard panel shows current watts (3 s), cadence,
  W/kg, session bests vs profile bests (bars turn red when a window exceeds
  the profile), and a 15-minute power sparkline.

Above the topology, a **rider panel** shows who is riding and where the
connection originates:

- identity: name, Zwift ID (and the player ID read live from Zwift's own
  log once the game starts), category, weight;
- **power profile**: FTP, W/kg, and a 5 s / 1 min / 5 min / 20 min best-power
  curve — fill these in under `rider_profile` in the config
  (`--write-config zwiftguard.json`);
- **connection origin**: public IP, LAN IP, ISP, city/country, and a live
  clock with the date/time at that location. Location and timezone are
  auto-detected from the public IP at session start (one HTTPS call to
  ipapi.co — set `"public_ip_lookup": false` to disable) or can be pinned
  in `rider_profile.city/country/timezone`.

Alert escalation, in order of loudness:

1. **Dashboard**: the device node and verdict pill turn red and pulse; the
   browser tab title changes to a red-dot alert.
2. **Desktop notification**: click "Enable desktop alerts" once and every
   ALERT raises a Windows notification via the browser, even when the
   dashboard tab is in the background.
3. **Sound**: the Windows error chime plays on every ALERT.
4. **Console**: the colored terminal log (red ALERT lines).
5. **After the ride**: the sealed JSON report and the process exit code
   (`0` clean / `1` warnings / `2` alerts) for scripted/organizer use.

Dashboard options: `--no-browser` (don't auto-open), `--dashboard-port N`,
`--disable dash` (headless).

## Installation

> ZwiftGuard is **proprietary software** — see the [License](#license)
> section. Downloading, installing, or using it requires authorization from
> the owner under the Proprietary License.

**Option A — standalone EXE (no Python required).**
Download `zwiftguard.exe` from the
[Releases page](https://github.com/jdrumm1209/ZwiftGuard/releases), then run it
from a terminal (PowerShell or Windows Terminal):

```powershell
.\zwiftguard.exe --register 60     # once, with your sensors awake
.\zwiftguard.exe                   # alongside every Zwift session
```

**Option B — pip install (Python 3.10+).**

```powershell
pip install git+https://github.com/jdrumm1209/ZwiftGuard.git
zwiftguard --register 60
```

**Option C — from a clone (development).**

```powershell
git clone https://github.com/jdrumm1209/ZwiftGuard.git
cd ZwiftGuard
pip install -e .
```

Requires Windows 10/11 with Bluetooth. Reports, `baseline.json`, and config
files are written to the directory you run it from.

### Uninstalling

`zwiftguard.exe` is a **portable, self-contained executable** — there is no
installer, no Windows service, no registry entries, and no auto-start hook
(verified: zero registry keys, services, startup entries, or leftover temp
folders after exit). To uninstall completely:

1. Delete `zwiftguard.exe`.
2. Delete the files it created in the folder you ran it from: `reports\`,
   `baseline.json`, and any config `.json` you generated.

That is everything. (While running, Windows briefly extracts the EXE to a
`_MEIxxxxxx` folder under `%TEMP%`, which is removed automatically on exit;
after a hard crash a stray one can be deleted harmlessly.) The pip install
uninstalls with `pip uninstall zwiftguard`.

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
  primary patterns in `zwiftguard/zwift_log.py` were verified against a real
  2026 PC-client session log (BLE role selection, ANT+ channel pairing and
  dID identification, Wahoo Direct Connect/TNP discovery, player ID); broad
  fallbacks cover other client versions, and every match stores the raw line
  as evidence. The log path honors OneDrive/Documents folder redirection.
- **Zwift Companion bridging** moves sensor traffic to the phone. ZwiftGuard
  flags it as R09 (pairing never seen on the local radio) rather than
  fingerprinting the phone-side sensor.
- **A sophisticated attacker who controls the firmware of a real trainer**
  presents a perfect identity. No external monitor can rule that out; this
  tool raises the bar so the cheap attacks (emulators, bridges, device swaps,
  proxies) leave evidence.

## License

Copyright (c) 2026 Jason Drummond. **All rights reserved.**

This repository is **proprietary software**, not open source. Viewing the
source is permitted; copying, modifying, redistributing, or using the
Software in any project requires **explicit written authorization** from the
owner. The full terms are in the [Proprietary License](Proprietary%20License)
file. Contributions are accepted only under the
[Contributor Agreement](Contributor%20Agreement) and become the property of
the owner. See also [COPYRIGHT](COPYRIGHT).

For usage authorization or licensing inquiries, contact the repository owner
via GitHub ([@jdrumm1209](https://github.com/jdrumm1209)).
