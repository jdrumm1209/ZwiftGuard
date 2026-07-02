"""Live web dashboard.

Serves a single-page view of the whole data path on 127.0.0.1:

    EQUIPMENT  ->  radio / LAN link  ->  THIS PC (Zwift)  ->  ZWIFT CLOUD
    (MAC, ANT+ ID, fingerprints)         (adapter MAC)        (server IPs)

with animated data flows, per-device integrity status (green/amber/red),
and the live event feed. The page polls /state every 2 seconds; alerts
flash the tab title, and desktop notifications can be enabled with one
click (browser Notification API).

Stdlib only (http.server in a daemon thread) so packaging stays simple.
"""

from __future__ import annotations

import json
import threading
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .engine import IntegrityEngine


class _Handler(BaseHTTPRequestHandler):
    def __init__(self, engine: IntegrityEngine, *args, **kwargs):
        self.engine = engine
        super().__init__(*args, **kwargs)

    def log_message(self, *_args) -> None:  # silence per-request logging
        pass

    def do_GET(self) -> None:
        if self.path.split("?")[0] in ("/", "/index.html"):
            body = DASHBOARD_HTML.encode("utf-8")
            ctype = "text/html; charset=utf-8"
        elif self.path.split("?")[0] == "/state":
            body = json.dumps(self.engine.state_snapshot(), default=str).encode("utf-8")
            ctype = "application/json"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (ConnectionAbortedError, BrokenPipeError):
            pass


class Dashboard:
    def __init__(self, engine: IntegrityEngine, port: int = 8377):
        self.engine = engine
        self.port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> str:
        handler = partial(_Handler, self.engine)
        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="zwiftguard-dashboard", daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{self._server.server_address[1]}/"

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZwiftGuard</title>
<style>
  :root{
    --bg:#0e1420; --card:#161e2e; --edge:#233046; --text:#dbe4f0; --dim:#8093ab;
    --ok:#2dd4a7; --warn:#eab308; --alert:#ef4444; --accent:#38bdf8;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
       font:14px/1.45 "Segoe UI",system-ui,sans-serif}
  header{display:flex;align-items:center;gap:14px;flex-wrap:wrap;
         padding:12px 20px;background:var(--card);border-bottom:1px solid var(--edge)}
  .brand{font-size:18px;font-weight:700;letter-spacing:.3px}
  .brand span{color:var(--accent)}
  .pill{padding:4px 14px;border-radius:999px;font-weight:700;font-size:13px}
  .pill.ok{background:#0c3b2e;color:var(--ok)}
  .pill.warn{background:#3b310c;color:var(--warn)}
  .pill.alert{background:#450f0f;color:var(--alert);animation:pulse 1s infinite}
  .pill.dead{background:#2a2a2a;color:var(--dim)}
  @keyframes pulse{50%{opacity:.45}}
  .meta{color:var(--dim);font-size:13px}
  #notifyBtn{margin-left:auto;background:transparent;border:1px solid var(--edge);
             color:var(--dim);border-radius:8px;padding:5px 12px;cursor:pointer}
  #notifyBtn:hover{color:var(--text);border-color:var(--accent)}
  main{padding:16px 20px;display:grid;gap:16px}
  .card{background:var(--card);border:1px solid var(--edge);border-radius:12px;padding:14px 16px}
  .card h2{margin:0 0 10px;font-size:13px;font-weight:600;color:var(--dim);
           text-transform:uppercase;letter-spacing:1px}
  svg{width:100%;display:block}
  svg text{font:13px "Segoe UI",system-ui,sans-serif;fill:var(--text)}
  svg .sub{fill:var(--dim);font-size:12px}
  svg .flow{fill:var(--accent);font-size:12px;font-weight:600}
  svg .flowup{fill:#c084fc;font-size:12px}
  svg .colhead{fill:var(--dim);font-size:12px;font-weight:700;letter-spacing:1.5px}
  .node{fill:#101827;stroke-width:1.6;rx:10}
  .node.ok{stroke:var(--ok)} .node.warn{stroke:var(--warn)}
  .node.alert{stroke:var(--alert);animation:pulse 1s infinite}
  .node.hub{stroke:var(--accent)} .node.cloud{stroke:#818cf8}
  path.wire{fill:none;stroke:#3b82f6;stroke-width:2;stroke-dasharray:7 6;
            animation:dashmove 1.2s linear infinite;opacity:.85}
  path.wire.up{stroke:#c084fc;stroke-width:1.4;animation-direction:reverse;opacity:.6}
  path.wire.dead{stroke:#37445c;animation:none}
  @keyframes dashmove{to{stroke-dashoffset:-13}}
  #events{max-height:340px;overflow-y:auto;font-size:13px}
  .ev{display:flex;gap:10px;padding:5px 4px;border-bottom:1px solid #1c2536;align-items:baseline}
  .ev .t{color:var(--dim);white-space:nowrap;font-variant-numeric:tabular-nums}
  .chip{font-size:11px;font-weight:700;border-radius:5px;padding:1px 8px;white-space:nowrap}
  .chip.INFO{background:#0c2d3b;color:var(--accent)}
  .chip.WARN{background:#3b310c;color:var(--warn)}
  .chip.ALERT{background:#450f0f;color:var(--alert)}
  .ev .r{color:var(--dim);white-space:nowrap}
  .legend{display:flex;gap:18px;color:var(--dim);font-size:12px;margin-top:8px}
  .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}
</style>
</head>
<body>
<header>
  <div class="brand">&#128737;&#65039; Zwift<span>Guard</span></div>
  <div id="verdict" class="pill ok">STARTING&hellip;</div>
  <div class="meta" id="counts"></div>
  <div class="meta" id="clock"></div>
  <div class="meta" id="baseline"></div>
  <button id="notifyBtn" onclick="askNotify()">&#128276; Enable desktop alerts</button>
</header>
<main>
  <div class="card">
    <h2>Equipment &rarr; Zwift data path</h2>
    <svg id="topo" viewBox="0 0 1140 300" preserveAspectRatio="xMidYMin meet"></svg>
    <div class="legend">
      <span><span class="dot" style="background:var(--ok)"></span>verified / unchanged</span>
      <span><span class="dot" style="background:var(--warn)"></span>suspicious &mdash; review</span>
      <span><span class="dot" style="background:var(--alert)"></span>integrity violation</span>
      <span><span class="dot" style="background:#3b82f6"></span>sensor data &rarr;</span>
      <span><span class="dot" style="background:#c084fc"></span>&larr; control (ERG / gradient)</span>
    </div>
  </div>
  <div class="card">
    <h2>Integrity events</h2>
    <div id="events"></div>
  </div>
</main>
<script>
const FLOWS = {
  "1826": {down:"power \\u00b7 cadence \\u00b7 speed", up:"resistance \\u00b7 gradient (ERG)"},
  "1818": {down:"power \\u00b7 cadence", up:null},
  "180d": {down:"heart rate", up:null},
  "1816": {down:"speed \\u00b7 cadence", up:null},
  "1814": {down:"pace \\u00b7 cadence", up:null}
};
let prevAlerts = 0, dead = false;

function esc(s){return String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}

function deviceFlows(d){
  let down=[], up=[];
  for(const s of (d.services||[])){ const f=FLOWS[s]; if(f){ down.push(f.down); if(f.up) up.push(f.up);} }
  if(d.source==="ant"){ down.push("ANT+ broadcast ("+esc(d.name||"sensor")+")"); }
  if(d.source==="network"){ down.push("trainer telemetry (direct connect)"); up.push("control"); }
  if(!down.length) down.push("sensor data");
  return {down:[...new Set(down)].join(" \\u00b7 "), up:[...new Set(up)].join(" \\u00b7 ")};
}

function transportLine(d){
  if(d.source==="ble") return "BLE \\u00b7 MAC "+esc(d.address);
  if(d.source==="ant") return "ANT+ \\u00b7 device ID "+esc(d.address);
  return "LAN \\u00b7 "+esc(d.address)+(d.mac?" \\u00b7 MAC "+esc(d.mac):"");
}

function node(x,y,w,h,cls,lines){
  let out = `<rect class="node ${cls}" x="${x}" y="${y}" width="${w}" height="${h}" rx="10"/>`;
  let ty = y+20;
  for(const ln of lines){
    out += `<text class="${ln.cls||''}" x="${x+12}" y="${ty}" font-weight="${ln.b?'700':'400'}">${ln.t}</text>`;
    ty += ln.gap||16;
  }
  return out;
}

function wire(x1,y1,x2,y2,cls){
  const mx=(x1+x2)/2;
  return `<path class="wire ${cls}" d="M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}"/>`;
}

function render(s){
  const equip = s.devices.filter(d=>d.source!=="network"||true);
  const rows = Math.max(equip.length,1);
  const rowH = 110, topPad = 34;
  const H = Math.max(rows*rowH+topPad+10, 300);
  const EQX=10, EQW=290, PCX=450, PCW=250, CLX=820, CLW=310;
  const pcY = H/2-62, pcH = 124, clY = H/2-62;
  let svg = "";
  svg += `<text class="colhead" x="${EQX+4}" y="18">EQUIPMENT</text>`;
  svg += `<text class="colhead" x="${PCX+4}" y="18">THIS PC</text>`;
  svg += `<text class="colhead" x="${CLX+4}" y="18">ZWIFT CLOUD</text>`;

  if(!equip.length){
    svg += `<text class="sub" x="${EQX+8}" y="70">No equipment observed yet &mdash; wake your sensors&hellip;</text>`;
  }
  equip.forEach((d,i)=>{
    const y = topPad + i*rowH, h = 88, yc = y+h/2;
    const fl = deviceFlows(d);
    const rssi = d.rssi_last!=null ? `RSSI ${d.rssi_last} dBm` : "";
    const cids = (d.company_ids&&d.company_ids.length)? "mfr 0x"+d.company_ids.map(c=>c.toString(16).padStart(4,"0")).join(", 0x") : "";
    svg += node(EQX,y,EQW,h,d.status,[
      {t:esc(d.name||"(no name)"),b:1},
      {t:transportLine(d),cls:"sub"},
      {t:"fingerprint "+esc(d.identity_hash)+(cids?" \\u00b7 "+cids:""),cls:"sub"},
      {t:rssi,cls:"sub"}
    ]);
    const deadCls = dead ? "dead" : "";
    svg += wire(EQX+EQW, yc-6, PCX, pcY+pcH/2, deadCls);
    svg += `<text class="flow" x="${(EQX+EQW+PCX)/2-90}" y="${(yc+pcY+pcH/2)/2-10}">&rarr; ${fl.down}</text>`;
    if(fl.up){
      svg += wire(PCX, pcY+pcH/2+10, EQX+EQW, yc+8, "up "+deadCls);
      svg += `<text class="flowup" x="${(EQX+EQW+PCX)/2-90}" y="${(yc+pcY+pcH/2)/2+16}">&larr; ${fl.up}</text>`;
    }
  });

  const zw = s.zwift_running ? esc(s.zwift_processes.join(", ")) : "Zwift not detected";
  svg += node(PCX,pcY,PCW,pcH,"hub",[
    {t:"Zwift app",b:1},
    {t:zw,cls:"sub"},
    {t:(s.local_adapter_macs&&s.local_adapter_macs.length)?"BT adapter "+esc(s.local_adapter_macs[0]):"",cls:"sub"},
    {t:"ZwiftGuard watching \\u2713",cls:"sub"}
  ]);

  const srvIps = Object.keys(s.zwift_servers||{});
  const srvLines = [{t:"Zwift servers",b:1}];
  if(srvIps.length){
    srvIps.slice(0,5).forEach(ip=>srvLines.push({t:esc(ip)+" : "+s.zwift_servers[ip].join(", "),cls:"sub"}));
    if(srvIps.length>5) srvLines.push({t:"+"+(srvIps.length-5)+" more endpoints",cls:"sub"});
  } else {
    srvLines.push({t:"no server connections observed",cls:"sub"});
    srvLines.push({t:"(start Zwift to see game endpoints)",cls:"sub"});
  }
  const clH = Math.max(60, 34+srvLines.length*16);
  svg += node(CLX,clY,CLW,clH,"cloud",srvLines);
  const cloudDead = (dead||!srvIps.length) ? "dead" : "";
  svg += wire(PCX+PCW, pcY+pcH/2-6, CLX, clY+clH/2, cloudDead);
  svg += `<text class="flow" x="${(PCX+PCW+CLX)/2-105}" y="${(pcY+clY+clH/2+pcH/2)/2-10}">&rarr; ride telemetry (TLS)</text>`;
  svg += wire(CLX, clY+clH/2+10, PCX+PCW, pcY+pcH/2+8, "up "+cloudDead);
  svg += `<text class="flowup" x="${(PCX+PCW+CLX)/2-105}" y="${(pcY+clY+clH/2+pcH/2)/2+16}">&larr; world state \\u00b7 other riders</text>`;

  const t = document.getElementById("topo");
  t.setAttribute("viewBox", `0 0 1140 ${H}`);
  t.innerHTML = svg;

  // header
  const c = s.severity_counts;
  const v = document.getElementById("verdict");
  v.textContent = s.verdict;
  v.className = "pill " + (c.ALERT? "alert" : c.WARN? "warn" : "ok");
  document.getElementById("counts").textContent =
    `${s.devices.length} device(s) \\u00b7 ${c.INFO||0} info / ${c.WARN||0} warn / ${c.ALERT||0} alert`;
  const el = Math.floor(s.now - s.started);
  document.getElementById("clock").textContent =
    "session " + String(Math.floor(el/60)).padStart(2,"0")+":"+String(el%60).padStart(2,"0");
  document.getElementById("baseline").textContent =
    s.baseline_locked ? "baseline: LOCKED \\ud83d\\udd12" : "baseline: learning\\u2026";

  // events (newest first)
  const evs = [...s.events].reverse();
  document.getElementById("events").innerHTML = evs.map(e=>{
    const d = new Date(e.ts*1000);
    const hh = d.toTimeString().slice(0,8);
    return `<div class="ev"><span class="t">${hh}</span>`+
           `<span class="chip ${e.severity}">${e.severity}</span>`+
           `<span class="r">${esc(e.rule)}</span><span>${esc(e.message)}</span></div>`;
  }).join("");

  // alert escalation: tab title + desktop notification
  if((c.ALERT||0) > prevAlerts){
    document.title = "\\ud83d\\udd34 ALERT \\u2014 ZwiftGuard";
    const last = evs.find(e=>e.severity==="ALERT");
    if(last && "Notification" in window && Notification.permission==="granted"){
      new Notification("ZwiftGuard \\u2014 integrity ALERT", {body:last.message});
    }
  } else if(!(c.ALERT||0)){
    document.title = "ZwiftGuard";
  }
  prevAlerts = c.ALERT||0;
}

function askNotify(){
  if("Notification" in window) Notification.requestPermission().then(p=>{
    document.getElementById("notifyBtn").textContent =
      p==="granted" ? "\\u2705 Desktop alerts on" : "\\u274c Alerts blocked";
  });
}

async function poll(){
  try{
    const s = await fetch("/state",{cache:"no-store"}).then(r=>r.json());
    dead = false;
    render(s);
  }catch(e){
    dead = true;
    const v = document.getElementById("verdict");
    v.textContent = "MONITOR STOPPED"; v.className = "pill dead";
  }
}
poll(); setInterval(poll, 2000);
</script>
</body>
</html>
"""
