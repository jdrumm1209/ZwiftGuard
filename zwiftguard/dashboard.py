"""Live web dashboard.

Serves a single-page view of the whole data path on 127.0.0.1:

    EQUIPMENT  ->  radio / LAN link  ->  THIS PC (Zwift)  ->  ZWIFT CLOUD
    (MAC, ANT+ ID, fingerprints)         (adapter MAC, IPs)    (server IPs)

plus a rider panel (identity, power profile, connection-origin IP, and the
local date/time at the rider's location). Wires are routed orthogonally on
a bus so nothing overlaps; each device card lists its own data flows.

The page polls /state every 2 seconds; the topology only re-renders when
its content changes (no animation flicker). Alerts flash the tab title and
can raise desktop notifications (browser Notification API).

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
    --bg:#0b0f17; --card:#111827; --edge:#1d2942; --text:#e2e9f4; --dim:#7e91ad;
    --ok:#34d399; --warn:#fbbf24; --alert:#f87171; --accent:#38bdf8;
    --wire:#3f8cff; --ctrl:#b07af8;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
       font:14px/1.5 "Inter","Segoe UI",system-ui,sans-serif;
       font-variant-numeric:tabular-nums}
  header{display:flex;align-items:center;gap:16px;flex-wrap:wrap;
         padding:12px 22px;background:var(--card);border-bottom:1px solid var(--edge)}
  .brand{font-size:17px;font-weight:800;letter-spacing:.2px}
  .brand span{color:var(--accent)}
  .pill{padding:4px 14px;border-radius:999px;font-weight:700;font-size:12.5px;letter-spacing:.4px}
  .pill.ok{background:#0a2e24;color:var(--ok)}
  .pill.warn{background:#332908;color:var(--warn)}
  .pill.alert{background:#3b0d0d;color:var(--alert);animation:pulse 1s infinite}
  .pill.dead{background:#22262e;color:var(--dim)}
  @keyframes pulse{50%{opacity:.45}}
  .meta{color:var(--dim);font-size:12.5px}
  #notifyBtn{margin-left:auto;background:transparent;border:1px solid var(--edge);
             color:var(--dim);border-radius:8px;padding:5px 12px;cursor:pointer;font-size:12.5px}
  #notifyBtn:hover{color:var(--text);border-color:var(--accent)}
  main{padding:16px 22px;display:grid;gap:14px;max-width:1280px;margin:0 auto}
  .card{background:var(--card);border:1px solid var(--edge);border-radius:14px;
        padding:14px 18px;box-shadow:0 10px 26px rgba(0,0,0,.32)}
  .card h2{margin:0 0 12px;font-size:11.5px;font-weight:700;color:var(--dim);
           text-transform:uppercase;letter-spacing:1.6px}
  /* ---- rider panel ---- */
  .rider{display:flex;gap:22px;align-items:stretch;flex-wrap:wrap}
  .avatar{width:58px;height:58px;border-radius:50%;flex:0 0 auto;align-self:center;
          display:flex;align-items:center;justify-content:center;font-size:21px;font-weight:800;
          background:linear-gradient(135deg,#0ea5e9,#6366f1);color:#fff}
  .rblock{display:flex;flex-direction:column;justify-content:center;gap:3px;min-width:170px}
  .rname{font-size:16.5px;font-weight:700}
  .rsub{color:var(--dim);font-size:12.5px}
  .rsub b{color:var(--text);font-weight:600}
  .mono{font-family:Consolas,monospace;font-size:12px}
  .vdiv{width:1px;background:var(--edge);align-self:stretch}
  .bigrow{display:flex;align-items:baseline;gap:6px}
  .big{font-size:24px;font-weight:800;color:var(--accent)}
  .big2{font-size:24px;font-weight:800;color:#a5b4fc;margin-left:14px}
  .unit{color:var(--dim);font-size:12px;font-weight:600}
  .bars{display:grid;grid-template-columns:34px 1fr 52px;gap:3px 8px;margin-top:6px;
        align-items:center;min-width:230px}
  .bars .lb{color:var(--dim);font-size:11.5px;text-align:right}
  .bars .tr{background:#0a101d;border-radius:4px;height:9px;overflow:hidden}
  .bars .fl{height:100%;border-radius:4px;background:linear-gradient(90deg,#0ea5e9,#818cf8)}
  .bars .w{font-size:11.5px;color:var(--text)}
  .rtime{font-size:23px;font-weight:800;letter-spacing:.5px}
  /* ---- live rider data ---- */
  .live{display:flex;gap:22px;align-items:stretch;flex-wrap:wrap}
  .lblock{display:flex;flex-direction:column;justify-content:center;align-items:center;min-width:86px}
  .lw{font-size:38px;font-weight:800;color:var(--accent);line-height:1.05}
  .lw2{font-size:26px;font-weight:800;color:#a5b4fc;line-height:1.1}
  .lunit{color:var(--dim);font-size:11.5px;letter-spacing:.6px;text-transform:uppercase}
  .lbests{display:grid;grid-template-columns:34px 1fr 58px 58px;gap:3px 10px;
          align-items:center;min-width:260px;align-self:center}
  .lbests .hd{color:var(--dim);font-size:10.5px;text-transform:uppercase;letter-spacing:.8px}
  .lbests .lb{color:var(--dim);font-size:11.5px;text-align:right}
  .lbests .tr{background:#0a101d;border-radius:4px;height:9px;overflow:hidden}
  .lbests .fl{height:100%;border-radius:4px;background:linear-gradient(90deg,#0ea5e9,#818cf8)}
  .lbests .fl.over{background:linear-gradient(90deg,#f59e0b,#ef4444)}
  .lbests .w{font-size:11.5px}
  .lbests .w.dimc{color:var(--dim)}
  #spark{width:340px;height:96px;align-self:center}
  #spark polyline{fill:none;stroke:var(--accent);stroke-width:1.6}
  #spark path{fill:rgba(56,189,248,.12)}
  #spark text{font-size:10px;fill:var(--dim)}
  #lSrc{margin-top:8px}
  /* ---- topology ---- */
  svg{width:100%;display:block}
  svg text{font:12.5px "Inter","Segoe UI",system-ui,sans-serif;fill:var(--text)}
  svg .sub{fill:var(--dim);font-size:11.5px}
  svg .ttl{font-weight:700;font-size:13px}
  svg .flow{fill:var(--wire);font-size:11.5px}
  svg .flowup{fill:var(--ctrl);font-size:11.5px}
  svg .colhead{fill:var(--dim);font-size:11px;font-weight:700;letter-spacing:1.8px}
  svg .statusw{font-size:11px;font-weight:700}
  .node{fill:#0f1626;stroke-width:1.4;rx:12}
  .node.ok{stroke:var(--ok)} .node.warn{stroke:var(--warn)}
  .node.alert{stroke:var(--alert);animation:pulse 1s infinite}
  .node.hub{stroke:var(--accent)} .node.cloud{stroke:#818cf8}
  path.wire{fill:none;stroke:var(--wire);stroke-width:1.7;stroke-linejoin:round;
            stroke-dasharray:6 7;animation:dashmove 1.1s linear infinite;opacity:.95}
  path.wire.up{stroke:var(--ctrl);stroke-width:1.4;opacity:.75}
  path.wire.dead{stroke:#33415e;animation:none;opacity:.6}
  @keyframes dashmove{to{stroke-dashoffset:-13}}
  /* ---- events ---- */
  #events{max-height:320px;overflow-y:auto;font-size:12.5px}
  #events::-webkit-scrollbar{width:9px}
  #events::-webkit-scrollbar-thumb{background:#243350;border-radius:5px}
  .ev{display:grid;grid-template-columns:64px 58px 150px 1fr;gap:10px;
      padding:5px 6px;border-bottom:1px solid #16203a;align-items:baseline}
  .ev:hover{background:#0e1524}
  .ev .t{color:var(--dim);white-space:nowrap}
  .chip{font-size:10.5px;font-weight:700;border-radius:5px;padding:1px 0;text-align:center}
  .chip.INFO{background:#0a2532;color:var(--accent)}
  .chip.WARN{background:#332908;color:var(--warn)}
  .chip.ALERT{background:#3b0d0d;color:var(--alert)}
  .ev .r{color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .legend{display:flex;gap:20px;color:var(--dim);font-size:12px;margin-top:10px;flex-wrap:wrap}
  .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
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
    <h2>Rider &amp; connection origin</h2>
    <div class="rider">
      <div class="avatar" id="rAvatar">?</div>
      <div class="rblock">
        <div class="rname" id="rName">&mdash;</div>
        <div class="rsub" id="rIds"></div>
        <div class="rsub" id="rCat"></div>
      </div>
      <div class="vdiv"></div>
      <div class="rblock">
        <div class="bigrow">
          <span class="big" id="rFtp">&mdash;</span><span class="unit">W FTP</span>
          <span class="big2" id="rWkg">&mdash;</span><span class="unit">W/kg</span>
        </div>
        <div class="bars" id="rBars"></div>
      </div>
      <div class="vdiv"></div>
      <div class="rblock">
        <div class="rsub"><b id="rWhere">detecting location&hellip;</b></div>
        <div class="rtime" id="rTime">&mdash;&thinsp;:&thinsp;&mdash;</div>
        <div class="rsub" id="rDate"></div>
        <div class="rsub mono" id="rIps"></div>
      </div>
    </div>
  </div>
  <div class="card">
    <h2>Live rider data</h2>
    <div class="live">
      <div class="lblock"><div class="lw" id="lWatts">&mdash;</div><div class="lunit">watts (3s)</div></div>
      <div class="lblock"><div class="lw2" id="lCad">&mdash;</div><div class="lunit">rpm</div></div>
      <div class="lblock"><div class="lw2" id="lWkg">&mdash;</div><div class="lunit">W/kg</div></div>
      <div class="vdiv"></div>
      <div class="lbests" id="lBests"></div>
      <div class="vdiv"></div>
      <svg id="spark" viewBox="0 0 340 96" preserveAspectRatio="none"></svg>
    </div>
    <div class="rsub" id="lSrc">live power feed: starting&hellip;</div>
  </div>
  <div class="card">
    <h2>Equipment &rarr; Zwift data path</h2>
    <svg id="topo" viewBox="0 0 1160 320" preserveAspectRatio="xMidYMin meet"></svg>
    <div class="legend">
      <span><span class="dot" style="background:var(--ok)"></span>verified / unchanged</span>
      <span><span class="dot" style="background:var(--warn)"></span>suspicious &mdash; review</span>
      <span><span class="dot" style="background:var(--alert)"></span>integrity violation</span>
      <span><span class="dot" style="background:var(--wire)"></span>sensor data &rarr;</span>
      <span><span class="dot" style="background:var(--ctrl)"></span>&larr; control (ERG / gradient)</span>
    </div>
  </div>
  <div class="card">
    <h2>Integrity events</h2>
    <div id="events"></div>
  </div>
</main>
<script>
const FLOWS = {
  "1826": {down:["power","cadence","speed"], up:["resistance","gradient (ERG)"]},
  "1818": {down:["power","cadence"], up:[]},
  "180d": {down:["heart rate"], up:[]},
  "1816": {down:["speed","cadence"], up:[]},
  "1814": {down:["pace","cadence"], up:[]}
};
const STATUS_TXT = {ok:["\\u25cf verified","var(--ok)"], warn:["\\u25cf suspicious","var(--warn)"],
                    alert:["\\u25cf VIOLATION","var(--alert)"]};
let prevAlerts=0, dead=false, topoKey="", evKey="", tz=null;

function esc(s){return String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}

function deviceFlows(d){
  let down=[], up=[];
  for(const s of (d.services||[])){ const f=FLOWS[s]; if(f){ down.push(...f.down); up.push(...f.up);} }
  if(d.source==="ant") down.push("ANT+ broadcast");
  if(d.source==="network"){ down.push("trainer telemetry"); up.push("resistance control"); }
  if(!down.length) down.push("sensor data");
  return {down:[...new Set(down)].join(" \\u00b7 "), up:[...new Set(up)].join(" \\u00b7 ")};
}
function transportLine(d){
  if(d.source==="ble") return "BLE \\u00b7 MAC "+esc(d.address);
  if(d.source==="ant") return "ANT+ \\u00b7 device ID "+esc(d.address);
  const ports=(d.services||[]).filter(s=>String(s).startsWith("tcp:")).map(s=>String(s).slice(4)).join(",");
  return "LAN \\u00b7 IP "+esc(d.address)+(d.mac?" \\u00b7 MAC "+esc(d.mac):"")+(ports?" \\u00b7 tcp "+ports:"");
}
function textEl(x,y,cls,str,anchor){
  return `<text class="${cls}" x="${x}" y="${y}"${anchor?` text-anchor="${anchor}"`:""}>${str}</text>`;
}

function renderTopo(s){
  const devs = s.devices;
  const rowH=140, cardH=118, top=34;
  const H = Math.max(devs.length*rowH+top+6, 320);
  const DX=16, DW=318, BUS1=372, BUS2=386, PCX=452, PCW=300, CLX=856, CLW=288;
  const pcH=138, pcY=H/2-pcH/2;
  const pcDataY=pcY+pcH/2-12, pcCtlY=pcY+pcH/2+16;
  let svg = `<defs>
    <marker id="arr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse">
      <path d="M0 0 L8 4 L0 8 z" fill="var(--wire)"/></marker>
    <marker id="arrp" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse">
      <path d="M0 0 L8 4 L0 8 z" fill="var(--ctrl)"/></marker>
  </defs>`;
  svg += textEl(DX+2,18,"colhead","EQUIPMENT");
  svg += textEl(PCX+2,18,"colhead","THIS PC");
  svg += textEl(CLX+2,18,"colhead","ZWIFT CLOUD");
  const deadCls = dead?" dead":"";

  if(!devs.length)
    svg += textEl(DX+8,80,"sub","No equipment observed yet \\u2014 wake your sensors\\u2026");

  devs.forEach((d,i)=>{
    const y=top+i*rowH, yc=y+cardH/2;
    const fl=deviceFlows(d);
    const st=STATUS_TXT[d.status]||STATUS_TXT.ok;
    const cids=(d.company_ids&&d.company_ids.length)
      ? " \\u00b7 mfr 0x"+d.company_ids.map(c=>c.toString(16).padStart(4,"0")).join(", 0x") : "";
    svg += `<rect class="node ${d.status}" x="${DX}" y="${y}" width="${DW}" height="${cardH}" rx="12"/>`;
    const nm=(d.name||"(no name)");
    svg += textEl(DX+14,y+22,"ttl",esc(nm.length>24?nm.slice(0,23)+"\\u2026":nm));
    svg += `<text class="statusw" x="${DX+DW-14}" y="${y+22}" text-anchor="end" fill="${st[1]}">${st[0]}</text>`;
    svg += textEl(DX+14,y+41,"sub",transportLine(d));
    svg += textEl(DX+14,y+58,"sub","fingerprint "+esc(d.identity_hash)+cids);
    svg += textEl(DX+14,y+75,"sub",(d.rssi_last!=null?"RSSI "+d.rssi_last+" dBm":""));
    svg += textEl(DX+14,y+94,"flow","\\u2192 sends: "+fl.down);
    if(fl.up) svg += textEl(DX+14,y+111,"flowup","\\u2190 gets: "+fl.up);
    // data wire: card -> bus -> PC inlet
    svg += `<path class="wire${deadCls}" marker-end="url(#arr)"
      d="M ${DX+DW} ${yc-8} H ${BUS1} V ${pcDataY} H ${PCX-3}"/>`;
    if(fl.up)
      svg += `<path class="wire up${deadCls}" marker-end="url(#arrp)"
        d="M ${PCX} ${pcCtlY} H ${BUS2} V ${yc+10} H ${DX+DW+3}"/>`;
  });

  // PC node
  const zw = s.zwift_running ? esc(s.zwift_processes.join(", ")) : "Zwift not detected";
  svg += `<rect class="node hub" x="${PCX}" y="${pcY}" width="${PCW}" height="${pcH}" rx="12"/>`;
  svg += textEl(PCX+14,pcY+22,"ttl","Zwift host PC");
  svg += textEl(PCX+14,pcY+41,"sub",zw);
  svg += textEl(PCX+14,pcY+58,"sub",(s.local_ips&&s.local_ips[0])?"LAN IP "+esc(s.local_ips[0]):"");
  svg += textEl(PCX+14,pcY+75,"sub",(s.local_adapter_macs&&s.local_adapter_macs[0])?"BT adapter "+esc(s.local_adapter_macs[0]):"");
  svg += textEl(PCX+14,pcY+92,"sub",(s.location&&s.location.public_ip)?"public IP "+esc(s.location.public_ip):"");
  svg += textEl(PCX+14,pcY+115,"sub","ZwiftGuard watching \\u2713");

  // cloud node (flow descriptions live inside the card so they never
  // collide with the wires, whatever the scale)
  const ips=Object.keys(s.zwift_servers||{});
  const lines=[{c:"flow",t:"\\u2190 receives: ride telemetry (TLS)"},
               {c:"flowup",t:"\\u2192 sends: world state \\u00b7 other riders"}];
  if(ips.length){
    ips.slice(0,6).forEach(ip=>lines.push({c:"sub mono",t:esc(ip)+" : "+s.zwift_servers[ip].join(", ")}));
    if(ips.length>6) lines.push({c:"sub",t:"+"+(ips.length-6)+" more endpoints"});
  } else {
    lines.push({c:"sub",t:"no server connections observed"});
    lines.push({c:"sub",t:"(start Zwift to see endpoints)"});
  }
  const clH=Math.max(110, 44+lines.length*17);
  const clY=H/2-clH/2;
  svg += `<rect class="node cloud" x="${CLX}" y="${clY}" width="${CLW}" height="${clH}" rx="12"/>`;
  svg += textEl(CLX+14,clY+22,"ttl","Zwift servers");
  lines.forEach((ln,i)=>{ svg += textEl(CLX+14,clY+44+i*17,ln.c,ln.t); });

  // trunk PC <-> cloud
  const cloudDead=(dead||!ips.length)?" dead":"";
  svg += `<path class="wire${cloudDead}" marker-end="url(#arr)"
    d="M ${PCX+PCW} ${pcDataY} H ${CLX-3}"/>`;
  svg += `<path class="wire up${cloudDead}" marker-end="url(#arrp)"
    d="M ${CLX} ${pcCtlY} H ${PCX+PCW+3}"/>`;

  const t=document.getElementById("topo");
  t.setAttribute("viewBox",`0 0 1160 ${H}`);
  t.innerHTML=svg;
}

function renderRider(s){
  const r=s.rider||{}, loc=s.location||{};
  const name=r.name||"Rider";
  document.getElementById("rName").textContent=name;
  document.getElementById("rAvatar").textContent =
    (name.match(/\\b\\w/g)||["?"]).slice(0,2).join("").toUpperCase();
  const ids=[];
  if(r.zwift_id) ids.push("Zwift ID "+r.zwift_id);
  if(r.player_id) ids.push("player "+r.player_id+" (from game log)");
  document.getElementById("rIds").textContent=ids.join(" \\u00b7 ")||"set rider_profile in config (--write-config)";
  const cat=[];
  if(r.category) cat.push("Cat "+r.category);
  if(r.weight_kg) cat.push(r.weight_kg+" kg");
  document.getElementById("rCat").textContent=cat.join(" \\u00b7 ");
  document.getElementById("rFtp").textContent=
    r.ftp_w ? (r.ftp_estimated?"~":"")+r.ftp_w : "\\u2014";
  document.getElementById("rWkg").textContent=
    (r.ftp_w&&r.weight_kg)?(r.ftp_w/r.weight_kg).toFixed(1):"\\u2014";
  const bests=r.power_bests_w||{};
  const order=["5s","1m","5m","20m"];
  const vals=order.map(k=>bests[k]||0), mx=Math.max(...vals,1);
  const src=r.bests_source
    ? `<span class="lb"></span><span class="rsub" style="grid-column:2/4">${esc(r.bests_source)}${r.ftp_estimated?" \\u00b7 FTP ~ 95% of 20m best":""}</span>` : "";
  document.getElementById("rBars").innerHTML = vals.some(v=>v)
    ? order.map((k,i)=>`<span class="lb">${k}</span>
        <span class="tr"><span class="fl" style="width:${Math.round(vals[i]/mx*100)}%"></span></span>
        <span class="w">${vals[i]?vals[i]+" W":"\\u2014"}</span>`).join("")+src
    : `<span class="lb"></span><span class="rsub" style="grid-column:2/4">add power_bests_w to config to show your power curve</span>`;
  // location + clocks
  tz = r.timezone || loc.timezone || null;
  const cityCfg=[r.city,r.country].filter(Boolean).join(", ");
  const cityIp=[loc.city,loc.region,loc.country].filter(Boolean).join(", ");
  const where=cityCfg||cityIp;
  document.getElementById("rWhere").textContent =
    where ? where+(cityCfg?"":" (via IP \\u00b7 approximate)")
          : (s.now?"location unknown":"detecting location\\u2026");
  const ipbits=[];
  if(loc.public_ip) ipbits.push("public "+loc.public_ip);
  if(s.local_ips&&s.local_ips[0]) ipbits.push("LAN "+s.local_ips[0]);
  if(loc.org) ipbits.push(loc.org);
  document.getElementById("rIps").textContent=ipbits.join(" \\u00b7 ");
  tickClock();
}

function renderLive(s){
  const p=s.power||{};
  document.getElementById("lWatts").textContent = p.avg3s!=null ? p.avg3s : "\\u2014";
  document.getElementById("lCad").textContent   = p.cadence!=null ? p.cadence : "\\u2014";
  document.getElementById("lWkg").textContent   = p.wkg!=null ? p.wkg.toFixed(2) : "\\u2014";
  // session bests vs profile bests
  const order=["5s","1m","5m","20m"];
  const sb=p.session_bests||{}, pb=p.profile_bests||{};
  const mx=Math.max(...order.map(k=>Math.max(sb[k]||0,pb[k]||0)),1);
  document.getElementById("lBests").innerHTML =
    `<span></span><span class="hd">session vs profile best</span><span class="hd">now</span><span class="hd">best</span>`+
    order.map(k=>{
      const s0=sb[k]||0, p0=pb[k]||0;
      const over = p0 && s0 > p0*1.15;
      return `<span class="lb">${k}</span>
        <span class="tr"><span class="fl${over?" over":""}" style="width:${Math.round(s0/mx*100)}%"></span></span>
        <span class="w${s0?"":" dimc"}">${s0?s0+" W":"\\u2014"}</span>
        <span class="w dimc">${p0?p0+" W":"\\u2014"}</span>`;
    }).join("");
  // sparkline: last 15 min, one point / 5s
  const h=p.history||[];
  const svg=document.getElementById("spark");
  if(h.length>1){
    const maxW=Math.max(...h.map(d=>d[1]),100);
    const X=t=>340*(t+900)/900, Y=w=>90-82*(w/maxW);
    const pts=h.map(d=>X(d[0]).toFixed(1)+","+Y(d[1]).toFixed(1)).join(" ");
    const last=h[h.length-1];
    svg.innerHTML=`<path d="M ${X(h[0][0]).toFixed(1)} 90 L ${pts.replace(/ /g," L ")} L ${X(last[0]).toFixed(1)} 90 Z"/>`+
      `<polyline points="${pts}"/>`+
      `<circle cx="${X(last[0]).toFixed(1)}" cy="${Y(last[1]).toFixed(1)}" r="2.6" fill="var(--accent)"/>`+
      `<text x="4" y="12">${maxW} W max \\u00b7 15 min</text>`;
  } else {
    svg.innerHTML=`<text x="4" y="50">no power samples yet</text>`;
  }
  document.getElementById("lSrc").textContent = p.connected
    ? "live power feed: connected to '"+(p.source||"?")+"' via BLE Cycling Power \\u2014 an independent "+
      "witness to the watts Zwift receives"
    : "live power feed: waiting for an advertising power source\\u2026 (unavailable if Zwift holds the "+
      "trainer's only BLE slot; harmless \\u2014 all other monitors keep running)";
}

function tickClock(){
  const now=new Date();
  const o=tz?{timeZone:tz}:{};
  try{
    document.getElementById("rTime").textContent =
      new Intl.DateTimeFormat("en-GB",{...o,hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:false}).format(now);
    document.getElementById("rDate").textContent =
      new Intl.DateTimeFormat("en-GB",{...o,weekday:"short",day:"numeric",month:"short",year:"numeric"}).format(now)
      +" \\u00b7 "+(tz||"system time");
  }catch(e){ tz=null; }
}
setInterval(tickClock,1000);

function render(s){
  // topology: only rebuild when content actually changes (keeps animation smooth)
  const key=JSON.stringify([s.devices.map(d=>[d.address,d.name,d.status,d.services,d.source,d.mac,
      d.identity_hash,Math.round((d.rssi_last||0)/6)]),
    s.zwift_servers,s.zwift_running,s.local_ips,s.local_adapter_macs,
    (s.location||{}).public_ip,dead]);
  if(key!==topoKey){ topoKey=key; renderTopo(s); }
  renderRider(s);
  renderLive(s);

  const c=s.severity_counts;
  const v=document.getElementById("verdict");
  v.textContent=s.verdict;
  v.className="pill "+(c.ALERT?"alert":c.WARN?"warn":"ok");
  document.getElementById("counts").textContent=
    `${s.devices.length} device(s) \\u00b7 ${c.INFO||0} info / ${c.WARN||0} warn / ${c.ALERT||0} alert`;
  const el=Math.floor(s.now-s.started);
  document.getElementById("clock").textContent=
    "session "+String(Math.floor(el/60)).padStart(2,"0")+":"+String(el%60).padStart(2,"0");
  document.getElementById("baseline").textContent=
    s.baseline_locked?"baseline: LOCKED \\ud83d\\udd12":"baseline: learning\\u2026";

  const evs=[...s.events].reverse();
  const ek=evs.length+":"+(evs[0]?evs[0].hash:"");
  if(ek!==evKey){
    evKey=ek;
    document.getElementById("events").innerHTML=evs.map(e=>{
      const hh=new Date(e.ts*1000).toTimeString().slice(0,8);
      return `<div class="ev"><span class="t">${hh}</span>`+
             `<span class="chip ${e.severity}">${e.severity}</span>`+
             `<span class="r">${esc(e.rule)}</span><span>${esc(e.message)}</span></div>`;
    }).join("");
  }

  if((c.ALERT||0)>prevAlerts){
    document.title="\\ud83d\\udd34 ALERT \\u2014 ZwiftGuard";
    const last=evs.find(e=>e.severity==="ALERT");
    if(last&&"Notification" in window&&Notification.permission==="granted")
      new Notification("ZwiftGuard \\u2014 integrity ALERT",{body:last.message});
  } else if(!(c.ALERT||0)) document.title="ZwiftGuard";
  prevAlerts=c.ALERT||0;
}

function askNotify(){
  if("Notification" in window) Notification.requestPermission().then(p=>{
    document.getElementById("notifyBtn").textContent=
      p==="granted"?"\\u2705 Desktop alerts on":"\\u274c Alerts blocked";
  });
}

async function poll(){
  try{
    const s=await fetch("/state",{cache:"no-store"}).then(r=>r.json());
    if(dead){dead=false;topoKey="";}
    render(s);
  }catch(e){
    if(!dead){dead=true;topoKey="";}
    const v=document.getElementById("verdict");
    v.textContent="MONITOR STOPPED";v.className="pill dead";
  }
}
poll(); setInterval(poll,2000);
</script>
</body>
</html>
"""
