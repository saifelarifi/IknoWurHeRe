"""Read-only FastAPI dashboard with a background authorized network watch."""

from __future__ import annotations

import asyncio
import html
import logging
import secrets
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from .database import DeviceStore
from .monitor import PassiveMonitor, current_gateway, persist_passive_event
from .notifications import notify_alerts
from .service import COMMON_TCP_PORTS, quick_port_scan, scan_and_record

logger = logging.getLogger("iknowurhere.dashboard")

INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IknoWurHeRe • Network overview</title>
<style>
:root{color-scheme:dark;--bg:#09111f;--panel:#111c2d;--line:#22334b;--ink:#e7efff;--muted:#96a9c5;--cyan:#69d5e8;--green:#58d49a;--amber:#ffca72;--red:#ff7b87}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#172b43 0,var(--bg) 60%);color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,sans-serif}
.wrap{max-width:1200px;margin:auto;padding:30px 22px 64px}.top{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:24px}.brand{display:flex;align-items:center;gap:14px}.mark{font-size:32px;color:var(--cyan)}h1{font-size:22px;margin:0;letter-spacing:.02em}.sub{color:var(--muted);font-size:13px}.pill{border:1px solid var(--line);border-radius:99px;padding:6px 12px;color:var(--green);font-size:12px}.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}.card,.panel{background:linear-gradient(145deg,rgba(22,36,56,.97),rgba(14,25,41,.97));border:1px solid var(--line);border-radius:16px;box-shadow:0 14px 40px #0003}.card{padding:18px}.label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.1em}.value{font-size:25px;margin-top:6px;font-weight:650}.panel{padding:20px;margin-top:16px}.panelhead{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}h2{font-size:16px;margin:0}.small{color:var(--muted);font-size:12px}.toolbar{display:flex;gap:10px;align-items:center;margin:12px 0 16px}.toolbar input,.toolbar select{background:#0b1626;color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:10px 12px;min-height:40px}.toolbar input{flex:1;min-width:180px}table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--muted);font-weight:550;padding:10px;border-bottom:1px solid var(--line)}td{padding:10px;border-bottom:1px solid #1c2b3e;vertical-align:top}tr:last-child td{border-bottom:0}.badge{color:var(--green);background:#1b4439;padding:3px 8px;border-radius:99px;font-size:11px}.source{color:var(--cyan)}.alert{border-left:3px solid var(--amber);padding:10px 12px;margin:10px 0;background:#182438;border-radius:0 9px 9px 0}.alert strong{color:var(--amber)}.error{color:var(--red)}.empty{padding:22px;color:var(--muted);text-align:center}.footer{margin-top:18px;color:var(--muted);font-size:12px}.scroll{overflow:auto}button{background:#1c3550;color:var(--ink);border:1px solid #2e4e6c;border-radius:8px;padding:8px 12px;cursor:pointer}button:hover{border-color:var(--cyan)}button:disabled{opacity:.6;cursor:wait}.primary{background:#116278;border-color:#227e95;font-weight:650}@media(max-width:980px){.grid{grid-template-columns:repeat(3,1fr)}}@media(max-width:760px){.grid{grid-template-columns:repeat(2,1fr)}.wrap{padding:20px 12px}.top{align-items:flex-start;flex-wrap:wrap}.toolbar{flex-wrap:wrap}.toolbar input{flex-basis:100%}}
</style><style>
:root{--bg:#03050b;--panel:#090d18;--line:#19334a;--ink:#eafaff;--muted:#8196ad;--cyan:#00eaff;--green:#62ffd1;--amber:#ffd166;--red:#ff477e;--pink:#ff2bd6}
body{background-color:var(--bg);background-image:radial-gradient(ellipse at 12% 0%,#09233a 0,transparent 40%),radial-gradient(ellipse at 92% 8%,#310d36 0,transparent 34%),linear-gradient(#06101b 1px,transparent 1px),linear-gradient(90deg,#06101b 1px,transparent 1px);background-size:auto,auto,36px 36px,36px 36px;background-attachment:fixed}
.wrap{position:relative}.brand h1{font-family:ui-monospace,monospace;font-weight:900;letter-spacing:.14em;text-transform:uppercase;color:#f4fbff;text-shadow:0 0 8px #00eaff,0 0 24px #00eaff77}.brand h1:after{content:attr(data-text);position:absolute;margin-left:2px;color:var(--pink);opacity:.55;transform:translate(-2px,1px);z-index:-1}.mark{display:grid;place-items:center;width:48px;height:48px;border:1px solid var(--cyan);border-radius:12px;background:#04121d;color:var(--cyan);text-shadow:0 0 14px var(--cyan);box-shadow:0 0 18px #00eaff44,inset 0 0 14px #00eaff22}
.card,.panel{background:linear-gradient(145deg,#0b1422f5,#080b14f5);border-color:#17445a;box-shadow:0 0 0 1px #00eaff0a,0 12px 36px #0009}.card{transition:border-color .2s,transform .2s,box-shadow .2s}.card:hover{transform:translateY(-2px);border-color:#ff2bd6aa;box-shadow:0 0 22px #ff2bd622}.panel{border-top:1px solid #00eaff66}.label{color:#78a8bd}.value{font-family:ui-monospace,monospace;text-shadow:0 0 14px #00eaff44}.panelhead h2{color:var(--cyan);letter-spacing:.06em;text-transform:uppercase}th{color:#ff69df}td{border-color:#122839}tbody tr:hover{background:#00eaff0a}.toolbar input:focus,.toolbar select:focus{outline:1px solid var(--cyan);box-shadow:0 0 12px #00eaff44}
button{background:#071923;border-color:#087f91;color:#bafaff;transition:all .18s}button:hover{border-color:var(--pink);color:#fff;box-shadow:0 0 16px #ff2bd644}.primary{background:linear-gradient(110deg,#08364a,#36103c);border-color:var(--cyan);color:#fff;box-shadow:0 0 15px #00eaff33,inset 0 0 14px #00eaff15}.primary:hover{box-shadow:0 0 20px #00eaff88,0 0 34px #ff2bd633}.pill{background:#06151c;border-color:#176174;color:var(--green);box-shadow:0 0 10px #00eaff20}.pill.error{border-color:var(--red);color:#ff8fb0;box-shadow:0 0 12px #ff477e33}.alert{background:#17101d;border-left-color:var(--pink);box-shadow:inset 0 0 18px #ff2bd611}.alert strong{color:#ff8be9}.source{color:var(--cyan)}.footer{border-top:1px solid #142c3d;padding-top:14px}
@media(max-width:760px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.panel{padding:14px}.top>div:last-child{display:flex;gap:8px;flex-wrap:wrap}.top .pill{flex-basis:100%;text-align:center}.brand h1{font-size:18px;letter-spacing:.08em}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
.footer strong{color:var(--pink);font-family:ui-monospace,monospace;text-shadow:0 0 12px #ff2bd655}.ports{color:var(--cyan);font-size:11px}.ack{border-color:#ff2bd688;color:#ff9cec}.ack:disabled{color:var(--green);border-color:#62ffd155;cursor:default}@media print{body{background:white!important;color:#111!important}.top button,.toolbar,.ports,.ack{display:none!important}.card,.panel{box-shadow:none!important;background:white!important;color:#111!important;border-color:#aaa!important}.value,h1,h2,.label,.small,td,th,.footer{color:#111!important;text-shadow:none!important}.wrap{max-width:none;padding:0}}</style></head><body><main class="wrap">
<header class="top"><div class="brand"><div class="mark">◈</div><div><h1 data-text="IknoWurHeRe">IknoWurHeRe</h1><div class="sub">Local network inventory & defensive signals</div></div></div><div><span id="status" class="pill">Connecting…</span> <button id="scanNow" class="primary">Scan now</button> <button id="refresh">Refresh</button> <button id="exportHtml">Export HTML</button> <button id="savePdf">Save PDF</button></div></header>
<section class="grid"><article class="card"><div class="label">Known devices</div><div id="count" class="value">—</div></article><article class="card"><div class="label">Gateway</div><div id="gateway" class="value" style="font-size:19px">—</div></article><article class="card"><div class="label">DNS resolvers</div><div id="dns" class="value" style="font-size:16px">—</div></article><article class="card"><div class="label">DHCP server</div><div id="dhcp" class="value" style="font-size:19px">—</div></article><article class="card"><div class="label">Recent alerts</div><div id="alertcount" class="value">—</div></article></section>
<section class="panel"><div class="panelhead"><h2>Device inventory</h2><span id="scaninfo" class="small">—</span></div><div class="toolbar"><input id="deviceSearch" type="search" placeholder="Search IP, MAC, vendor, or hostname" aria-label="Search devices"><select id="statusFilter" aria-label="Filter by status"><option value="all">All statuses</option><option value="recent">Recent</option><option value="stale">Stale</option></select></div><div class="scroll"><table><thead><tr><th>Status</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>Source</th><th>First seen</th><th>Last seen</th><th>Quick ports</th></tr></thead><tbody id="devices"></tbody></table></div><div id="no-devices" class="empty" hidden>No devices recorded yet.</div></section>
<section class="panel"><div class="panelhead"><h2>Defensive alerts</h2><span class="small">Most recent first</span></div><div class="toolbar"><input id="alertSearch" type="search" placeholder="Filter alerts by type, IP, or reason" aria-label="Filter alerts"></div><div id="alerts"></div><div id="no-alerts" class="empty" hidden>No alerts recorded.</div></section>
<section class="panel"><div class="panelhead"><h2>Observed traffic</h2><span id="trafficNote" class="small">Optional packet header counters</span></div><div class="scroll"><table><thead><tr><th>IP</th><th>As source</th><th>As destination</th><th>Total observed</th></tr></thead><tbody id="trafficRows"></tbody></table></div><div id="no-traffic" class="empty" hidden>No traffic counters yet. Start the web command with --traffic to enable best-effort counters.</div></section>
<div class="footer"><span>Passive observations are indicators, not proof of malicious activity. IP byte counts are best-effort interface visibility, not router totals.</span><strong>تم تطويره من قبل SAI</strong></div>
</main><script>
const $=id=>document.getElementById(id);
let apiToken=sessionStorage.getItem('ikno_api_token')||'';
let tokenPrompt=null,refreshInProgress=false,deviceCache=[],alertCache=[];
function requestToken(){if(!tokenPrompt){tokenPrompt=Promise.resolve().then(()=>{apiToken=(prompt('Enter the access token printed by the currently running IknoWurHeRe command')||'').trim();sessionStorage.setItem('ikno_api_token',apiToken);return apiToken}).finally(()=>{tokenPrompt=null})}return tokenPrompt}
async function api(path,options={}){const send=()=>fetch(path,{...options,headers:{...(options.headers||{}),'X-API-Key':apiToken},cache:'no-store'});let r=await send();if(r.status===401){await requestToken();r=await send()}if(r.status===401){apiToken='';sessionStorage.removeItem('ikno_api_token');throw Error('Token rejected. Use the latest token printed by the running server.')}if(!r.ok){let p={};try{p=await r.json()}catch{}throw Error(p.detail||`API returned ${r.status}`)}if((r.headers.get('content-type')||'').includes('text/html'))return await r.text();return await r.json()}
function cell(row,value,cls=''){let td=document.createElement('td');td.textContent=value??'—';if(cls)td.className=cls;row.appendChild(td)}
function fmt(v){if(!v)return'—';try{return new Date(v).toLocaleString()}catch{return v}}
function formatBytes(bytes){if(!bytes)return'0 B';const units=['B','KB','MB','GB'];let i=0,n=bytes;while(n>=1024&&i<units.length-1){n/=1024;i++}return`${n.toFixed(i?1:0)} ${units[i]}`}
function renderDevices(){let q=$('deviceSearch').value.trim().toLowerCase(),wanted=$('statusFilter').value;let rows=deviceCache.filter(d=>{let s=[d.ip,d.mac,d.vendor,d.hostname].filter(Boolean).join(' ').toLowerCase();return(!q||s.includes(q))&&(wanted==='all'||d.status===wanted)});let body=$('devices');body.replaceChildren();$('no-devices').hidden=rows.length>0;$('no-devices').textContent=deviceCache.length?'No devices match these filters.':'No devices recorded yet.';for(const d of rows){let tr=document.createElement('tr');cell(tr,d.status==='recent'?'Recent':d.status==='stale'?'Stale':d.status==='online'?'Online':'Unknown');cell(tr,d.ip);cell(tr,d.mac);cell(tr,d.vendor);cell(tr,d.hostname);cell(tr,d.source,'source');cell(tr,fmt(d.first_seen));cell(tr,fmt(d.last_seen));let td=document.createElement('td'),b=document.createElement('button');b.className='ports';b.textContent='Quick scan';b.onclick=()=>scanPorts(d.ip,b);td.appendChild(b);tr.appendChild(td);body.appendChild(tr)}}
function renderAlerts(){let q=$('alertSearch').value.trim().toLowerCase();let rows=alertCache.filter(a=>[a.event_type,a.ip,a.reason].join(' ').toLowerCase().includes(q));let box=$('alerts');box.replaceChildren();$('no-alerts').hidden=rows.length>0;$('no-alerts').textContent=alertCache.length?'No alerts match this filter.':'No alerts recorded.';for(const a of rows){let item=document.createElement('div');item.className='alert';let title=document.createElement('strong');title.textContent=`${a.event_type.replaceAll('_',' ')} · ${Math.round(a.confidence*100)}%`;let p=document.createElement('div');p.textContent=a.reason;let meta=document.createElement('div');meta.className='small';meta.textContent=`${a.ip||'network'} · ${fmt(a.observed_at)}`;let action=document.createElement('button');action.className='ack';action.textContent=a.acknowledged_at?'Acknowledged':'Acknowledge';action.disabled=!!a.acknowledged_at;if(!a.acknowledged_at)action.onclick=()=>acknowledge(a.alert_id,action);item.append(title,p,meta,action);box.appendChild(item)}}
async function loadTraffic(){const result=await api('/api/traffic');let body=$('trafficRows');body.replaceChildren();$('trafficNote').textContent=result.enabled?'Observed interface bytes • best effort':'Disabled • start server with --traffic';$('no-traffic').hidden=result.enabled&&result.items.length>0;$('no-traffic').textContent=result.enabled?'No matching traffic observed yet.':'Traffic counters are opt-in and require passive capture permissions.';for(const item of result.items){let tr=document.createElement('tr');cell(tr,item.ip);cell(tr,formatBytes(item.source_bytes));cell(tr,formatBytes(item.destination_bytes));cell(tr,formatBytes(item.total_bytes));body.appendChild(tr)}}
async function refresh(){if(refreshInProgress)return;refreshInProgress=true;try{const [overview,devices,alerts]=await Promise.all([api('/api/overview'),api('/api/devices'),api('/api/alerts'),loadTraffic()]);const state=overview.last_scan_status||'waiting';$('status').textContent=state==='running'?'Scan running…':state==='error'?`Scan failed: ${overview.last_scan_error||'unknown error'}`:state==='warning'?'Live • limited discovery':'Live • refreshing every 5s';$('status').className=state==='error'?'pill error':'pill';$('count').textContent=overview.device_count;$('gateway').textContent=overview.gateway||'Unknown';$('dns').textContent=(overview.dns||[]).join(', ')||'Unknown';$('dhcp').textContent=overview.dhcp||'Unknown';$('alertcount').textContent=overview.alert_count;$('scaninfo').textContent=overview.last_scan?`Last attempt: ${state} • ${fmt(overview.last_scan)}${overview.last_scan_duration==null?'':` • ${overview.last_scan_duration}s`}${state==='error'&&overview.last_scan_error?` • ${overview.last_scan_error}`:''}`:'Waiting for first scan';deviceCache=devices;alertCache=alerts;renderDevices();renderAlerts()}catch(e){$('status').textContent=`Dashboard error: ${e.message}`;$('status').className='pill error';console.error(e)}finally{refreshInProgress=false}}
async function scanNow(){let b=$('scanNow');b.disabled=true;b.textContent='Scanning…';$('status').textContent='Scan running…';try{const result=await api('/api/scan',{method:'POST'});$('scaninfo').textContent=`Scan complete • ${result.device_count} device(s)`;await refresh()}catch(e){$('status').textContent=`Scan failed: ${e.message}`;$('status').className='pill error'}finally{b.disabled=false;b.textContent='Scan now'}}
async function scanPorts(ip,button){button.disabled=true;button.textContent='Checking…';try{const result=await api(`/api/devices/${encodeURIComponent(ip)}/ports`,{method:'POST'});const text=result.open_ports.length?result.open_ports.map(p=>`${p.port}/${p.service}`).join(', '):'No common TCP ports responded';button.textContent=text;button.title=`Checked ${result.checked} fixed common TCP ports; no application data was sent.`}catch(e){button.textContent='Scan failed';button.title=e.message}finally{button.disabled=false}}
async function acknowledge(id,button){button.disabled=true;try{await api(`/api/alerts/${id}/ack`,{method:'POST'});await refresh()}catch(e){button.disabled=false;button.title=e.message}}
async function exportHtml(){try{const report=await api('/api/export/html');const url=URL.createObjectURL(new Blob([report],{type:'text/html'}));const a=document.createElement('a');a.href=url;a.download='iknowurhere-report.html';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}catch(e){$('status').textContent=`Export failed: ${e.message}`;$('status').className='pill error'}}
$('refresh').onclick=refresh;$('scanNow').onclick=scanNow;$('exportHtml').onclick=exportHtml;$('savePdf').onclick=()=>window.print();$('deviceSearch').addEventListener('input',renderDevices);$('statusFilter').addEventListener('change',renderDevices);$('alertSearch').addEventListener('input',renderAlerts);refresh();setInterval(refresh,5000);</script></body></html>"""


def create_dashboard_app(
    network: str,
    store: DeviceStore,
    *,
    interval: int = 60,
    interface: str | None = None,
    trusted_dhcp: set[str] | None = None,
    trusted_gateway: set[str] | None = None,
    trusted_dns: set[str] | None = None,
    api_token: str | None = None,
    traffic_enabled: bool = False,
    background_scan: bool = True,
    background_monitor: bool = True,
) -> FastAPI:
    monitor = PassiveMonitor(interface, traffic_enabled=traffic_enabled)
    scan_lock = asyncio.Lock()
    port_scan_lock = asyncio.Lock()

    def queue_notifications(alerts):
        if not alerts:
            return
        tasks = getattr(app.state, "notification_tasks", None)
        if tasks is None:
            app.state.notification_tasks = tasks = set()
        task = asyncio.create_task(notify_alerts(alerts))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    async def scan_loop(app: FastAPI) -> None:
        while True:
            started = asyncio.get_running_loop().time()
            app.state.last_scan_status = "running"
            app.state.last_scan_error = None
            try:
                async with scan_lock:
                    summary = await scan_and_record(
                        network, store, interface=interface,
                        trusted_gateway=trusted_gateway, trusted_dns=trusted_dns
                    )
                    app.state.last_scan = datetime.now(timezone.utc).isoformat()
                    app.state.scan_warning = summary.warning
                    app.state.last_scan_status = "warning" if summary.warning else "success"
                    app.state.last_scan_error = summary.warning
                    app.state.last_scan_duration = round(asyncio.get_running_loop().time() - started, 2)
                    app.state.last_error = summary.warning or app.state.capture_warning
                    queue_notifications(summary.alerts)
            except Exception as exc:  # Keep dashboard alive and expose a concise scan error.
                logger.exception("Background network scan failed")
                app.state.last_scan = datetime.now(timezone.utc).isoformat()
                app.state.last_scan_status = "error"
                app.state.last_scan_error = str(exc)
                app.state.last_scan_duration = round(asyncio.get_running_loop().time() - started, 2)
                app.state.scan_warning = app.state.last_scan_error
                app.state.last_error = app.state.last_scan_error
            await asyncio.sleep(interval)

    async def passive_loop(app: FastAPI) -> None:
        while True:
            try:
                event = await asyncio.to_thread(monitor.events.get, True, 1)
            except Exception:
                continue
            if event.kind == "error":
                app.state.capture_warning = event.value
                app.state.last_error = event.value
                continue
            try:
                gateway = current_gateway()
                alerts = persist_passive_event(
                    store, event, scope=network, gateway_ip=gateway, trusted_dhcp=trusted_dhcp
                )
                queue_notifications(alerts)
            except Exception as exc:
                logger.exception("Could not persist passive network observation")
                app.state.capture_warning = f"Passive observation could not be saved: {exc}"
                app.state.last_error = app.state.capture_warning

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.last_scan = None
        app.state.last_scan_status = "waiting"
        app.state.last_scan_error = None
        app.state.last_scan_duration = None
        app.state.scan_warning = None
        app.state.capture_warning = None
        app.state.last_error = None
        app.state.notification_tasks = set()
        if background_monitor:
            app.state.capture_warning = monitor.start()
            app.state.last_error = app.state.capture_warning
        tasks = []
        if background_scan:
            tasks.append(asyncio.create_task(scan_loop(app)))
        if background_monitor:
            tasks.append(asyncio.create_task(passive_loop(app)))
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            if background_monitor:
                monitor.stop()
            await asyncio.gather(*tasks, return_exceptions=True)
            if app.state.notification_tasks:
                await asyncio.gather(*app.state.notification_tasks, return_exceptions=True)
            store.close()

    app = FastAPI(title="IknoWurHeRe", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.network = network
    app.state.store = store
    app.state.last_scan = None
    app.state.last_scan_status = "waiting"
    app.state.last_scan_error = None
    app.state.last_scan_duration = None
    app.state.scan_warning = None
    app.state.capture_warning = None
    app.state.last_error = None
    app.state.scan_lock = scan_lock
    app.state.api_token = api_token
    app.state.traffic_enabled = traffic_enabled
    app.state.notification_tasks = set()
    app.state.started_at = datetime.now(timezone.utc).isoformat()

    @app.middleware("http")
    async def secure_responses(request: Request, call_next):
        if request.url.path.startswith("/api/") and api_token:
            supplied = request.headers.get("X-API-Key", "")
            if not secrets.compare_digest(supplied, api_token):
                from fastapi.responses import JSONResponse

                return JSONResponse({"detail": "Dashboard token required"}, status_code=401)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'"
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return INDEX_HTML

    @app.get("/api/overview")
    async def overview():
        devices = store.list_devices(scope=network)
        alerts = store.list_alerts(limit=100, scope=network)
        state = {item.key: item.value for item in store.list_network_state(scope=network)}
        import json

        try:
            dns = json.loads(state.get("dns", "[]"))
        except ValueError:
            dns = []
        try:
            gateway = json.loads(state.get("gateway", "null"))
        except ValueError:
            gateway = None
        try:
            dhcp = json.loads(state.get("dhcp", "null"))
        except ValueError:
            dhcp = None
        return {
            "network": network,
            "device_count": len(devices),
            "alert_count": len(alerts),
            "gateway": gateway,
            "dns": dns if isinstance(dns, list) else [dns],
            "dhcp": dhcp,
            "last_scan": app.state.last_scan,
            "last_scan_status": app.state.last_scan_status,
            "last_scan_error": app.state.last_scan_error,
            "last_scan_duration": app.state.last_scan_duration,
            "last_error": app.state.last_error,
        }

    @app.get("/api/devices")
    async def devices():
        return [asdict(device) for device in store.list_devices(scope=network)]

    @app.get("/api/alerts")
    async def alerts(limit: int = 100):
        return [asdict(alert) for alert in store.list_alerts(limit=max(1, min(limit, 500)), scope=network)]

    @app.get("/api/state")
    async def state():
        return [asdict(item) for item in store.list_network_state(scope=network)]

    @app.post("/api/scan")
    async def scan_now():
        started = asyncio.get_running_loop().time()
        app.state.last_scan_status = "running"
        app.state.last_scan_error = None
        async with scan_lock:
            try:
                summary = await scan_and_record(
                    network, store, interface=interface,
                    trusted_gateway=trusted_gateway, trusted_dns=trusted_dns
                )
            except Exception as exc:
                logger.exception("On-demand network scan failed")
                app.state.last_scan = datetime.now(timezone.utc).isoformat()
                app.state.last_scan_status = "error"
                app.state.last_scan_error = str(exc)
                app.state.last_scan_duration = round(asyncio.get_running_loop().time() - started, 2)
                app.state.scan_warning = str(exc)
                app.state.last_error = str(exc)
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            app.state.last_scan = datetime.now(timezone.utc).isoformat()
            app.state.scan_warning = summary.warning
            app.state.last_scan_status = "warning" if summary.warning else "success"
            app.state.last_scan_error = summary.warning
            app.state.last_scan_duration = round(asyncio.get_running_loop().time() - started, 2)
            app.state.last_error = summary.warning or app.state.capture_warning
            queue_notifications(summary.alerts)
            return {
                "ok": True,
                "device_count": len(summary.devices),
                "alert_count": len(summary.alerts),
                "last_scan": app.state.last_scan,
                "last_scan_status": app.state.last_scan_status,
                "last_scan_duration": app.state.last_scan_duration,
                "warning": summary.warning,
            }

    @app.post("/api/alerts/{alert_id}/ack")
    async def acknowledge_alert(alert_id: int):
        if alert_id < 1:
            raise HTTPException(status_code=422, detail="Alert id must be positive")
        if not store.acknowledge_alert(alert_id, scope=network):
            raise HTTPException(status_code=409, detail="Alert was already acknowledged or does not exist")
        return {"ok": True, "alert_id": alert_id}

    @app.post("/api/devices/{address}/ports")
    async def scan_common_ports(address: str):
        known = {device.ip for device in store.list_devices(scope=network)}
        if address not in known:
            raise HTTPException(status_code=404, detail="Target is not a device in the current inventory")
        try:
            async with port_scan_lock:
                ports = await quick_port_scan(network, address)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"ip": address, "checked": len(COMMON_TCP_PORTS), "open_ports": ports}

    @app.get("/api/traffic")
    async def traffic():
        if not traffic_enabled:
            return {"enabled": False, "items": []}
        counters = monitor.traffic_snapshot()
        items = []
        for device in store.list_devices(scope=network):
            observed = counters.get(device.ip, {"source_bytes": 0, "destination_bytes": 0})
            items.append({"ip": device.ip, **observed,
                          "total_bytes": observed["source_bytes"] + observed["destination_bytes"]})
        return {"enabled": True, "items": sorted(items, key=lambda item: item["total_bytes"], reverse=True)}

    @app.get("/api/export/html", response_class=HTMLResponse)
    async def export_html():
        devices = store.list_devices(scope=network)
        alerts = store.list_alerts(limit=500, scope=network)
        device_rows = "".join(
            "<tr>" + "".join(f"<td>{html.escape(str(value or '—'))}</td>" for value in
                (d.status, d.ip, d.mac, d.vendor, d.hostname, d.source, d.first_seen, d.last_seen)) + "</tr>"
            for d in devices
        )
        alert_rows = "".join(
            "<tr>" + "".join(f"<td>{html.escape(str(value or '—'))}</td>" for value in
                (a.observed_at, a.event_type, f"{a.confidence:.0%}", a.ip, a.reason,
                 "Acknowledged" if a.acknowledged_at else "Open")) + "</tr>"
            for a in alerts
        )
        report = f"""<!doctype html><html><head><meta charset="utf-8"><title>IknoWurHeRe report</title></head>
<body style="font:14px system-ui;background:#070b12;color:#e8f7ff;padding:24px">
<h1 style="color:#00eaff">IknoWurHeRe security report</h1><p>Network: {html.escape(network)} · Generated: {html.escape(datetime.now(timezone.utc).isoformat())}</p>
<h2>Device inventory ({len(devices)})</h2><table style="border-collapse:collapse;width:100%"><thead><tr><th>Status</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>Source</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>{device_rows}</tbody></table>
<h2>Alerts ({len(alerts)})</h2><table style="border-collapse:collapse;width:100%"><thead><tr><th>When</th><th>Type</th><th>Confidence</th><th>Address</th><th>Reason</th><th>State</th></tr></thead><tbody>{alert_rows}</tbody></table></body></html>"""
        return HTMLResponse(report, headers={"Content-Disposition": 'attachment; filename="iknowurhere-report.html"'})

    return app
