"""A local, zero-dependency web interface for the scanner.

``aegisml serve`` starts :mod:`http.server` on the loopback interface.  The page
is served from memory, makes no external requests, and the scan runs in the same
process with the same engine as the CLI — nothing is uploaded anywhere.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
from typing import Any

from . import __version__
from .rules import ALL_RULES, RULESET_VERSION
from .scanner import AegisML, ENGINE_VERSION


MAX_UPLOAD = 2 * 1024 * 1024 * 1024
_LOCK = threading.Lock()


def _page() -> str:
    return _PAGE.replace("__ENGINE__", ENGINE_VERSION).replace("__RULES__", RULESET_VERSION)


class _Handler(BaseHTTPRequestHandler):
    server_version = f"AegisML/{__version__}"
    root: Path = Path.cwd()

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter default logging
        if os.environ.get("AEGISML_SERVE_VERBOSE"):
            super().log_message(fmt, *args)

    # -- helpers ---------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _safe_path(self, raw: str) -> Path | None:
        candidate = (self.root / raw).resolve() if not os.path.isabs(raw) else Path(raw).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError:
            return None
        return candidate

    # -- routes ----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, _page().encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/api/info":
            self._json(200, {
                "version": __version__, "engine": ENGINE_VERSION, "ruleset": RULESET_VERSION,
                "rules": len(ALL_RULES), "root": str(self.root),
            })
        elif path == "/api/rules":
            self._json(200, {"ruleset": RULESET_VERSION,
                             "rules": [rule.to_dict() for rule in ALL_RULES]})
        elif path == "/api/files":
            entries = []
            for item in sorted(self.root.rglob("*"))[:5000]:
                if item.is_file() and not item.is_symlink():
                    entries.append({
                        "path": item.relative_to(self.root).as_posix(),
                        "size": item.stat().st_size,
                    })
            self._json(200, {"root": str(self.root), "files": entries})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/api/scan/path":
            self._scan_path()
        elif path == "/api/scan/upload":
            self._scan_upload()
        else:
            self._json(404, {"error": "not found"})

    def _scan_path(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(min(length, 65536)) or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON body"})
            return
        target = self._safe_path(str(payload.get("path", "")))
        if target is None or not target.is_file():
            self._json(400, {"error": "path is outside the served root or is not a file"})
            return
        self._respond_scan(lambda engine: engine.scan(target))

    def _scan_upload(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_UPLOAD:
            self._json(413, {"error": f"upload must be between 1 byte and {MAX_UPLOAD} bytes"})
            return
        name = self.headers.get("X-Artifact-Name") or "uploaded.bin"
        name = os.path.basename(name).replace("\x00", "")[:200] or "uploaded.bin"
        handle = tempfile.NamedTemporaryFile(
            prefix="aegisml-", suffix=f"-{name}", delete=False)
        try:
            remaining = length
            while remaining > 0:
                block = self.rfile.read(min(4 * 1024 * 1024, remaining))
                if not block:
                    break
                handle.write(block)
                remaining -= len(block)
            handle.close()
            temporary = Path(handle.name)
            self._respond_scan(lambda engine: engine.scan(temporary), display=name)
        finally:
            try:
                os.unlink(handle.name)
            except OSError:
                pass

    def _respond_scan(self, run, display: str | None = None) -> None:
        engine = AegisML(api_url="")
        try:
            with _LOCK:  # one scan at a time keeps memory predictable on a laptop
                result = run(engine)
        except (OSError, ValueError, RuntimeError) as error:
            self._json(400, {"error": str(error)})
            return
        payload = result.to_dict()
        if display:
            payload["filename"] = display
        self._json(200, payload)


def serve(*, host: str = "127.0.0.1", port: int = 8765, root: Path | None = None) -> int:
    handler = _Handler
    handler.root = (root or Path.cwd()).resolve()
    server = ThreadingHTTPServer((host, port), handler)
    address = f"http://{host}:{port}/"
    print(f"AegisML {__version__} · engine {ENGINE_VERSION} · rules {RULESET_VERSION}")
    print(f"local interface: {address}")
    print(f"scan root:       {handler.root}")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        print("warning: binding outside loopback exposes local file scanning to the network")
    print("press Ctrl-C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AegisML — local scanner</title>
<style>
:root{--bg:#07090f;--panel:#0e1320;--panel2:#131a2b;--line:#1e2740;--ink:#e8ecf6;
--muted:#8e9bb5;--accent:#5b8cff;--ok:#22c55e;--low:#38bdf8;--medium:#f59e0b;
--high:#f97316;--critical:#ef4444;--mono:ui-monospace,'SF Mono',Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1100px 600px at 15% -10%,#16203a,var(--bg) 55%);
color:var(--ink);font:15px/1.6 system-ui,-apple-system,'Segoe UI',sans-serif}
.wrap{max-width:1060px;margin:0 auto;padding:28px 18px 80px}
header{display:flex;gap:14px;align-items:baseline;flex-wrap:wrap;margin-bottom:24px}
h1{font-size:20px;margin:0;letter-spacing:-.02em}
h1 b{color:var(--accent)}
.meta{color:var(--muted);font-family:var(--mono);font-size:12.5px}
.drop{border:1.5px dashed var(--line);border-radius:16px;padding:38px 20px;text-align:center;
background:linear-gradient(180deg,var(--panel),var(--panel2));transition:.15s;cursor:pointer}
.drop.hot{border-color:var(--accent);background:rgba(91,140,255,.08)}
.drop h2{margin:0 0 6px;font-size:17px}
.drop p{margin:0;color:var(--muted);font-size:13.5px}
.row{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap}
input[type=text]{flex:1;min-width:240px;background:#0a0e18;border:1px solid var(--line);
border-radius:10px;color:var(--ink);padding:10px 12px;font-family:var(--mono);font-size:13px}
button{background:var(--accent);border:0;border-radius:10px;color:#04070f;font-weight:650;
padding:10px 18px;cursor:pointer;font-size:14px}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--ink);font-weight:500}
button:disabled{opacity:.5;cursor:progress}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));margin:24px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.card .k{color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.09em}
.card .v{font-size:21px;font-weight:650;margin-top:4px}
.verdict{display:inline-block;border-radius:999px;padding:5px 14px;font-weight:700;font-size:13px}
.v-SAFE{background:rgba(34,197,94,.15);color:var(--ok)}
.v-INCOMPLETE,.v-SUSPICIOUS{background:rgba(245,158,11,.15);color:var(--medium)}
.v-DANGEROUS{background:rgba(249,115,22,.16);color:var(--high)}
.v-CRITICAL{background:rgba(239,68,68,.18);color:var(--critical)}
details.f{border:1px solid var(--line);border-radius:13px;margin-bottom:10px;background:var(--panel)}
details.f>summary{cursor:pointer;padding:12px 16px;display:flex;gap:11px;align-items:center;list-style:none}
details.f>summary::-webkit-details-marker{display:none}
.sev{font-family:var(--mono);font-size:10.5px;font-weight:700;padding:3px 8px;border-radius:6px;flex:none}
.s-critical{background:rgba(239,68,68,.18);color:var(--critical)}
.s-high{background:rgba(249,115,22,.16);color:var(--high)}
.s-medium{background:rgba(245,158,11,.14);color:var(--medium)}
.s-low{background:rgba(56,189,248,.14);color:var(--low)}
.s-info{background:rgba(142,155,181,.12);color:var(--muted)}
.fid{font-family:var(--mono);font-size:12.5px;font-weight:600}
.fd{color:var(--muted);font-size:12.5px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.body{padding:0 16px 16px;display:grid;gap:10px;font-size:13.5px}
dl{display:grid;grid-template-columns:120px 1fr;gap:4px 12px;margin:0;font-size:12.5px}
dt{color:var(--muted)}dd{margin:0;font-family:var(--mono);word-break:break-all}
pre{background:#080b13;border:1px solid var(--line);border-radius:9px;padding:10px;margin:0;
overflow:auto;font-family:var(--mono);font-size:11.5px;color:#c9d4ee}
.fix{border-left:3px solid var(--accent);padding:7px 11px;background:rgba(91,140,255,.07)}
.files{max-height:220px;overflow:auto;border:1px solid var(--line);border-radius:12px;margin-top:12px}
.files div{padding:7px 12px;font-family:var(--mono);font-size:12px;cursor:pointer;
border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:12px}
.files div:hover{background:rgba(91,140,255,.09)}
.err{color:var(--critical);font-size:13.5px;margin-top:12px}
footer{color:var(--muted);font-size:12px;margin-top:36px;text-align:center}
</style></head><body><div class="wrap">
<header><h1>Aegis<b>ML</b></h1>
<div class="meta">engine __ENGINE__ · rules __RULES__ · running locally, nothing leaves this machine</div>
</header>

<div class="drop" id="drop">
  <h2>Drop a model artifact here</h2>
  <p>.safetensors · .gguf · .pt / .bin / .ckpt · .onnx · .h5 / .keras · .npy / .npz · .pkl · archives</p>
  <input type="file" id="file" hidden>
</div>
<div class="row">
  <input type="text" id="path" placeholder="…or a path relative to the scan root">
  <button id="scanPath" class="ghost">Scan path</button>
  <button id="list" class="ghost">Browse root</button>
</div>
<div class="files" id="files" hidden></div>
<div class="err" id="err" hidden></div>
<div id="out"></div>
<footer>Static analysis only — the artifact is never executed, imported, unpickled or extracted.</footer>
</div>
<script>
const $=(id)=>document.getElementById(id);
const bytes=(n)=>{const u=['B','KiB','MiB','GiB','TiB'];let i=0;n=Number(n)||0;
 while(n>=1024&&i<u.length-1){n/=1024;i++}return (i?n.toFixed(1):n)+' '+u[i]};
const esc=(s)=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function busy(on){document.querySelectorAll('button').forEach(b=>b.disabled=on);
 if(on){$('out').innerHTML='<div class="card"><div class="k">scanning</div><div class="v">…</div></div>'}}
function fail(m){$('err').hidden=false;$('err').textContent=m}
function clearErr(){$('err').hidden=true;$('err').textContent=''}

function render(r){
  const m=r.metadata||{},cov=m.coverage||{},c=r.severity_counts||{};
  const cards=[['verdict','<span class="verdict v-'+r.verdict+'">'+r.verdict+'</span>'],
   ['risk',(r.risk_score||0).toFixed(0)+'<span style="color:var(--muted);font-size:13px">/100</span>'],
   ['findings',(r.threats||[]).length],
   ['format',esc(m.format_detected||'—')],
   ['size',bytes(m.file_size)],
   ['throughput',(m.throughput_mib_s||0)+' MiB/s']];
  let h='<div class="grid">'+cards.map(([k,v])=>
    '<div class="card"><div class="k">'+k+'</div><div class="v">'+v+'</div></div>').join('')+'</div>';
  h+='<dl style="grid-template-columns:150px 1fr;margin-bottom:20px">'+
     '<dt>artifact</dt><dd>'+esc(r.filename)+'</dd>'+
     '<dt>sha256</dt><dd>'+esc(m.sha256||'')+'</dd>'+
     '<dt>signature tier</dt><dd>'+esc(cov.signatures||m.signature_tier||'—')+'</dd>'+
     '<dt>coverage</dt><dd>'+Object.entries(cov).filter(([k])=>k!=='complete')
       .map(([k,v])=>k+'='+v).join(', ')+'</dd>'+
     '<dt>severities</dt><dd>'+Object.entries(c).filter(([,v])=>v)
       .map(([k,v])=>k+'='+v).join(' ')+'</dd></dl>';
  const th=r.threats||[];
  if(!th.length){h+='<div class="card"><div class="v" style="color:var(--ok)">No findings</div></div>'}
  th.forEach(t=>{
    const rows=[['location',t.location],['region',t.region],
      ['byte offsets',(t.byte_offsets||[]).slice(0,8).join(', ')],
      ['occurrences',t.occurrences],['category',t.category],['cvss',t.cvss],
      ['confidence',t.confidence],['technique',(t.attack||[]).join(', ')],
      ['weakness',(t.cwe||[]).join(', ')],['references',(t.references||[]).join(', ')]]
      .filter(([,v])=>v!==''&&v!==undefined&&v!==null&&String(v).length);
    h+='<details class="f"'+(t.severity==='critical'||t.severity==='high'?' open':'')+'>'+
      '<summary><span class="sev s-'+t.severity+'">'+t.severity.toUpperCase()+'</span>'+
      '<span class="fid">'+esc(t.id)+'</span><span class="fd">'+esc(t.description)+'</span></summary>'+
      '<div class="body"><div>'+esc(t.description)+'</div>'+
      ((t.evidence||[]).length?'<pre>'+t.evidence.slice(0,3).map(esc).join('\\n')+'</pre>':'')+
      '<dl>'+rows.map(([k,v])=>'<dt>'+k+'</dt><dd>'+esc(v)+'</dd>').join('')+'</dl>'+
      (t.remediation?'<div class="fix"><b>Fix.</b> '+esc(t.remediation)+'</div>':'')+
      '</div></details>';
  });
  $('out').innerHTML=h;
}

async function post(url,body,headers){
  const res=await fetch(url,{method:'POST',body,headers});
  const data=await res.json();
  if(!res.ok||data.error){throw new Error(data.error||('HTTP '+res.status))}
  return data;
}
async function scanFile(f){
  clearErr();busy(true);
  try{render(await post('/api/scan/upload',f,{'X-Artifact-Name':f.name}))}
  catch(e){fail(e.message);$('out').innerHTML=''}finally{busy(false)}
}
async function scanPath(p){
  clearErr();busy(true);
  try{render(await post('/api/scan/path',JSON.stringify({path:p}),
    {'Content-Type':'application/json'}))}
  catch(e){fail(e.message);$('out').innerHTML=''}finally{busy(false)}
}
const drop=$('drop');
drop.onclick=()=>$('file').click();
$('file').onchange=e=>{if(e.target.files[0])scanFile(e.target.files[0])};
['dragenter','dragover'].forEach(ev=>drop.addEventListener(ev,e=>{
  e.preventDefault();drop.classList.add('hot')}));
['dragleave','drop'].forEach(ev=>drop.addEventListener(ev,e=>{
  e.preventDefault();drop.classList.remove('hot')}));
drop.addEventListener('drop',e=>{const f=e.dataTransfer.files[0];if(f)scanFile(f)});
$('scanPath').onclick=()=>{const v=$('path').value.trim();if(v)scanPath(v)};
$('path').addEventListener('keydown',e=>{if(e.key==='Enter'){const v=e.target.value.trim();if(v)scanPath(v)}});
$('list').onclick=async()=>{
  clearErr();
  try{const d=await(await fetch('/api/files')).json();
    $('files').hidden=false;
    $('files').innerHTML=d.files.map(f=>'<div data-p="'+esc(f.path)+'"><span>'+esc(f.path)+
      '</span><span style="color:var(--muted)">'+bytes(f.size)+'</span></div>').join('')
      ||'<div>no files under the scan root</div>';
    $('files').querySelectorAll('div[data-p]').forEach(el=>
      el.onclick=()=>{$('path').value=el.dataset.p;scanPath(el.dataset.p)});
  }catch(e){fail(e.message)}
};
</script></body></html>"""
