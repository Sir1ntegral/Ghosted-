#!/usr/bin/env python
"""
Rabbit Home — a sovereign, Google-like home page.

Pure-stdlib HTTP server (http.server) — no Flask, no Streamlit, no new deps.
Serves Rabbit's own search homepage: ghost-rabbit logo + a centered search box
that routes queries through the SovereignBrowserEngine (5-engine masks, Tor-by-
default). Binds 0.0.0.0 so it is reachable by IP across LAN / Tailscale /
WireGuard, and shows every address Rabbit is reachable at PLUS the current
egress IP (what the ISP / Tor exit sees).
"""
from __future__ import annotations

import html
import os
import secrets
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ── IP discovery ─────────────────────────────────────────────────────────────
def _primary_lan_ip() -> str:
    """The LAN IP the OS would use to reach the internet (no traffic sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


_LOCAL_IPS_CACHE: dict = {"ips": None, "at": 0.0}


def _all_local_ips() -> list[str]:
    # Cached 60s: the getaddrinfo + UDP-socket enumeration was running on EVERY
    # page render (egress was cached, this was missed). Local IPs rarely change.
    if _LOCAL_IPS_CACHE["ips"] is not None and (time.time() - _LOCAL_IPS_CACHE["at"] < 60):
        return _LOCAL_IPS_CACHE["ips"]
    ips: set[str] = set()
    try:
        host = socket.gethostname()
        for fam, *_rest, sockaddr in socket.getaddrinfo(host, None):
            if fam == socket.AF_INET:
                ips.add(sockaddr[0])
    except Exception:
        pass
    ips.add(_primary_lan_ip())
    result = sorted(ips)
    _LOCAL_IPS_CACHE["ips"] = result
    _LOCAL_IPS_CACHE["at"] = time.time()
    return result


def _classify(ips: list[str]) -> dict[str, list[str]]:
    # No Tailscale — Rabbit reaches across his OWN sovereign WireGuard PackMesh.
    out: dict[str, list[str]] = {"lan": [], "wireguard": [], "loopback": []}
    for ip in ips:
        if ip.startswith("127."):
            out["loopback"].append(ip)
        elif ip.startswith("10.44."):
            out["wireguard"].append(ip)          # Rabbit PackMesh default subnet
        else:
            out["lan"].append(ip)
    return out


_EGRESS_CACHE: dict = {"ip": None, "at": 0.0}


def _egress_ip() -> str:
    """What the outside world sees — via Rabbit's own sovereign HTTP (masked).
    Cached 120s so it never blocks page renders (perf: was adding ~5s/request)."""
    import time
    if _EGRESS_CACHE["ip"] and (time.time() - _EGRESS_CACHE["at"] < 120):
        return _EGRESS_CACHE["ip"]
    val = "unknown (offline or fetch failed)"
    try:
        from rabbit.core.sovereign_downloader import sovereign_http_get
        r = sovereign_http_get("https://api.ipify.org", connect_timeout=5, read_timeout=5)
        if r.success and r.body:
            val = r.body.decode(errors="replace").strip()
    except Exception:
        pass
    _EGRESS_CACHE["ip"] = val
    _EGRESS_CACHE["at"] = time.time()
    return val


def _search(query: str) -> list:
    try:
        from rabbit.research.sovereign_browser_engine import SovereignBrowserEngine
        results = SovereignBrowserEngine().web_search(query)
    except Exception as e:  # never let the page 500
        return [type("E", (), {"title": "search error", "url": "", "snippet": str(e)})()]
    try:  # semantic re-rank: meaning / context / sentiment (degrades, never breaks)
        from rabbitghost import semantic_search as rabbit_search
        return rabbit_search.rerank(query, results)
    except Exception:
        return results


# ── Gojo boundary safeguard ──────────────────────────────────────────────────
def _gojo_audit_path() -> str:
    """Windows-safe absolute audit log path (avoids cwd-relative 'logs' failure)."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "RabbitGhost", "logs")
    try:
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "security_audit.jsonl")
    except Exception:
        return ""  # MEMORY_MODE


_GATE = None
_GATE_TRIED = False
_GATE_LOCK = threading.Lock()


def _gate():
    global _GATE, _GATE_TRIED
    if _GATE_TRIED:  # fast path
        return _GATE
    with _GATE_LOCK:  # double-checked: only one thread constructs the gate
        if _GATE_TRIED:
            return _GATE
        try:
            from rabbit.security.boundary.gojo_boundary import GojoBoundaryGate
            ap = _gojo_audit_path()
            _GATE = GojoBoundaryGate(audit_log_path=ap) if ap else GojoBoundaryGate()
            print("🛡  Gojo boundary engaged — every request is gated, throttled, audited.")
        except Exception as e:
            print(f"[gojo] boundary unavailable — network access will be REFUSED, localhost only: {e}")
            _GATE = None
        _GATE_TRIED = True  # set LAST, after _GATE is assigned
    return _GATE


def _gojo_admits(client_ip: str, path: str) -> bool:
    """Gojo gates every request. Fail-closed: if the guard can't load or errs,
    only loopback is served — Rabbit is NEVER exposed to the network ungated."""
    local = client_ip.startswith("127.")
    gate = _gate()
    if gate is None:
        return local
    if local:
        source_class = "network_local"
    elif client_ip.startswith("10.44."):
        source_class = "network_mesh"      # 10.44.* = WireGuard mesh subnet (reachability, NOT crypto proof of identity — the WG tunnel authenticates the peer at the kernel; this prefix only routes trust tier)
    else:
        source_class = "network_remote"
    try:
        verdict = gate.evaluate_request(
            actor_role="anonymous_web",
            action="homepage_get",
            source_class=source_class,
            metadata={"path": path, "client": client_ip},
        )
        return verdict.get("decision") == "allow"
    except Exception:
        return local  # guard error → fail closed to local-only


# ── pages ────────────────────────────────────────────────────────────────────
_PORT = 7654

_CSS = """
*{box-sizing:border-box;font-family:Segoe UI,Arial,sans-serif}
body{margin:0;background:#0d1020;color:#e8e8f0;display:flex;flex-direction:column;
 align-items:center;min-height:100vh}
.logo{font-size:64px;margin-top:18vh;letter-spacing:1px}
.logo b{color:#9aa9ff}
.tag{color:#8890b0;margin:6px 0 26px}
form{width:min(560px,92vw)}
input[type=text]{width:100%;padding:15px 20px;border-radius:26px;border:1px solid #2a2f50;
 background:#161a30;color:#fff;font-size:17px;outline:none}
input[type=text]:focus{border-color:#9aa9ff;box-shadow:0 0 0 3px #9aa9ff22}
.btns{margin-top:18px;text-align:center}
button{background:#1b2140;color:#cfd6ff;border:1px solid #2a2f50;padding:10px 18px;
 border-radius:8px;font-size:14px;cursor:pointer;margin:0 6px}
button:hover{border-color:#9aa9ff}
.ips{position:fixed;bottom:0;left:0;right:0;background:#0a0c18;border-top:1px solid #1c2138;
 font-size:12px;color:#7e88ad;padding:8px 14px;display:flex;gap:18px;flex-wrap:wrap}
.ips b{color:#9aa9ff}
.res{width:min(680px,92vw);margin:26px 0 80px}
.r{padding:12px 0;border-bottom:1px solid #1c2138}
.r a{color:#9aa9ff;text-decoration:none;font-size:18px}
.r .u{color:#5f7a55;font-size:12px;word-break:break-all}
.r .s{color:#c2c8e0;font-size:14px;margin-top:3px}
.r .b{color:#6f7aa0;font-size:11px;margin-top:4px;letter-spacing:.3px}
.tabbar{position:fixed;top:0;left:0;right:0;display:flex;gap:2px;background:#0a0c18;border-bottom:1px solid #1c2138;padding:6px 8px 0;overflow-x:auto;z-index:10}
.tab{display:flex;align-items:center;gap:6px;background:#161a30;color:#aeb6dc;border:1px solid #1c2138;border-bottom:none;border-radius:8px 8px 0 0;padding:7px 12px;font-size:13px;white-space:nowrap;cursor:pointer}
.tab.active{background:#1b2140;color:#fff;border-color:#2a2f50}
.tab .t{overflow:hidden;text-overflow:ellipsis;max-width:150px}
.tab .x{color:#6f7aa0;font-weight:bold}
.tab .x:hover{color:#ff8aa0}
.newtab{background:#161a30;color:#9aa9ff;border:1px solid #1c2138;border-bottom:none;border-radius:8px 8px 0 0;padding:7px 12px;cursor:pointer;font-size:15px}
body{padding-top:44px}
.toolbar{position:fixed;top:7px;right:10px;z-index:13;display:flex;gap:6px}
.toolbar button{font-size:12px;padding:5px 10px;margin:0}
.panel{position:fixed;top:46px;right:10px;width:310px;max-height:74vh;overflow:auto;background:#11152a;border:1px solid #2a2f50;border-radius:10px;padding:10px;z-index:14;display:none;box-shadow:0 10px 34px #000a}
.panel .ph{display:flex;align-items:center;gap:8px;font-size:13px;color:#cfd6ff;margin-bottom:6px;flex-wrap:wrap}
.panel .priv{color:#6f7aa0;font-size:11px}
.panel .tg{font-size:11px;color:#aeb6dc;margin-left:auto;display:flex;align-items:center;gap:4px}
.panel .pi{padding:6px 0;border-bottom:1px solid #1c2138;font-size:13px;display:flex;justify-content:space-between;gap:8px}
.panel .pi a{color:#9aa9ff;text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.panel .pe{color:#6f7aa0;font-size:12px;padding:8px 0}
.panel .x{color:#6f7aa0;cursor:pointer}
.panel .x:hover{color:#ff8aa0}
#star{cursor:pointer;color:#9aa9ff;font-size:22px;margin-left:10px;vertical-align:middle}
"""

_TAB_JS = """
(function(){
 var KEY='rabbit_tabs';
 function load(){try{return JSON.parse(localStorage.getItem(KEY))||[]}catch(e){return[]}}
 function save(t){localStorage.setItem(KEY,JSON.stringify(t))}
 function cur(){var p=new URLSearchParams(location.search);return (p.get('q')||'').trim()}
 function render(){
  var tabs=load(),q=cur(),bar=document.getElementById('tabbar');if(!bar)return;
  if(q&&!tabs.some(function(t){return t.q===q})){tabs.push({q:q});save(tabs)}
  bar.innerHTML='';
  tabs.forEach(function(t){
   var d=document.createElement('div');d.className='tab'+(t.q===q?' active':'');
   var s=document.createElement('span');s.className='t';s.textContent=t.q;s.title=t.q;
   s.onclick=function(){location.href='/search?q='+encodeURIComponent(t.q)};
   var x=document.createElement('span');x.className='x';x.textContent='\\u00d7';
   x.onclick=function(e){e.stopPropagation();var n=load().filter(function(u){return u.q!==t.q});save(n);
    if(t.q===q){location.href=n.length?'/search?q='+encodeURIComponent(n[n.length-1].q):'/'}else{render()}};
   d.appendChild(s);d.appendChild(x);bar.appendChild(d);
  });
  var nt=document.createElement('div');nt.className='newtab';nt.textContent='+';nt.title='New tab';
  nt.onclick=function(){location.href='/'};bar.appendChild(nt);
 }
 render();
})();
"""

# History (private, on-device) + Favorites — pure client-side localStorage,
# so this data NEVER leaves the machine (completely private by default).
_PRIVACY_JS = """
(function(){
 var HK='rabbit_history',FK='rabbit_favorites',EK='rabbit_history_on';
 function get(k){try{return JSON.parse(localStorage.getItem(k))||[]}catch(e){return[]}}
 function set(k,v){localStorage.setItem(k,JSON.stringify(v))}
 function on(){return localStorage.getItem(EK)!=='0'}
 function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
 function curQ(){var p=new URLSearchParams(location.search);return (p.get('q')||'').trim()}
 var q=curQ();
 if(q&&on()){var h=get(HK).filter(function(e){return e.q!==q});h.unshift({q:q,t:Date.now()});set(HK,h.slice(0,100))}
 function render(kind){
  var p=document.getElementById('panel');if(!p)return;var rows='';
  if(kind==='hist'){
   rows='<div class=ph><b>History</b><span class=priv>private \\u00b7 on this device only</span>'
     +'<label class=tg><input type=checkbox '+(on()?'checked':'')+' onclick="rabbitHistToggle(this)"> record</label>'
     +'<span class=x onclick="rabbitClear()">clear</span></div>';
   var H=get(HK);H.forEach(function(e){rows+='<div class=pi><a href="/search?q='+encodeURIComponent(e.q)+'">'+esc(e.q)+'</a></div>'});
   if(!H.length)rows+='<div class=pe>no history</div>';
  }else{
   rows='<div class=ph><b>Favorites</b><span class=priv>saved on this device</span></div>';
   var F=get(FK);F.forEach(function(e,i){rows+='<div class=pi><a href="/search?q='+encodeURIComponent(e.q)+'">'+esc(e.q)+'</a><span class=x onclick="rabbitUnfav('+i+')">\\u00d7</span></div>'});
   if(!F.length)rows+='<div class=pe>no favorites yet \\u2014 star a search</div>';
  }
  p.innerHTML=rows;p.style.display='block';p.dataset.open=kind;
 }
 window.rabbitPanel=function(kind){var p=document.getElementById('panel');if(!p)return;if(p.dataset.open===kind){p.style.display='none';p.dataset.open='';return}render(kind)};
 window.rabbitHistToggle=function(cb){localStorage.setItem(EK,cb.checked?'1':'0')};
 window.rabbitClear=function(){set(HK,[]);render('hist')};
 window.rabbitUnfav=function(i){var f=get(FK);f.splice(i,1);set(FK,f);render('fav')};
 window.rabbitFav=function(){var x=curQ();if(!x)return;var f=get(FK);if(!f.some(function(e){return e.q===x})){f.unshift({q:x});set(FK,f)}var b=document.getElementById('star');if(b)b.textContent='\\u2605'};
 var b=document.getElementById('star');if(b&&q&&get(FK).some(function(e){return e.q===q}))b.textContent='\\u2605';
})();
"""

# Lola voice — browser-native speech synthesis (no deps, no server audio).
# Reads the results aloud (in case you don't want to read); click again to stop.
_VOICE_JS = """
window.rabbitSpeak=function(){
 if(!('speechSynthesis' in window)){alert('voice not supported in this browser');return}
 if(window.speechSynthesis.speaking){window.speechSynthesis.cancel();return}
 var parts=[],rs=document.querySelectorAll('.r');
 if(rs.length){rs.forEach(function(r){var a=r.querySelector('a'),s=r.querySelector('.s');parts.push((a?a.textContent:'')+'. '+(s?s.textContent:''))})}
 else{parts.push('Rabbit sovereign search. Type a query to begin.')}
 var u=new SpeechSynthesisUtterance(parts.join(' \\u2014 '));
 u.rate=1.0;u.pitch=1.05;
 var vs=window.speechSynthesis.getVoices();
 var f=vs.filter(function(v){return /female|zira|hazel|susan|aria|eva/i.test(v.name)})[0];
 if(f)u.voice=f;
 window.speechSynthesis.speak(u);
};
"""


def _ip_bar() -> str:
    cls = _classify(_all_local_ips())
    parts = [f"<span><b>egress (ISP/Tor sees):</b> {html.escape(_egress_ip())}</span>"]
    label = {"lan": "LAN", "wireguard": "WireGuard", "loopback": "local"}
    for k in ("lan", "wireguard", "loopback"):
        if cls[k]:
            joined = ", ".join(f"{ip}:{_PORT}" for ip in cls[k])
            parts.append(f"<span><b>{label[k]}:</b> {html.escape(joined)}</span>")
    return '<div class="ips">' + "".join(parts) + "</div>"


def _home_page() -> str:
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Rabbit</title><style>{_CSS}</style></head><body>
<div id="tabbar" class="tabbar"></div>
<div class="toolbar"><button onclick="rabbitPanel('hist')">🕘 History</button><button onclick="rabbitPanel('fav')">★ Favorites</button><button onclick="rabbitSpeak()" title="Lola reads the results aloud">🔊 Lola</button></div>
<div id="panel" class="panel"></div>
<div class="logo">🐰 <b>Rabbit</b></div>
<div class="tag">sovereign search — your own masks, your own HTTP</div>
<form action="/search" method="get" autocomplete="off">
  <input type="text" name="q" placeholder="Search the web through Rabbit…" autofocus>
  <div class="btns">
    <button type="submit">Rabbit Search</button>
    <button type="submit" name="lucky" value="1">I'm Feeling Sovereign</button>
  </div>
</form>
{_ip_bar()}
<script>{_TAB_JS}</script>
<script>{_PRIVACY_JS}</script>
<script>{_VOICE_JS}</script>
</body></html>"""


def _results_page(query: str) -> str:
    rows = []
    for r in _search(query):
        title = html.escape(getattr(r, "title", "") or "(no title)")
        raw_url = getattr(r, "url", "") or ""
        url = html.escape(raw_url)
        # XSS guard: only http(s)/relative hrefs are clickable; javascript:/data: → inert
        href = url if raw_url.lower().startswith(("http://", "https://", "/")) else "#"
        snip = html.escape(getattr(r, "snippet", "") or "")
        score = getattr(r, "_rabbit_score", None)
        senti = getattr(r, "_rabbit_sentiment", None)
        badge = ""
        if score is not None:
            mood = "😊 positive" if (senti or 0) > 0.15 else ("⚠ negative" if (senti or 0) < -0.15 else "· neutral")
            sem = getattr(r, "_rabbit_semantic", 0.0)
            meaning = f" · meaning {sem}" if sem else ""
            badge = f'<div class="b">relevance {score}{meaning} · sentiment {senti} {mood}</div>'
        rows.append(f'<div class="r"><a href="{href}">{title}</a>'
                    f'<div class="u">{url}</div><div class="s">{snip}</div>{badge}</div>')
    body = "".join(rows) or '<div class="r">no results</div>'
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>{html.escape(query)} — Rabbit</title><style>{_CSS}</style></head><body>
<div id="tabbar" class="tabbar"></div>
<div class="toolbar"><button onclick="rabbitPanel('hist')">🕘 History</button><button onclick="rabbitPanel('fav')">★ Favorites</button><button onclick="rabbitSpeak()" title="Lola reads the results aloud">🔊 Lola</button></div>
<div id="panel" class="panel"></div>
<div style="margin-top:24px;font-size:30px">🐰 <b style="color:#9aa9ff">Rabbit</b></div>
<form action="/search" method="get" style="margin-top:14px"><input type="text" name="q"
 value="{html.escape(query)}"><span id="star" onclick="rabbitFav()" title="Save to favorites">&#9734;</span></form>
<div class="res">{body}</div>
{_ip_bar()}
<script>{_TAB_JS}</script>
<script>{_PRIVACY_JS}</script>
<script>{_VOICE_JS}</script>
</body></html>"""


# ── app login gate ─────────────────────────────────────────────────────────
# Localhost is always open (you're at the machine). Remote (LAN / WireGuard mesh)
# must unlock with the vault master password — then it rides a session cookie.
_SESSIONS: dict = {}                 # token -> expiry epoch
_SESSIONS_LOCK = threading.Lock()
_SESSION_TTL = 12 * 3600             # sessions expire after 12h
_SESSIONS_MAX = 1024                 # bound the map (anti-growth)


def _local_ip(ip: str) -> bool:
    return ip.startswith("127.")


def _cookie_token(handler) -> str:
    for part in handler.headers.get("Cookie", "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == "rg_session":
            return v
    return ""


def _is_authed(handler) -> bool:
    ip = handler.client_address[0] if handler.client_address else ""
    if _local_ip(ip):
        return True
    tok = _cookie_token(handler)
    if not tok:
        return False
    with _SESSIONS_LOCK:
        exp = _SESSIONS.get(tok)
        if exp is None:
            return False
        if exp <= time.time():           # expired → evict + deny
            _SESSIONS.pop(tok, None)
            return False
        return True


def _login_page(msg: str = "") -> str:
    initd = True
    try:
        from rabbitghost import vault
        initd = vault.is_initialized()
    except Exception:
        pass
    note = "" if initd else '<div class="tag">no master password set yet — run <b>login</b> in the console first</div>'
    err = f'<div class="tag" style="color:#ff8aa0">{html.escape(msg)}</div>' if msg else ""
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Rabbit — unlock</title><style>{_CSS}</style></head><body>
<div class="logo">🐰 <b>Rabbit</b></div>
<div class="tag">remote access — unlock with your master password</div>
<form action="/login" method="post" autocomplete="off">
  <input type="password" name="pw" placeholder="master password" autofocus>
  <div class="btns"><button type="submit">Unlock</button></div>
</form>{note}{err}
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, code: int = 200) -> None:
        data = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if not _gojo_admits(self.client_address[0], parsed.path):
            self._send("<h1>403 — Gojo boundary denied</h1>", 403)
            return
        if parsed.path == "/logout":
            with _SESSIONS_LOCK:
                _SESSIONS.pop(_cookie_token(self), None)
            self.send_response(303)
            self.send_header("Set-Cookie", "rg_session=; Max-Age=0; Path=/")
            self.send_header("Location", "/")
            self.end_headers()
            return
        if not _is_authed(self):
            self._send(_login_page())  # remote + not unlocked → master-password gate
            return
        if parsed.path in ("/", "/index.html"):
            self._send(_home_page())
        elif parsed.path == "/search":
            q = (parse_qs(parsed.query).get("q") or [""])[0].strip()
            self._send(_home_page() if not q else _results_page(q))
        else:
            self._send("<h1>404</h1>", 404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if not _gojo_admits(self.client_address[0], parsed.path):
            self._send("<h1>403 — Gojo boundary denied</h1>", 403)
            return
        if parsed.path == "/login":
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                self._send("<h1>400 — bad Content-Length</h1>", 400)
                return
            if length > 64 * 1024:  # a login body is < 1KB; cap to stop memory-DoS
                self._send("<h1>413 — request too large</h1>", 413)
                return
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            pw = (parse_qs(body).get("pw") or [""])[0]
            ok = False
            try:
                from rabbitghost import vault
                ok = vault.login(pw)
            except Exception:
                ok = False
            if ok:
                tok = secrets.token_urlsafe(32)
                now = time.time()
                with _SESSIONS_LOCK:
                    for _k in [k for k, v in _SESSIONS.items() if v <= now]:
                        _SESSIONS.pop(_k, None)      # prune expired
                    if len(_SESSIONS) >= _SESSIONS_MAX:
                        _SESSIONS.clear()            # hard cap
                    _SESSIONS[tok] = now + _SESSION_TTL
                self.send_response(303)
                self.send_header("Set-Cookie", f"rg_session={tok}; HttpOnly; Path=/; SameSite=Strict")
                self.send_header("Location", "/")
                self.end_headers()
            else:
                self._send(_login_page("wrong password"))
        else:
            self._send("<h1>404</h1>", 404)

    def log_message(self, *a):  # quiet
        pass


def serve(port: int = _PORT) -> None:
    global _PORT
    _PORT = port
    httpd = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    # Pre-warm the dominance/intent engine in the background so the first search is fast.
    try:
        import threading as _t
        from rabbitghost import semantic_search as rabbit_search
        _t.Thread(target=rabbit_search.warm, daemon=True).start()
    except Exception:
        pass
    cls = _classify(_all_local_ips())
    print(f"🐰 Rabbit home page live — reachable by IP on port {port}:")
    print(f"   local:     http://127.0.0.1:{port}")
    for ip in cls["lan"] + cls["wireguard"]:
        print(f"   by IP:     http://{ip}:{port}")
    print(f"   egress IP (ISP/Tor sees): {_egress_ip()}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    serve()
