#!/usr/bin/env python
"""
Ghosted Home — a sovereign, Google-like home page.

Pure-stdlib HTTP server (http.server) — no Flask, no Streamlit, no new deps.
Serves Ghosted's own search homepage: ghost-rabbit logo + a centered search box
that routes queries through the SovereignBrowserEngine (5-engine masks, Tor-by-
default). Binds 0.0.0.0 so it is reachable by IP across LAN / Tailscale /
WireGuard, and shows every address Ghosted is reachable at PLUS the current
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
from urllib.parse import parse_qs, quote, urlparse

# The sovereign public domain — surfaced as the open-use URL. It is a .dmn sovereign
# TLD (resolved via the mesh/hosts, not public DNS); the server answers on any Host.
PUBLIC_DOMAIN = "sovereign.dmn"

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
    if _LOCAL_IPS_CACHE["ips"] is not None and (
        time.time() - _LOCAL_IPS_CACHE["at"] < 60
    ):
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
    # No Tailscale — Ghosted reaches across his OWN sovereign WireGuard PackMesh.
    out: dict[str, list[str]] = {"lan": [], "wireguard": [], "loopback": []}
    for ip in ips:
        if ip.startswith("127."):
            out["loopback"].append(ip)
        elif ip.startswith("10.44."):
            out["wireguard"].append(ip)  # Ghosted PackMesh default subnet
        else:
            out["lan"].append(ip)
    return out


_EGRESS_CACHE: dict = {"ip": None, "at": 0.0}


def _egress_ip() -> str:
    """What the outside world sees — via Ghosted's own sovereign HTTP (masked).
    Cached 120s so it never blocks page renders (perf: was adding ~5s/request)."""
    import time

    if _EGRESS_CACHE["ip"] and (time.time() - _EGRESS_CACHE["at"] < 120):
        return _EGRESS_CACHE["ip"]
    val = "unknown (offline or fetch failed)"
    try:
        from ghosted.http import sovereign_http_get

        r = sovereign_http_get(
            "https://api.ipify.org", connect_timeout=5, read_timeout=5
        )
        if r.success and r.body:
            val = r.body.decode(errors="replace").strip()
    except Exception:
        pass
    _EGRESS_CACHE["ip"] = val
    _EGRESS_CACHE["at"] = time.time()
    return val


def _search(query: str) -> list:
    try:
        from ghosted.web import SovereignBrowserEngine

        results = SovereignBrowserEngine().web_search(query)
    except Exception as e:  # never let the page 500
        return [
            type("E", (), {"title": "search error", "url": "", "snippet": str(e)})()
        ]
    try:  # semantic re-rank: meaning / context / sentiment (degrades, never breaks)
        from ghosted import semantic_search

        return semantic_search.rerank(query, results)
    except Exception:
        return results


# ── Gojo boundary safeguard ──────────────────────────────────────────────────
def _gojo_audit_path() -> str:
    """Windows-safe absolute audit log path (avoids cwd-relative 'logs' failure)."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "Ghosted", "logs")
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
            from ghosted.gate import GojoBoundaryGate

            ap = _gojo_audit_path()
            _GATE = GojoBoundaryGate(audit_log_path=ap) if ap else GojoBoundaryGate()
            print(
                "🛡  Security boundary engaged — every request is gated, throttled, audited."
            )
        except Exception as e:
            print(
                f"[gojo] boundary unavailable — remote access gated by master password only: {e}"
            )
            _GATE = None
        _GATE_TRIED = True  # set LAST, after _GATE is assigned
    return _GATE


def _request_source_class(handler) -> str:
    """Classify WHERE a request actually comes from, for Gojo's source boundary:
    loopback = the operator physically at the machine (internal); 10.44.* = the trusted
    WireGuard mesh; anything else = a remote network. Derived from the real client
    address, never asserted by the caller — this is what makes Gojo's boundary honest."""
    ip = handler.client_address[0] if getattr(handler, "client_address", None) else ""
    if ip.startswith("127."):
        return "internal"
    if ip.startswith("10.44."):
        return "network_mesh"
    return "network_remote"


def _gojo_admits(client_ip: str, path: str) -> bool:
    """Admission for a network request.

    Ghosted is a standalone Windows app: its real remote access control is the
    master-password session gate (_is_authed) plus the brute-force lockout and
    body cap in do_POST. On top of that, Ghosted OWNS its request boundary
    (ghosted.gate.GojoBoundaryGate): homepage_get is a *known* action with a
    real per-client throttle ceiling, so the DoS layer now ENFORCES rather than
    merely advises:

      * loopback (the operator at the machine) is always admitted;
      * a real throttle deny (flood control) is honored — the peer is blocked;
      * absence of the gate (import failed) or any unexpected deny reason fails
        OPEN — a legitimate remote peer must always be able to reach the login
        form, and _is_authed still gates all content behind the master password.

    (The gate is Ghosted's own — no rabbit ingress_policy.json coupling.)"""
    if client_ip.startswith("127."):
        return True  # loopback = at the machine; not network exposure
    gate = _gate()
    if gate is None:
        return True  # standalone (no rabbit boundary) — _is_authed enforces the remote gate
    if client_ip.startswith("10.44."):
        source_class = "network_mesh"  # 10.44.* = WireGuard mesh subnet (reachability, NOT crypto proof of identity — the WG tunnel authenticates the peer at the kernel; this prefix only routes trust tier)
    else:
        source_class = "network_remote"
    try:
        verdict = gate.evaluate_request(
            actor_role="anonymous_web",
            action="homepage_get",
            source_class=source_class,
            metadata={"path": path, "client": client_ip},
        )
        if verdict.get("decision") == "allow":
            return True
        # Honor a real throttle (flood control) → block. Any other/unexpected
        # deny reason fails open so a legitimate remote peer still reaches login.
        return verdict.get("reason") != "throttled"
    except Exception:
        return (
            True  # boundary error must not harden a standalone install into local-only
        )


# ── pages ────────────────────────────────────────────────────────────────────
_PORT = 7654

_CSS = """
*{box-sizing:border-box;-webkit-font-smoothing:antialiased}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;
 color:#e9ecf6;font-family:system-ui,'Segoe UI',Inter,Roboto,Arial,sans-serif;
 background:radial-gradient(1200px 620px at 50% -12%,#1a2046 0%,#0d1020 56%,#090b16 100%)}
.logo{font-size:60px;font-weight:300;margin-top:17vh;letter-spacing:.5px}
.logo b{font-weight:600;background:linear-gradient(90deg,#9aa9ff,#c8b6ff);
 -webkit-background-clip:text;background-clip:text;color:transparent}
.tag{color:#7e88b5;font-size:14px;margin:10px 0 30px;letter-spacing:.2px}
form{width:min(580px,92vw)}
input[type=text]{width:100%;padding:16px 22px;border-radius:30px;border:1px solid #2a2f55;
 background:rgba(22,26,48,.85);color:#fff;font-size:16.5px;outline:none;
 box-shadow:0 10px 34px rgba(0,0,0,.38);transition:border-color .16s,box-shadow .16s}
input[type=text]::placeholder{color:#6b73a0}
input[type=text]:focus{border-color:#9aa9ff;
 box-shadow:0 10px 34px rgba(0,0,0,.38),0 0 0 4px rgba(154,169,255,.16)}
.btns{margin-top:20px;text-align:center}
button{background:rgba(27,33,64,.8);color:#cfd6ff;border:1px solid #2a2f55;padding:10px 20px;
 border-radius:10px;font-size:13.5px;cursor:pointer;margin:0 6px;transition:all .16s}
button:hover{border-color:#9aa9ff;background:rgba(40,48,90,.85);transform:translateY(-1px)}
.ips{position:fixed;bottom:0;left:0;right:0;background:rgba(10,12,24,.9);backdrop-filter:blur(8px);
 border-top:1px solid #1c2138;font-size:11.5px;color:#7e88ad;padding:9px 16px;display:flex;gap:18px;flex-wrap:wrap}
.ips b{color:#9aa9ff;font-weight:600}
.res{width:min(700px,92vw);margin:30px 0 90px}
.r{padding:15px 16px;border-radius:12px;margin-bottom:8px;border:1px solid transparent;transition:background .16s,border-color .16s}
.r:hover{background:rgba(255,255,255,.03);border-color:#1c2138}
.r a{color:#9aa9ff;text-decoration:none;font-size:18px;font-weight:500}
.r a:hover{text-decoration:underline}
.r .u{color:#5f8a6a;font-size:12px;word-break:break-all;margin-top:2px}
.r .s{color:#bcc3dd;font-size:14px;margin-top:5px;line-height:1.45}
.r .b{color:#6f7aa0;font-size:11px;margin-top:6px;letter-spacing:.3px}
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
.dym{width:min(700px,92vw);margin:14px 0 -8px;color:#aeb6dc;font-size:14px}
.dym b{color:#cfd6ff}.dym a{color:#9aa9ff;text-decoration:none}.dym a:hover{text-decoration:underline}
.fbbar{margin:18px 0 8px;color:#8890b5;font-size:13px;display:flex;align-items:center;gap:8px}
.fbbar button{font-size:15px;padding:4px 10px;margin:0}
.fbbar #fbmsg{color:#7bd88f;font-size:12px}
.health{width:min(560px,92vw);margin:26px 0 90px}
.hcard{display:flex;justify-content:space-between;align-items:center;padding:13px 16px;border:1px solid #1c2138;border-radius:12px;margin-bottom:8px;background:rgba(22,26,48,.5)}
.hcard .hl{color:#cfd6ff;font-size:14px}.hcard .hv{font-size:14px;font-variant-numeric:tabular-nums}
.s-ok{color:#7bd88f}.s-warn{color:#ffcf6b}.s-critical{color:#ff8aa0}.s-none{color:#6f7aa0}
.acct{width:min(580px,92vw);margin:20px 0 100px;text-align:left}
.acct h3{color:#9aa9ff;font-size:15px;margin:30px 0 10px;font-weight:600;padding-top:14px;border-top:1px solid #232842}
.acct h3:first-of-type{border-top:none;padding-top:0}
.acct form{margin:0 0 16px;padding:14px 16px;border:1px solid #1c2138;border-radius:12px;background:rgba(22,26,48,.4)}
.acct .row{padding:10px 2px;border-bottom:1px solid #1c2138;font-size:13.5px;color:#cfd6ff;overflow:hidden}
.acct .row:last-child{border-bottom:none}
.acct .row label{margin-right:14px;display:inline-block}
.acct input[type=text],.acct input[type=password]{width:100%;margin:7px 0;padding:11px 14px;border-radius:10px;border:1px solid #2a2f55;background:rgba(22,26,48,.85);color:#fff;font-size:14px}
.acct select{margin:0 6px;padding:6px 10px;border-radius:8px;border:1px solid #2a2f55;background:rgba(22,26,48,.85);color:#fff}
.acct .btns{margin-top:14px;text-align:left}
.acct .btns button{margin:0 10px 0 0}
.acct .muted{color:#7e88b5;font-size:12px;margin:4px 0}
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
     +'<label class=tg><input type=checkbox '+(on()?'checked':'')+' onclick="ghostedHistToggle(this)"> record</label>'
     +'<span class=x onclick="ghostedClear()">clear</span></div>';
   var H=get(HK);H.forEach(function(e){rows+='<div class=pi><a href="/search?q='+encodeURIComponent(e.q)+'">'+esc(e.q)+'</a></div>'});
   if(!H.length)rows+='<div class=pe>no history</div>';
  }else{
   rows='<div class=ph><b>Favorites</b><span class=priv>saved on this device</span></div>';
   var F=get(FK);F.forEach(function(e,i){rows+='<div class=pi><a href="/search?q='+encodeURIComponent(e.q)+'">'+esc(e.q)+'</a><span class=x onclick="ghostedUnfav('+i+')">\\u00d7</span></div>'});
   if(!F.length)rows+='<div class=pe>no favorites yet \\u2014 star a search</div>';
  }
  p.innerHTML=rows;p.style.display='block';p.dataset.open=kind;
 }
 window.ghostedPanel=function(kind){var p=document.getElementById('panel');if(!p)return;if(p.dataset.open===kind){p.style.display='none';p.dataset.open='';return}render(kind)};
 window.ghostedHistToggle=function(cb){localStorage.setItem(EK,cb.checked?'1':'0')};
 window.ghostedClear=function(){set(HK,[]);render('hist')};
 window.ghostedUnfav=function(i){var f=get(FK);f.splice(i,1);set(FK,f);render('fav')};
 window.ghostedFav=function(){var x=curQ();if(!x)return;var f=get(FK);if(!f.some(function(e){return e.q===x})){f.unshift({q:x});set(FK,f)}var b=document.getElementById('star');if(b)b.textContent='\\u2605'};
 var b=document.getElementById('star');if(b&&q&&get(FK).some(function(e){return e.q===q}))b.textContent='\\u2605';
})();
"""

# Lola voice — browser-native speech synthesis (no deps, no server audio).
# Reads the results aloud (in case you don't want to read); click again to stop.
_VOICE_JS = """
window.ghostedSpeak=function(){
 if(!('speechSynthesis' in window)){alert('voice not supported in this browser');return}
 if(window.speechSynthesis.speaking){window.speechSynthesis.cancel();return}
 var parts=[],rs=document.querySelectorAll('.r');
 if(rs.length){rs.forEach(function(r){var a=r.querySelector('a'),s=r.querySelector('.s');parts.push((a?a.textContent:'')+'. '+(s?s.textContent:''))})}
 else{parts.push('Ghosted sovereign search. Type a query to begin.')}
 var u=new SpeechSynthesisUtterance(parts.join(' \\u2014 '));
 u.rate=1.0;u.pitch=1.05;
 var vs=window.speechSynthesis.getVoices();
 var f=vs.filter(function(v){return /female|zira|hazel|susan|aria|eva/i.test(v.name)})[0];
 if(f)u.voice=f;
 window.speechSynthesis.speak(u);
};
"""

# Feedback beacons — every interaction is a data point and must not be wasted.
# Captures result CLICKS (which link, what rank), DWELL (time on a result before you
# return), and explicit 👍/👎. Uses navigator.sendBeacon so signals survive navigation;
# falls back to keepalive fetch. All POST to the public /fb/* endpoints.
_FEEDBACK_JS = """
window.ghostedFB=(function(){
 var q=(new URLSearchParams(location.search).get('q')||'').trim();
 function beacon(path,obj){try{var b=new Blob([JSON.stringify(obj)],{type:'application/json'});
   if(navigator.sendBeacon&&navigator.sendBeacon(path,b))return;}catch(e){}
   try{fetch(path,{method:'POST',body:JSON.stringify(obj),keepalive:true,headers:{'Content-Type':'application/json'}})}catch(_){}}
 var last=null,t0=0;
 function clickResult(url,pos){last={q:q,url:url,pos:pos};t0=Date.now();beacon('/fb/click',last)}
 function flushDwell(){if(last&&t0){var d=(Date.now()-t0)/1000;if(d>0.4)beacon('/fb/dwell',{q:last.q,url:last.url,dwell:d});t0=0}}
 document.addEventListener('visibilitychange',function(){if(document.visibilityState==='hidden')flushDwell();else if(last)t0=Date.now()});
 window.addEventListener('pagehide',flushDwell);
 function rate(v){beacon('/fb/rate',{q:q,v:v});var e=document.getElementById('fbmsg');if(e)e.textContent=v>0?'\\u2713 thanks — marked helpful':'\\u2713 thanks — noted'}
 return {click:clickResult,rate:rate};
})();
"""


_EMAIL_AUTOCONFIG_JS = """
(function(){
 var P={'gmail.com':'gmail.com','googlemail.com':'gmail.com','outlook.com':'o','hotmail.com':'o',
  'live.com':'o','msn.com':'o','yahoo.com':'y','ymail.com':'y','aol.com':'aol','icloud.com':'i',
  'me.com':'i','zoho.com':'z','gmx.com':'gmx','fastmail.com':'fm'};
 var H={'gmail.com':['imap.gmail.com','pop.gmail.com','smtp.gmail.com'],
  'o':['outlook.office365.com','outlook.office365.com','smtp-mail.outlook.com'],
  'y':['imap.mail.yahoo.com','pop.mail.yahoo.com','smtp.mail.yahoo.com'],
  'aol':['imap.aol.com','pop.aol.com','smtp.aol.com'],
  'i':['imap.mail.me.com','imap.mail.me.com','smtp.mail.me.com'],
  'z':['imap.zoho.com','pop.zoho.com','smtp.zoho.com'],
  'gmx':['imap.gmx.com','pop.gmx.com','mail.gmx.com'],
  'fm':['imap.fastmail.com','pop.fastmail.com','smtp.fastmail.com']};
 var PT={imap:993,pop:995,smtp:587};
 function fill(){
  var e=document.getElementById('acemail'); if(!e)return;
  var at=e.value.indexOf('@'); if(at<0)return;
  var dom=e.value.slice(at+1).trim().toLowerCase(); if(!dom)return;
  var proto=(document.getElementById('acproto').value||'imap').trim().toLowerCase();
  if(['imap','pop','smtp'].indexOf(proto)<0)proto='imap';
  var key=P[dom], hosts=key?H[key]:null;
  var host=hosts?hosts[{imap:0,pop:1,smtp:2}[proto]]:(proto+'.'+dom);
  var h=document.getElementById('achost'), p=document.getElementById('acport');
  if(h&&!h.value)h.value=host;
  if(p&&!p.value)p.value=PT[proto];
  var note=document.getElementById('acauto');
  if(note)note.textContent=(key?'Recognised provider — ':'Guessed from domain — ')+'server set to '+host+':'+PT[proto]+' (edit if needed).';
 }
 var e=document.getElementById('acemail'), pr=document.getElementById('acproto');
 if(e){e.addEventListener('blur',fill);e.addEventListener('change',fill);}
 if(pr){pr.addEventListener('change',function(){var h=document.getElementById('achost');if(h)h.value='';var p=document.getElementById('acport');if(p)p.value='';fill();});}
})();
"""


def _ctx(handler) -> dict:
    """Per-request view context: is this the signed-in account holder, their display
    name, accent, and notification count. Guests get defaults (no personal data)."""
    authed = _is_authed(handler)
    name, accent, notes = "", "#9aa9ff", 0
    if authed:
        try:
            from ghosted import preferences

            name = preferences.get("display_name") or ""
            accent = preferences.accent_color()
        except Exception:
            pass
        try:
            from ghosted import notifications

            notes = notifications.count()
        except Exception:
            notes = 0
    return {"authed": authed, "name": name, "accent": accent, "notes": notes}


def _accent_style(ctx) -> str:
    """Personalise the page with the account holder's accent colour (when not default)."""
    a = ctx.get("accent")
    if not a or a == "#9aa9ff":
        return ""
    return (
        f"<style>.logo b{{background:linear-gradient(90deg,{a},{a});-webkit-background-clip:text;"
        f"background-clip:text;color:transparent}}.r a,.dym a,.dym b,.panel .pi a{{color:{a}}}"
        f"input[type=text]:focus{{border-color:{a}}}</style>"
    )


def _toolbar(ctx) -> str:
    """The toolbar shown on every page. Always carries the Email link; when signed in
    it shows the account holder's NAME (a link to their account info) + a notifications
    bell, so the active account is visible at all times."""
    authed = ctx.get("authed")
    email_btn = ('<button onclick="location.href=\'/mail\'" '
                 'title="Your email — read, send &amp; receive (IMAP)">✉ Email</button>')
    wg_btn = ('<button onclick="location.href=\'/wireguard\'" '
              'title="Your WireGuard mesh — enroll devices &amp; connect tunnels">🔒 WireGuard</button>'
              if authed else "")
    if authed:
        notes = ctx.get("notes", 0)
        badge = f" {notes}" if notes else ""
        bell = ('<button onclick="location.href=\'/account#notifications\'" '
                f'title="Notifications">🔔{badge}</button>')
        label = html.escape(ctx.get("name") or "Account")
        acct = ('<button onclick="location.href=\'/account\'" '
                f'title="Your account — personal data, history &amp; usage stats">👤 {label}</button>')
    else:
        bell = ""
        acct = ('<button onclick="location.href=\'/account\'" '
                'title="Sign in / create account">👤 Sign in</button>')
    return (
        '<div class="toolbar">'
        '<button onclick="location.href=\'/\'" title="Home">🏠 Home</button>'
        '<button onclick="ghostedPanel(\'hist\')">🕘 History</button>'
        '<button onclick="ghostedPanel(\'fav\')">★ Favorites</button>'
        '<button onclick="ghostedSpeak()" title="Lola reads the results aloud">🔊 Lola</button>'
        '<button onclick="location.href=\'/health\'" title="Device health monitor">🩺 Health</button>'
        + email_btn + wg_btn + bell + acct +
        '<button onclick="location.href=\'/help\'" title="Everything the app does">❔ Help</button>'
        '</div>'
    )


def _ip_bar() -> str:
    cls = _classify(_all_local_ips())
    parts = [
        f"<span><b>public:</b> http://{PUBLIC_DOMAIN}:{_PORT}</span>",
        f"<span><b>egress (ISP/Tor sees):</b> {html.escape(_egress_ip())}</span>",
    ]
    label = {"lan": "LAN", "wireguard": "WireGuard", "loopback": "local"}
    for k in ("lan", "wireguard", "loopback"):
        if cls[k]:
            joined = ", ".join(f"{ip}:{_PORT}" for ip in cls[k])
            parts.append(f"<span><b>{label[k]}:</b> {html.escape(joined)}</span>")
    return '<div class="ips">' + "".join(parts) + "</div>"


def _home_page(ctx: dict | None = None) -> str:
    ctx = ctx or {"authed": False, "name": "", "accent": "#9aa9ff", "notes": 0}
    signed = (f'<div class="tag">signed in as <b>{html.escape(ctx["name"] or "account holder")}</b> '
              f'· <a href="/account" style="color:#9aa9ff;text-decoration:none">your account</a></div>'
              if ctx.get("authed") else "")
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Ghosted</title><style>{_CSS}</style>{_accent_style(ctx)}</head><body>
<div id="tabbar" class="tabbar"></div>
{_toolbar(ctx)}
<div id="panel" class="panel"></div>
<div class="logo">🐰 <b>Ghosted</b></div>
<div class="tag">sovereign search — your own masks, your own HTTP</div>
{signed}
<form action="/search" method="get" autocomplete="off">
  <input type="text" name="q" placeholder="Search the web through Ghosted…" autofocus>
  <div class="btns">
    <button type="submit">Ghosted Search</button>
    <button type="submit" name="lucky" value="1">I'm Feeling Sovereign</button>
  </div>
</form>
{_ip_bar()}
<script>{_TAB_JS}</script>
<script>{_PRIVACY_JS}</script>
<script>{_VOICE_JS}</script>
<script>{_FEEDBACK_JS}</script>
</body></html>"""


def _results_page(query: str, ctx: dict | None = None) -> str:
    ctx = ctx or {"authed": False, "name": "", "accent": "#9aa9ff", "notes": 0}
    # Spell-check: auto-correct obvious typos and tell the user (intuitive, reversible).
    used, dym = query, ""
    try:
        from ghosted import spellcheck

        sp = spellcheck.correct(query)
        if sp["changed"]:
            used = sp["corrected"]
            dym = (
                f'<div class="dym">Showing results for '
                f'<b>{html.escape(used)}</b>. Search instead for '
                f'<a href="/search?q={quote(query)}">{html.escape(query)}</a>.</div>'
            )
    except Exception:
        used = query
    results = _search(used)
    # Every search is a data point — record it (volume feeds ranking + the dictionary).
    try:
        from ghosted import feedback

        feedback.record_search(used, len(results) if hasattr(results, "__len__") else 0)
    except Exception:
        pass
    rows = []
    for pos, r in enumerate(results):
        title = html.escape(getattr(r, "title", "") or "(no title)")
        raw_url = getattr(r, "url", "") or ""
        url = html.escape(raw_url)
        # XSS guard: only http(s)/relative hrefs are clickable; javascript:/data: → inert
        href = url if raw_url.lower().startswith(("http://", "https://", "/")) else "#"
        snip = html.escape(getattr(r, "snippet", "") or "")
        score = getattr(r, "_ghosted_score", None)
        senti = getattr(r, "_ghosted_sentiment", None)
        badge = ""
        if score is not None:
            mood = (
                "😊 positive"
                if (senti or 0) > 0.15
                else ("⚠ negative" if (senti or 0) < -0.15 else "· neutral")
            )
            sem = getattr(r, "_ghosted_semantic", 0.0)
            meaning = f" · meaning {sem}" if sem else ""
            badge = f'<div class="b">relevance {score}{meaning} · sentiment {senti} {mood}</div>'
        # click beacon: which result, what rank — captured, not wasted
        click = f"ghostedFB.click('{raw_url.replace(chr(39), '')}',{pos})"
        rows.append(
            f'<div class="r"><a href="{href}" onclick="{click}">{title}</a>'
            f'<div class="u">{url}</div><div class="s">{snip}</div>{badge}</div>'
        )
    body = "".join(rows) or '<div class="r">no results</div>'
    fbbar = (
        '<div class="fbbar">Were these helpful? '
        '<button onclick="ghostedFB.rate(1)">👍</button>'
        '<button onclick="ghostedFB.rate(-1)">👎</button>'
        '<span id="fbmsg"></span></div>'
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>{html.escape(query)} — Ghosted</title><style>{_CSS}</style>{_accent_style(ctx)}</head><body>
<div id="tabbar" class="tabbar"></div>
{_toolbar(ctx)}
<div id="panel" class="panel"></div>
<div style="margin-top:24px;font-size:30px">🐰 <b style="color:#9aa9ff">Ghosted</b></div>
<form action="/search" method="get" style="margin-top:14px"><input type="text" name="q"
 value="{html.escape(query)}"><span id="star" onclick="ghostedFav()" title="Save to favorites">&#9734;</span></form>
{dym}
<div class="res">{body}{fbbar}</div>
{_ip_bar()}
<script>{_TAB_JS}</script>
<script>{_PRIVACY_JS}</script>
<script>{_VOICE_JS}</script>
<script>{_FEEDBACK_JS}</script>
</body></html>"""


# ── app login gate ─────────────────────────────────────────────────────────
# Localhost is always open (you're at the machine). Remote (LAN / WireGuard mesh)
# must unlock with the vault master password — then it rides a session cookie.
_SESSIONS: dict = {}  # token -> expiry epoch
_SESSIONS_LOCK = threading.Lock()
_SESSION_TTL = 12 * 3600  # sessions expire after 12h
_REMEMBER_TTL = 30 * 24 * 3600  # "stay logged in" — persistent cookie, 30 days
_SESSIONS_MAX = 1024  # bound the map (anti-growth)
_LOGIN_FAILS: dict = {}  # ip -> (fail_count, window_start) — brute-force guard
_LOGIN_MAX = 5  # failures per window before lockout
_LOGIN_WINDOW = 300  # 5 min

# Webmail keeps the passphrase in MEMORY only (never disk) for the session, so the
# encrypted mailbox can be opened to read/search without re-typing it every action.
_MAIL_KEYS: dict = {}  # token -> (passphrase, expiry)
_MAIL_PREVIEW: dict = {}  # box path -> (subject, from) — cache so inbox re-renders are free
_MAIL_LOCK = threading.Lock()


def _mail_token(handler) -> str:
    tok = _cookie_token(handler)
    if tok:
        return tok
    ip = handler.client_address[0] if handler.client_address else ""
    return "local:" + ip  # localhost is authed without a cookie — key by address


def _mail_get_key(handler):
    tok = _mail_token(handler)
    with _MAIL_LOCK:
        ent = _MAIL_KEYS.get(tok)
        if ent and ent[1] > time.time():
            return ent[0]
        _MAIL_KEYS.pop(tok, None)
    return None


def _mail_set_key(handler, passphrase: str) -> None:
    with _MAIL_LOCK:
        for k in [k for k, v in _MAIL_KEYS.items() if v[1] <= time.time()]:
            _MAIL_KEYS.pop(k, None)
        _MAIL_KEYS[_mail_token(handler)] = (passphrase, time.time() + _SESSION_TTL)


def _mail_clear_key(handler) -> None:
    with _MAIL_LOCK:
        _MAIL_KEYS.pop(_mail_token(handler), None)


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
        if exp <= time.time():  # expired → evict + deny
            _SESSIONS.pop(tok, None)
            return False
        return True


def _login_page(msg: str = "") -> str:
    """The account gate. If no account exists yet, this IS the guided onboarding
    (create account + optional email). Once an account exists, it's the unlock form.
    Either way, guests never see this for search/health/help — only personal data."""
    initd = True
    try:
        from ghosted import vault

        initd = vault.is_initialized()
    except Exception:
        pass
    err = (
        f'<div class="tag" style="color:#ff8aa0">{html.escape(msg)}</div>' if msg else ""
    )
    if not initd:
        # First-run: set up the account holder right here on the website.
        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Ghosted — create account</title><style>{_CSS}</style></head><body>
<div class="logo">🐰 <b>Ghosted</b></div>
<div class="tag">create your account — opens your private vault, mail & mesh</div>
<form action="/setup" method="post" autocomplete="off" class="acct" style="text-align:center">
  <input type="text" name="display_name" placeholder="your display name (shown when signed in)" autofocus>
  <input type="password" name="pw" placeholder="create a master password">
  <input type="password" name="pw2" placeholder="confirm master password">
  <div class="muted" style="text-align:left;margin:2px 0 6px">Password must be at least 12
   characters, use 4+ different characters, and not be a common password — it seals your
   whole vault (mail + mesh), so make it strong.</div>
  <input type="text" name="email" placeholder="your email(s), comma-separated — blank uses @{PUBLIC_DOMAIN}">
  <div class="btns"><button type="submit">Create account</button></div>
  <div class="muted">Guests can search, check health & use every capability without an
   account. An account only unlocks <b>your</b> private data. Add 2FA factors next on your
   account page (authenticator/QR, text, location, recovery).</div>
</form>{err}
</body></html>"""
    # Account exists → multi-factor sign-in: master password + the enrolled factors.
    try:
        from ghosted import mfa

        enrolled = set(mfa.enrolled())
    except Exception:
        enrolled = set()
    fields = ""
    if "authenticator" in enrolled:
        fields += '<input type="text" name="authenticator" placeholder="authenticator 6-digit code" autocomplete="off">'
    if "email" in enrolled:
        fields += '<input type="text" name="email" placeholder="email code (use “Send email code”)" autocomplete="off">'
    if "phone" in enrolled:
        fields += '<input type="text" name="phone" placeholder="text-message code (use “Send text code”)" autocomplete="off">'
    if "recovery" in enrolled:
        fields += '<input type="text" name="recovery" placeholder="recovery code (optional)" autocomplete="off">'
    loc = ('<div class="muted">your trusted-location factor verifies automatically from this network</div>'
           if "location" in enrolled else "")
    send = ""
    if "email" in enrolled:
        send += '<button type="submit" name="send" value="email">Send email code</button>'
    if "phone" in enrolled:
        send += '<button type="submit" name="send" value="phone">Send text code</button>'
    policy = ('<div class="muted">master password + 2 security factors required</div>'
              if len(enrolled) >= 2 else
              '<div class="muted">add more factors in your account for full protection</div>')
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Ghosted — sign in</title><style>{_CSS}</style></head><body>
<div class="logo">🐰 <b>Ghosted</b></div>
<div class="tag">sign in — master password + your factors</div>
<form action="/login" method="post" autocomplete="off" class="acct" style="text-align:center">
  <input type="password" name="pw" placeholder="master password" autofocus>
  {fields}{loc}
  <label class="muted" style="display:block;margin:8px 0 2px;text-align:left">
    <input type="checkbox" name="remember" value="1"> stay logged in on this device</label>
  <div class="btns">{send}<button type="submit" name="submit" value="1">Sign in</button></div>
  {policy}
</form>
<div class="tag"><a href="/" style="color:#9aa9ff;text-decoration:none">← back to search (no account needed)</a></div>{err}
</body></html>"""


def _health_page(ctx: dict | None = None) -> str:
    """Device health monitor — public capability (a guest can read machine vitals,
    but never personal data). Renders one snapshot() with coloured states."""
    ctx = ctx or {"authed": False, "name": "", "accent": "#9aa9ff", "notes": 0}
    try:
        from ghosted import health

        snap = health.snapshot()
    except Exception as e:  # never 500
        return f"<h1>health unavailable</h1><p>{html.escape(str(e))}</p>"

    def card(label: str, value: str, state) -> str:
        cls = f"s-{state}" if state else "s-none"
        return (
            f'<div class="hcard"><span class="hl">{html.escape(label)}</span>'
            f'<span class="hv {cls}">{value}</span></div>'
        )

    cpu, mem, dsk = snap["cpu"], snap["memory"], snap["disk"]
    bat, up, net, sec = snap["battery"], snap["uptime"], snap["network"], snap["security"]
    cards = [
        card("CPU", f'{cpu.get("percent")}%' if cpu.get("percent") is not None else "—", cpu.get("state")),
        card("Memory", f'{mem.get("percent")}%  ({mem.get("used_gb")}/{mem.get("total_gb")} GB)' if mem.get("percent") is not None else "—", mem.get("state")),
        card("Disk", f'{dsk.get("percent")}%  ({dsk.get("free_gb")} GB free)' if dsk.get("percent") is not None else "—", dsk.get("state")),
    ]
    if bat.get("present"):
        cards.append(card("Battery", f'{bat.get("percent")}%  {"plugged" if bat.get("plugged") else "on battery"}', bat.get("state")))
    cards.append(card("Uptime", up.get("human", "—"), "none"))
    cards.append(card("Network", "online" if net.get("online") else ("offline" if net.get("online") is False else "—"), net.get("state")))
    cards.append(card("Security (EDR)", str(sec.get("edr", "—")), sec.get("state")))
    cards.append(card("Egress IP", html.escape(str(sec.get("egress_ip", "—"))), "none"))
    overall = snap.get("overall", "unknown")
    ocls = {"healthy": "s-ok", "degraded": "s-warn", "critical": "s-critical"}.get(overall, "s-none")
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Ghosted — Health</title>
<style>{_CSS}</style>{_accent_style(ctx)}</head><body>
{_toolbar(ctx)}
<div class="logo" style="font-size:40px;margin-top:64px">🩺 <b>Device Health</b></div>
<div class="tag">overall: <span class="{ocls}">{overall}</span> · live machine vitals</div>
<div class="health">{"".join(cards)}</div>
<div class="tag"><a href="/" style="color:#9aa9ff;text-decoration:none">← search</a></div>
</body></html>"""


def _account_page(ctx: dict | None = None, msg: str = "") -> str:
    """The account holder's full account-info page: all personal data + history +
    statistical use, plus preferences, optional notifications, and multi-factor setup.
    `msg` shows a result banner (green for success, red for an error starting with !)."""
    ctx = ctx or {"authed": True, "name": "", "accent": "#9aa9ff", "notes": 0}
    banner = ""
    if msg:
        err = msg.startswith("!")
        banner = (f'<div class="tag" style="color:{"#ff8aa0" if err else "#7bd88f"}">'
                  f'{html.escape(msg.lstrip("! "))}</div>')
    from ghosted import feedback, mail, mfa, notifications, preferences, vault

    prefs = preferences.all()
    fb = feedback.summary()
    hist = feedback.recent_queries(limit=15)
    status = mfa.status()
    enrolled = set(status["enrolled"])
    notes = notifications.collect()
    wg_status = '<span class="s-ok">✓ configured</span>' if vault.has_mesh() else '<span class="muted">(not set up)</span>'
    # Account-status summary so the site shows what's already enrolled/saved.
    _saved_pw = sum(1 for c in mail.accounts().values() if c.get("pw_blob"))
    _fac = len(enrolled)
    _two = '<span class="s-ok">✓</span>' if _fac >= 2 else f'<span class="s-warn">{_fac}/2</span>'
    _ext = len(mail.accounts())
    _status_summary = (
        '<div class="acct" style="margin-bottom:6px"><h3 style="border-top:none;padding-top:0">Status</h3>'
        f'<div class="row">Account <span class="s-ok">✓ created</span>'
        + (f' · signed in as <b>{html.escape(prefs["display_name"])}</b>' if prefs["display_name"] else '')
        + '</div>'
        f'<div class="row">Two-factor {_two} <span class="muted">· {_fac} factor(s): '
        f'{", ".join(sorted(enrolled)) or "none yet"}</span></div>'
        f'<div class="row">Email <span class="muted">· {len(mail.identities())} identity(ies), {_ext} server account(s), '
        f'{_saved_pw} with saved password</span></div>'
        f'<div class="row">WireGuard mesh {wg_status}</div></div>'
    )

    sovereign = mail.address("me")

    def _rm(action, key, val, label="remove"):
        return (f'<form action="/account" method="post" style="display:inline;float:right">'
                f'<input type="hidden" name="action" value="{action}">'
                f'<input type="hidden" name="{key}" value="{html.escape(val)}">'
                f'<button type="submit" style="padding:2px 9px;font-size:11px;margin:0">{label}</button></form>')

    ids = mail.identities()
    accts = mail.accounts()
    id_rows = "".join(
        f'<div class="row">{html.escape(a)}'
        + ('' if a == sovereign else _rm("remove_identity", "email", a))
        + '</div>'
        for a in ids
    )
    def acct_block(a, c):
        saved = "🔑 password saved" if c.get("pw_blob") else "no saved password"
        return (
            f'<div class="row">{html.escape(a)} — {html.escape(c.get("protocol",""))} '
            f'{html.escape(c.get("host",""))}:{c.get("port","")} '
            f'<span class="muted">· {saved}</span>' + _rm("remove_account", "email", a) + '</div>'
            f'<form action="/account" method="post"><input type="hidden" name="action" value="set_account_pw">'
            f'<input type="hidden" name="email" value="{html.escape(a)}">'
            f'<input type="password" name="password" placeholder="email password (save or change)">'
            f'<input type="password" name="pw" placeholder="your master password (to encrypt it)">'
            f'<div class="btns"><button type="submit">Save / change email password</button></div></form>'
        )

    acct_rows = "".join(acct_block(a, c) for a, c in accts.items()) \
        or '<div class="row muted">no external accounts configured</div>'

    def factor_row(f, label):
        on = f in enrolled
        if on:
            return (f'<div class="row">{label} — <span class="s-ok">✓ enrolled</span>'
                    + _rm("remove_factor", "factor", f, "disable") + '</div>')
        return f'<div class="row">{label} — <span class="muted">not set</span></div>'

    factors = (
        factor_row("authenticator", "Authenticator (QR / TOTP)")
        + factor_row("email", "Email code")
        + factor_row("phone", "Text message (SMS)")
        + factor_row("location", "Trusted location")
        + factor_row("recovery", "Recovery codes")
    )
    policy_note = (
        f'<div class="row muted">policy: {status["policy"]} · '
        f'{status["count"]} factor(s) enrolled · '
        + ("satisfiable ✓" if status["satisfiable"] else "enroll more to reach two") + "</div>"
    )
    stats = (
        f'<div class="row">searches: <b>{fb["searches"]}</b> · clicks: <b>{fb["clicks"]}</b> · '
        f'ratings: <b>{fb["ratings"]}</b> · learned: <b>{fb["learned_pairs"]}</b> · '
        f'adaptivity: <b>{fb["adaptivity"]}</b></div>'
    )
    hist_rows = "".join(
        f'<div class="row"><a href="/search?q={quote(q)}" style="color:#9aa9ff;text-decoration:none">{html.escape(q)}</a></div>'
        for q in reversed(hist)
    ) or '<div class="row muted">no recent searches</div>'
    note_rows = "".join(
        f'<div class="row {("s-warn" if n["level"]=="warn" else "s-critical" if n["level"]=="critical" else "")}">'
        f'{html.escape(n["text"])} '
        f'<a href="/account" onclick="fetch(\'/note/dismiss?id={quote(n["id"])}\',{{method:\'POST\'}}).then(()=>location.reload());return false" '
        f'style="color:#6f7aa0;float:right">dismiss</a></div>'
        for n in notes
    ) or '<div class="row muted">no notifications' + ('' if prefs["notifications"] else ' (turn them on below)') + '</div>'

    def opt(sel_val, val, text):
        return f'<option value="{val}"{" selected" if sel_val==val else ""}>{text}</option>'

    accents = "".join(opt(prefs["accent"], a, a) for a in preferences.ACCENTS)

    def chk(key):
        return "checked" if prefs.get(key) else ""

    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Ghosted — Account</title>
<style>{_CSS}</style>{_accent_style(ctx)}</head><body>
{_toolbar(ctx)}
<div class="logo" style="font-size:34px;margin-top:64px">👤 <b>{html.escape(prefs["display_name"] or "Your account")}</b></div>
<div class="tag">all your personal data, history &amp; usage — private to you</div>
{banner}
<div class="btns" style="margin:6px 0 4px"><button onclick="location.href='/mail'">✉ Open your mailbox</button>
 <button onclick="location.href='/'">🏠 Home</button></div>
{_status_summary}
<div class="acct">
  <div class="muted" style="margin-bottom:6px">Tip: edit a field and press its Save button. Use “remove”/“disable” to update entries.</div>
  <h3>Profile</h3>
  <form action="/account" method="post"><input type="hidden" name="action" value="save_prefs">
   <input type="text" name="display_name" value="{html.escape(prefs['display_name'])}" placeholder="display name">
   <div class="row">Accent <select name="accent">{accents}</select></div>
   <div class="row"><label><input type="checkbox" name="notifications" {chk('notifications')}> Enable notifications (optional)</label></div>
   <div class="row muted">notify about:
     <label><input type="checkbox" name="notify_health" {chk('notify_health')}> health</label>
     <label><input type="checkbox" name="notify_mail" {chk('notify_mail')}> mail</label>
     <label><input type="checkbox" name="notify_suggestions" {chk('notify_suggestions')}> suggestions</label></div>
   <div class="row"><label><input type="checkbox" name="voice_autoread" {chk('voice_autoread')}> Lola auto-reads results</label>
     &nbsp; <label><input type="checkbox" name="show_badges" {chk('show_badges')}> show relevance badges</label></div>
   <div class="btns"><button type="submit">Save preferences</button></div></form>

  <h3 id="notifications">Notifications</h3>{note_rows}

  <h3>Two-factor authentication <span class="muted">(password + 2 factors required)</span></h3>{factors}{policy_note}
  <form action="/account" method="post"><input type="hidden" name="action" value="enroll_authenticator">
   <input type="password" name="pw" placeholder="master password (to secure the secret)">
   <div class="btns"><button type="submit">Set up authenticator (get QR)</button></div></form>
  <form action="/account" method="post"><input type="hidden" name="action" value="enroll_phone">
   <input type="text" name="number" placeholder="mobile number for text codes">
   <input type="text" name="carrier" placeholder="carrier (att, tmobile, verizon, …)">
   <div class="btns"><button type="submit">Enroll text message</button></div></form>
  <form action="/account" method="post"><input type="hidden" name="action" value="enroll_location">
   <div class="muted">Trust this network as a location factor.</div>
   <div class="btns"><button type="submit">Trust this location</button></div></form>
  <form action="/account" method="post"><input type="hidden" name="action" value="enroll_recovery">
   <input type="password" name="pw" placeholder="master password (to secure the codes)">
   <div class="btns"><button type="submit">Generate recovery codes</button></div></form>

  <h3 id="email">Identities</h3>{id_rows}
  <form action="/account" method="post"><input type="hidden" name="action" value="add_identity">
   <input type="text" name="email" placeholder="add an email identity you own (used for email codes)">
   <div class="btns"><button type="submit">Add identity</button></div></form>

  <h3>External email accounts</h3>{acct_rows}
  <form action="/account" method="post"><input type="hidden" name="action" value="add_account">
   <input type="text" name="email" id="acemail" placeholder="email address (server details auto-fill)">
   <input type="text" name="protocol" id="acproto" placeholder="protocol: imap / pop / smtp (default imap)">
   <input type="text" name="host" id="achost" placeholder="server host (auto-filled from your email)">
   <input type="text" name="port" id="acport" placeholder="port (auto-filled)">
   <input type="password" name="password" placeholder="email password (optional — saved encrypted)">
   <input type="password" name="pw" placeholder="your master password (only if saving the email password)">
   <div class="muted" id="acauto">Enter your email and we fill in the IMAP/SMTP server for you
    (you can edit it). Leave the email password blank to enter it per fetch, or save it encrypted.</div>
   <div class="btns"><button type="submit">Save email account</button></div></form>
  <script>{_EMAIL_AUTOCONFIG_JS}</script>

  <h3>WireGuard mesh {wg_status}</h3>
  <div class="muted">Enroll your devices into a sovereign WireGuard mesh — every config is
   sealed in your vault. One device per line: <b>name endpoint</b> (endpoint optional / blank if NAT).</div>
  <form action="/account" method="post"><input type="hidden" name="action" value="build_mesh">
   <input type="text" name="hub" placeholder="hub device name (blank = full mesh)">
   <textarea name="devices" placeholder="phone&#10;laptop 203.0.113.5:51820&#10;nuc" style="width:100%;min-height:90px;margin:7px 0;padding:11px 14px;border-radius:10px;border:1px solid #2a2f55;background:rgba(22,26,48,.85);color:#fff;font:13px monospace"></textarea>
   <input type="password" name="pw" placeholder="your master password (seals the mesh)">
   <div class="btns"><button type="submit">Enroll devices / build mesh</button></div></form>
  <form action="/account" method="post"><input type="hidden" name="action" value="view_mesh">
   <input type="password" name="pw" placeholder="your master password (to view configs)">
   <div class="btns"><button type="submit">View / export mesh configs</button></div></form>

  <div class="muted" style="margin-top:8px">Enroll one device, connect/disconnect real
   tunnels, or join another mesh from the dedicated tab:</div>
  <div class="btns"><button onclick="location.href='/wireguard'">🔒 Open WireGuard</button></div>

  <h3>Connection &amp; hotspot</h3>
  <div class="muted">Get online by any available door (wifi / ethernet, else dial-up), and
   share it as a WiFi hotspot so your devices join. Hotspot needs admin + a capable adapter.</div>
  <form action="/account" method="post" style="display:inline-block;margin-right:8px">
   <input type="hidden" name="action" value="connect_any">
   <div class="btns"><button type="submit">🌐 Get online (any door)</button></div></form>
  <form action="/account" method="post" style="display:inline-block;margin-right:8px">
   <input type="hidden" name="action" value="hotspot_on">
   <div class="btns"><button type="submit">📶 Activate hotspot</button></div></form>
  <form action="/account" method="post" style="display:inline-block">
   <input type="hidden" name="action" value="hotspot_off">
   <div class="btns"><button type="submit">⏹ Deactivate hotspot</button></div></form>

  <h3>Usage statistics</h3>{stats}
  <h3>Recent search history</h3>{hist_rows}

  <div class="tag" style="margin-top:18px"><a href="/" style="color:#9aa9ff;text-decoration:none">← search</a>
   &nbsp;·&nbsp; <a href="/logout" style="color:#9aa9ff;text-decoration:none">sign out</a></div>
</div>
</body></html>"""


def _qr_page(enrollment: dict, ctx: dict | None = None) -> str:
    """Shown once right after authenticator enrollment — the QR + secret + recovery."""
    ctx = ctx or {"authed": True, "accent": "#9aa9ff"}
    try:
        from ghosted import qrcode

        qr = qrcode.svg(enrollment.get("uri", ""))
    except Exception:
        qr = "<p>(QR unavailable — use the secret below)</p>"
    secret = html.escape(enrollment.get("secret", ""))
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Ghosted — Authenticator</title>
<style>{_CSS}</style></head><body>
{_toolbar(ctx)}
<div class="logo" style="font-size:32px;margin-top:64px">🔐 <b>Scan this QR</b></div>
<div class="tag">scan with your authenticator app — or type the secret below</div>
<div style="background:#fff;padding:14px;border-radius:12px;margin:14px">{qr}</div>
<div class="acct" style="text-align:center">
  <div class="row">secret: <b>{secret}</b></div>
  <div class="muted">After scanning, your authenticator generates the 6-digit codes used at sign-in.</div>
  <div class="tag"><a href="/account" style="color:#9aa9ff;text-decoration:none">← back to account</a></div>
</div>
</body></html>"""


def _codes_page(codes: list, ctx: dict | None = None) -> str:
    """Shown once after generating recovery codes — store them safely (one-time use)."""
    rows = "".join(f'<div class="row"><b>{html.escape(c)}</b></div>' for c in codes)
    ctx = ctx or {"authed": True, "accent": "#9aa9ff", "notes": 0}
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Ghosted — Recovery codes</title>
<style>{_CSS}</style></head><body>
{_toolbar(ctx)}
<div class="logo" style="font-size:30px;margin-top:64px">🗝 <b>Recovery codes</b></div>
<div class="tag">store these safely — each works once if you lose a factor</div>
<div class="acct" style="text-align:center">{rows}
<div class="tag"><a href="/account" style="color:#9aa9ff;text-decoration:none">← back to account</a></div></div>
</body></html>"""


def _wireguard_page(ctx: dict | None = None, msg: str = "") -> str:
    """The WireGuard control center (its own tab): tunnel status + enroll / connect /
    join controls. Every form posts to /account's authed, Gojo-guarded handlers."""
    ctx = ctx or {"authed": True, "accent": "#9aa9ff", "notes": 0}
    banner = ""
    if msg:
        err = msg.startswith("!")
        banner = (f'<div class="tag" style="color:{"#ff8aa0" if err else "#7bd88f"}">'
                  f'{html.escape(msg.lstrip("! "))}</div>')
    try:
        from ghosted import wg_tunnel

        st = wg_tunnel.status()
        wg_installed = ("✓ WireGuard for Windows installed" if st.get("installed")
                        else "WireGuard for Windows not installed — tunnels export as .conf to import")
        tuns = ", ".join(st.get("active_tunnels") or []) or "none active"
    except Exception:
        wg_installed, tuns = "status unavailable", "unknown"
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Ghosted — WireGuard</title>
<style>{_CSS}</style>{_accent_style(ctx)}</head><body>
{_toolbar(ctx)}
<div class="logo" style="font-size:30px;margin-top:56px">🔒 <b>WireGuard</b></div>
<div class="tag">enroll your devices into a sovereign mesh and bring tunnels up — all sealed
 in your vault, guarded by Gojo</div>{banner}
<div class="acct" style="text-align:left">
  <div class="row muted">{html.escape(wg_installed)}</div>
  <div class="row muted">active tunnels: {html.escape(tuns)}</div>

  <h3>Enroll a device</h3>
  <div class="muted">Added to your mesh; existing devices keep their keys. Enrollment is
   remembered.</div>
  <form action="/account" method="post"><input type="hidden" name="action" value="wg_enroll_device">
   <input type="text" name="name" placeholder="device name (e.g. phone)">
   <input type="text" name="endpoint" placeholder="endpoint host:port (optional — blank if NAT)">
   <input type="text" name="hub" placeholder="hub device name (optional)">
   <input type="password" name="pw" placeholder="your master password">
   <div class="btns"><button type="submit">Enroll device</button></div></form>

  <h3>Connect / disconnect a tunnel</h3>
  <div class="muted">Real WireGuard for Windows (needs it installed + Administrator);
   otherwise the .conf is exported for you to import.</div>
  <form action="/account" method="post" style="display:inline-block;margin-right:8px">
   <input type="hidden" name="action" value="wg_connect">
   <input type="text" name="name" placeholder="device/tunnel name">
   <input type="password" name="pw" placeholder="master password">
   <div class="btns"><button type="submit">🔌 Connect</button></div></form>
  <form action="/account" method="post" style="display:inline-block">
   <input type="hidden" name="action" value="wg_disconnect">
   <input type="text" name="name" placeholder="tunnel name">
   <div class="btns"><button type="submit">⏹ Disconnect</button></div></form>

  <h3>Join an existing mesh</h3>
  <div class="muted">Your keys are generated on this device (private key never leaves it);
   hand the hub your public key so they can add you.</div>
  <form action="/account" method="post"><input type="hidden" name="action" value="wg_join">
   <input type="text" name="name" placeholder="this device's name">
   <input type="text" name="hub_pubkey" placeholder="hub public key">
   <input type="text" name="hub_endpoint" placeholder="hub endpoint host:port">
   <input type="password" name="pw" placeholder="your master password">
   <div class="btns"><button type="submit">Join mesh</button></div></form>

  <h3>View / export configs</h3>
  <form action="/account" method="post"><input type="hidden" name="action" value="view_mesh">
   <input type="password" name="pw" placeholder="your master password">
   <div class="btns"><button type="submit">View / export mesh configs</button></div></form>
  <div class="tag" style="margin-top:12px"><a href="/account" style="color:#9aa9ff;text-decoration:none">← account</a>
   &nbsp;·&nbsp; <a href="/" style="color:#9aa9ff;text-decoration:none">🏠 Home</a></div>
</div>
</body></html>"""


def _mesh_page(configs: dict, ctx: dict | None = None, msg: str = "") -> str:
    """Show each device's WireGuard .conf after enrolling — import into WireGuard."""
    ctx = ctx or {"authed": True, "accent": "#9aa9ff", "notes": 0}
    note = f'<div class="tag" style="color:#7bd88f">{html.escape(msg)}</div>' if msg else ""
    blocks = "".join(
        f'<h3>{html.escape(name)}</h3>'
        f'<textarea readonly style="width:100%;min-height:170px;padding:11px 14px;border-radius:10px;'
        f'border:1px solid #2a2f55;background:rgba(22,26,48,.85);color:#cfe;font:12px monospace">'
        f'{html.escape(conf)}</textarea>'
        for name, conf in (configs or {}).items()
    ) or '<div class="row muted">no devices in the mesh yet</div>'
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Ghosted — WireGuard</title>
<style>{_CSS}</style>{_accent_style(ctx)}</head><body>
{_toolbar(ctx)}
<div class="logo" style="font-size:30px;margin-top:64px">🔗 <b>Your WireGuard mesh</b></div>
<div class="tag">import each device's config into the WireGuard app (Add Tunnel → from text/file)</div>{note}
<div class="acct">{blocks}
<div class="tag" style="margin-top:14px"><a href="/account" style="color:#9aa9ff;text-decoration:none">← account</a>
 &nbsp;·&nbsp; <a href="/" style="color:#9aa9ff;text-decoration:none">🏠 Home</a></div></div>
</body></html>"""


def _mail_enroll_page(ctx: dict) -> str:
    """First-time email view: the user hasn't set up their own email yet, so guide
    them to enroll (add an identity / connect an external account) instead of dropping
    them at an unlock prompt for an empty mailbox. They can still open the private
    sovereign mailbox directly."""
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Ghosted — Set up email</title>
<style>{_CSS}</style>{_accent_style(ctx)}</head><body>
{_toolbar(ctx)}
<div class="logo" style="font-size:32px;margin-top:64px">✉ <b>Set up your email</b></div>
<div class="tag">connect your email once — then read, send, receive &amp; manage it here</div>
<div class="acct" style="text-align:center">
  <div class="muted" style="margin:8px 0 18px">Add an email address you own, or connect an external
   account (Gmail/Outlook/Yahoo/… — the server settings auto-fill). Everything is sealed at rest
   under your master password.</div>
  <div class="btns"><button onclick="location.href='/account#email'">Set up my email</button></div>
  <div class="tag" style="margin-top:16px">
   <a href="/mail?open=1" style="color:#9aa9ff;text-decoration:none">skip — open my private mailbox</a>
  </div>
</div>
</body></html>"""


def _mail_unlock_page(ctx: dict, msg: str = "") -> str:
    err = f'<div class="tag" style="color:#ff8aa0">{html.escape(msg)}</div>' if msg else ""
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Ghosted — Mail</title>
<style>{_CSS}</style>{_accent_style(ctx)}</head><body>
{_toolbar(ctx)}
<div class="logo" style="font-size:32px;margin-top:64px">✉ <b>Your mail</b></div>
<div class="tag">enter your passphrase to open your encrypted mailbox</div>
<form action="/mail" method="post" autocomplete="off" class="acct" style="text-align:center">
  <input type="hidden" name="action" value="unlock">
  <input type="password" name="pw" placeholder="your master password" autofocus>
  <div class="btns"><button type="submit">Unlock mailbox</button></div>
</form>{err}
</body></html>"""


def _mail_page(ctx: dict, pw: str, read_idx: int = -1, msg: str = "") -> str:
    """The webmail client: inbox, read, compose/send, and IMAP/POP receive."""
    from ghosted import mail

    boxes = mail.inbox()
    note = f'<div class="tag" style="color:#7bd88f">{html.escape(msg)}</div>' if msg else ""
    reading = ""
    if 0 <= read_idx < len(boxes):
        try:
            m = mail.read(boxes[read_idx], pw)
            reading = (
                '<div class="acct"><h3>Message</h3>'
                f'<div class="row">from: <b>{html.escape(str(m.get("from","")))}</b></div>'
                f'<div class="row">to: {html.escape(str(m.get("to","")))}</div>'
                f'<div class="row">subject: <b>{html.escape(str(m.get("subject","")))}</b></div>'
                f'<div class="row" style="white-space:pre-wrap">{html.escape(str(m.get("body","")))}</div>'
                '<div class="tag"><a href="/mail" style="color:#9aa9ff;text-decoration:none">← inbox</a></div></div>'
            )
        except Exception:
            reading = '<div class="acct"><div class="row muted">cannot open this message with your key</div></div>'
    rows = []
    for i, path in list(enumerate(boxes))[::-1][:60]:
        # Box files are immutable once sealed, so cache the decrypted (subject, from)
        # preview per path — re-renders of the inbox then cost zero crypto.
        prev = _MAIL_PREVIEW.get(path)
        if prev is None:
            try:
                m = mail.read(path, pw)
                prev = (str(m.get("subject", "(no subject)"))[:80], str(m.get("from", ""))[:40])
                _MAIL_PREVIEW[path] = prev
                if len(_MAIL_PREVIEW) > 500:  # bound the cache
                    _MAIL_PREVIEW.pop(next(iter(_MAIL_PREVIEW)))
            except Exception:
                rows.append('<div class="row muted">🔒 sealed (different key)</div>')
                continue
        subj, frm = html.escape(prev[0]), html.escape(prev[1])
        rows.append(f'<div class="row"><a href="/mail?id={i}" style="color:#9aa9ff;text-decoration:none">'
                    f'<b>{subj}</b> <span class="muted">— {frm}</span></a></div>')
    inbox_rows = "".join(rows) or '<div class="row muted">inbox empty</div>'
    accts = "".join(f'<option value="{html.escape(a)}">{html.escape(a)}</option>' for a in mail.accounts())
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Ghosted — Mail</title>
<style>{_CSS}</style>{_accent_style(ctx)}</head><body>
{_toolbar(ctx)}
<div class="logo" style="font-size:30px;margin-top:64px">✉ <b>Your mail</b></div>
<div class="tag">encrypted mailbox · send · receive · read — private to you</div>{note}
{reading}
<div class="acct">
  <h3>Compose</h3>
  <form action="/mail" method="post"><input type="hidden" name="action" value="send">
   <input type="text" name="to" placeholder="to (peer @sovereign.dmn or external address)">
   <input type="text" name="subject" placeholder="subject">
   <textarea name="body" placeholder="message" style="width:100%;min-height:120px;margin:6px 0;padding:11px 14px;border-radius:10px;border:1px solid #2a2f55;background:rgba(22,26,48,.85);color:#fff"></textarea>
   <div class="row"><label><input type="radio" name="mode" value="sovereign" checked> sovereign / mesh</label>
     &nbsp; <label><input type="radio" name="mode" value="external"> external SMTP</label></div>
   <div class="muted">External SMTP (optional): from / host / port / username / password (used once, never stored)</div>
   <input type="text" name="from_addr" placeholder="from address (external)">
   <input type="text" name="smtp_host" placeholder="smtp host (e.g. smtp.gmail.com)">
   <input type="text" name="smtp_port" placeholder="smtp port (587)">
   <input type="text" name="smtp_user" placeholder="smtp username">
   <input type="password" name="smtp_pass" placeholder="smtp password (one-time)">
   <div class="btns"><button type="submit">Send</button></div></form>

  <h3>Inbox</h3>{inbox_rows}

  <h3>Receive external mail (IMAP / POP)</h3>
  <form action="/mail" method="post"><input type="hidden" name="action" value="pull">
   <input type="text" name="host" placeholder="imap/pop host (e.g. imap.gmail.com)">
   <input type="text" name="username" placeholder="username / email">
   <input type="password" name="password" placeholder="password (blank = use your saved email password)">
   <input type="text" name="port" placeholder="port (993 imap / 995 pop)">
   <div class="row"><label><input type="radio" name="proto" value="imap" checked> IMAP</label>
     <label><input type="radio" name="proto" value="pop"> POP</label></div>
   <div class="muted">Leave the password blank to use the encrypted email password saved on your account.</div>
   <div class="btns"><button type="submit">Fetch into mailbox</button></div></form>

  <div class="tag" style="margin-top:14px"><a href="/" style="color:#9aa9ff;text-decoration:none">🏠 Home</a>
   &nbsp;·&nbsp; <a href="/account" style="color:#9aa9ff;text-decoration:none">account &amp; email settings</a>
   &nbsp;·&nbsp; <a href="/mail?lock=1" style="color:#9aa9ff;text-decoration:none">lock mailbox</a></div>
</div>
</body></html>"""


def _help_page() -> str:
    from ghosted import help_text

    rows = []
    for cat, items in help_text.HELP.items():
        rows.append(f'<div class="hc">{html.escape(cat)}</div>')
        for cmd, summary, detail in items:
            rows.append(
                f'<div class="hr"><b>{html.escape(cmd)}</b><span>{html.escape(summary)}</span>'
                f'<div class="hd">{html.escape(detail)}</div></div>'
            )
    body = "".join(rows)
    extra = (
        "<style>.help{width:min(760px,92vw);margin:26px 0 90px}"
        ".hc{color:#9aa9ff;font-size:18px;font-weight:600;margin:22px 0 8px}"
        ".hr{padding:10px 0;border-bottom:1px solid #1c2138}"
        ".hr b{color:#cfd6ff;font-size:14px}.hr span{color:#8890b5;font-size:13px;margin-left:10px}"
        ".hd{color:#aeb6dc;font-size:13px;margin-top:5px;line-height:1.45}</style>"
    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Ghosted — Help</title>
<style>{_CSS}</style>{extra}</head><body>
<div class="toolbar"><button onclick="location.href='/'" title="Home">🏠 Home</button></div>
<div class="logo" style="font-size:40px;margin-top:64px">🐰 <b>Ghosted</b> Help</div>
<div class="tag">everything the app does</div>
<div class="help">{body}<div class="hd" style="margin-top:24px">{html.escape(help_text.CAPABILITIES)}</div></div>
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
            self._send("<h1>403 — Access denied</h1>", 403)
            return
        path = parsed.path
        ctx = _ctx(self)
        # ── PUBLIC capability routes ──────────────────────────────────────────────
        # Open use: full capabilities for everyone (guests on any connection). Personal
        # data is never served here — only the app's public capabilities.
        if path in ("/", "/index.html"):
            self._send(_home_page(ctx))
            return
        if path == "/search":
            q = (parse_qs(parsed.query).get("q") or [""])[0].strip()
            self._send(_home_page(ctx) if not q else _results_page(q, ctx))
            return
        if path == "/help":
            self._send(_help_page())
            return
        if path == "/health":
            self._send(_health_page(ctx))
            return
        if path == "/favicon.ico":
            self._send_icon()
            return
        # ── PERSONAL routes — account holder only ─────────────────────────────────
        if path == "/logout":
            tok = _cookie_token(self)
            with _SESSIONS_LOCK:
                _SESSIONS.pop(tok, None)
            with _MAIL_LOCK:  # drop the in-memory mailbox key too
                _MAIL_KEYS.pop(tok, None)
            self.send_response(303)
            self.send_header("Set-Cookie", "rg_session=; Max-Age=0; Path=/")
            self.send_header("Location", "/")
            self.end_headers()
            return
        if path == "/account":
            from ghosted import vault

            # Managing an account requires the account to EXIST (a master password set).
            # Not initialized → onboarding; authed + initialized → dashboard; else unlock.
            if ctx["authed"] and vault.is_initialized():
                self._send(_account_page(ctx))
            else:
                self._send(_login_page())
            return
        if path == "/wireguard":
            from ghosted import vault

            if ctx["authed"] and vault.is_initialized():
                self._send(_wireguard_page(ctx))
            else:
                self._send(_login_page())
            return
        if path == "/mail":
            from ghosted import vault

            if not ctx["authed"] or not vault.is_initialized():
                self._send(_login_page())  # no account yet → create one first
                return
            q = parse_qs(parsed.query)
            if q.get("lock"):
                _mail_clear_key(self)
                self._send(_mail_unlock_page(ctx, "mailbox locked"))
                return
            # Enrollment gate: a user who hasn't set up their own email is guided to
            # setup; an enrolled user goes straight to their mailbox. "?open=1" lets a
            # not-yet-enrolled user open the private sovereign mailbox anyway.
            # Mail enrollment prompt happens ONCE, EVER (persisted), then never again:
            # a not-yet-enrolled user is guided to setup on their first ever mailbox
            # visit; afterwards (or with ?open=1, or once actually enrolled) they go
            # straight to the mailbox.
            try:
                from ghosted import mail as _mail
                from ghosted import preferences as _prefs

                enrolled = _mail.is_enrolled()
                prompted = bool(_prefs.get("mail_enroll_prompted"))
            except Exception:
                enrolled, prompted = True, True  # fail open — never trap out of mailbox
            if not enrolled and not q.get("open") and not prompted:
                try:
                    _prefs.set("mail_enroll_prompted", "1")  # mark shown — once, ever
                except Exception:
                    pass
                self._send(_mail_enroll_page(ctx))
                return
            pw = _mail_get_key(self)
            if not pw:
                self._send(_mail_unlock_page(ctx))
                return
            try:
                rid = int((q.get("id") or ["-1"])[0])
            except ValueError:
                rid = -1
            self._send(_mail_page(ctx, pw, rid))
            return
        self._send("<h1>404</h1>", 404)

    def _send_icon(self) -> None:
        """Serve the bundled ghost-rabbit icon as the favicon; 204 if not found."""
        try:
            import sys as _sys

            base = getattr(_sys, "_MEIPASS", None) or os.path.dirname(__file__)
            for cand in (
                os.path.join(base, "ghost_rabbit.ico"),
                os.path.join(base, "assets", "ghost_rabbit.ico"),
                os.path.join(os.path.dirname(base), "assets", "ghost_rabbit.ico"),
            ):
                if os.path.exists(cand):
                    with open(cand, "rb") as fh:
                        data = fh.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "image/x-icon")
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "max-age=86400")
                    self.end_headers()
                    self.wfile.write(data)
                    return
        except Exception:
            pass
        self.send_response(204)
        self.end_headers()

    def _read_body(self, cap: int = 64 * 1024) -> str | None:
        """Read the request body with a size cap (anti memory-DoS). None on error."""
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length < 0:
                raise ValueError("negative Content-Length")
        except ValueError:
            self._send("<h1>400 — bad Content-Length</h1>", 400)
            return None
        if length > cap:
            self._send("<h1>413 — request too large</h1>", 413)
            return None
        return self.rfile.read(length).decode("utf-8", "replace") if length else ""

    def _grant_session(self, remember: bool = False, passphrase: str | None = None) -> None:
        """Mint a session cookie and redirect home (shared by login + first-run setup).

        remember=True issues a persistent cookie (survives browser restarts while the
        app keeps running) with a longer TTL; otherwise a browser-session cookie.
        When the master passphrase is supplied it also opens the encrypted mailbox for
        this session, so login happens ONCE — /mail never re-prompts for the password.
        The passphrase is held in memory only, never written to disk.
        """
        tok = secrets.token_urlsafe(32)
        now = time.time()
        ttl = _REMEMBER_TTL if remember else _SESSION_TTL
        with _SESSIONS_LOCK:
            for _k in [k for k, v in _SESSIONS.items() if v <= now]:
                _SESSIONS.pop(_k, None)
            if len(_SESSIONS) >= _SESSIONS_MAX:
                _SESSIONS.clear()
            _SESSIONS[tok] = now + ttl
        # Login once: seed the mailbox key under the NEW session token (this request
        # carried no cookie yet), so /mail opens without a second password prompt.
        if passphrase:
            with _MAIL_LOCK:
                _MAIL_KEYS[tok] = (passphrase, now + ttl)
        cookie = f"rg_session={tok}; HttpOnly; Path=/; SameSite=Strict"
        if remember:  # persistent across browser restarts (session cookie otherwise)
            cookie += f"; Max-Age={int(ttl)}"
        self.send_response(303)
        self.send_header("Set-Cookie", cookie)
        self.send_header("Location", "/account")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if not _gojo_admits(self.client_address[0], parsed.path):
            self._send("<h1>403 — Access denied</h1>", 403)
            return
        path = parsed.path
        # ── public feedback beacons — every interaction is a data point ───────────
        if path in ("/fb/click", "/fb/dwell", "/fb/rate"):
            self._handle_feedback(path)
            return
        if path == "/login":
            self._handle_login()
            return
        if path == "/setup":
            self._handle_setup()
            return
        if path == "/account":
            self._handle_account_post()
            return
        if path == "/note/dismiss":
            self._handle_note_dismiss()
            return
        if path == "/mail":
            self._handle_mail_post()
            return
        self._send("<h1>404</h1>", 404)

    def _handle_mail_post(self) -> None:
        ctx = _ctx(self)
        if not ctx["authed"]:
            self._send(_login_page())
            return
        body = self._read_body(cap=512 * 1024)
        if body is None:
            return
        form = parse_qs(body)
        g = lambda k, d="": (form.get(k) or [d])[0]  # noqa: E731
        action = g("action")
        from ghosted import mail, vault

        if action == "unlock":
            pw = g("pw")
            if not vault.is_initialized():
                self._send(_login_page("no account yet — create one to set your password"))
                return
            if vault.login(pw):
                _mail_set_key(self, pw)
                self.send_response(303)
                self.send_header("Location", "/mail")
                self.end_headers()
            else:
                self._send(_mail_unlock_page(ctx, "incorrect master password"))
            return
        pw = _mail_get_key(self)
        if not pw:
            self._send(_mail_unlock_page(ctx))
            return
        def _port(s, default):
            if not s:
                return default
            if not s.isdigit() or not (1 <= int(s) <= 65535):
                raise ValueError(f"port must be 1–65535 (got '{s}')")
            return int(s)

        msg = ""
        try:
            if action == "send":
                to, subject, mbody = g("to").strip(), g("subject"), g("body")
                if "@" not in to:
                    raise ValueError("a recipient email address is required")
                if g("mode") == "external" and g("smtp_host"):
                    from ghosted import bridge

                    bridge.send_external(
                        to, subject, mbody,
                        from_addr=g("from_addr") or mail.address("me"),
                        smtp_host=g("smtp_host"),
                        smtp_port=_port(g("smtp_port"), 587),
                        username=g("smtp_user") or None,
                        password=g("smtp_pass") or None,
                    )
                    msg = f"sent to {to} via external email"
                else:
                    mail.send(to, subject, mbody, pw)
                    msg = f"message sent to {to} on the mesh"
            elif action == "pull":
                from ghosted import imap_pull

                host, user, pwd = g("host"), g("username"), g("password")
                if not host:
                    raise ValueError("the IMAP/POP server host is required")
                if not user:
                    raise ValueError("your email username is required")
                if not pwd:  # fall back to a saved (encrypted) email password
                    for addr, c in mail.accounts().items():
                        if user.lower() in (addr, c.get("username", "").lower()) or c.get("host") == host:
                            saved = mail.account_password(addr, pw)
                            if saved:
                                pwd = saved
                                break
                if not pwd:
                    raise ValueError("no password — enter it, or save one on your account first")
                if g("proto") == "pop":
                    r = imap_pull.pull_pop(host, user, pwd, pw, port=_port(g("port"), 995))
                else:
                    r = imap_pull.pull_imap(host, user, pwd, pw, port=_port(g("port"), 993))
                _MAIL_PREVIEW.clear()  # new mail arrived → refresh the inbox preview cache
                msg = f"imported {r.get('sealed', 0)} message(s) into your mailbox"
        except Exception as e:  # surface the error, never 500
            msg = f"could not complete: {e}"
        self._send(_mail_page(ctx, pw, -1, msg))

    def _record_fail(self, client: str, now: float) -> None:
        with _SESSIONS_LOCK:
            c, s = _LOGIN_FAILS.get(client, (0, now))
            if now - s > _LOGIN_WINDOW:
                c, s = 0, now
            _LOGIN_FAILS[client] = (c + 1, s)

    def _handle_login(self) -> None:
        client = self.client_address[0] if self.client_address else ""
        now = time.time()
        with _SESSIONS_LOCK:  # brute-force lockout per source IP
            cnt, start = _LOGIN_FAILS.get(client, (0, now))
            if now - start > _LOGIN_WINDOW:
                cnt, start = 0, now
            if cnt >= _LOGIN_MAX:
                self._send("<h1>429 — too many attempts, slow down</h1>", 429)
                return
        body = self._read_body()
        if body is None:
            return
        form = parse_qs(body)
        pw = (form.get("pw") or [""])[0]
        from ghosted import mfa, vault

        # Master password (first means of identification) must verify before anything.
        try:
            pw_ok = vault.login(pw)
        except Exception:
            pw_ok = False
        if not pw_ok:
            self._record_fail(client, now)
            self._send(_login_page("wrong password"))
            return
        # "Send code" for a delivery factor (email / text) → challenge, then re-prompt.
        send = (form.get("send") or [""])[0].strip()
        if send in ("email", "phone"):
            ch = mfa.challenge(send, pw)
            if ch.get("error"):
                msg = f"could not send {send} code: {ch['error']}"
            elif ch.get("shown"):
                msg = f"offline — your {send} code is {ch['shown']}"
            elif ch.get("delivered"):
                msg = f"code sent via {ch.get('via', send)} — enter it below"
            else:
                msg = f"could not deliver the {send} code — try another factor"
            self._send(_login_page(msg))
            return
        # Second + third means: collect factor proofs and validate (location auto).
        proofs = {f: (form.get(f) or [""])[0].strip()
                  for f in ("authenticator", "email", "phone", "recovery")
                  if (form.get(f) or [""])[0].strip()}
        result = mfa.validate(pw, proofs, client_ip=client)
        if result["ok"]:
            with _SESSIONS_LOCK:
                _LOGIN_FAILS.pop(client, None)
            remember = bool((form.get("remember") or [""])[0].strip())
            self._grant_session(remember=remember, passphrase=pw)
        else:
            self._record_fail(client, now)
            passed = ", ".join(result["passed"]) or "none"
            self._send(_login_page(
                f"two factors required — passed: {passed} (need {result['required']})"))

    def _handle_setup(self) -> None:
        """First-run account creation from the website. Only allowed when no account
        exists yet (or the caller is already authed) — never a way to reset someone."""
        from ghosted import vault

        if vault.is_initialized() and not _is_authed(self):
            self._send(_login_page("account already exists — sign in"))
            return
        body = self._read_body()
        if body is None:
            return
        form = parse_qs(body)
        pw = (form.get("pw") or [""])[0]
        pw2 = (form.get("pw2") or [""])[0]
        name = (form.get("display_name") or [""])[0].strip()
        emails = [e.strip() for e in (form.get("email") or [""])[0].replace(";", ",").split(",") if e.strip()]
        if not vault.is_initialized():
            if not pw or not pw2:
                self._send(_login_page("enter your password twice to create your account"))
                return
            if pw != pw2:
                self._send(_login_page("the two passwords did not match — try again"))
                return
            problems = vault.password_problems(pw)
            if problems:  # doesn't reach the requirements → tell them exactly what's missing
                self._send(_login_page("password must " + "; ".join(problems)))
                return
            try:
                vault.initialize(pw)
            except Exception as e:  # noqa: BLE001
                self._send(_login_page(f"could not create account: {e}"))
                return
        try:
            if name:
                from ghosted import preferences

                preferences.set("display_name", name)
            valid = [e for e in emails if "@" in e]
            if valid:
                from ghosted import mail, mfa

                for e in valid:
                    try:
                        mail.add_identity(e)
                    except Exception:
                        pass
                mfa.enroll("email", pw, addrs=valid)  # email factor for 2FA
        except Exception:
            pass
        # New account → straight in, mailbox already open (login once). pw is empty only
        # when an authed user re-runs setup to add email; then don't seed a blank key.
        remember = bool((form.get("remember") or [""])[0].strip())
        self._grant_session(remember=remember, passphrase=pw or None)

    def _handle_account_post(self) -> None:
        if not _is_authed(self):
            self._send(_login_page())
            return
        body = self._read_body()
        if body is None:
            return
        form = parse_qs(body)
        action = (form.get("action") or [""])[0]
        g = lambda k, d="": (form.get(k) or [d])[0].strip()  # noqa: E731
        from ghosted import mail, mfa, notifications, preferences, vault

        # The account must exist before you can manage it — no orphaned factors.
        if not vault.is_initialized():
            self._send(_login_page("create your account first (set a master password)"))
            return
        # Actions that seal data under the master password must verify it FIRST, so a
        # secret is never sealed under a key that doesn't match the vault.
        if action in ("enroll_authenticator", "enroll_recovery", "build_mesh", "view_mesh") \
                and not vault.login(g("pw")):
            self._send(_account_page(_ctx(self), "! wrong master password — nothing changed"))
            return

        def _port(s, default):
            if not s:
                return default
            if not s.isdigit() or not (1 <= int(s) <= 65535):
                raise ValueError(f"port must be 1–65535 (got '{s}')")
            return int(s)

        msg = ""
        try:
            if action == "save_prefs":
                bools = ("notifications", "notify_health", "notify_mail",
                         "notify_suggestions", "voice_autoread", "show_badges")
                vals = {b: (b in form) for b in bools}
                vals["display_name"] = g("display_name")
                vals["accent"] = g("accent", "violet")
                preferences.update(vals)
                notifications._invalidate()  # pref change may change the bell
                msg = "preferences saved"
            elif action == "enroll_authenticator":
                en = mfa.enroll("authenticator", g("pw"))
                self._send(_qr_page(en, _ctx(self)))  # show the QR once
                return
            elif action == "enroll_phone":
                if not g("number"):
                    raise ValueError("a mobile number is required for text codes")
                mfa.enroll("phone", g("pw"), number=g("number"), carrier=g("carrier"))
                msg = "text-message factor enrolled"
            elif action == "enroll_location":
                mfa.enroll("location", g("pw"), ip=self.client_address[0] if self.client_address else "")
                msg = "this network is now a trusted-location factor"
            elif action == "enroll_recovery":
                rc = mfa.enroll("recovery", g("pw"))
                self._send(_codes_page(rc["recovery_codes"], _ctx(self)))
                return
            elif action == "add_identity":
                if "@" not in g("email"):
                    raise ValueError("a valid email address is required")
                mail.add_identity(g("email"))
                msg = f"identity {g('email')} added"
            elif action == "add_account":
                if "@" not in g("email"):
                    raise ValueError("a valid email address is required")
                if g("password") and not vault.login(g("pw")):
                    raise ValueError("master password required (and correct) to save the email password")
                proto = g("protocol", "imap") or "imap"
                mail.set_account(g("email"), proto, g("host"), _port(g("port"), 0),
                                 g("email"), password=g("password"), master_pw=g("pw"))
                msg = f"email account {g('email')} saved" + (" with password" if g("password") else "")
            elif action == "set_account_pw":
                if not vault.login(g("pw")):
                    raise ValueError("wrong master password — email password not saved")
                if mail.set_account_password(g("email"), g("password"), g("pw")):
                    msg = "email password saved (encrypted)" if g("password") else "email password removed"
                else:
                    raise ValueError("no such email account")
            elif action == "remove_identity":
                msg = "identity removed" if mail.remove_identity(g("email")) else "identity not found"
            elif action == "remove_account":
                msg = "email account removed" if mail.remove_account(g("email")) else "account not found"
            elif action == "remove_factor":
                msg = "factor disabled" if mfa.remove(g("factor"), g("pw")) \
                    else "! could not disable that factor (check your master password)"
            elif action == "build_mesh":
                pw = g("pw")
                devices = []
                for line in (form.get("devices") or [""])[0].splitlines():
                    parts = line.split()
                    if parts:
                        devices.append((parts[0], parts[1] if len(parts) > 1 else ""))
                if not devices:
                    raise ValueError("add at least one device (one per line)")
                vault.build_and_seal_mesh(devices, pw, hub=g("hub"))
                self._send(_mesh_page(vault.unseal_mesh(pw), _ctx(self),
                                      f"enrolled {len(devices)} device(s) into your mesh"))
                return
            elif action == "view_mesh":
                if not vault.has_mesh():
                    raise ValueError("no WireGuard mesh configured yet — build one first")
                self._send(_mesh_page(vault.unseal_mesh(g("pw")), _ctx(self)))
                return
            elif action == "wg_enroll_device":
                from ghosted import wg_enroll

                if not g("name"):
                    raise ValueError("a device name is required")
                r = wg_enroll.add_peer(g("name"), endpoint=g("endpoint"),
                                       passphrase=g("pw"), hub=g("hub"),
                                       source_class=_request_source_class(self))
                if not r.get("ok"):
                    raise ValueError(r.get("error", "enrollment failed"))
                self._send(_mesh_page({r["name"]: r["config"]}, _ctx(self),
                                      f"enrolled '{r['name']}' — {r['count']} device(s) in your mesh"))
                return
            elif action == "wg_join":
                from ghosted import wg_enroll

                for req in ("name", "hub_pubkey", "hub_endpoint"):
                    if not g(req):
                        raise ValueError("name, hub public key and hub endpoint are all required")
                r = wg_enroll.join_mesh(g("name"), g("hub_pubkey"), g("hub_endpoint"), g("pw"),
                                        source_class=_request_source_class(self))
                if not r.get("ok"):
                    raise ValueError(r.get("error", "join failed"))
                self._send(_mesh_page({r["name"]: r["config"]}, _ctx(self),
                                      f"joined — hand the hub your public key: {r['public_key']}"))
                return
            elif action == "wg_connect":
                from ghosted import wg_enroll, wg_tunnel

                conf = wg_enroll.device_config(g("name"), g("pw"))
                if not conf:
                    raise ValueError("no such enrolled device / wrong master password")
                r = wg_tunnel.connect(g("name"), conf, source_class=_request_source_class(self))
                wmsg = (f"tunnel '{g('name')}' up" if r.get("ok")
                        else f"! {r.get('error', 'connect failed')}"
                             + (f" — {r['hint']}" if r.get("hint") else ""))
                self._send(_wireguard_page(_ctx(self), wmsg))
                return
            elif action == "wg_disconnect":
                from ghosted import wg_tunnel

                r = wg_tunnel.disconnect(g("name"), source_class=_request_source_class(self))
                wmsg = f"tunnel '{g('name')}' down" if r.get("ok") else f"! {r.get('error', r.get('detail', 'failed'))}"
                self._send(_wireguard_page(_ctx(self), wmsg))
                return
            elif action == "connect_any":
                from ghosted import connectivity

                r = connectivity.ensure_online_any()
                msg = (f"online via {r.get('via')}" if r.get("online")
                       else f"! {r.get('via', 'no path available')}")
            elif action == "hotspot_on":
                from ghosted import connectivity

                r = connectivity.start_hotspot()
                msg = "hotspot activated" if r.get("ok") else f"! hotspot failed: {r.get('error', r.get('detail', 'unknown'))}"
            elif action == "hotspot_off":
                from ghosted import connectivity

                r = connectivity.stop_hotspot()
                msg = "hotspot deactivated" if r.get("ok") else f"! could not stop hotspot: {r.get('error', r.get('detail', 'unknown'))}"
        except Exception as e:  # surface the failure instead of silently swallowing it
            msg = f"! {e}"
        # Re-render the dashboard with a result banner so the user always sees the outcome.
        self._send(_account_page(_ctx(self), msg))

    def _handle_note_dismiss(self) -> None:
        if not _is_authed(self):
            self.send_response(403)
            self.end_headers()
            return
        nid = (parse_qs(urlparse(self.path).query).get("id") or [""])[0]
        try:
            from ghosted import notifications

            notifications.dismiss(nid)
        except Exception:
            pass
        self.send_response(204)
        self.end_headers()

    def _handle_feedback(self, path: str) -> None:
        """Record a click / dwell / rating beacon, then 204. Public + best-effort:
        all input is a data point, but a malformed beacon never errors the client."""
        body = self._read_body(cap=8 * 1024)
        if body is None:
            return
        try:
            import json

            data = json.loads(body) if body else {}
            from ghosted import feedback

            q = str(data.get("q", ""))
            url = str(data.get("url", ""))
            if path == "/fb/click":
                feedback.record_click(q, url, int(data.get("pos", -1)), float(data.get("dwell", 0) or 0))
            elif path == "/fb/dwell":
                feedback.record_dwell(q, url, float(data.get("dwell", 0) or 0))
            elif path == "/fb/rate":
                feedback.record_rating(q, float(data.get("v", 0) or 0), str(data.get("note", "")), url)
        except Exception:
            pass
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):  # quiet
        pass


def serve(port: int = _PORT) -> None:
    global _PORT
    _PORT = port
    try:
        httpd = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    except OSError as e:
        print(
            f"[homepage] cannot bind 0.0.0.0:{port} — {e}\n"
            f"           the port is likely already in use; start on another port:\n"
            f"           ghosted-home <port>   (or  python -m ghosted.homepage <port>)"
        )
        return
    # Pre-warm the dominance/intent engine in the background so the first search is fast.
    try:
        import threading as _t

        from ghosted import semantic_search

        _t.Thread(target=semantic_search.warm, daemon=True).start()
    except Exception:
        pass
    try:  # complete spooled mesh-mail / fetch the instant connectivity returns
        from ghosted import flusher

        flusher.start_autoflush()
    except Exception:
        pass
    try:  # bring Ghosted's self-defense online (Gojo + crypto + EDR + event bus)
        from ghosted import defense

        defense.boot("ghosted-homepage")
    except Exception:
        pass
    try:  # bring Tor up in the background so the Tor egress face is always ready
        import threading as _t2

        from ghosted import tor

        _t2.Thread(target=tor.start, daemon=True).start()
    except Exception:
        pass
    cls = _classify(_all_local_ips())
    print(f"🐰 Ghosted home page live — reachable by IP on port {port}:")
    print(f"   local:     http://127.0.0.1:{port}")
    for ip in cls["lan"] + cls["wireguard"]:
        print(f"   by IP:     http://{ip}:{port}")
    print(f"   egress IP (ISP/Tor sees): {_egress_ip()}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else _PORT)
