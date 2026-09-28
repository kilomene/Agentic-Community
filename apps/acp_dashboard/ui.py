"""Single-page dashboard UI for the ACP 1.0 Agent Community connector.

render_page(lang) -> str: a complete self-contained HTML document.
No external assets (no CDN): all CSS/JS is inline so the page works
fully offline. Dynamic labels come from acp_i18n for the active locale;
the client talks to the JSON REST API under /api/* with the
X-ACP-Token header (the token is typed once into the unlock box and kept
in sessionStorage — it is never baked into the page).
"""

import html
import json
import sys

sys.path.insert(0, __import__("os").path.join(
    __import__("os").path.dirname(__import__("os").path.abspath(__file__)),
    "..", "..", "packages"))

try:
    from acp_i18n import t, available_langs, lang_name
except ImportError:  # pragma: no cover - defensive
    def t(key, lang="en"):
        return key

    def available_langs():
        return ["en"]

    def lang_name(code):
        return code

# Keys the JS needs at runtime (labels, buttons, status lines, errors).
_JS_KEYS = (
    "nav_overview nav_peers nav_conversations nav_files nav_projects "
    "nav_permissions nav_pairing nav_audit "
    "btn_send btn_grant btn_revoke btn_create btn_add btn_update btn_cancel "
    "btn_refresh btn_initiate btn_set btn_login btn_delete btn_confirm "
    "btn_broadcast "
    "status_online status_offline status_busy status_paused status_unknown "
    "msg_no_peers msg_inbox_empty msg_no_projects msg_no_tasks msg_no_files "
    "msg_no_audit msg_sent msg_sending msg_pairing_sent msg_granted "
    "msg_revoked msg_created msg_updated msg_presence_set msg_type_message "
    "msg_confirm_revoke msg_file_sent msg_file_sending msg_token_required "
    "msg_pairing_sessions "
    "err_unauthorized err_not_found err_unknown_peer err_invalid_input "
    "err_send_failed err_pair_failed err_unknown_scope err_internal "
    "err_method "
    "label_handle label_peer_id label_presence label_token label_language "
    "label_host label_port label_text label_scope label_title label_notes "
    "label_assignee label_status label_path label_state label_actions "
    "label_peer label_name label_size label_direction label_created "
    "label_project label_granted_by label_expires label_session label_role "
    "label_details label_action label_actor label_result label_time "
    "label_messages label_progress label_transfer "
    "app_title app_subtitle"
).split()


def _strings(lang):
    return {k: t(k, lang) for k in _JS_KEYS}


def render_page(lang="en"):
    S = _strings(lang)
    s_json = json.dumps(S, ensure_ascii=False).replace("</", "<\\/")
    lang_opts = "".join(
        '<option value="%s"%s>%s</option>' % (
            html.escape(c), " selected" if c == lang else "",
            html.escape(lang_name(c)))
        for c in available_langs())
    # Server-rendered (works before JS runs / with JS disabled for text).
    return """<!DOCTYPE html>
<html lang="%s">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
:root{--bg:#0f1420;--panel:#182032;--panel2:#1f2940;--line:#2a3652;--fg:#e8eefc;
--mut:#93a1c0;--acc:#5aa2ff;--ok:#43c98a;--warn:#f0b429;--bad:#ef5b6e}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{display:flex;align-items:center;gap:12px;padding:10px 16px;
background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
header h1{font-size:17px;margin:0}
header .sub{color:var(--mut);font-size:12px}
header .sp{flex:1}
select,input,textarea,button{font:inherit;color:var(--fg);background:var(--panel2);
border:1px solid var(--line);border-radius:6px;padding:6px 9px}
button{cursor:pointer;background:#27406b;border-color:#33507f}
button:hover{background:#2f4c80}
button.danger{background:#5c2430;border-color:#7d3040}
button.danger:hover{background:#6e2b39}
button:disabled{opacity:.5;cursor:default}
nav{display:flex;gap:4px;padding:8px 16px;background:var(--panel);
border-bottom:1px solid var(--line);flex-wrap:wrap}
nav button{background:transparent;border-color:transparent;color:var(--mut)}
nav button.on{background:var(--panel2);color:var(--fg);border-color:var(--line)}
main{padding:16px;max-width:1100px;margin:0 auto}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:14px;margin-bottom:14px}
.card h2{margin:0 0 10px;font-size:15px}
table{width:100%%;border-collapse:collapse}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);
font-size:13px;vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;
letter-spacing:.04em}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.mut{color:var(--mut)}
.ok{color:var(--ok)} .bad{color:var(--bad)} .warn{color:var(--warn)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:6px 0}
.pill{display:inline-block;padding:2px 9px;border-radius:20px;font-size:12px;
background:var(--panel2);border:1px solid var(--line)}
.pill.on{color:var(--ok);border-color:#2c6b4f}
.bubbles{display:flex;flex-direction:column;gap:6px;max-height:420px;
overflow-y:auto;padding:6px 2px}
.bub{max-width:75%%;padding:8px 12px;border-radius:12px;background:var(--panel2);
border:1px solid var(--line)}
.bub.out{align-self:flex-end;background:#27406b}
.bub .meta{font-size:11px;color:var(--mut);margin-top:4px}
.peerlist{display:flex;flex-direction:column;gap:4px;min-width:200px}
.peerlist button{text-align:left}
.chatwrap{display:flex;gap:14px}
.chatmain{flex:1;min-width:0}
#gate{max-width:420px;margin:60px auto}
.hidden{display:none!important}
.toast{position:fixed;bottom:18px;right:18px;background:var(--panel2);
border:1px solid var(--line);padding:10px 14px;border-radius:8px;z-index:50}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:800px){.grid2{grid-template-columns:1fr}.chatwrap{flex-direction:column}}
.stat{display:flex;gap:18px;flex-wrap:wrap}
.stat div{background:var(--panel2);border:1px solid var(--line);border-radius:8px;
padding:10px 16px;min-width:110px}
.stat b{font-size:20px;display:block}
.stat span{color:var(--mut);font-size:12px}
</style>
</head>
<body>
<header>
<h1>%s</h1><span class="sub">%s</span><span class="sp"></span>
<label class="mut" for="langsel">%s</label>
<select id="langsel">%s</select>
</header>
<div id="gate" class="card">
<h2>%s</h2>
<p class="mut">%s</p>
<div class="row"><input id="token" type="password" style="flex:1"
placeholder="%s" autocomplete="off"><button id="gobtn">%s</button></div>
<p id="gateerr" class="bad"></p>
</div>
<div id="app" class="hidden">
<nav id="tabs"></nav>
<main id="view"></main>
</div>
<div id="toast" class="toast hidden"></div>
<script>
"use strict";
const STR=%s;
let TOKEN=sessionStorage.getItem("acp_token")||"";
let TAB="overview", CHATPEER=null, POLL=null;
const $=id=>document.getElementById(id);
function toast(m,cls){const e=$("toast");e.textContent=m;
e.className="toast"+(cls?" "+cls:"");e.hidden=false;
clearTimeout(e._t);e._t=setTimeout(()=>e.hidden=true,3500);}
async function api(method,path,body){
  const o={method:method,headers:{"X-ACP-Token":TOKEN}};
  if(body!==undefined){o.headers["Content-Type"]="application/json";
    o.body=JSON.stringify(body);}
  const r=await fetch(path,o);
  if(r.status===401){showGate(STR.err_unauthorized);throw new Error("401");}
  let j=null;try{j=await r.json();}catch(e){}
  if(!r.ok)throw new Error((j&&(j.detail||j.code))||("HTTP "+r.status));
  return j;
}
const get=p=>api("GET",p), post=(p,b)=>api("POST",p,b||{});
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,
c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function ts(t){if(!t)return "—";const d=new Date(t*1000);
return d.toLocaleString();}
function short(id,n){id=String(id||"");n=n||12;
return id.length>n?id.slice(0,n)+"…":id;}
function showGate(msg){$("app").classList.add("hidden");
$("gate").classList.remove("hidden");if(msg)$("gateerr").textContent=msg;}
function showApp(){$("gate").classList.add("hidden");
$("app").classList.remove("hidden");renderTabs();render();}
function renderTabs(){
  const tabs=["overview","peers","conversations","files","projects",
"permissions","pairing","audit"];
  $("tabs").innerHTML=tabs.map(x=>
'<button data-t="'+x+'" class="'+(x===TAB?"on":"")+'">'+esc(STR["nav_"+x])+
"</button>").join("");
  $("tabs").querySelectorAll("button").forEach(b=>b.onclick=()=>{TAB=b.dataset.t;
renderTabs();render();});
}
async function render(){
  clearInterval(POLL);POLL=null;
  const v=$("view");v.innerHTML="<p class='mut'>…</p>";
  try{
    if(TAB==="overview")await vOverview(v);
    else if(TAB==="peers")await vPeers(v);
    else if(TAB==="conversations")await vConvs(v);
    else if(TAB==="files")await vFiles(v);
    else if(TAB==="projects")await vProjects(v);
    else if(TAB==="permissions")await vPerms(v);
    else if(TAB==="pairing")await vPairing(v);
    else if(TAB==="audit")await vAudit(v);
  }catch(e){v.innerHTML="<p class='bad'>"+esc(e.message)+"</p>";}
}
/* ---------------- overview ---------------- */
async function vOverview(v){
  const s=await get("/api/status");
  const c=s.counts||{};
  v.innerHTML=
'<div class="card"><h2>'+esc(STR.nav_overview)+"</h2>"+
'<div class="row"><span class="pill">'+esc(STR.label_handle)+": <b>"+
esc(s.handle)+"</b></span>"+
'<span class="pill mono" title="'+esc(s.peer_id)+'">'+esc(STR.label_peer_id)+
": "+esc(short(s.peer_id,20))+"</span>"+
'<span class="pill '+(s.presence==="online"?"on":"")+'">'+
esc(STR.label_presence)+": "+esc(s.presence)+"</span></div>"+
'<div class="stat">'+
"<div><b>"+c.peers+"</b><span>"+esc(STR.nav_peers)+"</span></div>"+
"<div><b>"+c.messages+"</b><span>"+esc(STR.label_messages)+"</span></div>"+
"<div><b>"+c.projects+"</b><span>"+esc(STR.nav_projects)+"</span></div>"+
"<div><b>"+c.tasks+"</b><span>"+esc(STR.nav_tasks||"tasks")+"</span></div>"+
"<div><b>"+c.transfers+"</b><span>"+esc(STR.nav_files)+"</span></div>"+
"</div></div>"+
'<div class="card"><h2>'+esc(STR.label_presence)+"</h2>"+
'<div class="row"><select id="psel">'+["online","offline","busy","paused",
"unknown"].map(x=>'<option value="'+x+'"'+(x===s.presence?" selected":"")+">"+
esc(STR["status_"+x])+"</option>").join("")+"</select>"+
'<button id="pset">'+esc(STR.btn_set)+"</button></div></div>";
  $("pset").onclick=async()=>{try{await post("/api/presence",
{state:$("psel").value});toast(STR.msg_presence_set,"ok");render();}
catch(e){toast(e.message,"bad");}};
}
/* ---------------- peers ---------------- */
async function vPeers(v){
  const peers=await get("/api/peers");
  let h='<div class="card"><h2>'+esc(STR.nav_peers)+
' <button id="rl" style="float:right">'+esc(STR.btn_refresh)+"</button></h2>";
  if(!peers.length)h+="<p class='mut'>"+esc(STR.msg_no_peers)+"</p>";
  else{h+="<table><tr><th>"+esc(STR.label_peer)+"</th><th>"+
esc(STR.label_handle)+"</th><th>"+esc(STR.label_presence)+"</th><th>"+
esc(STR.label_actions)+"</th></tr>";
  for(const p of peers){
    h+="<tr><td class='mono' title='"+esc(p.agent_id)+"'>"+
esc(short(p.agent_id,16))+"</td><td>"+esc(p.display_name||"—")+"</td><td>"+
esc(p.presence||"?")+(p.revoked?' <span class="bad">✕</span>':"")+"</td><td>"+
'<button data-chat="'+esc(p.agent_id)+'">💬</button> '+
'<button data-rev="'+esc(p.agent_id)+'" class="danger">'+esc(STR.btn_revoke)+
"</button></td></tr>";}
  h+="</table>";}
  h+="</div>";
  h+='<div class="card"><h2>'+esc(STR.nav_pairing)+"</h2>"+
'<div class="row"><input id="ph" placeholder="'+esc(STR.label_host)+
'" value="127.0.0.1" size="14"><input id="pp" placeholder="'+
esc(STR.label_port)+'" size="6"><button id="pgo">'+esc(STR.btn_initiate)+
"</button></div><p class='mut' id='pmsg'></p></div>";
  v.innerHTML=h;
  $("rl").onclick=render;
  v.querySelectorAll("[data-chat]").forEach(b=>b.onclick=()=>{
CHATPEER=b.dataset.chat;TAB="conversations";renderTabs();render();});
  v.querySelectorAll("[data-rev]").forEach(b=>b.onclick=async()=>{
if(!confirm(STR.msg_confirm_revoke))return;
try{await post("/api/peer/revoke",{peer:b.dataset.rev});
toast(STR.msg_revoked,"ok");render();}catch(e){toast(e.message,"bad");}});
  $("pgo").onclick=async()=>{try{const r=await post("/api/pair/initiate",
{host:$("ph").value,port:parseInt($("pp").value,10)});
$("pmsg").textContent=STR.msg_pairing_sent+" ("+r.session_id.slice(0,12)+"…)";}
catch(e){$("pmsg").textContent=e.message;}};
}
/* ---------------- conversations ---------------- */
async function vConvs(v){
  const convs=await get("/api/conversations");
  let h='<div class="card"><h2>'+esc(STR.nav_conversations)+"</h2>";
  if(!convs.length){h+="<p class='mut'>"+esc(STR.msg_inbox_empty)+
"</p></div>";v.innerHTML=h;return;}
  if(!CHATPEER||!convs.find(c=>c.peer_id===CHATPEER))CHATPEER=convs[0].peer_id;
  h+='<div class="chatwrap"><div class="peerlist">'+convs.map(c=>
'<button data-p="'+esc(c.peer_id)+'" class="'+(c.peer_id===CHATPEER?"on":"")+
'">'+esc(c.handle||short(c.peer_id))+
' <span class="mut">('+c.messages.length+")</span></button>").join("")+
'</div><div class="chatmain"><div class="bubbles" id="bub">';
  const c=convs.find(x=>x.peer_id===CHATPEER);
  for(const m of c.messages){
    h+='<div class="bub '+(m.direction==="out"?"out":"")+'">'+
esc(m.text)+'<div class="meta">'+ts(m.created_at)+" · "+esc(m.status)+
"</div></div>";}
  h+='</div><div class="row"><input id="cin" style="flex:1" placeholder="'+
esc(STR.msg_type_message)+'"><button id="csend">'+esc(STR.btn_send)+
"</button></div></div></div></div>";
  v.innerHTML=h;
  const bub=$("bub");bub.scrollTop=bub.scrollHeight;
  v.querySelectorAll("[data-p]").forEach(b=>b.onclick=()=>{
CHATPEER=b.dataset.p;render();});
  const send=async()=>{const inp=$("cin"),tx=inp.value.trim();if(!tx)return;
inp.value="";$("csend").disabled=true;
try{await post("/api/message/send",{peer:CHATPEER,text:tx});
toast(STR.msg_sending,"ok");setTimeout(render,1500);}catch(e){
toast(e.message,"bad");$("csend").disabled=false;}};
  $("csend").onclick=send;
  $("cin").onkeydown=e=>{if(e.key==="Enter")send();};
  POLL=setInterval(async()=>{try{const cs=await get("/api/conversations");
const cur=cs.find(x=>x.peer_id===CHATPEER);
if(cur&&cur.messages.length!==c.messages.length)render();}catch(e){}},4000);
}
/* ---------------- files ---------------- */
async function vFiles(v){
  const files=await get("/api/files");
  const peers=await get("/api/peers");
  let h='<div class="card"><h2>'+esc(STR.nav_files)+"</h2>";
  if(!files.length)h+="<p class='mut'>"+esc(STR.msg_no_files)+"</p>";
  else{h+="<table><tr><th>"+esc(STR.label_transfer)+"</th><th>"+
esc(STR.label_name)+"</th><th>"+esc(STR.label_direction)+"</th><th>"+
esc(STR.label_peer)+"</th><th>"+esc(STR.label_size)+"</th><th>"+
esc(STR.label_progress)+"</th><th>"+esc(STR.label_status)+"</th><th>"+
esc(STR.label_time)+"</th></tr>";
  for(const f of files){
    const pc=f.count?Math.round(100*f.received/f.count):0;
    h+="<tr><td class='mono'>"+esc(short(f.transfer_id))+"</td><td>"+
esc(f.name)+"</td><td>"+esc(f.direction)+"</td><td class='mono'>"+
esc(short(f.peer_id,10))+"</td><td>"+f.size+"</td><td>"+pc+"%%</td><td>"+
esc(f.state)+"</td><td>"+ts(f.created_at)+"</td></tr>";}
  h+="</table>";}
  h+="</div>"+
'<div class="card"><h2>'+esc(STR.btn_send)+" — "+esc(STR.nav_files)+"</h2>"+
'<div class="row"><select id="fpeer">'+peers.map(p=>'<option value="'+
esc(p.agent_id)+'">'+esc(p.display_name||short(p.agent_id))+"</option>")+
'</select><input id="fpath" style="flex:1;min-width:220px" placeholder="'+
esc(STR.label_path)+'"><button id="fgo">'+esc(STR.btn_send)+
"</button></div><p class='mut' id='fmsg'></p></div>";
  v.innerHTML=h;
  $("fgo").onclick=async()=>{try{await post("/api/file/send",
{peer:$("fpeer").value,path:$("fpath").value});
$("fmsg").textContent=STR.msg_file_sending;setTimeout(render,3000);}
catch(e){$("fmsg").textContent=e.message;}};
}
/* ---------------- projects ---------------- */
async function vProjects(v){
  const projs=await get("/api/projects");
  let h='<div class="card"><h2>'+esc(STR.nav_projects)+
' <button id="rl" style="float:right">'+esc(STR.btn_refresh)+"</button></h2>";
  if(!projs.length)h+="<p class='mut'>"+esc(STR.msg_no_projects)+"</p>";
  for(const p of projs){
    h+='<div class="card" style="margin:10px 0"><b>'+esc(p.title)+
"</b> <span class='mut mono'>"+esc(p.project_id)+"</span>";
    if(p.notes)h+="<div class='mut'>"+esc(p.notes)+"</div>";
    const tasks=await get("/api/tasks?project_id="+encodeURIComponent(p.project_id));
    if(!tasks.length)h+="<p class='mut'>"+esc(STR.msg_no_tasks)+"</p>";
    else{h+="<table><tr><th>"+esc(STR.label_title)+"</th><th>"+
esc(STR.label_status)+"</th><th>"+esc(STR.label_assignee)+"</th><th>"+
esc(STR.label_actions)+"</th></tr>";
    for(const t of tasks){
      h+="<tr><td>"+esc(t.title)+"</td><td>"+esc(t.status)+"</td><td class='mono'>"+
esc(t.assignee?short(t.assignee,10):"—")+"</td><td>"+
'<button data-done="'+esc(t.task_id)+'">✓</button></td></tr>";}
    h+="</table>";}
    h+='<div class="row"><input data-tp="'+esc(p.project_id)+
'" placeholder="'+esc(STR.label_title)+'" size="18"><input data-np="'+
esc(p.project_id)+'" placeholder="'+esc(STR.label_notes)+
'" size="24"><button data-add="'+esc(p.project_id)+'">'+esc(STR.btn_add)+
"</button></div></div>";}
  h+="</div>"+
'<div class="card"><h2>'+esc(STR.btn_create)+" — "+esc(STR.nav_projects)+
"</h2>"+
'<div class="row"><input id="pt" placeholder="'+esc(STR.label_title)+
'"><input id="pn" placeholder="'+esc(STR.label_notes)+
'" style="flex:1"><button id="pgo">'+esc(STR.btn_create)+"</button></div></div>";
  v.innerHTML=h;
  $("rl").onclick=render;
  $("pgo").onclick=async()=>{try{await post("/api/project/create",
{title:$("pt").value,notes:$("pn").value});
toast(STR.msg_created,"ok");render();}catch(e){toast(e.message,"bad");}};
  v.querySelectorAll("[data-add]").forEach(b=>b.onclick=async()=>{
const pid=b.dataset.add;
const ti=v.querySelector('[data-tp="'+pid+'"]'),
ni=v.querySelector('[data-np="'+pid+'"]');
try{await post("/api/task/add",{project_id:pid,title:ti.value,notes:ni.value});
toast(STR.msg_created,"ok");render();}catch(e){toast(e.message,"bad");}});
  v.querySelectorAll("[data-done]").forEach(b=>b.onclick=async()=>{
try{await post("/api/task/update",{task_id:b.dataset.done,status:"done"});
toast(STR.msg_updated,"ok");render();}catch(e){toast(e.message,"bad");}});
}
/* ---------------- permissions ---------------- */
const SCOPES=["read_profile","send_message","send_file","family_read",
"family_write","project_read","project_write","task_assign"];
async function vPerms(v){
  const grants=await get("/api/permissions");
  const peers=await get("/api/peers");
  const byPeer={};
  for(const g of grants){(byPeer[g.agent_id]=byPeer[g.agent_id]||{})[g.scope]=g;}
  const names={};for(const p of peers)names[p.agent_id]=p.display_name;
  let h='<div class="card"><h2>'+esc(STR.nav_permissions)+
' <button id="rl" style="float:right">'+esc(STR.btn_refresh)+"</button></h2>";
  if(!peers.length)h+="<p class='mut'>"+esc(STR.msg_no_peers)+"</p>";
  else{h+="<table><tr><th>"+esc(STR.label_peer)+"</th>"+
SCOPES.map(s=>"<th>"+esc(s)+"</th>").join("")+"</tr>";
  for(const p of peers){
    const g=byPeer[p.agent_id]||{};
    h+="<tr><td title='"+esc(p.agent_id)+"'>"+
esc(names[p.agent_id]||short(p.agent_id,12))+"</td>"+
SCOPES.map(s=>"<td><input type='checkbox' data-p='"+esc(p.agent_id)+
"' data-s='"+s+"'"+(g[s]&&g[s].granted?" checked":"")+"></td>").join("")+
"</tr>";}
  h+="</table><p class='mut'>"+esc(STR.label_granted_by)+
" / "+esc(STR.label_expires)+"</p>";}
  h+="</div>";
  v.innerHTML=h;
  $("rl").onclick=render;
  v.querySelectorAll("input[type=checkbox]").forEach(cb=>cb.onchange=async()=>{
try{if(cb.checked)await post("/api/permission/grant",
{peer:cb.dataset.p,scope:cb.dataset.s});
else await post("/api/permission/revoke",{peer:cb.dataset.p,scope:cb.dataset.s});
toast(cb.checked?STR.msg_granted:STR.msg_revoked,"ok");}
catch(e){toast(e.message,"bad");cb.checked=!cb.checked;}});
}
/* ---------------- pairing ---------------- */
async function vPairing(v){
  const sess=await get("/api/pairings");
  let h='<div class="card"><h2>'+esc(STR.msg_pairing_sessions)+"</h2>";
  if(!sess.length)h+="<p class='mut'>—</p>";
  else{h+="<table><tr><th>"+esc(STR.label_session)+"</th><th>"+
esc(STR.label_role)+"</th><th>"+esc(STR.label_peer)+"</th><th>"+
esc(STR.label_status)+"</th><th>"+esc(STR.label_time)+"</th></tr>";
  for(const s of sess){
    h+="<tr><td class='mono'>"+esc(short(s.session_id))+"</td><td>"+
esc(s.role)+"</td><td class='mono'>"+esc(short(s.peer_id||"—",12))+"</td><td>"+
esc(s.state)+"</td><td>"+ts(s.created_at)+"</td></tr>";}
  h+="</table>";}
  h+="</div>"+
'<div class="card"><h2>'+esc(STR.btn_initiate)+" — "+esc(STR.nav_pairing)+
"</h2>"+
'<div class="row"><input id="ph" placeholder="'+esc(STR.label_host)+
'" value="127.0.0.1" size="14"><input id="pp" placeholder="'+
esc(STR.label_port)+'" size="6"><button id="pgo">'+esc(STR.btn_initiate)+
"</button></div><p class='mut' id='pmsg'></p>"+
'<div class="row"><input id="cs" placeholder="session_id" size="20">'+
'<input id="cc" placeholder="code" size="8"><button id="cgo">'+
esc(STR.btn_confirm)+"</button></div></div>";
  v.innerHTML=h;
  $("pgo").onclick=async()=>{try{const r=await post("/api/pair/initiate",
{host:$("ph").value,port:parseInt($("pp").value,10)});
$("pmsg").textContent=STR.msg_pairing_sent+" session="+r.session_id;}
catch(e){$("pmsg").textContent=e.message;}};
  $("cgo").onclick=async()=>{try{const r=await post("/api/pair/confirm",
{session_id:$("cs").value,code:$("cc").value});
toast("state: "+r.state,"ok");render();}catch(e){toast(e.message,"bad");}};
}
/* ---------------- audit ---------------- */
async function vAudit(v){
  const rows=await get("/api/audit?limit=120");
  let h='<div class="card"><h2>'+esc(STR.nav_audit)+
' <button id="rl" style="float:right">'+esc(STR.btn_refresh)+"</button></h2>";
  if(!rows.length)h+="<p class='mut'>"+esc(STR.msg_no_audit)+"</p>";
  else{h+="<table><tr><th>"+esc(STR.label_time)+"</th><th>"+
esc(STR.label_action)+"</th><th>"+esc(STR.label_actor)+"</th><th>"+
esc(STR.label_result)+"</th><th>"+esc(STR.label_details)+"</th></tr>";
  for(const r of rows){
    h+="<tr><td>"+ts(r.timestamp)+"</td><td class='mono'>"+esc(r.action)+
"</td><td class='mono'>"+esc(short(r.actor,14))+"</td><td>"+
(r.result==="denied"||r.result==="failed"?'<span class="bad">':"<span>")+
esc(r.result)+"</span></td><td class='mut mono'>"+esc(r.details||"")+
"</td></tr>";}
  h+="</table>";}
  h+="</div>";
  v.innerHTML=h;
  $("rl").onclick=render;
}
/* ---------------- boot ---------------- */
$("gobtn").onclick=async()=>{TOKEN=$("token").value.trim();
if(!TOKEN){showGate(STR.msg_token_required);return;}
sessionStorage.setItem("acp_token",TOKEN);
try{await get("/api/status");showApp();}catch(e){showGate(e.message);}};
$("token").onkeydown=e=>{if(e.key==="Enter")$("gobtn").click();};
$("langsel").onchange=e=>{location.search="?lang="+
encodeURIComponent(e.target.value);};
if(TOKEN){$("token").value=TOKEN;
get("/api/status").then(showApp).catch(e=>showGate(e.message));}
else showGate();
</script>
</body>
</html>""" % (lang, html.escape(S["app_title"]), html.escape(S["app_title"]),
              html.escape(S["app_subtitle"]), html.escape(S["label_language"]),
              lang_opts, html.escape(S["btn_login"]),
              html.escape(S["msg_token_required"]),
              html.escape(S["label_token"]), html.escape(S["btn_login"]),
              s_json)
