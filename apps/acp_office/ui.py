"""acp_office UI: Phoenix Fleet command center.

Single-page dashboard (inline HTML/CSS/JS, no CDN, no build step).
The page embeds NO data. The office password comes from the ?token=
query param (bookmarked URL) or the login screen, stored in
sessionStorage. A JS poll engine re-syncs every few seconds and updates
the DOM incrementally — no manual refresh needed. A LIVE indicator in
the sidebar shows sync state at all times.
"""


def render_page():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phoenix Fleet &mdash; Office</title>
<style>
:root{
  --bg0:#090d12; --bg:#0f1419; --panel:#141c25; --panel2:#182230;
  --line:#26313f; --line2:#314052;
  --text:#dbe4ec; --dim:#8b9aab; --faint:#5b6a7c;
  --acc:#f5a623; --green:#3fb950; --red:#f85149; --amber:#d29922;
  --blue:#58a6ff; --purple:#a371f7;
  --r:10px;
}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  background:var(--bg0);color:var(--text);font-size:14px;-webkit-text-size-adjust:100%}
/* ---------- auth ---------- */
#authwrap{min-height:100vh;display:flex;align-items:center;justify-content:center;
  padding:20px;background:radial-gradient(900px 500px at 50% -10%,#1b2534 0%,var(--bg0) 60%)}
#authbox{width:100%;max-width:400px;background:var(--panel);border:1px solid var(--line);
  border-radius:14px;padding:34px 30px;text-align:center;box-shadow:0 24px 60px rgba(0,0,0,.5)}
#authbox .mark{font-size:44px}
#authbox h2{margin:10px 0 4px;font-size:20px}
#authbox p{color:var(--dim);font-size:13px;margin:0 0 6px}
#authbox input{width:100%;padding:12px 14px;border-radius:8px;border:1px solid var(--line2);
  background:var(--bg);color:var(--text);margin:14px 0 10px;font-size:15px}
#authbox input:focus{outline:none;border-color:var(--acc)}
#authbox button{width:100%;padding:12px;border-radius:8px;border:none;background:var(--acc);
  color:#181206;font-weight:800;font-size:15px;cursor:pointer}
#authbox button:active{transform:scale(.99)}
#authErr{display:none;color:var(--red);font-size:13px;margin-top:10px}
.shake{animation:shake .3s}
@keyframes shake{25%{transform:translateX(-6px)}75%{transform:translateX(6px)}}
/* ---------- layout ---------- */
#app{display:flex;height:100vh;height:100dvh;overflow:hidden}
#sidebar{width:252px;flex:0 0 252px;background:var(--bg);border-right:1px solid var(--line);
  display:flex;flex-direction:column;z-index:60}
.brand{display:flex;align-items:center;gap:10px;padding:16px 16px 14px;border-bottom:1px solid var(--line)}
.brand .mark{font-size:26px}
.brand b{font-size:15px;display:block;letter-spacing:.2px}
.brand span{font-size:11px;color:var(--dim)}
#sidebar nav{padding:10px;display:flex;flex-direction:column;gap:2px;flex:1;overflow-y:auto}
#sidebar nav button{display:flex;align-items:center;gap:10px;width:100%;text-align:left;
  background:none;border:none;color:var(--dim);padding:10px 12px;border-radius:8px;
  font-size:14px;cursor:pointer}
#sidebar nav button .ico{font-size:16px;width:22px;text-align:center}
#sidebar nav button:hover{background:var(--panel);color:var(--text)}
#sidebar nav button.active{background:var(--panel2);color:var(--acc);font-weight:600}
.badge{margin-left:auto;background:var(--acc);color:#181206;font-size:11px;font-weight:800;
  min-width:20px;height:20px;border-radius:10px;display:none;align-items:center;justify-content:center;padding:0 6px}
.badge.on{display:inline-flex}
.side-foot{border-top:1px solid var(--line);padding:12px}
.conn{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--dim);padding:2px 4px 10px}
#liveDot{width:9px;height:9px;border-radius:50%;background:var(--faint);flex:0 0 9px}
#liveDot.live{background:var(--green);animation:pulse 1.6s infinite}
#liveDot.syncing{background:var(--amber)}
#liveDot.error{background:var(--red)}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(63,185,80,.5)}70%{box-shadow:0 0 0 7px rgba(63,185,80,0)}100%{box-shadow:0 0 0 0 rgba(63,185,80,0)}}
#logoutBtn{width:100%;display:flex;align-items:center;justify-content:center;gap:8px;
  background:var(--panel);border:1px solid var(--line);color:var(--text);
  padding:10px;border-radius:8px;font-size:14px;cursor:pointer}
#logoutBtn:hover{border-color:var(--red);color:var(--red)}
.main{flex:1;display:flex;flex-direction:column;min-width:0}
.topbar{display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid var(--line);
  background:rgba(15,20,25,.92);backdrop-filter:blur(6px);position:sticky;top:0;z-index:40}
.topbar h2{margin:0;font-size:17px;font-weight:700}
.topbar .spacer{flex:1}
#menuBtn{display:none;background:var(--panel);border:1px solid var(--line);color:var(--text);
  border-radius:8px;font-size:18px;padding:6px 10px;cursor:pointer}
#syncNote{font-size:12px;color:var(--faint)}
#clock{font-size:12px;color:var(--dim);font-variant-numeric:tabular-nums}
#views{flex:1;overflow-y:auto;padding:18px 20px 40px}
.view{display:none;animation:fadein .25s}
.view.active{display:block}
@keyframes fadein{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
#scrim{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:55}
/* ---------- cards / tiles ---------- */
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:14px 16px}
.tile .k{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px}
.tile .v{font-size:26px;font-weight:800;margin-top:4px;font-variant-numeric:tabular-nums}
.tile .s{font-size:12px;color:var(--faint);margin-top:2px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:14px 16px;margin-bottom:12px}
.card h3{margin:0 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:.6px;color:var(--dim)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.dim{color:var(--dim);font-size:12px}
.flash{animation:flash 1.6s}
@keyframes flash{0%{background:rgba(245,166,35,.22)}100%{background:transparent}}
/* ---------- agents ---------- */
.agent-row{display:flex;align-items:center;gap:12px;padding:10px 4px;border-bottom:1px solid var(--line)}
.agent-row:last-child{border-bottom:none}
.avatar{width:38px;height:38px;border-radius:50%;flex:0 0 38px;display:flex;align-items:center;justify-content:center;
  font-weight:800;font-size:16px;color:#0c0f14}
.agent-row .nm{font-weight:600}
.agent-row .sub{font-size:12px;color:var(--dim)}
.dot{width:10px;height:10px;border-radius:50%;flex:0 0 10px}
.dot.alive{background:var(--green);box-shadow:0 0 6px rgba(63,185,80,.7)}
.dot.idle{background:var(--amber)} .dot.stale{background:var(--faint)}
.agent-row .right{margin-left:auto;text-align:right;font-size:12px;color:var(--dim)}
.tag{display:inline-block;font-size:11px;padding:2px 8px;border-radius:10px;background:var(--panel2);
  border:1px solid var(--line2);color:var(--dim);margin:2px 4px 2px 0}
.statline{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--dim);margin-top:6px}
.statline b{color:var(--text)}
/* ---------- chat ---------- */
#view-chat{display:none;height:100%}
#view-chat.active{display:flex;flex-direction:column}
#chatList{flex:1;overflow-y:auto;min-height:0;padding:6px 2px}
.daydiv{text-align:center;margin:14px 0 8px;position:relative}
.daydiv span{background:var(--panel2);border:1px solid var(--line);font-size:11px;color:var(--dim);
  padding:3px 12px;border-radius:12px}
.msg{margin:8px 0;max-width:82%}
.msg .head{font-size:12px;margin-bottom:3px;display:flex;gap:8px;align-items:baseline}
.msg .who{font-weight:700}
.msg .when{color:var(--faint);font-size:11px}
.msg .bubble{background:var(--panel);border:1px solid var(--line);border-radius:4px 12px 12px 12px;
  padding:9px 12px;white-space:pre-wrap;word-wrap:break-word;line-height:1.45}
.msg.you{margin-left:auto}
.msg.you .bubble{background:#2a2113;border-color:#5a451f;border-radius:12px 4px 12px 12px}
.msg.you .head{justify-content:flex-end}
.msg.new .bubble{animation:flash 1.8s}
#newPill{display:none;position:sticky;bottom:10px;margin:0 auto;background:var(--acc);color:#181206;
  font-size:12px;font-weight:700;border:none;border-radius:16px;padding:7px 16px;cursor:pointer;z-index:5}
/* ---------- kanban ---------- */
.kanban{display:grid;grid-template-columns:repeat(4,minmax(220px,1fr));gap:12px;align-items:start}
.kcol{background:var(--bg);border:1px solid var(--line);border-radius:var(--r);padding:10px;min-height:120px}
.kcol h4{margin:2px 4px 10px;font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:var(--dim)}
.kcol h4 .n{color:var(--text);background:var(--panel2);border-radius:10px;padding:1px 8px;margin-left:6px}
.kcard{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin-bottom:8px}
.kcard .t{font-weight:600;font-size:13px;margin:4px 0}
.kcard .m{font-size:11px;color:var(--dim)}
.pill{display:inline-block;font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;
  border:1px solid var(--line2);margin-right:6px;text-transform:uppercase;letter-spacing:.4px}
.st-open{color:var(--blue)} .st-assigned{color:var(--purple)} .st-acked{color:#79c0ff}
.st-in_progress{color:var(--amber)} .st-done{color:var(--green)} .st-failed{color:var(--red)}
.st-blocked{color:#fff;background:var(--red);border-color:var(--red)}
/* ---------- timeline ---------- */
.tl{position:relative;margin:6px 0 0 8px;padding-left:22px;border-left:2px solid var(--line)}
.tl-ev{position:relative;padding:0 0 16px}
.tl-ev .ic{position:absolute;left:-33px;top:0;width:22px;height:22px;border-radius:50%;
  background:var(--panel2);border:1px solid var(--line2);display:flex;align-items:center;
  justify-content:center;font-size:12px}
.tl-ev .tx{font-size:13px}
.tl-ev .tx b{font-weight:700}
.tl-ev .mt{font-size:11px;color:var(--faint);margin-top:2px}
/* ---------- toasts ---------- */
#toasts{position:fixed;right:16px;bottom:16px;z-index:100;display:flex;flex-direction:column;gap:8px;max-width:min(340px,90vw)}
.toast{background:var(--panel2);border:1px solid var(--line2);border-left:3px solid var(--acc);
  border-radius:8px;padding:10px 14px;font-size:13px;box-shadow:0 10px 30px rgba(0,0,0,.5);
  animation:fadein .25s}
.toast.err{border-left-color:var(--red)}
/* ---------- misc ---------- */
.spark{width:100%;height:44px}
.empty{color:var(--faint);font-size:13px;padding:18px;text-align:center}
@media (max-width:1100px){.tiles{grid-template-columns:repeat(2,1fr)}.grid2{grid-template-columns:1fr}}
@media (max-width:900px){
  #sidebar{position:fixed;top:0;bottom:0;left:0;transform:translateX(-105%);transition:transform .25s ease}
  #sidebar.open{transform:none}
  #scrim.on{display:block}
  #menuBtn{display:inline-block}
  .kanban{grid-template-columns:minmax(240px,85vw);grid-auto-flow:column;overflow-x:auto;padding-bottom:8px}
  #views{padding:14px 14px 40px}
}
</style>
</head>
<body>
<div id="authwrap">
  <div id="authbox">
    <div class="mark">&#128293;</div>
    <h2>Phoenix Fleet &mdash; Office</h2>
    <p>Enter your office password to continue.</p>
    <input id="tokeninput" type="password" placeholder="Office password"
           autocomplete="off" autocapitalize="off" spellcheck="false">
    <button id="unlockBtn">Unlock dashboard</button>
    <div id="authErr"></div>
  </div>
</div>

<div id="app" style="display:none">
  <aside id="sidebar">
    <div class="brand">
      <span class="mark">&#128293;</span>
      <div><b>Phoenix Fleet</b><span>Office Command</span></div>
    </div>
    <nav id="sideNav">
      <button data-view="overview" class="active"><span class="ico">&#9783;</span>Overview</button>
      <button data-view="chat"><span class="ico">&#128172;</span>Fleet Chat<span class="badge" id="chatBadge"></span></button>
      <button data-view="tasks"><span class="ico">&#128193;</span>Task Board</button>
      <button data-view="activity"><span class="ico">&#9889;</span>Activity</button>
      <button data-view="agents"><span class="ico">&#128101;</span>Agents</button>
    </nav>
    <div class="side-foot">
      <div class="conn"><span id="liveDot"></span><span id="liveText">connecting&hellip;</span></div>
      <button id="logoutBtn">&#9211; Log out</button>
    </div>
  </aside>

  <div class="main">
    <header class="topbar">
      <button id="menuBtn" aria-label="menu">&#9776;</button>
      <h2 id="viewTitle">Overview</h2>
      <span class="spacer"></span>
      <span id="syncNote"></span>
      <span id="clock"></span>
    </header>
    <main id="views">
      <section id="view-overview" class="view active"></section>
      <section id="view-chat" class="view">
        <div id="chatList"></div>
        <button id="newPill"></button>
        <div class="dim" style="padding:12px 2px;font-size:12px">Read-only &mdash; fleet messages go through Phoenix in the main chat.</div>
      </section>
      <section id="view-tasks" class="view"></section>
      <section id="view-activity" class="view"></section>
      <section id="view-agents" class="view"></section>
    </main>
  </div>
</div>
<div id="scrim"></div>
<div id="toasts"></div>
<script>
"use strict";
/* ============================== core ============================== */
var S = {
  token: null, view: 'overview',
  chat: [], chatIds: {}, unread: 0,
  tasks: [], byState: {}, events: [], agentStats: [], presence: [], roster: [],
  cache: {}, lastSync: 0, liveState: 'connecting',
  firstPoll: true, serverTime: 0, sending: false, groupId: ''
};
function $(sel){ return document.querySelector(sel); }
function esc(s){
  return String(s == null ? '' : s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function hue(str){
  var h = 0;
  for (var i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) % 360;
  return h;
}
function avatarColor(name){ return 'hsl(' + hue(name) + ',55%,62%)'; }
function pad(n){ return (n < 10 ? '0' : '') + n; }
function fmtClock(d){
  return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
}
function fmtDay(ts){
  var d = new Date(ts * 1000), now = new Date();
  var day = d.toDateString(), today = now.toDateString();
  var y = new Date(now - 864e5).toDateString();
  if (day === today) return 'Today';
  if (day === y) return 'Yesterday';
  return d.toLocaleDateString();
}
function ago(ts){
  if (ts == null) return 'never';
  if (typeof ts !== 'number' || isNaN(ts)) return '\\u2014';
  var s = Math.floor(Date.now() / 1000 - ts);
  if (s < 0) s = 0;
  if (s < 10) return 'just now';
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}
function toast(msg, isErr){
  var box = $('#toasts');
  var t = document.createElement('div');
  t.className = 'toast' + (isErr ? ' err' : '');
  t.textContent = msg;
  box.appendChild(t);
  while (box.children.length > 4) box.removeChild(box.firstChild);
  setTimeout(function(){ t.style.opacity = '0'; t.style.transition = 'opacity .4s';
    setTimeout(function(){ t.remove(); }, 420); }, 4200);
}
/* ---------- auth ---------- */
function getToken(){
  if (S.token) return S.token;
  var m = /[?&]token=([^&]+)/.exec(location.search);
  if (m) { S.token = decodeURIComponent(m[1]); sessionStorage.setItem('office_token', S.token); return S.token; }
  S.token = sessionStorage.getItem('office_token');
  return S.token;
}
function saveToken(){
  var v = $('#tokeninput').value.trim();
  if (!v) return;
  sessionStorage.setItem('office_token', v);
  S.token = v;
  $('#authErr').style.display = 'none';
  boot();
}
function authFail(msg){
  S.token = null;
  sessionStorage.removeItem('office_token');
  stopPollers();
  $('#app').style.display = 'none';
  $('#authwrap').style.display = 'flex';
  var e = $('#authErr');
  e.textContent = msg || 'Wrong password — try again.';
  e.style.display = 'block';
  var box = $('#authbox');
  box.classList.remove('shake'); void box.offsetWidth; box.classList.add('shake');
  $('#tokeninput').value = '';
  $('#tokeninput').focus();
}
function doLogout(){
  sessionStorage.removeItem('office_token');
  S.token = null;
  /* strip a bookmarked ?token= so logout actually logs out */
  location.href = location.pathname;
}
/* ---------- live indicator ---------- */
function setLive(state){
  if (S.liveState === state) return;
  S.liveState = state;
  var dot = $('#liveDot'), txt = $('#liveText');
  dot.className = state === 'live' ? 'live' : state;
  txt.textContent = state === 'live' ? 'LIVE' :
    state === 'syncing' ? 'syncing…' :
    state === 'error' ? 'connection issue' : 'connecting…';
}
/* ---------- api ---------- */
function getJSON(path){
  return fetch(path, {headers: {'X-Office-Token': S.token}}).then(function(r){
    if (r.status === 401) throw {unauth: true};
    if (!r.ok) throw new Error('http ' + r.status);
    return r.json();
  });
}
function changed(key, obj){
  var s = JSON.stringify(obj);
  if (S.cache[key] === s) return false;
  S.cache[key] = s;
  return true;
}
/* ---------- poll engine: the realtime core.
   Every POLL_MS the page re-syncs all feeds and patches only what
   changed — new messages slide in, the LIVE dot pulses, nothing here
   ever needs a manual refresh. */
var POLL_MS = 4000;
var pollTimer = null, tickTimer = null;
function poll(){
  if (!S.token) return;
  setLive('syncing');
  Promise.all([
    getJSON('/api/status'),
    getJSON('/api/chat?limit=100'),
    getJSON('/api/tasks'),
    getJSON('/api/ledger?limit=100'),
    getJSON('/api/presence'),
    getJSON('/api/roster')
  ]).then(function(res){
    S.serverTime = res[0].server_time || 0;
    S.groupId = res[0].group_id || '';
    applyChat(res[1]);
    applyTasks(res[2]);
    applyLedger(res[3]);
    applyPresence(res[4]);
    applyRoster(res[5]);
    S.lastSync = Date.now();
    setLive('live');
    renderActive();
    S.firstPoll = false;
  }).catch(function(e){
    if (e && e.unauth) authFail();
    else setLive('error');
  });
}
function startPollers(){
  stopPollers();
  poll();
  pollTimer = setInterval(poll, POLL_MS);
  tickTimer = setInterval(tick, 1000);
}
function stopPollers(){
  if (pollTimer) clearInterval(pollTimer);
  if (tickTimer) clearInterval(tickTimer);
  pollTimer = tickTimer = null;
}
/* 1-second ticker: clock, "synced Ns ago", and every relative
   timestamp on the page stays fresh without re-fetching. */
function tick(){
  $('#clock').textContent = fmtClock(new Date());
  var note = $('#syncNote');
  if (S.lastSync){
    var s = Math.floor((Date.now() - S.lastSync) / 1000);
    note.textContent = s < 2 ? 'synced just now' : 'synced ' + s + 's ago';
  }
  var nodes = document.querySelectorAll('[data-ago]');
  for (var i = 0; i < nodes.length; i++)
    nodes[i].textContent = ago(parseFloat(nodes[i].getAttribute('data-ago')));
}
/* ---------- navigation ---------- */
var TITLES = {overview:'Overview', chat:'Fleet Chat', tasks:'Task Board',
              activity:'Activity', agents:'Agents'};
function switchView(name){
  S.view = name;
  var btns = document.querySelectorAll('#sideNav button');
  for (var i = 0; i < btns.length; i++)
    btns[i].classList.toggle('active', btns[i].getAttribute('data-view') === name);
  var views = document.querySelectorAll('.view');
  for (var j = 0; j < views.length; j++)
    views[j].classList.toggle('active', views[j].id === 'view-' + name);
  $('#viewTitle').textContent = TITLES[name] || name;
  $('#sidebar').classList.remove('open');
  $('#scrim').classList.remove('on');
  if (name === 'chat'){
    S.unread = 0; updateBadge();
    renderChat(true);
  }
  renderActive();
}
function updateBadge(){
  var b = $('#chatBadge');
  b.textContent = S.unread > 99 ? '99+' : S.unread;
  b.classList.toggle('on', S.unread > 0);
}
/* ============================== data apply ============================== */
function applyChat(d){
  var msgs = (d && d.messages) || [];
  var fresh = [];
  for (var i = 0; i < msgs.length; i++){
    if (!S.chatIds[msgs[i].id]){ S.chatIds[msgs[i].id] = 1; fresh.push(msgs[i]); }
  }
  var isNew = changed('chat', msgs);
  S.chat = msgs;
  if (!S.firstPoll && fresh.length && isNew){
    var names = {};
    fresh.forEach(function(m){ names[m.sender_name] = 1; });
    var who = Object.keys(names).join(', ');
    toast(fresh.length === 1 ? 'New message from ' + who : fresh.length + ' new messages (' + who + ')');
    if (S.view !== 'chat'){ S.unread += fresh.length; updateBadge(); }
  }
  S._chatFresh = fresh;
}
function applyTasks(d){
  S.tasks = (d && d.tasks) || [];
  S.byState = (d && d.by_state) || {};
  if (!S.firstPoll && changed('tasks', S.tasks)){
    var open = S.tasks.filter(function(t){ return t.state !== 'done' && t.state !== 'failed'; }).length;
    toast('Task board updated — ' + open + ' in flight');
  } else changed('tasks', S.tasks);
}
function applyLedger(d){
  var evs = (d && d.events) || [];
  if (!S.firstPoll && changed('events', evs) && evs.length){
    var e = evs[0];
    toast('Activity: ' + e.agent + ' ' + e.event + (e.task_id ? ' (' + e.task_id + ')' : ''));
  } else changed('events', evs);
  S.events = evs;
  S.agentStats = (d && d.agents) || [];
  changed('agentStats', S.agentStats);
}
function applyPresence(d){
  S.presence = (d && d.agents) || [];
  changed('presence', S.presence);
}
function applyRoster(d){
  S.roster = (d && d.agents) || [];
  changed('roster', S.roster);
}
function renderActive(){
  if (S.view === 'overview') renderOverview();
  else if (S.view === 'chat') renderChat(false);
  else if (S.view === 'tasks') renderTasks();
  else if (S.view === 'activity') renderActivity();
  else if (S.view === 'agents') renderAgents();
}
/* merge presence + roster + ledger stats into one agent model */
function fleetAgents(){
  var byId = {}, order = [];
  S.presence.forEach(function(p){
    var key = p.agent_id || p.display_name;
    byId[key] = {agent_id: p.agent_id, display_name: p.display_name,
      handle: null, state: p.state || 'stale', last_seen: p.last_seen,
      age_s: p.age_s, note: '', stats: null};
    order.push(key);
  });
  S.roster.forEach(function(r){
    var key = r.agent_id || r.display_name;
    var a = byId[key];
    if (!a){
      a = {agent_id: r.agent_id, display_name: r.display_name, handle: r.handle,
        state: 'stale', last_seen: null, age_s: null, note: '', stats: null};
      byId[key] = a; order.push(key);
    }
    a.handle = r.handle || a.handle;
    if (r.display_name) a.display_name = r.display_name;
    a.note = r.note || '';
  });
  S.agentStats.forEach(function(st){
    var nm = String(st.agent || '').toLowerCase();
    for (var k in byId){
      var a = byId[k];
      var cand = [a.display_name, a.handle].filter(Boolean).map(function(x){ return String(x).toLowerCase(); });
      if (cand.indexOf(nm) >= 0){ a.stats = st; break; }
    }
  });
  return order.map(function(k){ return byId[k]; });
}
/* ============================== overview ============================== */
function startOfToday(){
  var d = new Date(); d.setHours(0, 0, 0, 0);
  return Math.floor(d.getTime() / 1000);
}
function sparkline(series, w, h){
  w = w || 220; h = h || 44;
  if (!series.length) return '<div class="empty">no data yet</div>';
  var max = Math.max.apply(null, series.concat([1]));
  var pts = series.map(function(v, i){
    var x = series.length === 1 ? w / 2 : (i / (series.length - 1)) * w;
    var y = h - 4 - (v / max) * (h - 10);
    return x.toFixed(1) + ',' + y.toFixed(1);
  }).join(' ');
  return '<svg class="spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
    '<polyline points="' + pts + '" fill="none" stroke="#f5a623" stroke-width="2"/></svg>';
}
function renderOverview(){
  var box = $('#view-overview');
  var agents = fleetAgents();
  var alive = agents.filter(function(a){ return a.state === 'alive'; }).length;
  var inFlight = S.tasks.filter(function(t){ return t.state !== 'done' && t.state !== 'failed'; });
  var sod = startOfToday();
  var msgsToday = S.chat.filter(function(m){ return m.created_at >= sod; }).length;
  var evsToday = S.events.filter(function(e){ return e.ts >= sod; }).length;
  var blocked = S.tasks.filter(function(t){ return t.blocked; });
  /* events per hour, last 24h */
  var buckets = [], nowH = Math.floor(Date.now() / 3600000);
  for (var i = 23; i >= 0; i--) buckets.push(0);
  S.events.forEach(function(e){
    var h = Math.floor(e.ts / 3600), idx = h - (nowH - 23);
    if (idx >= 0 && idx < 24) buckets[idx]++;
  });
  var h = '<div class="tiles">' +
    tile('Agents online', alive + '<span style="font-size:14px;color:var(--dim)"> / ' + agents.length + '</span>', agents.length ? 'fleet presence' : 'no agents yet') +
    tile('Tasks in flight', inFlight.length, blocked.length ? blocked.length + ' blocked' : 'nothing blocked') +
    tile('Messages today', msgsToday, S.chat.length + ' total in room') +
    tile('Work events today', evsToday, S.events.length + ' total logged') +
    '</div><div class="grid2">';
  /* fleet status */
  h += '<div class="card"><h3>Fleet status</h3>';
  if (!agents.length) h += '<div class="empty">No agents yet.</div>';
  agents.slice(0, 7).forEach(function(a){
    h += '<div class="agent-row">' +
      '<span class="avatar" style="background:' + avatarColor(a.display_name) + '">' + esc(a.display_name.charAt(0).toUpperCase()) + '</span>' +
      '<span class="dot ' + a.state + '"></span>' +
      '<div><div class="nm">' + esc(a.display_name) + '</div>' +
      '<div class="sub">' + esc(a.state) + '</div></div>' +
      '<div class="right"><span data-ago="' + (a.last_seen || '') + '">' + ago(a.last_seen) + '</span></div>' +
      '</div>';
  });
  h += '</div>';
  /* activity pulse */
  h += '<div class="card"><h3>Activity pulse &mdash; last 24h</h3>' +
    sparkline(buckets) +
    '<div class="dim" style="margin-top:8px">' + evsToday + ' events today &middot; ' +
    (S.events.length ? 'latest: ' + esc(S.events[0].agent) + ' ' + esc(S.events[0].event) +
      ' <span data-ago="' + S.events[0].ts + '">' + ago(S.events[0].ts) + '</span>' : 'no events yet') + '</div>';
  if (blocked.length){
    h += '<h3 style="margin-top:14px">Needs attention</h3>';
    blocked.slice(0, 3).forEach(function(t){
      h += '<div class="dim" style="margin:4px 0">&#128308; <b style="color:var(--text)">' + esc(t.title) +
        '</b> blocked by ' + esc((t.open_blockers || []).join(', ')) + '</div>';
    });
  }
  h += '</div></div>';
  box.innerHTML = h;
}
function tile(k, v, s){
  return '<div class="tile"><div class="k">' + k + '</div><div class="v">' + v +
    '</div><div class="s">' + s + '</div></div>';
}
/* ============================== chat ============================== */
function renderChat(forceBottom){
  var box = $('#chatList');
  var atBottom = forceBottom ||
    (box.scrollHeight - box.scrollTop - box.clientHeight < 80);
  var h = '', lastDay = '';
  var freshIds = {};
  (S._chatFresh || []).forEach(function(m){ freshIds[m.id] = 1; });
  S.chat.forEach(function(m){
    var day = fmtDay(m.created_at);
    if (day !== lastDay){ h += '<div class="daydiv"><span>' + day + '</span></div>'; lastDay = day; }
    var isYou = !!m.local;
    h += '<div class="msg' + (isYou ? ' you' : '') + (freshIds[m.id] ? ' new' : '') + '">' +
      '<div class="head"><span class="who" style="color:' +
        (isYou ? 'var(--acc)' : 'hsl(' + hue(m.sender_name || '?') + ',55%,68%)') + '">' +
        esc(isYou ? 'You' : m.sender_name) + '</span>' +
      '<span class="when" data-ago="' + m.created_at + '">' + ago(m.created_at) + '</span></div>' +
      '<div class="bubble">' + esc(m.text) + '</div></div>';
  });
  if (!S.chat.length) h = '<div class="empty">No messages yet.</div>';
  box.innerHTML = h;
  if (atBottom) box.scrollTop = box.scrollHeight;
  else {
    var n = (S._chatFresh || []).length;
    var pill = $('#newPill');
    if (n > 0 && !forceBottom){
      pill.textContent = '\u2193 ' + n + ' new message' + (n > 1 ? 's' : '');
      pill.style.display = 'block';
    } else pill.style.display = 'none';
  }
  S._chatFresh = [];
  box.onscroll = function(){
    var atB = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
    if (atB){ $('#newPill').style.display = 'none'; S.unread = 0; updateBadge(); }
  };
}
/* Chat is read-only by design: fleet messages pass through Phoenix in the
   main chat, never through this page. */
/* (sendChat removed 2026-09-30 per owner's order) */
/* ============================== tasks ============================== */
var KANBAN = [
  {key: 'queue', label: 'Queue', states: ['open', 'assigned', 'acked', 'blocked']},
  {key: 'progress', label: 'In progress', states: ['in_progress']},
  {key: 'done', label: 'Done', states: ['done']},
  {key: 'failed', label: 'Failed', states: ['failed']}
];
function renderTasks(){
  var box = $('#view-tasks');
  var h = '<div class="kanban">';
  KANBAN.forEach(function(col){
    var cards = S.tasks.filter(function(t){ return col.states.indexOf(t.state) >= 0; });
    h += '<div class="kcol"><h4>' + col.label + '<span class="n">' + cards.length + '</span></h4>';
    if (!cards.length) h += '<div class="empty">—</div>';
    cards.forEach(function(t){
      h += '<div class="kcard">' +
        (t.blocked ? '<span class="pill st-blocked">blocked</span>' : '') +
        '<span class="pill st-' + esc(t.state) + '">' + esc(t.state.replace('_', ' ')) + '</span>' +
        '<div class="t">' + esc(t.title) + '</div>' +
        '<div class="m">#' + esc(t.id) + ' &middot; ' + esc(t.assignee || 'unassigned') +
        (t.open_blockers && t.open_blockers.length ? ' &middot; waits on ' + esc(t.open_blockers.join(', ')) : '') +
        '<br>updated <span data-ago="' + (t.updated_at ? Date.parse(t.updated_at) / 1000 : '') + '">' +
          (t.updated_at ? ago(Date.parse(t.updated_at) / 1000) : '—') + '</span></div></div>';
    });
    h += '</div>';
  });
  box.innerHTML = h + '</div>';
}
/* ============================== activity ============================== */
var EV_ICON = {assigned: '&#128203;', acked: '&#128064;', done: '&#9989;', failed: '&#10060;'};
function renderActivity(){
  var box = $('#view-activity');
  var h = '';
  if (S.agentStats.length){
    h += '<div class="card"><h3>Per-agent performance</h3>';
    S.agentStats.forEach(function(a){
      h += '<div style="margin-bottom:10px"><b>' + esc(a.agent) + '</b>' +
        '<span class="dim"> &middot; done ' + a.tasks_completed + ' &middot; failed ' + a.tasks_failed +
        (a.avg_ack_latency_s != null ? ' &middot; avg ack ' + Math.round(a.avg_ack_latency_s) + 's' : '') +
        (a.avg_completion_time_s != null ? ' &middot; avg done ' + Math.round(a.avg_completion_time_s) + 's' : '') +
        '</span>';
      var counts = Object.keys(a.counts || {}).map(function(k){ return k + ': ' + a.counts[k]; }).join(' &middot; ');
      if (counts) h += '<div class="dim">' + counts + '</div>';
      h += '</div>';
    });
    h += '</div>';
  }
  h += '<div class="card"><h3>Event timeline</h3>';
  if (!S.events.length) h += '<div class="empty">No events yet.</div>';
  else {
    h += '<div class="tl">';
    S.events.slice(0, 60).forEach(function(e){
      h += '<div class="tl-ev"><span class="ic">' + (EV_ICON[e.event] || '&#9889;') + '</span>' +
        '<div class="tx"><b>' + esc(e.agent) + '</b> ' + esc(e.event) +
        (e.task_id ? ' <span class="tag">#' + esc(e.task_id) + '</span>' : '') + '</div>' +
        (e.detail ? '<div class="tx dim">' + esc(String(e.detail).slice(0, 140)) + '</div>' : '') +
        '<div class="mt"><span data-ago="' + e.ts + '">' + ago(e.ts) + '</span></div></div>';
    });
    h += '</div>';
  }
  box.innerHTML = h + '</div>';
}
/* ============================== agents ============================== */
function renderAgents(){
  var box = $('#view-agents');
  var agents = fleetAgents();
  var h = '';
  if (!agents.length) h = '<div class="empty">No agents yet.</div>';
  agents.forEach(function(a){
    h += '<div class="card"><div class="agent-row" style="border:none;padding:0">' +
      '<span class="avatar" style="background:' + avatarColor(a.display_name) + '">' +
        esc(a.display_name.charAt(0).toUpperCase()) + '</span>' +
      '<span class="dot ' + a.state + '"></span>' +
      '<div><div class="nm">' + esc(a.display_name) + '</div>' +
      '<div class="sub">' + esc([a.handle, a.agent_id ? a.agent_id.slice(0, 10) + '\\u2026' : ''].filter(Boolean).join(' \\u00b7 ')) + '</div></div>' +
      '<div class="right">' + esc(a.state) + '<br><span data-ago="' + (a.last_seen || '') + '">' + ago(a.last_seen) + '</span></div>' +
      '</div>';
    if (a.note) h += '<div class="dim" style="margin-top:8px">' + esc(a.note) + '</div>';
    if (a.stats){
      var st = a.stats;
      h += '<div class="statline"><span>tasks done <b>' + st.tasks_completed + '</b></span>' +
        '<span>failed <b>' + st.tasks_failed + '</b></span>' +
        (st.avg_ack_latency_s != null ? '<span>avg ack <b>' + Math.round(st.avg_ack_latency_s) + 's</b></span>' : '') +
        (st.avg_completion_time_s != null ? '<span>avg done <b>' + Math.round(st.avg_completion_time_s) + 's</b></span>' : '') +
        '</div>';
    }
    h += '</div>';
  });
  box.innerHTML = h;
}
/* ============================== boot ============================== */
function boot(){
  if (!getToken()){
    $('#authwrap').style.display = 'flex';
    $('#app').style.display = 'none';
    $('#tokeninput').focus();
    return;
  }
  $('#authwrap').style.display = 'none';
  $('#app').style.display = 'flex';
  setLive('connecting');
  startPollers();
}
document.querySelectorAll('#sideNav button').forEach(function(b){
  b.addEventListener('click', function(){ switchView(b.getAttribute('data-view')); });
});
$('#logoutBtn').addEventListener('click', doLogout);
$('#unlockBtn').addEventListener('click', saveToken);
$('#tokeninput').addEventListener('keydown', function(e){ if (e.key === 'Enter') saveToken(); });
$('#menuBtn').addEventListener('click', function(){
  $('#sidebar').classList.toggle('open');
  $('#scrim').classList.toggle('on');
});
$('#scrim').addEventListener('click', function(){
  $('#sidebar').classList.remove('open');
  $('#scrim').classList.remove('on');
});
$('#newPill').addEventListener('click', function(){
  var box = $('#chatList');
  box.scrollTop = box.scrollHeight;
  $('#newPill').style.display = 'none';
  S.unread = 0; updateBadge();
});
boot();
</script>
</body>
</html>
"""
