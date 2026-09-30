"""acp_office UI: single-page dashboard (inline HTML/CSS/JS, no CDN).

The page embeds NO data. The API token comes from the ?token= query
param (bookmarked URL) or a one-time prompt, stored in sessionStorage.
Data is polled every 5 seconds.
"""


def render_page():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phoenix Fleet &mdash; Office</title>
<style>
:root { --bg:#0f1419; --panel:#182028; --line:#2a3540; --text:#d7e0e8;
        --dim:#8a99a8; --acc:#f5a623; --green:#3fb950; --red:#f85149;
        --amber:#d29922; }
* { box-sizing:border-box; }
body { margin:0; font-family:system-ui,-apple-system,sans-serif;
       background:var(--bg); color:var(--text); }
header { padding:12px 18px; border-bottom:1px solid var(--line);
         display:flex; align-items:center; gap:14px; position:sticky;
         top:0; background:var(--bg); z-index:10; }
header h1 { font-size:18px; margin:0; color:var(--acc); }
header .sub { color:var(--dim); font-size:12px; }
header .spacer { flex:1; }
#clock { color:var(--dim); font-size:12px; }
nav { display:flex; gap:6px; padding:10px 18px; border-bottom:1px solid
      var(--line); position:sticky; top:53px; background:var(--bg);
      z-index:10; }
nav button { background:var(--panel); color:var(--text);
             border:1px solid var(--line); border-radius:6px;
             padding:8px 16px; cursor:pointer; font-size:14px; }
nav button.active { border-color:var(--acc); color:var(--acc); }
main { padding:16px 18px; max-width:1100px; margin:0 auto; }
.tab { display:none; }
.tab.active { display:block; }
.card { background:var(--panel); border:1px solid var(--line);
        border-radius:8px; padding:12px 14px; margin-bottom:10px; }
.dim { color:var(--dim); font-size:12px; }
.msg { border-bottom:1px solid var(--line); padding:8px 2px; }
.msg .who { color:var(--acc); font-weight:600; font-size:13px; }
.msg .when { color:var(--dim); font-size:11px; margin-left:8px; }
.msg .body { margin-top:4px; white-space:pre-wrap; word-wrap:break-word; }
.pill { display:inline-block; font-size:11px; padding:2px 8px;
        border-radius:10px; border:1px solid var(--line); margin-right:6px; }
.state-open { color:#58a6ff; } .state-assigned { color:#a371f7; }
.state-acked { color:#79c0ff; } .state-in_progress { color:var(--amber); }
.state-done { color:var(--green); } .state-failed { color:var(--red); }
.state-blocked { color:var(--red); }
.dot { display:inline-block; width:10px; height:10px; border-radius:50%;
       margin-right:8px; }
.dot.alive { background:var(--green); } .dot.idle { background:var(--amber); }
.dot.stale { background:var(--red); }
table { width:100%; border-collapse:collapse; font-size:13px; }
th, td { text-align:left; padding:6px 8px;
         border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--dim); font-weight:600; font-size:12px; }
#error { display:none; background:#3d1d1d; border:1px solid var(--red);
         padding:10px 14px; margin:0 18px; border-radius:6px; font-size:13px; }
#authbox { max-width:420px; margin:60px auto; text-align:center; }
#authbox input { width:100%; padding:10px; border-radius:6px;
                 border:1px solid var(--line); background:var(--panel);
                 color:var(--text); margin:10px 0; }
#authbox button { padding:10px 24px; border-radius:6px; border:none;
                  background:var(--acc); color:#111; font-weight:700;
                  cursor:pointer; }
</style>
</head>
<body>
<div id="authbox" style="display:none">
  <h2>Phoenix Fleet &mdash; Office</h2>
  <p class="dim">Enter the office API token to continue.</p>
  <input id="tokeninput" type="password" placeholder="API token"
         autocomplete="off">
  <button onclick="saveToken()">Open dashboard</button>
</div>
<div id="app" style="display:none">
<header>
  <h1>&#128293; Phoenix Fleet &mdash; Office</h1>
  <span class="sub" id="srcnote"></span>
  <span class="spacer"></span>
  <span id="clock"></span>
</header>
<div id="error"></div>
<nav>
  <button data-tab="chat" class="active" onclick="showTab('chat')">Group chat</button>
  <button data-tab="tasks" onclick="showTab('tasks')">Task board</button>
  <button data-tab="activity" onclick="showTab('activity')">Activity</button>
  <button data-tab="presence" onclick="showTab('presence')">Presence</button>
</nav>
<main>
  <div class="tab active" id="tab-chat"><div id="chat"></div></div>
  <div class="tab" id="tab-tasks"><div id="tasks"></div></div>
  <div class="tab" id="tab-activity"><div id="activity"></div></div>
  <div class="tab" id="tab-presence"><div id="tabpresence"></div></div>
</main>
</div>
<script>
var TOKEN = null;
function getToken() {
  if (TOKEN) return TOKEN;
  var m = /[?&]token=([^&]+)/.exec(location.search);
  if (m) { TOKEN = decodeURIComponent(m[1]); sessionStorage.setItem('office_token', TOKEN); return TOKEN; }
  TOKEN = sessionStorage.getItem('office_token');
  return TOKEN;
}
function saveToken() {
  var v = document.getElementById('tokeninput').value.trim();
  if (!v) return;
  sessionStorage.setItem('office_token', v);
  boot();
}
function showTab(name) {
  var tabs = document.querySelectorAll('.tab');
  for (var i=0;i<tabs.length;i++) tabs[i].classList.remove('active');
  document.getElementById('tab-'+name).classList.add('active');
  var btns = document.querySelectorAll('nav button');
  for (var j=0;j<btns.length;j++)
    btns[j].classList.toggle('active', btns[j].dataset.tab===name);
  refresh();
}
function api(path) {
  return fetch(path, {headers:{'X-Office-Token': getToken()}}).then(function(r){
    if (r.status===401) throw new Error('unauthorized');
    if (!r.ok) throw new Error('http '+r.status);
    return r.json();
  });
}
function esc(s){ return String(s==null?'':s); }
function el(tag, cls, text){ var e=document.createElement(tag);
  if(cls)e.className=cls; if(text!=null)e.textContent=text; return e; }
function fmtTime(ms){ if(!ms) return 'never';
  var d=new Date(ms*1000); return d.toLocaleString(); }
function ago(ts){ if(!ts) return 'never'; var s=Math.floor(Date.now()/1000-ts);
  if(s<60) return s+'s ago'; if(s<3600) return Math.floor(s/60)+'m ago';
  if(s<86400) return Math.floor(s/3600)+'h ago';
  return Math.floor(s/86400)+'d ago'; }
function showError(msg){ var e=document.getElementById('error');
  e.style.display='block'; e.textContent=msg; }
function clearError(){ document.getElementById('error').style.display='none'; }

function renderChat(data){
  var box=document.getElementById('chat'); box.innerHTML='';
  if(!data.messages.length){ box.appendChild(el('p','dim','No messages yet.')); return; }
  data.messages.forEach(function(m){
    var d=el('div','msg');
    var head=el('div'); head.appendChild(el('span','who',m.sender_name));
    head.appendChild(el('span','when',fmtTime(m.created_at)));
    d.appendChild(head);
    d.appendChild(el('div','body',m.text));
    box.appendChild(d);
  });
}
function renderTasks(data){
  var box=document.getElementById('tasks'); box.innerHTML='';
  var keys=Object.keys(data.by_state).sort();
  var bar=el('div','card');
  bar.appendChild(el('span','dim',
    keys.length? keys.map(function(k){return k+': '+data.by_state[k];}).join('  ·  ')
                 : 'No tasks yet.'));
  box.appendChild(bar);
  data.tasks.forEach(function(t){
    var d=el('div','card');
    var h=el('div');
    var pill=el('span','pill state-'+t.state, t.state);
    h.appendChild(pill);
    h.appendChild(el('strong',null,t.title));
    if(t.blocked){ var b=el('span','pill state-blocked','BLOCKED');
      h.insertBefore(b,h.firstChild); }
    d.appendChild(h);
    var meta=el('div','dim',
      'id '+t.id+' · assignee '+(t.assignee||'—')+' · updated '+fmtTime(Date.parse(t.updated_at)/1000||0));
    d.appendChild(meta);
    if(t.open_blockers && t.open_blockers.length)
      d.appendChild(el('div','dim','blocked by: '+t.open_blockers.join(', ')));
    box.appendChild(d);
  });
}
function renderActivity(data){
  var box=document.getElementById('activity'); box.innerHTML='';
  data.agents.forEach(function(a){
    var d=el('div','card');
    var h=el('div');
    h.appendChild(el('strong',null,a.agent));
    h.appendChild(el('span','dim',
      '  · done '+a.tasks_completed+' · failed '+a.tasks_failed+
      (a.avg_ack_latency_s!=null?' · avg ack '+Math.round(a.avg_ack_latency_s)+'s':'')+
      (a.avg_completion_time_s!=null?' · avg done '+Math.round(a.avg_completion_time_s)+'s':'')));
    d.appendChild(h);
    var counts=Object.keys(a.counts).map(function(k){return k+': '+a.counts[k];}).join('  ·  ');
    if(counts) d.appendChild(el('div','dim',counts));
    box.appendChild(d);
  });
  var h2=el('h3',null,'Recent events'); box.appendChild(h2);
  var t=el('table'); var tb=el('tbody');
  data.events.slice(0,60).forEach(function(e){
    var tr=el('tr');
    tr.appendChild(el('td',null,ago(e.ts)));
    tr.appendChild(el('td',null,e.agent));
    tr.appendChild(el('td',null,e.event));
    tr.appendChild(el('td',null,e.task_id));
    tr.appendChild(el('td','dim',esc(e.detail||'').slice(0,80)));
    tb.appendChild(tr);
  });
  t.appendChild(tb); box.appendChild(t);
}
function renderPresence(data){
  var box=document.getElementById('tabpresence'); box.innerHTML='';
  data.agents.forEach(function(a){
    var d=el('div','card');
    var h=el('div');
    var dot=el('span','dot '+a.state); h.appendChild(dot);
    h.appendChild(el('strong',null,a.display_name||a.agent_id));
    h.appendChild(el('span','dim','  · '+a.state+' · last seen '+(a.last_seen?ago(a.last_seen):'never')));
    d.appendChild(h);
    box.appendChild(d);
  });
  if(!data.agents.length) box.appendChild(el('p','dim','No agents yet.'));
}
var since=0;
function refresh(){
  if(!getToken()) return;
  clearError();
  api('/api/status').then(function(s){
    var notes=Object.keys(s.sources).map(function(k){return k+': '+s.sources[k];}).join('  ·  ');
    document.getElementById('srcnote').textContent=notes;
    document.getElementById('clock').textContent=new Date(s.server_time*1000).toLocaleString();
  }).catch(function(e){ showError('status: '+e.message); });
  api('/api/chat?limit=100&since='+since).then(function(d){
    if(d.messages && d.messages.length) since=d.messages[d.messages.length-1].created_at;
    renderChat(d);
  }).catch(function(e){ showError('chat: '+e.message); });
  api('/api/tasks').then(renderTasks).catch(function(e){ showError('tasks: '+e.message); });
  api('/api/ledger?limit=100').then(renderActivity).catch(function(e){ showError('activity: '+e.message); });
  api('/api/presence').then(renderPresence).catch(function(e){ showError('presence: '+e.message); });
}
function boot(){
  if(!getToken()){
    document.getElementById('authbox').style.display='block';
    return;
  }
  document.getElementById('authbox').style.display='none';
  document.getElementById('app').style.display='block';
  refresh();
  setInterval(refresh, 5000);
}
document.getElementById('tokeninput').addEventListener('keydown', function(e){
  if(e.key==='Enter') saveToken();
});
boot();
</script>
</body>
</html>
"""
