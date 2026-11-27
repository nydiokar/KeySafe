"use strict";

const icons = {
  vault: 'M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z M9 12l2 2 4-4',
  grid: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  star: 'm12 3 2.8 5.7 6.2.9-4.5 4.4 1 6.2-5.5-3-5.5 3 1-6.2L3 9.6l6.2-.9Z',
  login: 'M4 4h16v16H4z M4 9h16 M8 14h8 M8 17h5',
  key: 'M15 3a6 6 0 0 0-5 9L3 19v2h4l2-2v-2h2l3-3a6 6 0 1 0 1-11Z M16 8h.01',
  note: 'M5 3h10l4 4v14H5z M9 11h6 M9 15h6',
  recovery: 'M3 12a9 9 0 1 1 2 6 M3 5v7h7 M12 8v5l3 2',
  lock: 'M5 11h14v10H5z M8 11V7a4 4 0 0 1 8 0v4 M12 15v2',
  plus: 'M12 5v14M5 12h14',
  search: 'M21 21l-5-5 M18 11a7 7 0 1 1-14 0 7 7 0 0 1 14 0Z',
  clock: 'M12 7v5l3 2 M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0Z',
  activity: 'M3 12h4l3-7 4 14 3-7h4',
  settings: 'M4 6h16 M4 12h16 M4 18h16 M8 4v4 M16 10v4 M10 16v4',
  eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7Z M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z',
  copy: 'M8 8h12v12H8z M16 4H4v12',
  edit: 'm4 16-1 5 5-1L21 7l-4-4Z M14 6l4 4',
  x: 'm6 6 12 12M18 6 6 18'
};
const icon = name => `<svg class="icon" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round"><path d="${icons[name]}"/></svg>`;
const esc = value => String(value ?? "").replace(/[&<>"']/g, char => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
})[char]);
const types = {login:"Login", key:"API key", note:"Secure note", recovery:"Recovery"};
const seed = [
  ["Cloud console","login","ops@example.test","Infrastructure","Rotate soon",true],
  ["Deployment token","key","Production automation","Infrastructure","Review scope",true],
  ["Design workspace","login","design@example.test","Work","",false],
  ["Device recovery","recovery","Laptop · disk encryption","Devices","",true],
  ["Signing service","key","Release pipeline","Infrastructure","",false],
  ["Recovery contacts","note","Emergency checklist","Personal","",false],
  ["Source control","login","dev@example.test","Work","",false],
  ["Source control recovery","recovery","Offline backup codes","Work","",false],
  ["Wi-Fi setup","note","Home network","Personal","",false]
];
const items = seed.map(([name,type,account,tag,issue,favorite],index) => ({
  id:String(index+1),name,type,account,tag,issue,favorite,
  secret:`DEMO-ONLY-${index+1}-J7q49`, notes:index===0?"Shared infrastructure account. Rotate the password after maintenance.":""
}));
const events = [{title:"Demo vault opened", time:Date.now()}];
const app = document.querySelector("#app");
const modal = document.querySelector("#modal");
const toast = document.querySelector("#toast");
let view="all", selected="1", query="", sort="default", locked=false, revealed=false;
let timeout=300, expires=Date.now()+timeout*1000, revealTimer, toastTimer;

function notify(message) {
  toast.textContent=message;
  toast.className="toast-show";
  clearTimeout(toastTimer);
  toastTimer=setTimeout(()=>{toast.className=""; toast.textContent="";},2800);
}
function log(title) {
  events.unshift({title,time:Date.now()});
}
function hideSecret() {
  revealed=false;
  clearTimeout(revealTimer);
  updateDetail();
}
function visibleItems() {
  const search=query.trim().toLowerCase();
  const visible=items.filter(item=>
    (view==="all" || view==="favorites" && item.favorite || view===item.type)
    && [item.name,item.account,item.tag,types[item.type]].some(value=>value.toLowerCase().includes(search))
  );
  if(sort==="name") visible.sort((a,b)=>a.name.localeCompare(b.name));
  if(sort==="type") visible.sort((a,b)=>types[a.type].localeCompare(types[b.type]) || a.name.localeCompare(b.name));
  return visible;
}
const tile = name => `<span class="tile ${name}">${icon(name)}</span>`;
const mainNav=[["all","grid","All items"],["favorites","star","Favorites"],["login","login","Logins"],["key","key","API keys"],["note","note","Secure notes"],["recovery","recovery","Recovery"]];
const toolNav=[["health","vault","Vault health"],["activity","activity","Activity"],["settings","settings","Settings"]];
function nav(rows) {
  return rows.map(([id,glyph,label])=>`<button data-view="${id}" ${view===id?'class="active" aria-current="page"':""}>${icon(glyph)}${label}</button>`).join("");
}
function stat(glyph,number,label,destination) {
  return `<button class="stat" data-view="${destination}">${tile(glyph)}<span><strong>${number}</strong><small>${label}</small></span></button>`;
}
function currentItem() {
  return visibleItems().find(item=>item.id===selected);
}
function render() {
  if(locked) {
    app.innerHTML=`<main class="locked"><section class="panel"><span class="mark">${icon("vault")}</span><h1>Vault locked</h1><p class="muted">Your demo session has ended. Open the sample vault to continue.</p><button class="primary" data-action="unlock">${icon("lock")} Unlock demo</button><small>Fictional data · browser memory only</small></section></main>`;
    app.querySelector("button").focus();
    return;
  }
  const currentNav=[...mainNav,...toolNav].find(([id])=>id===view);
  const isList=mainNav.some(([id])=>id===view);
  app.innerHTML=`<div class="shell"><aside class="side"><div class="brand"><span class="mark">${icon("vault")}</span> Vaultroom</div>
    <nav aria-label="Vault"><div class="nav-label">Vault</div>${nav(mainNav)}</nav>
    <nav aria-label="Tools"><div class="nav-label">Tools</div>${nav(toolNav)}<button data-action="generator">${icon("key")} Password generator</button></nav>
    <div class="side-bottom"><a href="PLAN.md" target="_blank" rel="noopener">Implementation plan</a><small>Interactive prototype · sample data</small></div></aside>
    <main><header class="top"><span class="muted">Personal vault</span><div class="actions"><div class="status"><span class="dot"></span><span>Unlocked</span><span id="countdown"></span></div><button data-action="lock">${icon("lock")} Lock vault</button></div></header>
    <div class="wrap"><section class="hero"><div><span class="eyebrow">Personal workspace</span><h1>${view==="all"?"Your vault":currentNav[2]}</h1><p>${({all:"Find, organize, and manage your credentials in one place.",favorites:"Quick access to the entries you use most.",health:"Prioritize credentials that need attention.",activity:"Review actions taken during this demo session.",settings:"Manage this demo’s vault session and data tools."})[view] || "Browse this credential type."}</p></div><button class="primary" data-action="add">${icon("plus")} New item</button></section>
    <div class="stats">${stat("grid",items.length,"Vault items","all")}${stat("star",items.filter(x=>x.favorite).length,"Favorites","favorites")}${stat("vault",items.filter(x=>x.issue).length,"Need attention","health")}</div>
    ${isList?`<div class="workspace"><section class="panel pad"><div class="bar"><h2>${currentNav[2]}</h2><small id="count"></small></div><div class="controls"><label class="search">${icon("search")}<input id="search" aria-label="Search vault" placeholder="Search names, accounts, tags…" value="${esc(query)}"><kbd>/</kbd></label><select id="sort" aria-label="Sort vault items"><option value="default">Vault order</option><option value="name">Name A–Z</option><option value="type">Type</option></select></div><ul class="list" id="list"></ul></section><section class="panel" id="detail" aria-label="Credential details"></section></div>`:subpage()}
    </div></main></div>`;
  if(isList) {
    document.querySelector("#sort").value=sort;
    updateList();
  }
  updateClock();
}
function row(item) {
  const active=selected===item.id;
  return `<li><button class="row ${active?"selected":""}" data-item="${item.id}" ${active?'aria-current="true"':""}>${tile(item.type)}<span class="text"><strong>${esc(item.name)}</strong><small>${esc(item.account || types[item.type])}</small></span>${item.favorite?'<span class="highlight" title="Favorite" aria-label="Favorite">★</span>':""}</button></li>`;
}
function updateList() {
  const list=document.querySelector("#list");
  if(!list) return;
  const visible=visibleItems();
  if(!visible.some(item=>item.id===selected)) {
    selected=visible[0]?.id;
    revealed=false;
  }
  document.querySelector("#count").textContent=`${visible.length} ${visible.length===1?"item":"items"}`;
  list.innerHTML=visible.map(row).join("") || '<li class="empty">No matching items. Try another search or add an entry.</li>';
  updateDetail();
}
function updateDetail() {
  const panel=document.querySelector("#detail");
  if(!panel) return;
  const item=currentItem();
  if(!item) {panel.innerHTML='<p class="empty">Select a credential to see its details.</p>';return;}
  panel.innerHTML=`<div class="detail-head bar"><div class="identity">${tile(item.type)}<div><h2>${esc(item.name)}</h2><small>${types[item.type]}</small></div></div><button class="ghost ${item.favorite?"highlight":""}" data-action="favorite" aria-pressed="${item.favorite}" aria-label="Favorite">${icon("star")}</button></div>
  <div class="detail-body">
    ${item.account?`<div class="field"><small>Account or reference</small><b>${esc(item.account)}</b></div>`:""}
    <div class="field secret"><div><small>Secret</small><b>${revealed?esc(item.secret):"••••••••••••"}</b></div><div class="actions"><button data-action="reveal">${icon("eye")} ${revealed?"Hide":"Reveal"}</button><button data-action="copy">${icon("copy")} Copy</button></div></div>
    ${item.tag?`<div class="chips"><span class="chip">${esc(item.tag)}</span></div>`:""}
    ${item.notes?`<div class="field"><small>Notes</small><b>${esc(item.notes)}</b></div>`:""}
    ${item.issue?`<div class="alert">${esc(item.issue)} · Sample finding</div>`:""}
    <div class="actions"><button data-action="edit">${icon("edit")} Edit item</button><button class="ghost danger" data-action="delete">Delete</button></div>
  </div>`;
}
function subpage() {
  if(view==="health"){
    const issues=items.filter(item=>item.issue);
    return `<section class="panel pad subpage"><h2>Review queue</h2><small>These sample findings illustrate manual rotation and scope reviews.</small>${issues.map(item=>`<article class="event">${tile(item.type)}<div><h3>${esc(item.name)}</h3><small>${esc(item.issue)} · ${item.type==="key"?"Verify permissions with the token issuer.":"Rotate at the provider, then update the vault."}</small></div><button data-item="${item.id}">Open</button></article>`).join("") || '<p class="muted">No pending reviews.</p>'}</section>`;
  }
  if(view==="activity") return `<section class="panel pad"><h2>Session activity</h2>${events.map(event=>`<article class="event">${tile("activity")}<span>${esc(event.title)}</span><time datetime="${new Date(event.time).toISOString()}">${new Date(event.time).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"})}</time></article>`).join("")}</section>`;
  return `<section class="panel pad subpage"><h2>Session</h2><label>Auto-lock after<select id="timeout">${[60,180,300,600].map(seconds=>`<option value="${seconds}" ${seconds===timeout?"selected":""}>${seconds/60} min</option>`).join("")}</select></label><p class="muted">Browser actions restart the demo idle timer. Revealed values hide after 15 seconds.</p><h2>Data tools</h2><div class="actions"><button data-action="import">Review import</button><button data-action="backup">Backup workflow</button></div><small>Data tools preview proposed workflows with sample content.</small></section>`;
}
function openDialog(title,body){
  modal.innerHTML=`<header class="dialog-head bar"><h2 id="dialog-title">${title}</h2><button class="ghost" data-action="close" aria-label="Close dialog">${icon("x")}</button></header><div class="dialog-body">${body}</div>`;
  if(!modal.open) modal.showModal();
}
function authorizeSecret(item, action) {
  openDialog(action==="copy"?"Copy secret":"Reveal secret",`<form id="authorize" class="subpage">
    <p>Enter the credential password for <strong>${esc(item.name)}</strong>.</p>
    <label>Credential password<input name="credential" type="password" required autocomplete="off" aria-describedby="sample-password"></label>
    <small id="sample-password">Demo credential password is <code>demo</code>.</small>
    <p id="auth-error" role="alert"></p>
    <button class="primary">${action==="copy"?"Verify and copy":"Verify and reveal"}</button>
  </form>`);
  const form=document.querySelector("#authorize");
  form.elements.credential.focus();
  form.addEventListener("submit",event=>{
    event.preventDefault();
    const password=form.elements.credential.value;
    form.reset();
    if(password!=="demo"){
      form.querySelector("#auth-error").textContent="Incorrect demo credential password.";
      form.elements.credential.focus();
      return;
    }
    modal.close();
    if(action==="copy"){void copy(item.secret,"secret");return;}
    revealed=true;
    revealTimer=setTimeout(hideSecret,15000);
    log("Secret revealed");
    updateDetail();
    app.querySelector('[data-action="reveal"]')?.focus();
  });
}
function edit(item) {
  openDialog(item?"Edit item":"New item",`<form id="editor" class="subpage">
    <label>Name<input name="name" required maxlength="120" value="${esc(item?.name)}"></label>
    <div class="form-grid"><label>Type<select name="type">${Object.entries(types).map(([type,label])=>`<option value="${type}" ${item?.type===type?"selected":""}>${label}</option>`).join("")}</select></label><label>Tag<input name="tag" maxlength="60" value="${esc(item?.tag)}"></label></div>
    <label>Account or reference<input name="account" maxlength="120" value="${esc(item?.account)}"></label>
    <label>${item?"Replace secret (optional)":"Sample secret"}<input name="secret" type="password" ${item?"":"required"} autocomplete="off" maxlength="256"></label>
    <div class="actions"><button type="button" data-action="generate-editor">${icon("key")} Generate secret</button></div>
    <label>Notes<textarea name="notes" maxlength="500">${esc(item?.notes)}</textarea></label>
    ${item?.issue?'<label class="check"><input type="checkbox" name="resolve"> Mark sample review resolved</label>':""}
    <small>Use fictional information. Changes last until reload.</small>
    <div class="actions"><button class="primary">Save item</button><button type="button" data-action="close">Cancel</button></div>
    </form>`);
  const form=document.querySelector("#editor");
  form.elements.name.focus();
  form.addEventListener("submit",event=>{
    event.preventDefault();
    const data=Object.fromEntries(new FormData(form));
    data.name=data.name.trim();
    if(!data.name) {notify("Enter a name.");return;}
    if(items.some(x=>x!==item && x.name.toLowerCase()===data.name.toLowerCase())) {notify("An item with that name already exists.");return;}
    const saved=item || {id:crypto.randomUUID?.() || String(Date.now()),favorite:false,issue:""};
    Object.assign(saved,{name:data.name,type:data.type,tag:data.tag.trim(),account:data.account.trim(),notes:data.notes.trim(),secret:data.secret || item?.secret});
    if(data.resolve) saved.issue="";
    if(!item) items.unshift(saved);
    log(item?"Item updated":"Item created");
    view="all"; query=""; selected=saved.id;
    closeAndRender("Item saved");
  });
}
function closeAndRender(message){
  modal.close();
  hideSecret();
  render();
  if(message) notify(message);
}
function generate(length) {
  const alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%*-_+";
  const result=[];
  while(result.length<length) {
    for(const byte of crypto.getRandomValues(new Uint8Array(32))) {
      if(byte<256-256%alphabet.length) result.push(alphabet[byte%alphabet.length]);
      if(result.length===length) return result.join("");
    }
  }
}
async function copy(value,kind) {
  try{
    await navigator.clipboard.writeText(value);
    log(kind==="secret"?"Secret copied":"Generated password copied");
    if(!locked) notify("Copied to clipboard");
  }catch{
    if(!locked) notify("Clipboard unavailable in this browser.");
  }
}
function generator() {
  openDialog("Password generator",`<label>Length<input type="range" min="12" max="64" value="24" id="length"></label>
    <div class="field"><small id="length-label">24 characters</small><b id="generated"></b></div>
    <div class="actions"><button data-action="regenerate">Regenerate</button><button data-action="copy-generated">${icon("copy")} Copy</button></div>`);
  regenerate();
}
function regenerate() {
  const length=Number(document.querySelector("#length").value);
  document.querySelector("#length-label").textContent=`${length} characters`;
  document.querySelector("#generated").textContent=generate(length);
}
function lock() {
  locked=true; hiddenCleanup();
  log("Demo vault locked");
  render();
}
function hiddenCleanup(){
  hideSecret();
  if(modal.open) modal.close();
  modal.replaceChildren();
  query="";
  toast.className="";
  toast.textContent="";
}
function updateClock() {
  if(locked) return;
  const seconds=Math.max(0,Math.ceil((expires-Date.now())/1000));
  if(!seconds){lock();return;}
  const countdown=document.querySelector("#countdown");
  if(countdown) countdown.textContent=`${Math.floor(seconds/60)}:${String(seconds%60).padStart(2,"0")}`;
}
function touch() {
  if(!locked && Date.now()>=expires) lock();
  if(!locked) expires=Date.now()+timeout*1000;
}
setInterval(updateClock,1000);
document.addEventListener("pointerdown",touch);
document.addEventListener("keydown",event=>{
  touch();
  if(event.key==="/" && !modal.open && !event.target.matches("input, textarea, select, [contenteditable]") && !locked) {
    event.preventDefault();
    if(!document.querySelector("#search")) {view="all";render();}
    document.querySelector("#search").focus();
  }
});
document.addEventListener("visibilitychange",()=>{if(document.hidden)hideSecret();else updateClock();});
document.addEventListener("input",event=>{
  if(event.target.id==="search"){query=event.target.value;hideSecret();updateList();}
  if(event.target.id==="length")regenerate();
});
document.addEventListener("change",event=>{
  if(event.target.id==="sort"){sort=event.target.value;updateList();}
  if(event.target.id==="timeout"){timeout=Number(event.target.value);touch();updateClock();notify("Auto-lock updated");}
});
modal.addEventListener("close",()=>{if(!modal.open)modal.replaceChildren();});
document.addEventListener("click",event=>{
  const button=event.target.closest("button");
  if(!button || !button.isConnected) return;
  if(button.dataset.view) {
    hideSecret();view=button.dataset.view;query="";render();
    app.querySelector(`[data-view="${view}"]`)?.focus({preventScroll:true});
    return;
  }
  if(button.dataset.item) {
    hideSecret();selected=button.dataset.item;
    if(view==="health"){view="all";query="";render();}else updateList();
    const row=app.querySelector(`[data-item="${selected}"]`);
    row?.focus({preventScroll:true});
    if(matchMedia("(max-width: 790px)").matches) document.querySelector("#detail").scrollIntoView({block:"nearest"});
    return;
  }
  const item=currentItem();
  switch(button.dataset.action){
    case "lock": lock();break;
    case "unlock": locked=false;expires=Date.now()+timeout*1000;log("Demo vault opened");render();break;
    case "add": edit();break;
    case "edit": if(item)edit(item);break;
    case "close": modal.close();break;
    case "favorite":
      if(item){item.favorite=!item.favorite;log(item.favorite?"Favorite added":"Favorite removed");render();app.querySelector('[data-action="favorite"]')?.focus();}
      break;
    case "reveal":
      if(!item)break;
      if(revealed){
        hideSecret();
        app.querySelector('[data-action="reveal"]')?.focus();
      }else authorizeSecret(item,"reveal");
      break;
    case "copy": if(item)authorizeSecret(item,"copy");break;
    case "delete":
      if(item) openDialog("Delete item",`<p>Delete <strong>${esc(item.name)}</strong> from this demo session?</p><div class="actions"><button data-action="confirm-delete" class="danger">Delete item</button><button data-action="close">Cancel</button></div>`);
      break;
    case "confirm-delete":
      if(item){items.splice(items.indexOf(item),1);log("Item deleted");closeAndRender("Item deleted");}
      break;
    case "generator": generator();break;
    case "regenerate": regenerate();break;
    case "copy-generated": void copy(document.querySelector("#generated").textContent,"generated");break;
    case "generate-editor":
      document.querySelector("#editor").elements.secret.value=generate(24);
      notify("Generated a 24-character secret");
      break;
    case "import":
      openDialog("Review sample import",`<p class="muted">Preview from a fictional source. Production would validate file contents, map fields, and report conflicts here.</p><div class="field"><small>Ready to import</small><b>Status dashboard · Login</b></div><div class="field"><small>Skipped duplicate</small><b>Cloud console</b></div><div class="actions"><button class="primary" data-action="apply-import">Import sample entry</button></div>`);
      break;
    case "apply-import":
      if(items.some(x=>x.name.toLowerCase()==="status dashboard")){notify("Status dashboard already exists.");break;}
      items.unshift({id:"imported",name:"Status dashboard",type:"login",account:"status@example.test",tag:"Imported",secret:"DEMO-ONLY-IMPORT",notes:"",issue:"",favorite:false});
      log("Sample entry imported");closeAndRender("1 item imported");break;
    case "backup":
      openDialog("Encrypted backup",`<p>In production, the server would prepare a verified encrypted KeePass snapshot for download.</p><div class="field"><small>Sample backup</small><b>personal-vault.kdbx</b></div><button data-action="preview-backup">Preview completion</button>`);
      break;
    case "preview-backup":
      modal.close();notify("Backup workflow preview complete");break;
  }
});
render();
