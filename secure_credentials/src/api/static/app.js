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
const types = {login:"Login", key:"API key", note:"Secure note", recovery:"Recovery", other:"Other"};
const app = document.querySelector("#app");
const modal = document.querySelector("#modal");
const toast = document.querySelector("#toast");
let items=[], events=[], writable=false, revision=null, selected=null;
let view="all", query="", sort="default", locked=true, revealed=null;
let timeout=300, timeoutMax=300, expires=0, revealTimer, toastTimer, loadError="";
let sessionVersion=0, requests=new AbortController(), browserRequest=0;
let statusPending=false, working=false, locking=false, lastDeadlineUpdate=0;
const sync = typeof BroadcastChannel === "function" ? new BroadcastChannel("vaultroom-session") : null;

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status=status;
  }
}

async function api(path, {method="GET", body, write=false, raw=false}={}) {
  const version=sessionVersion;
  const started=performance.now();
  const signal=requests.signal;
  const headers={};
  if(body!==undefined) headers["Content-Type"]="application/json";
  if(write) headers["If-Match"]=revision;
  const response=await fetch(`/api/${path}`,{
    method, headers, signal, cache:"no-store", body:body===undefined?undefined:JSON.stringify(body)
  });
  if(version!==sessionVersion || locking && path!=="lock") {
    throw new DOMException("Session changed","AbortError");
  }
  const idle=response.headers.get("X-Vault-Idle");
  if(idle!==null && started>=lastDeadlineUpdate) {
    lastDeadlineUpdate=started;
    expires=Date.now()+Number(idle)*1000;
  }
  if(!response.ok) {
    if(response.status===401 && !locked) clearSession();
    if(response.status===429) {
      throw new ApiError(`Too many attempts. Try again in ${response.headers.get("Retry-After") || "a few"} seconds.`,429);
    }
    const payload=await response.json().catch(()=>null);
    throw new ApiError(payload?.detail || `Request failed (${response.status}).`,response.status);
  }
  const result=raw?await response.blob():await response.json();
  if(version!==sessionVersion || locking && path!=="lock") {
    throw new DOMException("Session changed","AbortError");
  }
  return result;
}
function errorText(error) {
  return error instanceof ApiError?error.message:"Could not reach the vault. Try again.";
}
function visibleType(item) {
  return Object.hasOwn(types,item.type)?types[item.type]:item.type;
}
function itemIcon(item) {
  return ["login","key","note","recovery"].includes(item.type)?item.type:"grid";
}

function notify(message) {
  toast.textContent=message;
  toast.className="toast-show";
  clearTimeout(toastTimer);
  toastTimer=setTimeout(()=>{toast.className=""; toast.textContent="";},2800);
}
function hideSecret() {
  revealed=null;
  clearTimeout(revealTimer);
  updateDetail();
}
function visibleItems() {
  const search=query.trim().toLowerCase();
  const visible=items.filter(item=>
    (view==="all" || view==="favorites" && item.favorite || view===itemIcon(item) || view==="other" && itemIcon(item)==="grid")
    && [item.name,item.account,item.tag,visibleType(item)].some(value=>value.toLowerCase().includes(search))
  );
  if(sort==="name") visible.sort((a,b)=>a.name.localeCompare(b.name));
  if(sort==="type") visible.sort((a,b)=>visibleType(a).localeCompare(visibleType(b)) || a.name.localeCompare(b.name));
  return visible;
}
const tile = name => `<span class="tile ${name}">${icon(name)}</span>`;
const mainNav=[["all","grid","All items"],["favorites","star","Favorites"],["login","login","Logins"],["key","key","API keys"],["note","note","Secure notes"],["recovery","recovery","Recovery"],["other","note","Other"]];
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
    app.innerHTML=`<main class="locked"><section class="panel"><span class="mark">${icon("vault")}</span><h1>Vault locked</h1><form id="unlock" class="subpage"><label>Master password<input name="password" type="password" autocomplete="current-password" required maxlength="1024"></label><p class="form-error" role="alert"></p><button class="primary">${icon("lock")} Unlock vault</button></form></section></main>`;
    bindForm(document.querySelector("#unlock"),async (data, form)=>{
      form.reset();
      await api("unlock",{method:"POST",body:{master_password:data.password}});
      await checkStatus();
    });
    app.querySelector("input").focus();
    return;
  }
  const currentNav=[...mainNav,...toolNav].find(([id])=>id===view);
  const isList=mainNav.some(([id])=>id===view);
  app.innerHTML=`<div class="shell"><aside class="side"><div class="brand"><span class="mark">${icon("vault")}</span> Vaultroom</div>
    <nav aria-label="Vault"><div class="nav-label">Vault</div>${nav(mainNav)}</nav>
    <nav aria-label="Tools"><div class="nav-label">Tools</div>${nav(toolNav)}<button data-action="generator">${icon("key")} Password generator</button></nav>
    <div class="side-bottom"><small>KeePass vault</small></div></aside>
    <main><header class="top"><span class="muted">Personal vault</span><div class="actions"><div class="status" aria-label="Vault unlocked"><span class="dot"></span><span>Unlocked</span><span id="countdown" aria-label="Time until auto-lock"></span></div><button data-action="lock">${icon("lock")} Lock vault</button></div></header>
    <div class="wrap"><section class="hero"><div><h1>${view==="all"?"Your vault":currentNav[2]}</h1><p>${({all:"Find, organize, and manage your credentials in one place.",favorites:"Quick access to the entries you use most.",health:"Prioritize credentials that need attention.",activity:"Review recent vault actions.",settings:"Manage your vault session and data tools."})[view] || "Browse this credential type."}</p></div>${writable?`<button class="primary" data-action="add">${icon("plus")} New item</button>`:""}</section>
    ${loadError?`<div class="alert bar"><span>${esc(loadError)}</span><button data-action="refresh">Refresh</button></div>`:""}
    <div class="stats">${stat("grid",items.length,"Vault items","all")}${stat("star",items.filter(x=>x.favorite).length,"Favorites","favorites")}${stat("vault",items.filter(x=>x.issue).length,"Need attention","health")}</div>
    ${isList?`<div class="workspace"><section class="panel pad"><div class="bar"><h2>${currentNav[2]}</h2><small id="count"></small></div><div class="controls"><label class="search">${icon("search")}<input id="search" aria-label="Search vault" placeholder="Search vault…" value="${esc(query)}"><kbd>/</kbd></label><select id="sort" aria-label="Sort vault items"><option value="default">Vault order</option><option value="name">Name A–Z</option><option value="type">Type</option></select></div><ul class="list" id="list"></ul></section><section class="panel" id="detail" aria-label="Credential details"></section></div>`:subpage()}
    </div></main></div>`;
  if(isList) {
    document.querySelector("#sort").value=sort;
    updateList();
  }
  updateClock();
}
function row(item) {
  const active=selected===item.id;
  return `<li><button class="row ${active?"selected":""}" data-item="${esc(item.id)}" ${active?'aria-current="true"':""}>${tile(itemIcon(item))}<span class="text"><strong>${esc(item.name)}</strong><small>${esc(item.account || visibleType(item))}</small></span>${item.favorite?'<span class="highlight" title="Favorite" aria-label="Favorite">★</span>':""}</button></li>`;
}
function updateList() {
  const list=document.querySelector("#list");
  if(!list) return;
  const visible=visibleItems();
  if(!visible.some(item=>item.id===selected)) {
    selected=visible[0]?.id;
    revealed=null;
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
  panel.innerHTML=`<div class="detail-head bar"><div class="identity">${tile(itemIcon(item))}<div><h2>${esc(item.name)}</h2><small>${esc(visibleType(item))}</small></div></div><button class="ghost ${item.favorite?"highlight":""}" data-action="favorite" ${writable?"":"disabled"} aria-pressed="${item.favorite}" aria-label="Favorite">${icon("star")}</button></div>
  <div class="detail-body">
    ${item.account?`<div class="field"><small>Account or reference</small><b>${esc(item.account)}</b></div>`:""}
    <div class="field secret"><div><small>Secret</small><b>${revealed?esc(revealed.value):"••••••••••••"}</b></div><div class="actions"><button data-action="reveal">${icon("eye")} ${revealed?"Hide":"Reveal"}</button><button data-action="copy">${icon("copy")} Copy</button></div></div>
    ${item.tag?`<div class="chips"><span class="chip">${esc(item.tag)}</span></div>`:""}
    ${revealed?.notes?`<div class="field"><small>Notes</small><b>${esc(revealed.notes)}</b></div>`:""}
    ${item.issue?`<div class="alert">${esc(item.issue)}</div>`:""}
    ${writable?`<div class="actions"><button data-action="edit">${icon("edit")} Edit item</button><button class="ghost danger" data-action="delete">Move to trash</button></div>`:""}
  </div>`;
}
function subpage() {
  if(view==="health"){
    const issues=items.filter(item=>item.issue);
    return `<section class="panel pad subpage"><h2>Review queue</h2><small>Review reminders saved with your entries.</small>${issues.map(item=>`<article class="event">${tile(itemIcon(item))}<div><h3>${esc(item.name)}</h3><small>${esc(item.issue)} · ${item.type==="key"?"Verify permissions with the token issuer.":"Rotate at the provider, then update the vault."}</small></div><button data-item="${esc(item.id)}">Open</button></article>`).join("") || '<p class="muted">No pending reviews.</p>'}</section>`;
  }
  if(view==="activity") return `<section class="panel pad"><div class="bar"><h2>Recent server activity</h2><button data-action="refresh">Refresh</button></div>${events.map(event=>`<article class="event">${tile("activity")}<span>${esc(event.action)}</span><time datetime="${esc(event.at)}">${new Date(event.at).toLocaleString()}</time></article>`).join("") || '<p class="muted">No recent events.</p>'}</section>`;
  const choices=[10,30,60,180,300,600,timeout,timeoutMax].filter(value=>value<=timeoutMax);
  return `<section class="panel pad subpage"><h2>Session</h2><label>Auto-lock after<select id="timeout">${[...new Set(choices)].sort((a,b)=>a-b).map(seconds=>`<option value="${seconds}" ${seconds===timeout?"selected":""}>${seconds%60===0?`${seconds/60} min`:`${seconds} sec`}</option>`).join("")}</select></label><p class="muted">The server tracks idle time. Lock vault closes all active sessions. Revealed values hide after 15 seconds.</p><h2>Data tools</h2><div class="actions">${writable?'<button data-action="import">Review import</button>':""}<button data-action="backup">Download encrypted backup</button></div>${writable?"":'<small>This server is configured for read-only vault access.</small>'}</section>`;
}
function openDialog(title,body) {
  hideSecret();
  modal.innerHTML=`<header class="dialog-head bar"><h2 id="dialog-title">${title}</h2><button class="ghost" data-action="close" aria-label="Close dialog">${icon("x")}</button></header><div class="dialog-body">${body}</div>`;
  if(!modal.open) modal.showModal();
}
function bindForm(form,submit) {
  form.addEventListener("submit",async event=>{
    event.preventDefault();
    const button=form.querySelector('button[type="submit"], button:not([type])');
    if(button.disabled) return;
    button.disabled=true;
    const error=form.querySelector(".form-error");
    error.textContent="";
    const data=Object.fromEntries(new FormData(form));
    for(const field of form.querySelectorAll('input[type="password"]')) field.value="";
    try{
      await submit(data,form);
    }catch(failure){
      if(form.isConnected && failure.name!=="AbortError") {
        error.textContent=errorText(failure);
        if(failure.status===409) markConflict();
      }
    }finally{
      button.disabled=false;
    }
  });
}
const errorLine='<p class="form-error" role="alert"></p>';
const passwordField='<label>Credential password<input name="credential_password" type="password" required maxlength="1024" autocomplete="off"></label>';

function authorizeSecret(item, action) {
  openDialog(action==="copy"?"Copy secret":"Reveal secret",`<form id="authorize" class="subpage">
    <p>Enter the credential password for <strong>${esc(item.name)}</strong>.</p>
    ${passwordField}${errorLine}<button class="primary" type="submit">Verify</button></form>`);
  bindForm(modal.querySelector("form"),async (data,form)=>{
    const result=await api(`workspace/items/${item.id}/retrieve`,{method:"POST",body:data});
    void checkStatus();
    if(!modal.open || !form.isConnected || document.hidden || currentItem()!==item || Date.now()>=expires) return;
    if(action==="copy"){
      openDialog("Copy secret",'<p>Credential verified. Copy the value to your clipboard.</p><button data-action="copy-verified">Copy to clipboard</button>');
      const button=modal.querySelector('[data-action="copy-verified"]');
      const clear=setTimeout(()=>{if(button.isConnected)closeDialog();},15000);
      modal.addEventListener("close",()=>clearTimeout(clear),{once:true});
      button.addEventListener("click",async ()=>{
        if(button.disabled) return;
        button.disabled=true;
        if(await copy(result.value) && button.isConnected) closeDialog();
        button.disabled=false;
      });
      button.focus();
      return;
    }
    closeDialog();
    revealed=result;
    revealTimer=setTimeout(hideSecret,15000);
    updateDetail();
    app.querySelector('[data-action="reveal"]')?.focus();
  });
}
function edit(item) {
  const options=Object.entries(types);
  if(item && !Object.hasOwn(types,item.type)) options.push([item.type,item.type]);
  openDialog(item?"Edit item":"New item",`<form id="editor" class="subpage">
    <label>Name<input name="name" required maxlength="256" value="${esc(item?.name)}"></label>
    <div class="form-grid"><label>Type<select name="type">${options.map(([type,label])=>`<option value="${esc(type)}" ${item?.type===type?"selected":""}>${esc(label)}</option>`).join("")}</select></label><label>Tag<input name="tag" maxlength="100" value="${esc(item?.tag)}"></label></div>
    <label>Account or reference<input name="account" maxlength="256" value="${esc(item?.account)}"></label>
    <label>${item?"Replace secret (optional)":"Secret"}<input name="secret" type="password" ${item?"":"required"} autocomplete="off" maxlength="8192"></label>
    <div class="actions"><button type="button" data-action="generate-editor">${icon("key")} Generate secret</button></div>
    <label>${item?"Replace protected notes (optional)":"Protected notes"}<textarea name="notes" maxlength="2000"></textarea></label>
    ${item?'<label class="check"><input type="checkbox" name="clear_notes"> Clear existing protected notes</label>':""}
    <label>Review reminder<input name="issue" maxlength="150" value="${esc(item?.issue)}" placeholder="e.g. Rotate in June"></label>
    ${passwordField}${errorLine}
    <div class="actions"><button class="primary" type="submit">Save item</button><button type="button" data-action="close">Cancel</button></div>
    </form>`);
  const form=modal.querySelector("form");
  form.elements.name.focus();
  bindForm(form,async(data)=>{
    const {secret, notes, clear_notes, ...body}=data;
    if(secret) body.secret=secret;
    if(notes || clear_notes) body.notes=clear_notes?"":notes;
    const result=await api(item?`workspace/items/${item.id}`:"workspace/items",{
      method:item?"PATCH":"POST",body,write:true
    });
    if(form.isConnected){
      closeDialog();
      view="all"; query=""; selected=item?.id || result.ids[0];
    }
    await refreshAfterWrite("Item saved");
  });
}
function markConflict() {
  loadError="The vault may have changed. Refresh before retrying.";
  if(!modal.open) render();
}

function closeDialog() {
  if(modal.open) modal.close();
  modal.replaceChildren();
}
function deleteItem(item) {
  openDialog("Move item to trash",`<form class="subpage"><p>Move <strong>${esc(item.name)}</strong> to the KeePass recycle bin?</p>${passwordField}${errorLine}<div class="actions"><button class="danger" type="submit">Move to trash</button><button type="button" data-action="close">Cancel</button></div></form>`);
  bindForm(modal.querySelector("form"),async (data,form)=>{
    await api(`workspace/items/${item.id}`,{method:"DELETE",body:data,write:true});
    if(form.isConnected) closeDialog();
    await refreshAfterWrite("Moved to trash");
  });
}
function generate(length, symbols=true) {
  const alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"+(symbols?"!@#$%*-_+":"");
  const result=[];
  while(result.length<length) {
    for(const byte of crypto.getRandomValues(new Uint8Array(32))) {
      if(byte<256-256%alphabet.length) result.push(alphabet[byte%alphabet.length]);
      if(result.length===length) return result.join("");
    }
  }
}
async function copy(value) {
  try{
    await navigator.clipboard.writeText(value);
    if(!locked) notify("Copied to clipboard");
    return true;
  }catch{
    if(!locked) notify("Clipboard unavailable. Use HTTPS or a localhost connection.");
    return false;
  }
}
function generator() {
  openDialog("Password generator",`<label>Length<input type="range" min="12" max="64" value="24" id="length"></label>
    <label class="check"><input type="checkbox" id="symbols" checked> Include symbols</label>
    <div class="field"><small id="length-label">24 characters</small><b id="generated"></b></div>
    <div class="actions"><button data-action="regenerate">Regenerate</button><button data-action="copy-generated">${icon("copy")} Copy</button></div>`);
  regenerate();
}
function regenerate() {
  const length=Number(modal.querySelector("#length").value);
  modal.querySelector("#length-label").textContent=`${length} characters`;
  modal.querySelector("#generated").textContent=generate(length,modal.querySelector("#symbols").checked);
}
function reviewImport() {
  openDialog("Review import",`<form class="subpage"><label>Select a JSON file<input type="file" accept=".json,application/json" name="file" required></label><small>Use an array of up to 20 entries with name, type, secret, and credential_password. Types are login, key, note, recovery, or other. Optional fields are account, tag, issue, and notes. Max file size is 16 KB.</small>${errorLine}<button class="primary" type="submit">Review entries</button></form>`);
  bindForm(modal.querySelector("form"),async ({file},form)=>{
    if(file.size>16384) throw new ApiError("File exceeds 16 KB.");
    let parsed;
    try{parsed=JSON.parse(await file.text());}catch{throw new ApiError("Invalid JSON file.");}
    if(!form.isConnected || !modal.open) return;
    const valid=Array.isArray(parsed) && parsed.length>0 && parsed.length<=20 &&
      parsed.every(item=>item && typeof item.name==="string" && item.name.trim() &&
      Object.hasOwn(types,item.type) && typeof item.secret==="string" && item.secret &&
      typeof item.credential_password==="string" && item.credential_password);
    if(!valid) throw new ApiError("Each entry needs a name, valid type, secret, and credential_password.");
    const names=new Set(items.map(item=>item.name.trim().toLowerCase()));
    const ready=[];
    const rows=parsed.map(item=>{
      const key=item.name.trim().toLowerCase();
      if(names.has(key)) return [item.name,"Skipped duplicate"];
      names.add(key);
      ready.push(item);
      return [item.name,"Ready"];
    });
    openDialog("Confirm import",`<form class="subpage"><ul>${rows.map(([name,status])=>`<li>${esc(name)} · ${status}</li>`).join("")}</ul>${errorLine}<button class="primary" type="submit" ${ready.length?"":"disabled"}>Import ${ready.length} entries</button></form>`);
    bindForm(modal.querySelector("form"),async (_,confirmation)=>{
      await api("workspace/import",{method:"POST",body:{entries:ready},write:true});
      if(confirmation.isConnected) closeDialog();
      await refreshAfterWrite("Import complete");
    });
  });
}
async function downloadBackup() {
  const blob=await api("workspace/backup",{raw:true});
  const url=URL.createObjectURL(blob);
  const link=document.createElement("a");
  link.href=url;
  link.download="vault-backup.kdbx";
  link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
  notify("Encrypted backup downloaded");
}
function clearSession() {
  requests.abort();
  requests=new AbortController();
  sessionVersion++;
  working=false;
  locking=false;
  statusPending=false;
  lastDeadlineUpdate=0;
  locked=true;
  expires=0;
  closeDialog();
  hideSecret();
  items=[]; events=[]; revision=null; writable=false; selected=null; query=""; view="all"; loadError="";
  clearTimeout(toastTimer); toast.className=""; toast.textContent="";
  render();
}
async function refresh() {
  const sequence=++browserRequest;
  const data=await api("workspace");
  if(browserRequest!==sequence || locked) return;
  hideSecret();
  items=data.items;
  events=data.activity;
  writable=data.writable;
  revision=data.revision;
  timeoutMax=data.timeout_max;
  loadError="";
  render();
}
async function refreshAfterWrite(message) {
  try{
    await refresh();
    if(!locked) notify(message);
  }catch(error){
    if(!locked && error.name!=="AbortError") {
      revision=null;
      loadError=`${message}. Refresh to see the current workspace.`;
      render();
    }
  }finally{
    void checkStatus();
  }
}
async function checkStatus() {
  if(statusPending || locking) return;
  statusPending=true;
  const version=sessionVersion;
  const started=performance.now();
  try{
    const status=await api("status");
    if(started<lastDeadlineUpdate) return;
    if(status.locked){
      if(!locked) clearSession();
      return;
    }
    lastDeadlineUpdate=started;
    expires=Date.now()+status.seconds_until_lock*1000;
    timeout=status.timeout_seconds;
    if(locked){
      locked=false;
      timeoutMax=timeout;
      try{
        await refresh();
      }catch(error){
        if(locked || error.name==="AbortError") return;
        loadError=errorText(error);
        render();
      }
    }
    updateClock();
  }catch(error){
    if(version===sessionVersion && !locked) updateClock();
  }finally{
    if(version===sessionVersion) statusPending=false;
  }
}
function updateClock() {
  if(locked) return;
  const seconds=Math.max(0,Math.ceil((expires-Date.now())/1000));
  if(!seconds){clearSession();return;}
  const countdown=document.querySelector("#countdown");
  if(countdown) countdown.textContent=`${Math.floor(seconds/60)}:${String(seconds%60).padStart(2,"0")}`;
}
async function runAction(action) {
  if(working) return;
  working=true;
  const version=sessionVersion;
  try{await action();}
  catch(error){
    if(error.name!=="AbortError"){
      if(error.status===409) markConflict();
      notify(errorText(error));
    }
  }
  finally{if(version===sessionVersion) working=false;}
}
sync?.addEventListener("message",event=>{if(event.data==="locked" && !locked) clearSession();});
document.addEventListener("visibilitychange",()=>{
  if(document.hidden){hideSecret();closeDialog();}else void checkStatus();
});
document.addEventListener("keydown",event=>{
  if(event.key==="/" && !modal.open && !locked && !event.target.matches("input, textarea, select, [contenteditable]")){
    event.preventDefault();
    if(!document.querySelector("#search")){view="all"; render();}
    document.querySelector("#search").focus();
  }
});
document.addEventListener("input",event=>{
  if(event.target.id==="search"){query=event.target.value;hideSecret();updateList();}
  if(event.target.id==="length") regenerate();
});
document.addEventListener("change",event=>{
  if(event.target.id==="symbols") regenerate();
  if(event.target.id==="sort"){sort=event.target.value;updateList();}
  if(event.target.id==="timeout"){
    const control=event.target;
    void runAction(async ()=>{
      try{
        const result=await api("workspace/timeout",{method:"POST",body:{seconds:Number(control.value)}});
        timeout=result.timeout_seconds;
        expires=Date.now()+timeout*1000;
        updateClock();
        notify("Auto-lock updated for this session");
      }finally{control.value=timeout;}
    });
  }
});
modal.addEventListener("close",()=>{
  if(!modal.open) {
    modal.replaceChildren();
    if(loadError && !locked) render();
  }
});
window.addEventListener("pagehide",()=>{if(!locked) clearSession();});
window.addEventListener("pageshow",event=>{if(event.persisted) void checkStatus();});

async function lockVault() {
  if(locking) return;
  locking=true;
  hideSecret();
  closeDialog();
  try{
    await api("lock",{method:"POST"});
    sync?.postMessage("locked");
    if(!locked) clearSession();
  }catch(error){
    if(error.name!=="AbortError") notify(errorText(error));
  }finally{
    locking=false;
  }
}
document.addEventListener("click",event=>{
  const button=event.target.closest("button");
  if(!button || !button.isConnected || locked || locking) return;
  if(button.dataset.view){
    hideSecret(); view=button.dataset.view; query=""; render();
    app.querySelector(`[data-view="${view}"]`)?.focus({preventScroll:true});
    if(view==="activity") void runAction(refresh);
    return;
  }
  if(button.dataset.item){
    hideSecret(); selected=button.dataset.item;
    if(view==="health"){view="all";query="";render();}else updateList();
    app.querySelector(`[data-item="${selected}"]`)?.focus({preventScroll:true});
    if(matchMedia("(max-width: 790px)").matches) document.querySelector("#detail").scrollIntoView({block:"nearest"});
    return;
  }
  const item=currentItem();
  switch(button.dataset.action){
    case "lock": void lockVault();break;
    case "refresh": void runAction(async ()=>{await refresh();await checkStatus();});break;
    case "add": if(writable) edit();break;
    case "edit": if(writable && item) edit(item);break;
    case "close": closeDialog();break;
    case "favorite":
      if(writable && item) void runAction(async ()=>{
        await api(`workspace/items/${item.id}/favorite`,{method:"POST",body:{favorite:!item.favorite},write:true});
        await refreshAfterWrite("Favorite updated");
      });
      break;
    case "reveal":
      if(!item)break;
      if(revealed){hideSecret();app.querySelector('[data-action="reveal"]')?.focus();}
      else authorizeSecret(item,"reveal");
      break;
    case "copy": if(item)authorizeSecret(item,"copy");break;
    case "delete": if(writable && item) deleteItem(item);break;
    case "generator": generator();break;
    case "regenerate": regenerate();break;
    case "copy-generated": void copy(modal.querySelector("#generated").textContent);break;
    case "generate-editor":
      modal.querySelector("#editor").elements.secret.value=generate(24);
      notify("Generated a 24-character secret");
      break;
    case "import": if(writable) reviewImport();break;
    case "backup": void runAction(downloadBackup);break;
  }
});
render();
void checkStatus();
setInterval(checkStatus,3000);
setInterval(updateClock,500);
