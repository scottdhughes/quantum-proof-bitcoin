"use strict";
const token = document.querySelector('meta[name="console-token"]').content;
const el = id => document.getElementById(id);
let setupRequired = false;
let busy = false;
function show(value) { el("result").textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2); }
function render(status) {
  const wallet = status.wallet;
  setupRequired = status.setup_required;
  el("phase").textContent = `${status.phase} · wallet ${wallet.locked ? "locked" : "unlocked"} · ${(status.nodes[0] || {}).peers || 0} peers`;
  el("balance").textContent = `${wallet.spendable_sats} spendable test sats · ${wallet.pending_sats} pending · ${wallet.immature_sats || 0} immature`;
  el("identity").textContent = wallet.wallet_id ? `Wallet ${wallet.wallet_id} · receive floor ${wallet.next_receive} · change floor ${wallet.next_change}` : "No wallet set up yet.";
  el("access-button").textContent = setupRequired ? "Set up new wallet" : "Unlock wallet";
  const selected = el("backups").value;
  el("backups").replaceChildren(...status.backups.map(item => {
    const option = document.createElement("option"); option.value = item.id; option.textContent = `${item.created_at} · ${item.id.slice(0, 8)}`; return option;
  }));
  if ([...el("backups").options].some(option => option.value === selected)) el("backups").value = selected;
}
async function status() {
  if (busy) return;
  try { const body = await (await fetch("/api/status", {cache: "no-store"})).json(); if (!body.ok) throw Error(body.error); render(body.data); }
  catch (error) { el("phase").textContent = error.message; }
}
async function action(name, params = {}) {
  if (busy) return;
  busy = true;
  document.querySelectorAll("button").forEach(button => button.disabled = true);
  try {
    const response = await fetch("/api/action", {method: "POST", headers: {"Content-Type": "application/json", "X-Console-Token": token},
      body: JSON.stringify({action: name, params, request_id: crypto.randomUUID()})});
    const body = await response.json(); if (!body.ok) throw Error(body.error);
    render(body.data.status); show(body.data.result);
    if (name === "receive") el("receive-address").textContent = body.data.result.address;
  } catch (error) { show(error.message); }
  finally { busy = false; document.querySelectorAll("button").forEach(button => button.disabled = false); await status(); }
}
document.querySelectorAll("[data-action]").forEach(button => button.addEventListener("click", () => action(button.dataset.action)));
el("access").addEventListener("submit", event => {event.preventDefault(); const password = el("password").value; el("password").value = ""; action(setupRequired ? "setup" : "unlock", {password});});
el("send").addEventListener("submit", event => {event.preventDefault(); action("send", {address: el("destination").value.trim(), amount_sats: Number(el("amount").value), fee_sats: Number(el("fee").value)});});
el("recover").addEventListener("submit", event => {event.preventDefault(); const password = el("recovery-password").value; el("recovery-password").value = ""; action("recover", {backup_id: el("backups").value, password});});
el("peer").addEventListener("submit", event => {event.preventDefault(); action("peer", {endpoint: el("endpoint").value.trim()});});
status(); setInterval(status, 5000);
