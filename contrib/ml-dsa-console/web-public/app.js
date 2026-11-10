"use strict";
const token = document.querySelector('meta[name="console-token"]').content;
const el = id => document.getElementById(id);
let setupRequired = false;
let busy = false;
function show(value) {
  const text = typeof value === "string" ? value : "Action completed.";
  el("result").textContent = text.length > 1024 ? text.slice(0, 1023) + "…" : text;
}
function successMessage(name, result) {
  const value = result && typeof result === "object" ? result : {};
  const field = key => typeof value[key] === "string" ? value[key].slice(0, 256) : "";
  const sats = key => Number.isSafeInteger(value[key]) ? `${value[key].toLocaleString("en-US")} test sats` : "";
  switch (name) {
    case "receive": return `New receive address:\n${field("address")}`;
    case "send": return `Broadcast ${sats("amount_sats") || "test payment"}.\nTransaction: ${field("txid")}\nFee: ${sats("fee_sats") || "see transaction"}`;
    case "mine":
    case "fund": {
      const count = Array.isArray(value.blocks) ? value.blocks.length : 0;
      const height = Number.isSafeInteger(value.height) ? ` Height ${value.height.toLocaleString("en-US")}.` : "";
      return `Mined ${count} ${count === 1 ? "block" : "blocks"}.${height}`;
    }
    case "backup": return `Encrypted backup saved. Wallet locked.\nBackup: ${field("id")}`;
    case "recover": return "Wallet recovered and unlocked.";
    case "setup": return "New wallet created and unlocked.";
    case "unlock": return "Wallet unlocked.";
    case "lock": return "Wallet locked.";
    case "start": return "Public test node is running.";
    case "stop": return "Public test node stopped. Wallet locked.";
    case "peer": return `Peer connection requested: ${field("peer")}`;
    case "bootstrap": return "Test-chain activation block mined. You can now set up or unlock the wallet.";
    default: return "Action completed.";
  }
}
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
    render(body.data.status); show(successMessage(name, body.data.result));
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
