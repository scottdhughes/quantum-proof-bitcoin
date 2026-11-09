"use strict";

(() => {
  const MAX_MONEY = 2100000000000000n;
  const SATS_PER_COIN = 100000000n;
  const POLL_INTERVAL = 5000;
  const $ = (id) => document.getElementById(id);
  const state = { status: null, connected: false, busy: false, polling: false, epoch: 0, receive: null, recoveryId: null, pendingSend: null };
  const csrfToken = document.querySelector('meta[name="console-token"]').content;
  const sendFields = [$("send-address"), $("send-amount"), $("send-fee")];
  const busyMessages = { start: "Starting your local network…", stop: "Stopping your local network…", receive: "Creating a receive address…", fund: "Adding test coins…", send: "Sending test coins…", mine: "Mining a block…", backup: "Creating a backup…", recover: "Recovering the selected backup…", lock: "Locking your wallet…", unlock: "Unlocking your wallet…" };

  function moneyValue(value) {
    if (typeof value === "number" && (!Number.isSafeInteger(value) || value < 0)) return null;
    if (typeof value !== "number" && (typeof value !== "string" || !/^\d+$/.test(value))) return null;
    try { const amount = BigInt(value); return amount >= 0n && amount <= MAX_MONEY ? amount : null; } catch (_) { return null; }
  }

  function formatCoins(value) {
    const sats = moneyValue(value);
    if (sats === null) return "—";
    return `${sats / SATS_PER_COIN}.${(sats % SATS_PER_COIN).toString().padStart(8, "0")}`;
  }

  function amountToSats(raw) {
    const value = raw.trim();
    if (value.length > 32 || !/^(?:\d+(?:\.\d{0,8})?|\.\d{1,8})$/.test(value)) throw new Error("Enter an amount with up to 8 decimal places.");
    const [whole, fraction = ""] = value.split(".");
    const sats = BigInt(whole || "0") * SATS_PER_COIN + BigInt(fraction.padEnd(8, "0"));
    if (sats <= 0n) throw new Error("Enter an amount greater than zero.");
    if (sats > MAX_MONEY) throw new Error("The amount exceeds the test coin limit.");
    return sats;
  }

  function feeToSats(raw) {
    const value = raw.trim();
    if (value.length > 16 || !/^\d+$/.test(value)) throw new Error("Enter the fee as a whole number of sats.");
    const sats = BigInt(value);
    if (sats > MAX_MONEY) throw new Error("The fee exceeds the test coin limit.");
    return sats;
  }

  function setFeedback(message, tone = "info", source = "action") {
    $("feedback").dataset.tone = tone;
    $("feedback").dataset.source = source;
    $("feedback").textContent = message;
    $("feedback").hidden = !message;
  }

  function renderStartupFeedback(status) {
    const detail = typeof status.startup_error === "string" ? status.startup_error.replace(/\s+/g, " ").trim() : "";
    if (detail) {
      const boundedDetail = detail.length > 300 ? `${detail.slice(0, 300)}…` : detail;
      setFeedback(`Wallet could not resume. Open Backup & recovery to restore a saved wallet. Details: ${boundedDetail}`, "error", "startup");
    } else if ($("feedback").dataset.source === "startup" && status.phase === "running" && status.ready === true) {
      setFeedback("");
    }
  }

  function formError(message, field) {
    $("send-error").textContent = message;
    $("send-error").hidden = !message;
    sendFields.forEach((input) => input.removeAttribute("aria-invalid"));
    if (field) { field.setAttribute("aria-invalid", "true"); field.focus(); }
  }

  function requestId() {
    if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    return Array.from(bytes, (byte, index) => `${[4, 6, 8, 10].includes(index) ? "-" : ""}${byte.toString(16).padStart(2, "0")}`).join("");
  }

  function uncertainError(message) {
    const error = new Error(message);
    error.uncertain = true;
    return error;
  }

  async function api(path, options) {
    let response;
    try { response = await fetch(path, { cache: "no-store", credentials: "same-origin", ...options }); }
    catch (_) { throw uncertainError("The console could not be reached. Check its terminal, then refresh status before trying again."); }
    let body;
    try { body = await response.json(); }
    catch (_) { throw uncertainError("The console returned an unreadable response. Refresh status before trying again."); }
    if (!response.ok || !body || body.ok !== true) throw new Error(typeof body?.error === "string" ? body.error : "The request failed. Refresh status and try again.");
    return body.data;
  }

  function canUseWallet() {
    return state.connected && state.status?.phase === "running" && state.status?.ready === true && !!state.status?.wallet;
  }

  function selectedBackup() {
    return (state.status?.backups || []).find((backup) => String(backup.id) === $("backup-select").value);
  }

  function currentAddress() {
    const wallet = state.status?.wallet;
    if (!wallet) return null;
    if (state.receive?.walletId === wallet.wallet_id) return state.receive.address;
    const addresses = Array.isArray(wallet.addresses) ? wallet.addresses : [];
    const receiveAddresses = addresses.filter((item) => item && typeof item.address === "string" && ["receive", "external", "0"].includes(String(item.branch).toLowerCase()));
    receiveAddresses.sort((a, b) => Number(a.index || 0) - Number(b.index || 0));
    return receiveAddresses.length ? receiveAddresses[receiveAddresses.length - 1].address : null;
  }

  function updateControls() {
    const running = state.status?.phase === "running";
    const walletReady = canUseWallet();
    const unlocked = walletReady && state.status.wallet.locked === false;
    const locked = state.status?.wallet?.locked === true;
    const canUnlock = state.connected && running && locked && typeof state.status.wallet.wallet_id === "string" && state.status.wallet.wallet_id.length > 0;
    document.querySelectorAll("[data-mutation]").forEach((control) => { control.disabled = state.busy || !walletReady; });
    $("start-button").hidden = !!running;
    $("stop-button").hidden = !running;
    $("start-button").disabled = state.busy || !state.connected || !!running;
    $("stop-button").disabled = state.busy || !state.connected || !running;
    [$("receive-button"), $("fund-button"), $("send-button"), ...sendFields].forEach((control) => { control.disabled = state.busy || !unlocked; });
    $("lock-button").textContent = locked ? "Unlock wallet" : "Lock wallet";
    $("lock-button").dataset.action = locked ? "unlock" : "lock";
    $("lock-button").disabled = state.busy || (locked ? !canUnlock : !walletReady);
    $("backup-select").disabled = state.busy || !(state.status?.backups || []).length;
    $("recover-button").disabled = state.busy || !state.connected || !selectedBackup();
    $("confirm-recover-button").disabled = state.busy || !state.connected || !state.recoveryId;
    $("cancel-recover-button").disabled = state.busy;
    $("copy-address-button").disabled = state.busy || !currentAddress();
    $("refresh-button").disabled = state.busy || state.polling;
    $("console-main").setAttribute("aria-busy", String(state.busy));
  }

  function dateLabel(value, withDate = false) {
    const date = new Date(typeof value === "number" && value < 1e12 ? value * 1000 : value);
    if (!value || Number.isNaN(date.getTime())) return "Time unavailable";
    return withDate ? date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }) : date.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  }

  function renderNodes(nodes) {
    const list = $("node-list");
    list.replaceChildren();
    if (!nodes.length) { const item = document.createElement("li"); item.className = "empty-note"; item.textContent = "Start the network to see your nodes."; list.append(item); return; }
    nodes.forEach((node, index) => {
      const item = document.createElement("li"); item.dataset.testid = `node-${index + 1}`;
      const heading = document.createElement("div"); heading.className = "node-heading";
      const name = document.createElement("strong"); name.textContent = node.name || `Node ${index + 1}`;
      const height = document.createElement("span"); height.className = "node-height"; height.dataset.testid = "node-height"; height.textContent = Number.isSafeInteger(node.height) ? `Block ${node.height.toLocaleString()}` : "Height unavailable";
      heading.append(name, height);
      const details = document.createElement("div"); details.className = "node-details";
      const peers = document.createElement("span"); peers.textContent = Number.isSafeInteger(node.peers) ? `${node.peers} ${node.peers === 1 ? "peer" : "peers"}` : "Peers unavailable";
      const tip = document.createElement("code"); tip.textContent = typeof node.tip === "string" ? node.tip : ""; tip.title = typeof node.tip === "string" ? node.tip : ""; tip.setAttribute("aria-label", `Chain tip: ${node.tip || "unavailable"}`);
      details.append(peers, tip); item.append(heading, details); list.append(item);
    });
  }

  function renderActivity(activity) {
    const list = $("activity-list"); list.replaceChildren();
    if (!activity.length) { const item = document.createElement("li"); item.className = "empty-note"; item.textContent = "Your wallet activity will appear here."; list.append(item); return; }
    [...activity].reverse().slice(0, 8).forEach((entry) => {
      const item = document.createElement("li");
      const time = document.createElement("time"); time.textContent = dateLabel(entry.time); const parsed = new Date(typeof entry.time === "number" && entry.time < 1e12 ? entry.time * 1000 : entry.time); if (!Number.isNaN(parsed.getTime())) time.dateTime = parsed.toISOString();
      const message = document.createElement("p"); message.className = "activity-message"; message.textContent = entry.message || entry.kind || "Wallet updated";
      item.append(time, message);
      if (typeof entry.txid === "string") { const txid = document.createElement("code"); txid.className = "activity-txid"; txid.textContent = entry.txid; item.append(txid); }
      list.append(item);
    });
  }

  function describeBackup(backup) {
    return `${dateLabel(backup.created_at, true)} · Block ${Number.isSafeInteger(backup.height) ? backup.height.toLocaleString() : "unknown"}`;
  }

  function updateBackupDescription() {
    const backup = selectedBackup();
    $("backup-description").textContent = backup ? `${describeBackup(backup)}. Backup ${backup.id}` : "Create a backup after the network starts.";
  }

  function renderBackups(backups) {
    const select = $("backup-select"); const previous = select.value;
    select.replaceChildren();
    if (!backups.length) { const option = document.createElement("option"); option.value = ""; option.textContent = "No backups yet"; select.append(option); }
    else [...backups].reverse().forEach((backup) => { const option = document.createElement("option"); option.value = String(backup.id); option.textContent = describeBackup(backup); select.append(option); });
    if (backups.some((backup) => String(backup.id) === previous)) select.value = previous;
    $("backup-count").textContent = backups.length ? `${backups.length} saved ${backups.length === 1 ? "backup" : "backups"}` : "Saved locally";
    if (state.recoveryId && !backups.some((backup) => String(backup.id) === state.recoveryId)) hideRecovery();
    updateBackupDescription();
  }

  function renderStatus(status) {
    state.status = status;
    const running = status.phase === "running";
    const nodes = Array.isArray(status.nodes) ? status.nodes : [];
    const wallet = status.wallet;
    $("phase-badge").dataset.phase = status.phase || "unknown";
    $("phase-label").textContent = running ? (status.ready ? "Running locally" : "Starting") : status.phase === "error" ? "Needs attention" : "Network stopped";
    $("startup-note").hidden = running && status.ready === true;
    $("startup-title").textContent = status.phase === "error" ? "Your network needs attention." : running ? "Opening your local wallet." : "A small network, ready when you are.";
    $("startup-message").textContent = status.phase === "error" ? "Check the message above or refresh status. Your saved backups are available below." : running ? "Your nodes are starting. Wallet controls will be ready shortly." : "Start the network to receive, send, and recover local test coins.";
    $("balance").textContent = formatCoins(wallet?.balance_sats);
    $("confirmed-balance").textContent = formatCoins(wallet?.confirmed_sats);
    $("spendable-balance").textContent = formatCoins(wallet?.spendable_sats);
    $("pending-balance").textContent = formatCoins(wallet?.pending_sats);
    const pending = moneyValue(wallet?.pending_sats);
    const immature = moneyValue(wallet?.immature_sats);
    $("wallet-note").textContent = !running ? "Start the network to open your wallet." : !wallet ? "Your wallet is opening." : wallet.locked ? "Wallet locked. Unlock it to create addresses or send test coins." : pending !== null && pending > 0n ? "You have pending test coins. Mine a block to confirm them." : immature !== null && immature > 0n ? "Some mined test coins need more blocks before they can be spent." : "Your spendable test coins are ready to send.";
    const address = currentAddress();
    $("receive-address").textContent = address || "No receive address yet";
    const sameTip = nodes.length >= 2 && nodes.every((node) => typeof node.tip === "string" && node.tip === nodes[0].tip && node.height === nodes[0].height);
    $("sync-label").textContent = !running ? "Network stopped" : sameTip && status.ready ? "Nodes in sync" : status.ready ? "Syncing nodes" : "Starting nodes";
    $("sync-description").textContent = !running ? "Start the network to connect your nodes." : sameTip && status.ready ? "Both nodes share the same chain." : "Waiting for both nodes to share a chain.";
    renderNodes(nodes); renderActivity(Array.isArray(status.activity) ? status.activity : []); renderBackups(Array.isArray(status.backups) ? status.backups : []); renderStartupFeedback(status); updateControls();
  }

  async function refreshStatus(manual = false) {
    if (state.busy || state.polling) return;
    const epoch = state.epoch;
    state.polling = true; updateControls();
    try {
      const status = await api("/api/status");
      if (state.busy || epoch !== state.epoch) return;
      state.connected = true; renderStatus(status);
      if ($("feedback").dataset.source !== "startup") {
        if (manual) setFeedback("Status refreshed.", "success");
        else if ($("feedback").dataset.source === "connection") setFeedback("Console connection restored.", "success");
      }
    } catch (error) {
      if (state.busy || epoch !== state.epoch) return;
      state.connected = false;
      $("phase-badge").dataset.phase = "error"; $("phase-label").textContent = "Console unavailable";
      $("sync-label").textContent = "Connection unavailable";
      $("sync-description").textContent = "Check the console terminal, then refresh.";
      setFeedback(error.message, "error", "connection");
    } finally { state.polling = false; updateControls(); }
  }

  function hideRecovery() { state.recoveryId = null; $("recovery-confirmation").hidden = true; }

  async function runAction(action, params = {}) {
    if (state.busy) return;
    const fingerprint = action === "send" ? JSON.stringify(params) : null;
    const id = action === "send" && state.pendingSend?.fingerprint === fingerprint ? state.pendingSend.id : requestId();
    if (action === "send") state.pendingSend = { fingerprint, id };
    state.busy = true; state.epoch += 1; updateControls();
    setFeedback(busyMessages[action] || "Updating your wallet…", "busy");
    try {
      const data = await api("/api/action", { method: "POST", headers: { "Content-Type": "application/json", "X-Console-Token": csrfToken }, body: JSON.stringify({ action, params, request_id: id }) });
      if (!data || !data.status) throw uncertainError("The console returned no status. Refresh before trying again.");
      state.connected = true;
      if (action === "recover") { state.receive = null; hideRecovery(); $("transaction-receipt").hidden = true; }
      if (action === "receive" && typeof data.result?.address === "string") state.receive = { address: data.result.address, walletId: data.status.wallet?.wallet_id };
      renderStatus(data.status);
      const messages = { start: "Your local network is running.", stop: "Your local network is stopped.", receive: "Receive address created.", fund: "Confirmed test coins added. They are ready to send.", mine: "Block mined. Balances are updated.", backup: "Backup created and saved locally.", recover: "Backup recovered. Your wallet is ready.", lock: "Wallet locked.", unlock: "Wallet unlocked." };
      if (action === "send") {
        state.pendingSend = null;
        const txid = data.result?.txid;
        if (typeof txid === "string" && txid) { $("sent-txid").textContent = txid; $("transaction-receipt").hidden = false; }
        $("send-amount").value = ""; updateSendTotal();
        setFeedback("Test coins sent. Mine a block to confirm the transaction.", "success");
      } else setFeedback(messages[action] || "Wallet updated.", "success");
      if (action === "backup" && data.result?.id) { $("backup-select").value = String(data.result.id); updateBackupDescription(); }
    } catch (error) {
      if (action === "send" && !error.uncertain) state.pendingSend = null;
      setFeedback(error.message, "error");
      if (action === "send") formError(`${error.message} Check activity before sending again.`);
    } finally { state.busy = false; updateControls(); }
  }

  function updateSendTotal() {
    try {
      const total = amountToSats($("send-amount").value) + feeToSats($("send-fee").value);
      $("send-total").textContent = total <= MAX_MONEY ? `${formatCoins(total.toString())} testBTC` : "Exceeds test coin limit";
    } catch (_) { $("send-total").textContent = "—"; }
  }

  function selectTab(tab) {
    [$("receive-tab"), $("send-tab")].forEach((item) => { const selected = item === tab; item.setAttribute("aria-selected", String(selected)); item.tabIndex = selected ? 0 : -1; $(item.getAttribute("aria-controls")).hidden = !selected; });
  }

  document.querySelectorAll("[data-action]").forEach((button) => button.addEventListener("click", () => {
    const action = button.dataset.action;
    const params = action === "fund" ? { amount_sats: 2000000 } : action === "mine" ? { blocks: 1 } : {};
    runAction(action, params);
  }));
  [$("receive-tab"), $("send-tab")].forEach((tab) => {
    tab.addEventListener("click", () => selectTab(tab));
    tab.addEventListener("keydown", (event) => { if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return; event.preventDefault(); const next = event.key === "Home" ? $("receive-tab") : event.key === "End" ? $("send-tab") : tab === $("receive-tab") ? $("send-tab") : $("receive-tab"); selectTab(next); next.focus(); });
  });
  $("refresh-button").addEventListener("click", () => refreshStatus(true));
  $("copy-address-button").addEventListener("click", async () => {
    const address = currentAddress(); if (!address) return;
    try { await navigator.clipboard.writeText(address); setFeedback("Receive address copied.", "success"); }
    catch (_) { setFeedback("Select and copy the receive address below. Automatic copying is unavailable.", "error"); const range = document.createRange(); range.selectNodeContents($("receive-address")); const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range); $("receive-address").focus(); }
  });
  sendFields.forEach((input) => input.addEventListener("input", () => { state.pendingSend = null; formError(""); updateSendTotal(); }));
  $("send-form").addEventListener("submit", (event) => {
    event.preventDefault(); if (state.busy || !canUseWallet() || state.status.wallet.locked) return;
    formError(""); const address = $("send-address").value.trim();
    if (!address) { formError("Enter the recipient’s test address.", $("send-address")); return; }
    if (address.length > 512 || /\s/.test(address)) { formError("Enter a test address without spaces.", $("send-address")); return; }
    let amount, fee;
    try { amount = amountToSats($("send-amount").value); } catch (error) { formError(error.message, $("send-amount")); return; }
    try { fee = feeToSats($("send-fee").value); } catch (error) { formError(error.message, $("send-fee")); return; }
    if (amount + fee > MAX_MONEY) { formError("The amount and fee exceed the test coin limit.", $("send-amount")); return; }
    const spendable = moneyValue(state.status.wallet.spendable_sats);
    if (spendable !== null && amount + fee > spendable) { formError("The amount and fee exceed your spendable test coins.", $("send-amount")); return; }
    runAction("send", { address, amount_sats: Number(amount), fee_sats: Number(fee) });
  });
  $("backup-select").addEventListener("change", () => { hideRecovery(); updateBackupDescription(); updateControls(); });
  $("recover-button").addEventListener("click", () => {
    const backup = selectedBackup(); if (!backup || state.busy) return;
    state.recoveryId = String(backup.id); $("recovery-confirmation-description").textContent = describeBackup(backup); $("recovery-backup-id").textContent = String(backup.id); $("recovery-confirmation").hidden = false; updateControls(); $("confirm-recover-button").focus();
  });
  $("cancel-recover-button").addEventListener("click", () => { hideRecovery(); updateControls(); $("recover-button").focus(); });
  $("confirm-recover-button").addEventListener("click", () => { if (state.recoveryId) runAction("recover", { backup_id: state.recoveryId }); });
  updateControls(); refreshStatus(); window.setInterval(() => refreshStatus(), POLL_INTERVAL);
})();
