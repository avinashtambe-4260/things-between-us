/**
 * Cipher — encrypted secret chat with Cloudflare mailbox
 * - Messages are encrypted in-browser, then stored in a Worker KV mailbox
 * - Peer can close the tab; the other person still receives messages later
 * - After the recipient reads (ACK), messages are deleted from the mailbox
 * - PeerJS is an optional fast path when both are online
 */

(function () {
  "use strict";

  const MAILBOX_URL = "https://cipher-mailbox.cipher-chat.workers.dev";
  const PEER_PREFIX = "cipher-v1-";
  const PBKDF2_SALT = "cipher-secret-chat-v1";
  const PBKDF2_ITERATIONS = 120000;
  const CLIENT_KEY = "cipher-client-id-v1";
  const POLL_MS = 2000;

  const gateEl = document.getElementById("gate");
  const chatEl = document.getElementById("chat");
  const joinForm = document.getElementById("join-form");
  const roomCodeInput = document.getElementById("room-code");
  const gateError = document.getElementById("gate-error");
  const joinBtn = document.getElementById("join-btn");
  const leaveBtn = document.getElementById("leave-btn");
  const statusEl = document.getElementById("status");
  const chatTitle = document.getElementById("chat-title");
  const messagesEl = document.getElementById("messages");
  const sendForm = document.getElementById("send-form");
  const messageInput = document.getElementById("message-input");
  const sendBtn = document.getElementById("send-btn");

  let peer = null;
  let conn = null;
  let cryptoKey = null;
  let roomCode = "";
  let roomHash = "";
  let clientId = "";
  let destroyed = false;
  let guestRetryTimer = null;
  let pollTimer = null;
  let mailboxOk = true;

  /** @type {Map<string, { id: string, text: string, delivered: boolean }>} */
  const myPending = new Map();
  const seenIncoming = new Set();

  function normalizeCode(raw) {
    return String(raw || "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "-");
  }

  function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    return "m-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 10);
  }

  function getClientId() {
    try {
      let id = localStorage.getItem(CLIENT_KEY);
      if (!id) {
        id = "c-" + uuid();
        localStorage.setItem(CLIENT_KEY, id);
      }
      return id;
    } catch (_) {
      return "c-" + uuid();
    }
  }

  function showGateError(msg) {
    gateError.hidden = !msg;
    gateError.textContent = msg || "";
  }

  function setStatus(text, kind) {
    statusEl.textContent = text;
    statusEl.classList.remove("is-ready", "is-waiting", "is-error");
    if (kind) statusEl.classList.add(kind);
  }

  function setComposerEnabled(on) {
    messageInput.disabled = !on;
    sendBtn.disabled = !on;
    if (on) messageInput.focus();
  }

  function isPeerLive() {
    return !!(conn && conn.open);
  }

  function refreshStatus() {
    const pending = [...myPending.values()].filter((m) => !m.delivered).length;
    if (isPeerLive()) {
      if (pending > 0) {
        setStatus("Live · " + pending + " waiting to be read", "is-ready");
      } else {
        setStatus("Connected (live)", "is-ready");
      }
      return;
    }
    if (!mailboxOk) {
      setStatus("Mailbox unreachable — retrying…", "is-error");
      return;
    }
    if (pending > 0) {
      setStatus(
        pending === 1
          ? "Saved in mailbox — waiting for them"
          : pending + " messages saved in mailbox",
        "is-waiting"
      );
    } else {
      setStatus("Room open — send anytime", "is-waiting");
    }
  }

  function bufToHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function b64Encode(bytes) {
    let s = "";
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
    return btoa(s);
  }

  function b64Decode(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function sha256Hex(text) {
    const data = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return bufToHex(hash);
  }

  async function deriveHostPeerId(code) {
    const hex = await sha256Hex(code);
    return PEER_PREFIX + hex;
  }

  async function deriveAesKey(code) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(code),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: enc.encode(PBKDF2_SALT),
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptText(plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      new TextEncoder().encode(plaintext)
    );
    return {
      v: 1,
      type: "msg",
      id: uuid(),
      iv: b64Encode(iv),
      ct: b64Encode(cipher),
    };
  }

  async function decryptPayload(payload) {
    if (!payload || !payload.iv || !payload.ct) {
      throw new Error("Invalid payload");
    }
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64Decode(payload.iv) },
      cryptoKey,
      b64Decode(payload.ct)
    );
    return new TextDecoder().decode(plain);
  }

  function appendMessage(text, kind, opts) {
    const options = opts || {};
    const el = document.createElement("div");
    el.className = "msg msg-" + kind;
    if (options.id) el.dataset.msgId = options.id;
    if (options.pending) el.classList.add("is-pending");

    if (kind === "mine" || kind === "theirs") {
      const meta = document.createElement("span");
      meta.className = "msg-meta";
      if (kind === "mine") {
        meta.textContent = options.pending ? "You · in mailbox" : "You · read";
      } else {
        meta.textContent = "Peer";
      }
      el.appendChild(meta);
      const body = document.createElement("span");
      body.className = "msg-body";
      body.textContent = text;
      el.appendChild(body);
    } else {
      el.textContent = text;
    }

    messagesEl.appendChild(el);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    return el;
  }

  function markMineDelivered(ids) {
    (ids || []).forEach((id) => {
      const entry = myPending.get(id);
      if (entry) {
        entry.delivered = true;
        myPending.delete(id);
      }
      const el = messagesEl.querySelector('.msg-mine[data-msg-id="' + CSS.escape(id) + '"]');
      if (el) {
        el.classList.remove("is-pending");
        const meta = el.querySelector(".msg-meta");
        if (meta) meta.textContent = "You · read";
      }
    });
    refreshStatus();
  }

  function clearMessages() {
    messagesEl.replaceChildren();
  }

  async function mailboxFetch(path, options) {
    const res = await fetch(MAILBOX_URL + path, options);
    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(errText || "Mailbox HTTP " + res.status);
    }
    return res.json();
  }

  async function mailboxPost(payload) {
    await mailboxFetch("/api/room/" + roomHash + "/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: payload.id,
        iv: payload.iv,
        ct: payload.ct,
        from: clientId,
        ts: Date.now(),
      }),
    });
  }

  async function mailboxAck(ids) {
    if (!ids.length) return;
    await mailboxFetch("/api/room/" + roomHash + "/ack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids: ids }),
    });
  }

  async function mailboxList() {
    return mailboxFetch("/api/room/" + roomHash + "/messages", { method: "GET" });
  }

  async function pollMailbox() {
    if (destroyed || !roomHash || !cryptoKey) return;
    try {
      const data = await mailboxList();
      mailboxOk = true;
      const messages = (data && data.messages) || [];
      const stillMine = new Set();
      const toAck = [];

      for (let i = 0; i < messages.length; i++) {
        const msg = messages[i];
        if (!msg || !msg.id) continue;

        if (msg.from === clientId) {
          stillMine.add(msg.id);
          continue;
        }

        if (seenIncoming.has(msg.id)) {
          toAck.push(msg.id);
          continue;
        }

        try {
          const text = await decryptPayload(msg);
          seenIncoming.add(msg.id);
          appendMessage(text, "theirs", { id: msg.id });
          toAck.push(msg.id);
        } catch (err) {
          console.error(err);
          appendMessage("Could not decrypt a mailbox message.", "system");
          toAck.push(msg.id);
        }
      }

      // My messages no longer in mailbox → peer read them
      const deliveredIds = [];
      myPending.forEach((entry, id) => {
        if (!entry.delivered && !stillMine.has(id)) {
          deliveredIds.push(id);
        }
      });
      if (deliveredIds.length) markMineDelivered(deliveredIds);

      if (toAck.length) {
        try {
          await mailboxAck(toAck);
        } catch (err) {
          console.warn("ack failed", err);
        }
      }

      refreshStatus();
    } catch (err) {
      console.warn(err);
      mailboxOk = false;
      refreshStatus();
    }
  }

  function startPolling() {
    stopPolling();
    pollMailbox();
    pollTimer = window.setInterval(pollMailbox, POLL_MS);
  }

  function stopPolling() {
    if (pollTimer) {
      window.clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function sendPacket(obj) {
    if (!isPeerLive()) return false;
    try {
      conn.send(obj);
      return true;
    } catch (err) {
      console.error(err);
      return false;
    }
  }

  async function handlePeerData(data) {
    let packet = data;
    if (typeof data === "string") {
      try {
        packet = JSON.parse(data);
      } catch (_) {
        return;
      }
    }
    if (!packet || packet.v !== 1) return;

    if (packet.type === "ack" && Array.isArray(packet.ids)) {
      markMineDelivered(packet.ids);
      return;
    }

    if (packet.type === "msg" || (packet.iv && packet.ct)) {
      const id = packet.id || uuid();
      if (seenIncoming.has(id)) {
        sendPacket({ v: 1, type: "ack", ids: [id] });
        return;
      }
      try {
        const text = await decryptPayload(packet);
        seenIncoming.add(id);
        appendMessage(text, "theirs", { id: id });
        sendPacket({ v: 1, type: "ack", ids: [id] });
        // Also remove from mailbox if present
        mailboxAck([id]).catch(function () {});
      } catch (err) {
        console.error(err);
        appendMessage("Could not decrypt a message.", "system");
      }
    }
  }

  function wireConnection(c) {
    if (conn && conn !== c) {
      try {
        conn.close();
      } catch (_) {
        /* ignore */
      }
    }
    conn = c;

    c.on("open", () => {
      appendMessage("Live link up — mailbox still keeps messages if someone leaves.", "system");
      refreshStatus();
    });

    c.on("data", (data) => {
      handlePeerData(data);
    });

    c.on("close", () => {
      conn = null;
      appendMessage("Live link closed. Mailbox delivery still works.", "system");
      refreshStatus();
    });

    c.on("error", (err) => {
      console.error(err);
    });
  }

  function stopGuestRetry() {
    if (guestRetryTimer) {
      window.clearInterval(guestRetryTimer);
      guestRetryTimer = null;
    }
  }

  function destroySession() {
    destroyed = true;
    stopGuestRetry();
    stopPolling();
    setComposerEnabled(false);

    try {
      if (conn) conn.close();
    } catch (_) {
      /* ignore */
    }
    conn = null;
    try {
      if (peer) peer.destroy();
    } catch (_) {
      /* ignore */
    }
    peer = null;
    cryptoKey = null;
    roomCode = "";
    roomHash = "";
    myPending.clear();
    seenIncoming.clear();
    clearMessages();
    chatEl.hidden = true;
    gateEl.hidden = false;
    showGateError("");
    setStatus("Connecting…", "is-waiting");
    joinBtn.disabled = false;
    roomCodeInput.focus();
    destroyed = false;
  }

  function createPeer(id) {
    if (id) return new Peer(id, { debug: 0 });
    return new Peer({ debug: 0 });
  }

  function becomeHost(hostId) {
    peer = createPeer(hostId);

    peer.on("open", () => {
      if (destroyed) return;
      setComposerEnabled(true);
      refreshStatus();
    });

    peer.on("connection", (c) => {
      if (destroyed) {
        c.close();
        return;
      }
      if (conn && conn.open) {
        c.on("open", () => {
          try {
            c.send({ v: 1, type: "busy" });
          } catch (_) {
            /* ignore */
          }
          c.close();
        });
        return;
      }
      wireConnection(c);
    });

    peer.on("error", (err) => {
      if (destroyed) return;
      if (err && err.type === "unavailable-id") {
        becomeGuest(hostId);
        return;
      }
      console.warn("PeerJS error (mailbox still works)", err);
      setComposerEnabled(true);
      refreshStatus();
    });

    peer.on("disconnected", () => {
      if (destroyed) return;
      try {
        peer.reconnect();
      } catch (_) {
        /* ignore */
      }
    });
  }

  function tryGuestConnect(hostId) {
    if (destroyed || isPeerLive() || !peer || peer.destroyed) return;
    try {
      const c = peer.connect(hostId, {
        reliable: true,
        serialization: "json",
      });
      wireConnection(c);
    } catch (err) {
      console.warn(err);
    }
  }

  function becomeGuest(hostId) {
    stopGuestRetry();
    if (peer) {
      try {
        peer.destroy();
      } catch (_) {
        /* ignore */
      }
      peer = null;
    }
    peer = createPeer();

    peer.on("open", () => {
      if (destroyed) return;
      setComposerEnabled(true);
      tryGuestConnect(hostId);
      stopGuestRetry();
      guestRetryTimer = window.setInterval(() => {
        if (destroyed || isPeerLive()) {
          stopGuestRetry();
          return;
        }
        tryGuestConnect(hostId);
      }, 5000);
      refreshStatus();
    });

    peer.on("error", () => {
      if (destroyed) return;
      setComposerEnabled(true);
      refreshStatus();
    });
  }

  async function enterRoom(code) {
    destroyed = false;
    roomCode = code;
    clientId = getClientId();
    roomHash = await sha256Hex("cipher-room:" + code);
    cryptoKey = await deriveAesKey(code);
    const hostId = await deriveHostPeerId(code);

    myPending.clear();
    seenIncoming.clear();

    gateEl.hidden = true;
    chatEl.hidden = false;
    chatTitle.textContent = code;
    clearMessages();
    setComposerEnabled(false);
    showGateError("");
    appendMessage(
      "Mailbox ready. You can send and leave — they’ll get messages when they open this room.",
      "system"
    );

    startPolling();
    becomeHost(hostId);
    setComposerEnabled(true);
    refreshStatus();
  }

  joinForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    showGateError("");
    const code = normalizeCode(roomCodeInput.value);
    if (code.length < 3) {
      showGateError("Use at least 3 characters after normalizing.");
      roomCodeInput.focus();
      return;
    }
    roomCodeInput.value = code;
    joinBtn.disabled = true;
    try {
      await enterRoom(code);
    } catch (err) {
      console.error(err);
      showGateError(err.message || "Failed to enter room.");
      destroySession();
    } finally {
      joinBtn.disabled = false;
    }
  });

  leaveBtn.addEventListener("click", () => {
    // Local UI clears; undelivered ciphertext stays in mailbox for the peer
    destroySession();
  });

  sendForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text || !cryptoKey || !roomHash) return;

    try {
      const payload = await encryptText(text);
      myPending.set(payload.id, { id: payload.id, text: text, delivered: false });
      appendMessage(text, "mine", { id: payload.id, pending: true });
      messageInput.value = "";
      messageInput.focus();

      try {
        await mailboxPost(payload);
        mailboxOk = true;
      } catch (err) {
        console.error(err);
        mailboxOk = false;
        appendMessage("Could not reach mailbox. Message kept locally only for now.", "system");
      }

      // Fast path if peer is live
      sendPacket(payload);
      refreshStatus();
    } catch (err) {
      console.error(err);
      appendMessage("Failed to encrypt/send message.", "system");
    }
  });

  window.addEventListener("beforeunload", () => {
    stopPolling();
    stopGuestRetry();
    try {
      if (conn) conn.close();
    } catch (_) {
      /* ignore */
    }
    try {
      if (peer) peer.destroy();
    } catch (_) {
      /* ignore */
    }
  });

  roomCodeInput.focus();
})();
