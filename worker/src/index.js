/**
 * Cipher mailbox Worker — stores encrypted messages in KV until peer ACKs.
 */
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const ROOM_HASH_RE = /^[0-9a-f]{64}$/i;
const MAX_BODY = 8 * 1024;
const MSG_TTL = 86400;
const MAX_MESSAGES = 100;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

function corsPreflight() {
  return new Response(null, { status: 204, headers: CORS });
}

function notFound() {
  return json({ error: "not found" }, 404);
}

function badRequest(msg) {
  return json({ error: msg }, 400);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return corsPreflight();
    }

    const url = new URL(request.url);
    let path = url.pathname;
    if (path.endsWith("/") && path.length > 1) path = path.slice(0, -1);

    if (path === "/api/health" && request.method === "GET") {
      return json({ ok: true });
    }

    const roomMatch = path.match(/^\/api\/room\/([^/]+)\/(messages|ack)$/);
    if (!roomMatch) {
      return notFound();
    }

    const roomHash = roomMatch[1];
    const action = roomMatch[2];

    if (!ROOM_HASH_RE.test(roomHash)) {
      return badRequest("invalid roomHash");
    }

    if (action === "messages" && request.method === "POST") {
      return postMessage(request, env, roomHash);
    }
    if (action === "messages" && request.method === "GET") {
      return listMessages(env, roomHash);
    }
    if (action === "ack" && request.method === "POST") {
      return ackMessages(request, env, roomHash);
    }

    return notFound();
  },
};

async function postMessage(request, env, roomHash) {
  const contentLength = request.headers.get("content-length");
  if (contentLength && Number(contentLength) > MAX_BODY) {
    return badRequest("body too large");
  }

  let raw;
  try {
    raw = await request.text();
  } catch {
    return badRequest("invalid body");
  }
  if (raw.length > MAX_BODY) {
    return badRequest("body too large");
  }

  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    return badRequest("invalid JSON");
  }

  const { id, iv, ct, from, ts } = body ?? {};
  if (typeof id !== "string" || id.length === 0) {
    return badRequest("id required");
  }
  if (typeof iv !== "string" || typeof ct !== "string" || typeof from !== "string") {
    return badRequest("iv, ct, from must be strings");
  }
  if (ts !== undefined && typeof ts !== "number" && typeof ts !== "string") {
    return badRequest("invalid ts");
  }

  const value = JSON.stringify({ id, iv, ct, from, ts });
  if (value.length > MAX_BODY) {
    return badRequest("body too large");
  }

  const key = `room:${roomHash}:msg:${id}`;
  await env.MAILBOX.put(key, value, { expirationTtl: MSG_TTL });
  return json({ ok: true });
}

async function listMessages(env, roomHash) {
  const prefix = `room:${roomHash}:msg:`;
  const listed = await env.MAILBOX.list({ prefix, limit: MAX_MESSAGES });
  const messages = [];

  for (const key of listed.keys) {
    const val = await env.MAILBOX.get(key.name);
    if (val == null) continue;
    try {
      messages.push(JSON.parse(val));
    } catch {
      // skip corrupt
    }
  }

  messages.sort((a, b) => {
    const ta = Number(a.ts) || 0;
    const tb = Number(b.ts) || 0;
    return ta - tb;
  });

  return json({ messages });
}

async function ackMessages(request, env, roomHash) {
  let body;
  try {
    body = await request.json();
  } catch {
    return badRequest("invalid JSON");
  }

  const ids = body?.ids;
  if (!Array.isArray(ids)) {
    return badRequest("ids must be an array");
  }

  let deleted = 0;
  for (const id of ids) {
    if (typeof id !== "string" || id.length === 0) continue;
    const key = `room:${roomHash}:msg:${id}`;
    await env.MAILBOX.delete(key);
    deleted += 1;
  }

  return json({ ok: true, deleted });
}
