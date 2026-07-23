# Cipher

Secret two-person chat. Share a code, join the same room, message with end-to-end AES-GCM encryption.

**Live app:** https://avinashtambe-4260.github.io/cipher-chat/  
**Mailbox Worker:** https://cipher-mailbox.cipher-chat.workers.dev

## How it works

1. Both people enter the same shared chat code.
2. You can **send immediately** — the other person can be offline.
3. Ciphertext is stored in a **Cloudflare Worker + KV mailbox** (24h TTL).
4. When they open the same room, they receive waiting messages and **ACK** them (deleted from the mailbox).
5. PeerJS is an optional live link when both are online; the mailbox is the source of truth.
6. Leaving clears *your* screen; undelivered messages remain in the mailbox for the peer.

Only ciphertext is stored. The room path is `SHA-256` of the code — the Worker never sees plaintext.

## Local use

```bash
npx --yes serve .
```

## Mailbox Worker

```bash
cd worker
npx wrangler deploy
```

Requires a Cloudflare account (free). KV binding `MAILBOX` is configured in `worker/wrangler.toml`.

## Stack

- GitHub Pages (static UI)
- Cloudflare Workers + KV (mailbox)
- PeerJS (optional realtime)
- Web Crypto API (AES-GCM)

## Privacy notes

- Choose a long, uncommon code.
- Only two live PeerJS seats; mailbox works regardless.
- Abandoned messages expire from KV after 24 hours.

## License

MIT
