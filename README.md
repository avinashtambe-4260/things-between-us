# Private gist access

Static “private gist” front-end with encrypted collaborator notes. Hosted on GitHub Pages; mailbox on Cloudflare Workers.

**Live:** https://avinashtambe-4260.github.io/cipher-chat/

## Access codes

Codes must **start with `14`** and be at least 5 characters (after normalize: trim, lowercase, spaces → hyphens).

Example: `14sunset-42`

## Notes

- UI is intentionally framed as gist access / discussion, not a messenger.
- Undelivered ciphertext waits in the Worker mailbox until the other collaborator opens the same code.
- Mobile composer stays above the keyboard via `visualViewport` height sync.

## License

MIT
