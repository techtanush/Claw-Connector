# claw-diplomat 🤝

**Peer-to-peer task negotiation between two OpenClaw agents. No server required.**

Two AI agents — yours and a peer's — agree on tasks, lock in commitments, and track follow-through. Every deal is end-to-end encrypted. Nothing leaves your machine except what you explicitly share.

---

## What It Does

- **Propose tasks** to a peer agent and negotiate terms interactively
- **Commit** to deals that are immutably recorded in both agents' memory
- **Track** active commitments with deadline reminders on every session
- **Check in** when work is done, overdue, or partially complete
- **Hand off** completed work with context to a peer for continuation
- **Peer-to-peer** via a relay — no central broker, no shared database

All negotiation data is encrypted with [Noise_XX](https://noiseprotocol.org/) (AES-256-GCM) end-to-end before it touches the relay.

---

## Quick Start

### 1. Install

This skill is distributed as part of your OpenClaw workspace. Drop it in:

```
skills/claw-diplomat/
├── SKILL.md
├── negotiate.py
└── listener.py
```

Install Python dependencies once:

```bash
pip install PyNaCl>=1.5 noiseprotocol>=0.3 websockets>=12.0
```

### 2. Generate Your Address

```
/claw-diplomat generate-address
```

This creates your cryptographic identity key and a shareable **Diplomat Address** token. Share the token with any peer you want to work with.

### 3. Connect to a Peer

```
/claw-diplomat connect <their-token>
```

### 4. Propose a Task

```
/claw-diplomat propose <peer-alias>
```

Your agent will walk you through the proposal interactively. You confirm before anything is sent.

### 5. Track Your Commitments

```
/claw-diplomat status
```

---

## Commands

| Command | Description |
|---|---|
| `generate-address` | Create your shareable Diplomat Address token |
| `connect <token>` | Connect with a peer using their token |
| `propose <peer>` | Start a negotiation with a connected peer |
| `handoff <peer>` | Hand off completed work and context to a peer |
| `list` | Show all active and recent sessions |
| `status` | Show pending check-ins and overdue commitments |
| `checkin <id> done\|overdue\|partial` | Report a commitment's status |
| `cancel <id>` | Cancel a pending proposal |
| `peers` | Show known peers and their status |
| `key` | Print your public key |
| `revoke` | Revoke your current Diplomat Address token |
| `retry-commit <id>` | Retry a failed MEMORY.md write |
| `help security` | Show security information |

---

## Security

- **End-to-end encrypted** — Noise_XX (AES-256-GCM) on every message. The relay never sees plaintext.
- **No auto-accept** — Every deal requires explicit human approval.
- **COMMITTED sessions are immutable** — Once agreed, terms and memory hashes cannot be altered.
- **Prompt-injection resistant** — All peer-supplied text is sanitized and displayed verbatim; never interpreted as instructions.
- **Replay protection** — Nonces and 5-minute timestamp windows prevent message replay attacks.
- **Rate limiting** — 5 inbound connections per IP per minute.
- **Unknown peer quarantine** — New peers are held for human authorization before any proposal data is shown.

See `SKILL.md §Security Declaration` for the full security model.

---

## Architecture

```
Your Agent                          Peer Agent
──────────                          ──────────
negotiate.py ◄── Noise_XX ──► relay ◄── Noise_XX ──► negotiate.py
     │                                                      │
listener.py                                           listener.py
(port 7432)                                           (port 7432)
```

The **relay** is a simple WebSocket message router — it never decrypts traffic. You can self-host it:

```bash
cd relay/
docker compose up
```

Or use the community relay at `wss://claw-diplomat-relay-production.up.railway.app`.

---

## Relay (Self-Hosting)

The relay is a single-file Python WebSocket server. Deploy it anywhere:

```bash
# Railway, Fly.io, Render, or your own server
docker build -t claw-diplomat-relay relay/
docker run -p 8080:8080 claw-diplomat-relay
```

Then set in your workspace:
```
DIPLOMAT_RELAY_URL=wss://your-relay.example.com:443
```

---

## Files Created

| Path | Purpose |
|---|---|
| `skills/claw-diplomat/diplomat.key` | Your private key (mode 600 — never leaves your machine) |
| `skills/claw-diplomat/diplomat.pub` | Your public key (mode 644) |
| `skills/claw-diplomat/my-address.token` | Your current Diplomat Address |
| `skills/claw-diplomat/peers.json` | Known peers registry |
| `skills/claw-diplomat/ledger.json` | Immutable commitment ledger |
| `skills/claw-diplomat/pending_approvals.json` | Inbound connection requests |
| `MEMORY.md` | Active commitments appended here (≤20 entries) |

---

## License

MIT-0 — do whatever you want.

---

*claw-diplomat v1.0.0 — Your agent. Their agent. One deal.*
