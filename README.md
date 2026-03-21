# Kalshi Command — Trading Dashboard

A self-hosted dashboard for managing Kalshi prediction market trades, with combo/parlay leg tracking, live WebSocket price updates, and inline trading.

## Quick Start (Local)

```bash
node server/index.js
# Open http://localhost:3456
# Enter your Kalshi API Key ID + PEM private key in the login form
```

## Deploy to a Server

Set environment variables to skip the login form and auto-connect:

```bash
export KALSHI_KEY_ID="your-api-key-id"
export KALSHI_PRIVATE_KEY="$(cat /path/to/key.pem)"  # or just the file path
export KALSHI_PASSWORD="your-secret-password"          # optional: protect trading
export PORT=3456

node server/index.js
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `KALSHI_KEY_ID` | For server mode | Your Kalshi API key ID |
| `KALSHI_PRIVATE_KEY` | For server mode | PEM private key (inline or file path) |
| `KALSHI_PASSWORD` | No | If set, requires password to place trades. Without it, full access. |
| `KALSHI_READ_ONLY` | No | Set to `1` to permanently disable all trading |
| `KALSHI_DEMO` | No | Set to `1` to use Kalshi demo environment |
| `PORT` | No | Server port (default: 3456) |

### Access Modes

| Mode | How | Trading |
|------|-----|---------|
| **Local** | No env vars, login form | Full access |
| **Server** | `KALSHI_KEY_ID` + `KALSHI_PRIVATE_KEY` | Full access |
| **Server + Password** | Above + `KALSHI_PASSWORD` | Read-only until password entered |
| **Read-only** | Above + `KALSHI_READ_ONLY=1` | Never (no unlock option) |

## Features

- **Combo/Parlay Tracking** — Each leg shown with live prices, momentum arrows, and settled ✓/✗ status
- **Real-time WebSocket** — Prices update live without polling
- **Inline Trading** — Buy/Sell Yes/No on any leg (when write access enabled)
- **Entry Prices** — Shows what price you opened each combo at
- **Password Protection** — Optional write-access gating for public deployments
- **Zero Dependencies** — Pure Node.js, no npm install needed
