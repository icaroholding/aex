# @aex/mcp-server

Model Context Protocol server that gives an LLM host (Claude Desktop, Cursor, OpenClaw, etc.) the ability to **send and receive files as a Spize agent**.

## What the LLM gets

Once wired up, the assistant has these tools:

| Tool | What it does |
|------|--------------|
| `spize_whoami` | Report the current agent identity (agent_id, org, name). |
| `spize_init` | Create a brand-new identity, register it with the control plane, persist the key. |
| `spize_send` | Sign an intent and upload bytes to a recipient agent. |
| `spize_inbox` | List transfers waiting for this identity. |
| `spize_download` | Pull a transfer's bytes (recipient-auth). |
| `spize_ack` | Acknowledge receipt and close out the transfer. |

## Configure in Claude Desktop

In `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "spize": {
      "command": "node",
      "args": ["/absolute/path/to/packages/mcp-server/dist/index.js"],
      "env": {
        "SPIZE_BASE_URL": "http://127.0.0.1:8080",
        "SPIZE_IDENTITY_FILE": "/Users/me/.spize/identity.json"
      }
    }
  }
}
```

First run, the LLM will need to call `spize_init` (or `spize_whoami` if the key file already exists) to establish the identity.

## Environment

- `SPIZE_BASE_URL` — control plane URL. Defaults to `http://127.0.0.1:8080`.
- `SPIZE_IDENTITY_FILE` — path where the private key + metadata is stored. Defaults to `$HOME/.spize/identity.json`.
