# @aexproto/mcp-server

Model Context Protocol server that gives an LLM host (Claude Desktop, Cursor, OpenClaw, etc.) the ability to **send and receive files as an AEX agent**.

## What the LLM gets

Once wired up, the assistant has these tools:

| Tool (v2) | Legacy alias | What it does |
|---|---|---|
| `aex_whoami` | `spize_whoami` | Report the current agent identity (agent_id, org, name). |
| `aex_init` | `spize_init` | Create a brand-new identity, register it with the control plane, persist the key. |
| `aex_send` | `spize_send` | Sign an intent and upload bytes to a recipient agent. |
| `aex_inbox` | `spize_inbox` | List transfers waiting for this identity. |
| `aex_download` | `spize_download` | Pull a transfer's bytes (recipient-auth). |
| `aex_ack` | `spize_ack` | Acknowledge receipt and close out the transfer. |
| `aex_send_via_tunnel` | `spize_send_via_tunnel` | M2 P2P send: announce an intent without uploading bytes. |
| `aex_request_ticket` | `spize_request_ticket` | M2 P2P pickup: request a signed data-plane ticket. |
| `aex_fetch_from_tunnel` | `spize_fetch_from_tunnel` | M2 P2P pickup + fetch in one call. |

The `spize_*` aliases remain callable for the duration of the v1→v2 grace window (ADR-0043) so MCP hosts that cached the legacy names keep working. Each first call to a legacy alias emits a one-shot deprecation note on stderr — `tools/list` flags them DEPRECATED in their description.

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
