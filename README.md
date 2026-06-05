# BurpMCP+

**An LLM-friendly Burp Suite MCP server.** A fork of PortSwigger's official
[mcp-server](https://github.com/PortSwigger/mcp-server) that makes Burp's proxy history
actually usable by AI clients: a flat, scannable request table instead of a multi-megabyte
raw dump, on-demand full entries (with cookies/headers never truncated), content search,
WebSocket summaries, and one-call **TLS pass-through** management to silence tracker noise.

Built for real engagements where the proxy history is 3,000–4,000+ requests and most of it is
analytics garbage.

---

## Installation

### Option 1 — Download the release (recommended)

1. Download **[`burpmcp-plus.jar`](https://github.com/RamKansal/BurpMCP/releases/latest/download/burpmcp-plus.jar)**
   from the [latest release](https://github.com/RamKansal/BurpMCP/releases).
2. In Burp: **Extensions** → **Add**
   - **Extension type:** `Java`
   - **Select file…** → choose `burpmcp-plus.jar`
   - **Next** → wait for it to load → **Close**
3. Open the **MCP** tab in Burp, tick **Enabled**, and note the server address
   (default `http://127.0.0.1:9876`).

> Upgrading from the stock extension or an older build? Untick/Remove the old MCP extension
> first so they don't both bind the port, then reconnect your MCP client.

### Option 2 — Build from source

**Prerequisites:** Java 21 on your `PATH`, and the `jar` command available.

```bash
./gradlew embedProxyJar
```

Output: **`build/libs/burpmcp-plus.jar`**. Load it into Burp exactly as in Option 1.

---

## Connect your AI client

BurpMCP+ exposes an **SSE MCP server** at the address shown in the MCP tab
(default `http://127.0.0.1:9876`). Point your client at it:

```
http://127.0.0.1:9876
```
or, depending on the client, with the SSE path:
```
http://127.0.0.1:9876/sse
```

For clients that only speak stdio (e.g. Claude Desktop), the extension's installer can wire up
the bundled stdio proxy automatically — see the **MCP** tab in Burp. The first time a tool reads
history, Burp shows a data-access approval prompt; click **Allow**.

---

## What BurpMCP+ adds

The original extension returned the *entire* proxy history as raw request/response strings and
truncated each entry at 5,000 chars — corrupting cookies and blowing past most clients' ~1 MB
limit. BurpMCP+ replaces that with a triage-first toolset.

| Tool | What it does |
|---|---|
| **`get_proxy_http_history_summary`** | **Primary view.** A flat, newest-first table — one compact row per request (`id \| method \| host \| path \| status \| len \| mime`), like Burp's HTTP history pane. Range-chunked (`fromId`/`toId`), filterable (`hosts`, `methods`, `statusCodes`, `hideNoise`, `dedupe`, …), and hard-capped so output never exceeds the size limit. |
| **`get_proxy_http_entry`** | Full request + response for one entry by its Burp `id`. **Headers/cookies are never truncated;** large bodies cap at `maxBodyBytes` and resume via `bodyOffset`. `contextBefore`/`contextAfter` show the surrounding request sequence. |
| **`search_proxy_http_history`** | Regex/term search across raw requests+responses → matching rows **+ a snippet** around each hit. Never dumps full bodies. |
| **`get_proxy_http_history_stats`** | Aggregate shape-check: counts per host / method / status-class / mime-class + id range. ~1–3 KB for any history size. |
| **`get_proxy_websocket_history_summary`** | Lightweight WebSocket message summaries (direction, size, preview) instead of full payloads. |
| **`get_proxy_tls_passthrough`** | Read Burp's TLS pass-through configuration (rules + flags). |
| **`set_proxy_tls_passthrough`** | Add/remove TLS pass-through host rules and toggle flags — exclude noisy trackers from interception at the source. Reads back from Burp to confirm what was actually stored. |

### The workflow

```
stats()                          → see the shape; spot the noisy hosts
summary(hideNoise, dedupe)       → flat table of what matters; pick an id
entry(id, contextAfter=5)        → full request/response + what fired after it
search(regex="Authorization")    → locate where a token/header lives
set_proxy_tls_passthrough(...)   → silence the trackers so history stays clean
```

Everything from the original extension (HTTP/1.1 & HTTP/2 sending, Repeater/Intruder, scanner
issues, Collaborator, encoders, config import/export, …) is unchanged and still available.

---

## Credits

Forked from PortSwigger's [Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
(Daniel S & Daniel Allen, PortSwigger). Licensed under the same terms — see [LICENSE](LICENSE).
