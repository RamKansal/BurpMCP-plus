# BurpMCP LLM-Friendly HTTP History Overhaul

## The Problem

The current `get_proxy_http_history` tool is **catastrophically unusable** for LLMs in real-world pentesting:

1. **Data Explosion**: A typical pentest session has 3,000-4,000 HTTP history items. The tool dumps the **full raw request AND full raw response** for every single one. That's easily 50-100MB of text.

2. **LLM Output Cap**: Most LLMs cap at ~1MB of output. When the response is too large, it gets **truncated mid-stream** — cookies get cut off, auth headers disappear, response bodies are incomplete. The data you get is unreliable.

3. **Zero Intelligence in Filtering**: The only filter is regex (which searches the raw text) and dumb pagination (offset+count). There's no way to say "show me only POST requests to api.dyson.com" or "what endpoints return JSON?"

4. **Trash Analytics Pollution**: Real browsing generates hundreds of requests to analytics domains (google-analytics, doubleclick, facebook pixel, hotjar, etc.). These are **useless** for pentesting but flood the history.

5. **Dumb Truncation**: The 5,000-char truncation (`truncateIfNeeded`) just chops at character 5000. Headers (containing cookies, auth tokens, CSRF tokens) often appear AFTER the response body starts — so the important stuff gets cut while useless HTML is preserved.

6. **No Metadata Layer**: An LLM needs to **browse before diving deep**. Currently there's no way to get an overview of what's in the history without downloading everything.

7. **No Deduplication**: The same endpoint hit 50 times produces 50 full copies of the request+response. An LLM doesn't need 50 copies of `GET /favicon.ico`.

8. **Wasted Rich API**: The Montoya API provides `id()`, `time()`, `mimeType()`, `request().method()`, `request().url()`, `request().path()`, `request().parameters()`, `request().hasParameters()`, `request().contentType()`, `request().fileExtension()`, `response().statusCode()`, `response().mimeType()`, `response().headers()`, `response().cookies()`, and much more. The current code ignores ALL of this and just calls `.toString()`.

---

## The Solution: A 3-Tier LLM-Friendly Architecture

The core insight: **LLMs need to browse → filter → inspect**, not get blasted with everything.

### TIER 1: `get_http_history_overview` — The Map

**Purpose**: Give the LLM a bird's-eye view of the entire history in a single, small response.

**Parameters**: None (or optional `exclude_analytics: Boolean = true`)

**Returns** (structured JSON):
```json
{
  "total_items": 3847,
  "unique_hosts": ["api.dyson.com", "www.dyson.com", "cdn.dyson.com", "accounts.dyson.com"],
  "analytics_hosts_filtered": 142,
  "by_method": {"GET": 2100, "POST": 580, "PUT": 45, "DELETE": 12, "OPTIONS": 310, "HEAD": 30},
  "by_status": {"2xx": 1800, "3xx": 450, "4xx": 380, "5xx": 12, "no_response": 5},
  "by_mime_type": {"JSON": 890, "HTML": 650, "JavaScript": 420, "CSS": 180, "Image": 340, "Other": 167},
  "hosts_detail": [
    {"host": "api.dyson.com", "count": 1200, "methods": ["GET", "POST", "PUT"], "has_params": 890},
    {"host": "www.dyson.com", "count": 800, "methods": ["GET", "POST"], "has_params": 120}
  ],
  "time_range": {"earliest": "2025-06-05T10:00:00Z", "latest": "2025-06-05T14:30:00Z"}
}
```

**Why this matters**: In ONE tool call the LLM knows: "Okay, there are 3847 items, mostly targeting api.dyson.com and www.dyson.com. 142 analytics requests filtered out. Lots of GET+POST to the API. Let me look at the API endpoints."

**Size**: ~1-2KB regardless of history size. Always fits in context.

---

### TIER 2: `search_http_history` — The Smart Filter

**Purpose**: Search and list history items with rich filters, returning **compact metadata only** (no request/response bodies).

**Parameters**:
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | `String?` | null | Filter by host (supports wildcards: `*.dyson.com`) |
| `method` | `String?` | null | HTTP method filter (GET, POST, etc.) |
| `path_pattern` | `String?` | null | Regex for URL path (e.g., `/api/v[12]/users.*`) |
| `status_code` | `String?` | null | Status code filter: exact (`200`), range (`4xx`), or comma-separated (`200,201,302`) |
| `mime_type` | `String?` | null | Response MIME type filter (JSON, HTML, XML, etc.) |
| `has_params` | `Boolean?` | null | Only items with query/body parameters |
| `search` | `String?` | null | Free-text search in request+response |
| `exclude_analytics` | `Boolean` | true | Filter out common analytics/tracking domains |
| `deduplicate` | `Boolean` | false | Group by method+path, return unique endpoints only |
| `count` | `Int` | 50 | Max items to return |
| `offset` | `Int` | 0 | Pagination offset |

**Returns** (compact metadata per item):
```json
[
  {
    "id": 42,
    "time": "2025-06-05T10:15:32Z",
    "method": "POST",
    "url": "https://api.dyson.com/v1/auth/login",
    "status": 200,
    "mime_type": "JSON",
    "request_content_type": "application/json",
    "request_size": 156,
    "response_size": 1842,
    "has_params": true,
    "param_names": ["email", "password"],
    "notes": ""
  },
  ...
]
```

**If `deduplicate: true`**:
```json
[
  {
    "method": "POST",
    "path": "/v1/auth/login",
    "host": "api.dyson.com",
    "count": 3,
    "status_codes": [200, 401],
    "item_ids": [42, 67, 123]
  },
  ...
]
```

**Why this matters**: The LLM can now say: "Show me all POST requests to api.dyson.com that return JSON" and get back a clean list of 50 entries with IDs, each ~200 bytes. That's 10KB instead of 10MB. Then it picks the interesting ones.

**Size**: ~200 bytes per item × 50 items = ~10KB. Always manageable.

---

### TIER 3: `get_http_history_detail` — The Microscope

**Purpose**: Retrieve the full request/response for specific items by ID, with smart controls over what's included.

**Parameters**:
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ids` | `List<Int>` | required | Item IDs (from Tier 2 search) |
| `include_request_headers` | `Boolean` | true | Include request headers |
| `include_request_body` | `Boolean` | true | Include request body |
| `include_response_headers` | `Boolean` | true | Include response headers |
| `include_response_body` | `Boolean` | false | **OFF by default** — this is the big one |
| `max_body_size` | `Int` | 10000 | Max chars per body (smart truncation) |

**Smart Truncation** (replaces the dumb 5000-char cutoff):
- Headers are NEVER truncated (cookies, auth tokens, CSRF tokens are critical)
- Body truncation includes a note: `"... [truncated, 45230 chars total]"`
- Binary content detection: returns `"[binary content, 23KB, mime: image/png]"` instead of garbage

**Returns**:
```json
[
  {
    "id": 42,
    "method": "POST",
    "url": "https://api.dyson.com/v1/auth/login",
    "status": 200,
    "request_headers": "POST /v1/auth/login HTTP/1.1\r\nHost: api.dyson.com\r\nCookie: session=abc123...\r\nContent-Type: application/json\r\n",
    "request_body": "{\"email\":\"test@test.com\",\"password\":\"****\"}",
    "response_headers": "HTTP/1.1 200 OK\r\nSet-Cookie: auth_token=xyz789...\r\nContent-Type: application/json\r\n",
    "response_body": null
  }
]
```

**Why this matters**: The LLM asks for exactly what it needs. "Give me items 42, 67, and 123 with request+response headers but skip response bodies." It gets 3 focused items instead of 3000 full dumps.

**Size**: Fully controlled. Headers-only for 5 items is ~5KB. With response bodies enabled and capped at 10K, worst case ~55KB.

---

### Built-in Analytics Domain Filter

A hardcoded set of common analytics/tracking domains that pollute HTTP history. Applied by default in Tier 1 and Tier 2.

```
google-analytics.com, googletagmanager.com, doubleclick.net, 
facebook.com/tr, connect.facebook.net, analytics.google.com,
hotjar.com, clarity.ms, newrelic.com, sentry.io,
segment.io, mixpanel.com, amplitude.com, 
cdn.cookielaw.org, onetrust.com, cookiebot.com,
fonts.googleapis.com, fonts.gstatic.com,
*.cloudfront.net (common CDN patterns), etc.
```

The user can opt out with `exclude_analytics: false`.

---

## LLM Workflow Example

Here's how an LLM would actually use these tools during a pentest:

```
Step 1: LLM calls get_http_history_overview()
→ "I see 3847 items across 12 hosts. api.dyson.com has 1200 hits, mostly GET/POST. Let me explore the API."

Step 2: LLM calls search_http_history(host="api.dyson.com", method="POST", deduplicate=true)
→ "Found 23 unique POST endpoints. /v1/auth/login, /v1/user/profile, /v1/cart/add, /v1/payment/process..."

Step 3: LLM calls search_http_history(host="api.dyson.com", has_params=true, status_code="4xx")
→ "12 requests returned 4xx. Items 42, 67, 89 look like auth failures. Let me inspect them."

Step 4: LLM calls get_http_history_detail(ids=[42, 67, 89], include_response_body=true, max_body_size=5000)
→ Gets exactly 3 items with full context. Notices an IDOR pattern in the error messages.

Step 5: LLM crafts and sends a test request via send_http1_request to confirm the IDOR.
```

**Total data transferred**: ~20KB across 4 calls instead of 50MB in one call.

---

## Implementation Plan

### Files to Modify

1. **`src/main/kotlin/net/portswigger/mcp/schema/serialization.kt`**
   - Add new data classes: `HttpHistoryOverview`, `HttpHistorySearchResult`, `HttpHistoryDetail`, `HostSummary`, `DeduplicatedEntry`
   - Add `toMetadataForm()` extension on `ProxyHttpRequestResponse` (extracts structured metadata without full body)
   - Add `toDetailForm()` extension with configurable include flags

2. **`src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`**
   - Add `get_http_history_overview` tool (new data class + handler)
   - Add `search_http_history` tool (new data class with all filter params + handler)
   - Add `get_http_history_detail` tool (new data class + handler)
   - Keep existing `get_proxy_http_history` and `get_proxy_http_history_regex` for backwards compatibility
   - Add analytics domain filter constant

3. **`src/main/kotlin/net/portswigger/mcp/tools/McpTool.kt`**
   - No changes needed — existing `mcpTool` infrastructure supports the new tools

4. **`src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`**
   - Add tests for overview tool
   - Add tests for search filtering (host, method, status, path, dedup)
   - Add tests for detail tool (include/exclude flags, smart truncation)
   - Add tests for analytics domain filtering

### Implementation Order

1. **Phase 1**: New serializable data classes in `serialization.kt`
2. **Phase 2**: Analytics domain filter + helper functions
3. **Phase 3**: `get_http_history_overview` tool
4. **Phase 4**: `search_http_history` tool
5. **Phase 5**: `get_http_history_detail` tool  
6. **Phase 6**: Tests for all new tools
7. **Phase 7**: Update tool descriptions to guide LLMs toward the new workflow

### Backwards Compatibility

The existing `get_proxy_http_history` and `get_proxy_http_history_regex` tools remain unchanged. They still work, but the new tools are designed to be what LLMs actually reach for. The tool descriptions will guide LLMs toward the new workflow.

---

## Summary

| | Current | After |
|---|---------|-------|
| **Get overview of 4000 items** | Impossible without downloading all | 1 call, ~2KB |
| **Find POST endpoints** | Download all, hope regex works | 1 call, ~10KB |
| **Inspect specific request** | Page through offset/count, get full dump | 1 call, ~2KB per item |
| **Analytics noise** | Mixed in with everything | Filtered by default |
| **Duplicate requests** | 50 copies of same endpoint | Deduplicated view |
| **Cookie/auth preservation** | Truncated at 5000 chars randomly | Headers never truncated |
| **Binary content** | Garbage text dump | Clean placeholder |
| **Total data for typical workflow** | 50-100MB | 20-50KB |
