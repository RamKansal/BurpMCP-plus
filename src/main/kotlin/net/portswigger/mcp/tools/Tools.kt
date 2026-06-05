package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.HistoryStats
import net.portswigger.mcp.schema.HttpRequestSummary
import net.portswigger.mcp.schema.toDetail
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.schema.toSummary
import net.portswigger.mcp.schema.toWebSocketSummary
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    return (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: return normalizePrelude(content)
    return normalizePrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")   // Literal \r\n escape sequences → LF
    .replace("\\n", "\n")      // Remaining literal \n → LF
    .replace("\\r", "")        // Remaining literal \r → remove
    .replace("\r", "")          // Actual CR → remove
    .replace("\n", "\r\n")      // All LF → proper CRLF

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = normalizeHttpContent(content)

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>(
        "Returns full raw proxy HTTP history entries (entire request + response as strings). HIGH " +
        "TOKEN COST. Prefer get_proxy_http_history_summary to scan the history as a flat table and " +
        "identify entries by id, then get_proxy_http_entry to fetch specific ones in full."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>(
        "Filters proxy HTTP history by regex and returns full raw entries. HIGH TOKEN COST. Prefer " +
        "search_proxy_http_history, which returns matching rows + a snippet instead of full bodies, " +
        "or get_proxy_http_history_summary with the structured filters."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { Json.encodeToString(it.toSerializableForm()) }
    }

    mcpTool<GetProxyHttpHistorySummary>(
        "PRIMARY tool for browsing proxy HTTP history. Returns a flat, ungrouped table — one " +
        "compact row per request (id | method | host | path | status | len | mime), like Burp's " +
        "HTTP history pane. Rows are newest-first by default and preserve send order so you can " +
        "reason about request sequences. Use the 'id' column with get_proxy_http_entry to read a " +
        "full request/response. Browse large histories in chunks with fromId/toId (e.g. toId=390 " +
        "returns requests at or below id 390); after new traffic arrives, use fromId=<lastSeenId+1> " +
        "to fetch ONLY new requests. Optional filters (the LLM decides what is relevant — there is " +
        "no scope filter): hosts, methods, statusCodes, statusMin/statusMax, pathContains, hasNotes, " +
        "hideNoise (drop static assets like js/css/images), dedupe (collapse identical endpoints). " +
        "pathMaxChars caps long paths (default 80). format='json' returns structured rows instead of the table."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history summary")
        }
        if (!allowed) return@mcpTool "HTTP history access denied by Burp Suite"

        renderHistoryTable(api.proxy().history(), this)
    }

    mcpTool<GetProxyHttpEntry>(
        "Returns the full request and response for a single proxy history entry by its Burp 'id' " +
        "(the id column from get_proxy_http_history_summary). Headers are NEVER truncated; large " +
        "bodies are capped (maxBodyBytes, default 50000) and resumable via bodyOffset. " +
        "include = all | request | response | request_headers | response_headers — use the " +
        "*_headers modes when you only need cookies/auth headers. contextBefore/contextAfter also " +
        "return the neighbouring summary rows so you can see what fired around this request."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history entry")
        }
        if (!allowed) return@mcpTool "HTTP history access denied by Burp Suite"

        val history = api.proxy().history()
        if (history.isEmpty()) return@mcpTool "Proxy HTTP history is empty."

        val entry = history.find { it.id() == id }
            ?: run {
                val min = history.minOf { it.id() }
                val max = history.maxOf { it.id() }
                return@mcpTool "No proxy history entry with id=$id. Valid ids range $min..$max (${history.size} total)."
            }

        val detail = entry.toDetail(include ?: "all", maxBodyBytes ?: 50_000, bodyOffset ?: 0)
        val out = StringBuilder(Json.encodeToString(detail))

        val before = (contextBefore ?: 0).coerceIn(0, 50)
        val after = (contextAfter ?: 0).coerceIn(0, 50)
        if (before > 0 || after > 0) {
            val sorted = history.sortedBy { it.id() }
            val idx = sorted.indexOfFirst { it.id() == id }
            if (before > 0) {
                val pre = sorted.subList((idx - before).coerceAtLeast(0), idx)
                if (pre.isNotEmpty()) {
                    out.append("\n\nContext BEFORE (older):\n")
                    out.append(pre.joinToString("\n") { summaryRow(it.toSummary(), 80) })
                }
            }
            if (after > 0) {
                val post = sorted.subList(idx + 1, (idx + 1 + after).coerceAtMost(sorted.size))
                if (post.isNotEmpty()) {
                    out.append("\n\nContext AFTER (newer):\n")
                    out.append(post.joinToString("\n") { summaryRow(it.toSummary(), 80) })
                }
            }
        }

        out.toString()
    }

    mcpTool<SearchProxyHttpHistory>(
        "Searches proxy HTTP history by regex or literal term across raw requests+responses and " +
        "returns matching rows (id | method | host | path | status | len | mime) plus a short " +
        "snippet around each match. NEVER returns full bodies. Use the id with get_proxy_http_entry " +
        "for full detail. Optional filters: hosts, methods, hideNoise. caseSensitive defaults to false."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history search")
        }
        if (!allowed) return@mcpTool "HTTP history access denied by Burp Suite"

        val pattern = regex?.takeIf { it.isNotEmpty() }?.let {
            Pattern.compile(it, if (caseSensitive == true) 0 else Pattern.CASE_INSENSITIVE)
        }
        if (pattern == null && term.isNullOrEmpty()) {
            return@mcpTool "Provide either 'regex' or 'term' to search for."
        }

        val limit = (count ?: 50).coerceIn(1, 500)
        val results = ArrayList<String>()
        for (entry in api.proxy().history().sortedByDescending { it.id() }) {
            val s = entry.toSummary()
            if (hosts != null && hosts.none { s.host.contains(it, ignoreCase = true) }) continue
            if (methods != null && methods.none { it.equals(s.method, ignoreCase = true) }) continue
            if (hideNoise == true && isNoise(s)) continue

            val haystack = (entry.request()?.toString() ?: "") + "\n" + (entry.response()?.toString() ?: "")
            val (matched, snippet) = findSnippet(haystack, pattern, term, caseSensitive == true)
            if (!matched) continue

            results.add(summaryRow(s, 80) + "\n    ↳ " + snippet)
            if (results.size >= limit) break
        }

        if (results.isEmpty()) {
            "No matches found."
        } else {
            val (body, truncated, returned) = joinWithBudget(results, MAX_RESPONSE_CHARS, "\n")
            "META: {\"matches\":${results.size},\"returned\":$returned,\"truncatedForSize\":$truncated}\n$body"
        }
    }

    mcpTool<GetProxyHttpHistoryStats>(
        "Optional fast shape-check over proxy HTTP history. Returns aggregate counts only (per host, " +
        "method, status class, mime class) plus the id range — no per-request data. Useful to size up " +
        "a large history before pulling rows with get_proxy_http_history_summary. topHosts limits the " +
        "host breakdown (default 25)."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history stats")
        }
        if (!allowed) return@mcpTool "HTTP history access denied by Burp Suite"

        val history = api.proxy().history()
        if (history.isEmpty()) return@mcpTool "Proxy HTTP history is empty."

        Json.encodeToString(buildHistoryStats(history, topHosts ?: 25))
    }

    mcpPaginatedTool<GetOrganizerItems>("Displays items within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        api.organizer().items().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetOrganizerItemsRegex>("Displays items matching a specified regex within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.organizer().items { it.contains(compiledRegex) }.asSequence()
            .map { Json.encodeToString(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { Json.encodeToString(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { Json.encodeToString(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistorySummary>(
        "Returns lightweight summaries of proxy WebSocket messages (index, direction, payload size, " +
        "a short payload preview) instead of full payloads. Use this to scan WebSocket traffic; use " +
        "get_proxy_websocket_history for full payloads of specific messages."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history summary")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .mapIndexed { index, message -> Json.encodeToString(message.toWebSocketSummary(index)) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool(
        "get_proxy_tls_passthrough",
        "Returns Burp's current TLS pass-through configuration (the proxy.ssl_pass_through section): " +
        "the list of host rules plus the 'apply to out-of-scope items' and 'auto-add on TLS negotiation " +
        "failure' flags. TLS pass-through tells Burp to NOT intercept/decrypt traffic for matching hosts " +
        "(it forwards the encrypted bytes straight through) — commonly used for certificate-pinned hosts. " +
        "Read-only."
    ) {
        val exported = api.burpSuite().exportProjectOptionsAsJson("proxy.ssl_pass_through")
        val section = Json.parseToJsonElement(exported).jsonObject["proxy"]?.jsonObject?.get("ssl_pass_through")
        section?.toString() ?: exported
    }

    mcpTool<SetProxyTlsPassthrough>(
        "Adds/removes Burp TLS pass-through host rules or toggles its flags. TLS pass-through makes Burp " +
        "forward encrypted traffic for matching hosts WITHOUT intercepting/decrypting it (useful for " +
        "certificate-pinned hosts that break under interception). Hosts are regexes, e.g. '.*\\.example\\.com'. " +
        "Use addHosts / removeHosts to edit the list, replaceAllRules to set it wholesale, and " +
        "applyToOutOfScopeItems / autoAddOnNegotiationFailure to toggle the flags. Unspecified fields are " +
        "left unchanged. Requires 'Enable tools that can edit your config' in the Burp MCP tab."
    ) {
        if (!config.configEditingTooling) return@mcpTool toolingDisabledMessage

        val exported = api.burpSuite().exportProjectOptionsAsJson("proxy.ssl_pass_through")
        val current = Json.parseToJsonElement(exported).jsonObject["proxy"]?.jsonObject
            ?.get("ssl_pass_through")?.jsonObject

        val currentRules = current?.get("rules")?.jsonArray?.map { it.jsonObject } ?: emptyList()
        val applyFlag = applyToOutOfScopeItems
            ?: current?.get("apply_to_out_of_scope_items")?.jsonPrimitive?.booleanOrNull ?: true
        val autoAddFlag = autoAddOnNegotiationFailure
            ?: current?.get("automatically_add_entries_on_client_ssl_negotiation_failure")?.jsonPrimitive?.booleanOrNull
            ?: false

        fun hostOf(rule: JsonObject) = rule["host"]?.jsonPrimitive?.contentOrNull ?: ""

        val rulePort = port ?: "443"
        val ruleProtocol = protocol ?: "any"

        val newRules: List<JsonObject> = if (replaceAllRules != null) {
            replaceAllRules.filter { it.isNotBlank() }.map { tlsPassthroughRule(it, rulePort, ruleProtocol) }
        } else {
            val list = currentRules.toMutableList()
            if (removeHosts != null) list.removeAll { hostOf(it) in removeHosts }
            if (addHosts != null) {
                val present = list.map { hostOf(it) }.toSet()
                for (host in addHosts) {
                    if (host.isNotBlank() && host !in present) list.add(tlsPassthroughRule(host, rulePort, ruleProtocol))
                }
            }
            list
        }

        val section = buildJsonObject {
            put("apply_to_out_of_scope_items", applyFlag)
            put("automatically_add_entries_on_client_ssl_negotiation_failure", autoAddFlag)
            put("rules", JsonArray(newRules))
        }
        val payload = buildJsonObject {
            put("proxy", buildJsonObject { put("ssl_pass_through", section) })
        }

        api.logging().logToOutput("MCP updating TLS pass-through (${newRules.size} rule(s))")
        api.burpSuite().importProjectOptionsFromJson(payload.toString())

        // Read the ACTUAL stored config back from Burp so we never report a phantom success.
        val verifyExport = api.burpSuite().exportProjectOptionsAsJson("proxy.ssl_pass_through")
        val stored = Json.parseToJsonElement(verifyExport).jsonObject["proxy"]?.jsonObject?.get("ssl_pass_through")
        val storedCount = stored?.jsonObject?.get("rules")?.jsonArray?.size ?: 0

        if (storedCount != newRules.size) {
            "WARNING: requested ${newRules.size} rule(s) but Burp stored $storedCount — Burp rejected some " +
                "entries. Current ssl_pass_through:\n${stored ?: verifyExport}"
        } else {
            "TLS pass-through updated ($storedCount rule(s)). Burp now reports:\n${stored ?: verifyExport}"
        }
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetProxyTlsPassthrough(
    val addHosts: List<String>? = null,
    val removeHosts: List<String>? = null,
    val replaceAllRules: List<String>? = null,
    val applyToOutOfScopeItems: Boolean? = null,
    val autoAddOnNegotiationFailure: Boolean? = null,
    val port: String? = null,
    val protocol: String? = null,
)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItems(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItemsRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)

// ---------------------------------------------------------------------------
// LLM-friendly HTTP history tools. All params are nullable so the MCP input
// schema marks them optional (JsonSchema treats only non-nullable props as
// required); defaults are applied in code.
// ---------------------------------------------------------------------------

@Serializable
data class GetProxyHttpHistorySummary(
    val fromId: Int? = null,
    val toId: Int? = null,
    val count: Int? = null,
    val offset: Int? = null,
    val oldestFirst: Boolean? = null,
    val pathMaxChars: Int? = null,
    val format: String? = null,
    val hosts: List<String>? = null,
    val methods: List<String>? = null,
    val statusCodes: List<Int>? = null,
    val statusMin: Int? = null,
    val statusMax: Int? = null,
    val pathContains: String? = null,
    val hasNotes: Boolean? = null,
    val hideNoise: Boolean? = null,
    val dedupe: Boolean? = null,
)

@Serializable
data class GetProxyHttpEntry(
    val id: Int,
    val include: String? = null,
    val maxBodyBytes: Int? = null,
    val bodyOffset: Int? = null,
    val contextBefore: Int? = null,
    val contextAfter: Int? = null,
)

@Serializable
data class SearchProxyHttpHistory(
    val regex: String? = null,
    val term: String? = null,
    val caseSensitive: Boolean? = null,
    val count: Int? = null,
    val hosts: List<String>? = null,
    val methods: List<String>? = null,
    val hideNoise: Boolean? = null,
)

@Serializable
data class GetProxyHttpHistoryStats(
    val topHosts: Int? = null,
)

@Serializable
data class GetProxyWebsocketHistorySummary(override val count: Int, override val offset: Int) : Paginated

private fun tlsPassthroughRule(host: String, port: String, protocol: String): JsonObject = buildJsonObject {
    put("enabled", true)
    put("host", host)
    put("port", port)
    put("protocol", protocol)
}

// ----- helpers for the flat-table history tools -----

private fun summaryRow(s: HttpRequestSummary, pathMax: Int): String {
    val path = if (s.path.length > pathMax) s.path.take((pathMax - 1).coerceAtLeast(1)) + "…" else s.path
    return "${s.id} | ${s.method} | ${s.host} | $path | ${s.statusCode} | ${s.responseSize} | ${shortMime(s.mimeType)}"
}

private fun shortMime(name: String?): String = when {
    name == null -> ""
    name == "JSON" -> "json"
    name == "HTML" -> "html"
    name == "CSS" -> "css"
    name == "SCRIPT" -> "script"
    name == "XML" -> "xml"
    name == "PLAIN_TEXT" -> "text"
    name == "NONE" || name == "UNKNOWN" -> ""
    name.startsWith("IMAGE") -> "image"
    name.startsWith("FONT") -> "font"
    name == "SOUND" || name == "VIDEO" -> "media"
    else -> name.lowercase()
}

private fun statusClass(code: Int): String = when (code) {
    in 100..199 -> "1xx"
    in 200..299 -> "2xx"
    in 300..399 -> "3xx"
    in 400..499 -> "4xx"
    in 500..599 -> "5xx"
    else -> "none"
}

private val NOISE_EXTENSIONS = setOf(
    "js", "css", "png", "gif", "svg", "ico", "woff", "woff2", "map", "jpg", "jpeg", "webp", "ttf", "eot"
)

private fun isNoise(s: HttpRequestSummary): Boolean {
    when (shortMime(s.mimeType)) {
        "script", "css", "image", "font", "media" -> return true
    }
    val cleanPath = s.path.substringBefore('?').substringBefore('#')
    val ext = cleanPath.substringAfterLast('.', "").lowercase()
    return ext.isNotEmpty() && ext in NOISE_EXTENSIONS
}

private fun findSnippet(
    haystack: String,
    pattern: Pattern?,
    term: String?,
    caseSensitive: Boolean,
): Pair<Boolean, String> {
    val idx: Int
    val matchLen: Int
    if (pattern != null) {
        val m = pattern.matcher(haystack)
        if (!m.find()) return false to ""
        idx = m.start()
        matchLen = (m.end() - m.start()).coerceAtLeast(1)
    } else if (!term.isNullOrEmpty()) {
        idx = haystack.indexOf(term, ignoreCase = !caseSensitive)
        if (idx < 0) return false to ""
        matchLen = term.length
    } else {
        return false to ""
    }
    val start = (idx - 60).coerceAtLeast(0)
    val end = (idx + matchLen + 60).coerceAtMost(haystack.length)
    val snippet = haystack.substring(start, end).replace('\n', ' ').replace('\r', ' ').trim()
    return true to "…$snippet…"
}

private fun buildHistoryStats(history: List<ProxyHttpRequestResponse>, topHosts: Int): HistoryStats {
    val byHost = HashMap<String, Int>()
    val byMethod = HashMap<String, Int>()
    val byStatus = HashMap<String, Int>()
    val byMime = HashMap<String, Int>()
    for (entry in history) {
        val s = entry.toSummary()
        byHost.merge(s.host.ifEmpty { "(unknown)" }, 1) { a, b -> a + b }
        byMethod.merge(s.method.ifEmpty { "(none)" }, 1) { a, b -> a + b }
        byStatus.merge(statusClass(s.statusCode), 1) { a, b -> a + b }
        byMime.merge(shortMime(s.mimeType).ifEmpty { "(none)" }, 1) { a, b -> a + b }
    }
    val topHostMap = byHost.entries.sortedByDescending { it.value }
        .take(topHosts.coerceAtLeast(1))
        .associate { it.key to it.value }
    return HistoryStats(
        total = history.size,
        idRange = "${history.minOf { it.id() }}..${history.maxOf { it.id() }}",
        byHost = topHostMap,
        byMethod = byMethod.toSortedMap(),
        byStatusClass = byStatus.toSortedMap(),
        byMimeClass = byMime.toSortedMap(),
    )
}

private fun renderHistoryTable(history: List<ProxyHttpRequestResponse>, p: GetProxyHttpHistorySummary): String {
    val total = history.size
    if (total == 0) return "META: {\"total\":0}\nNo requests in proxy HTTP history yet."

    val minId = history.minOf { it.id() }
    val maxId = history.maxOf { it.id() }

    val fromId = p.fromId
    val toIdParam = p.toId
    val hosts = p.hosts
    val methods = p.methods
    val statusCodes = p.statusCodes
    val statusMin = p.statusMin
    val statusMax = p.statusMax
    val pathContains = p.pathContains
    val hasNotes = p.hasNotes
    val hideNoise = p.hideNoise == true
    val dedupe = p.dedupe == true

    // Past-the-end fromId: clear signal (also = "nothing new since last poll").
    if (fromId != null && fromId > maxId) {
        return "META: {\"total\":$total,\"idRange\":\"$minId..$maxId\",\"returned\":0}\n" +
            "No requests with id >= $fromId. Highest id in history is $maxId ($total total)."
    }

    // Clamp an over-shooting toId instead of erroring.
    var clampedToId: Int? = null
    val effectiveToId = if (toIdParam != null && toIdParam > maxId) {
        clampedToId = maxId
        maxId
    } else {
        toIdParam
    }

    val pathMax = (p.pathMaxChars ?: 80).coerceIn(8, 4000)

    var filtered = history.asSequence()
        .map { it.toSummary() }
        .filter { fromId == null || it.id >= fromId }
        .filter { effectiveToId == null || it.id <= effectiveToId }
        .filter { s -> hosts == null || hosts.any { s.host.contains(it, ignoreCase = true) } }
        .filter { s -> methods == null || methods.any { it.equals(s.method, ignoreCase = true) } }
        .filter { statusCodes == null || statusCodes.contains(it.statusCode) }
        .filter { statusMin == null || it.statusCode >= statusMin }
        .filter { statusMax == null || it.statusCode <= statusMax }
        .filter { s -> pathContains == null || s.path.contains(pathContains, ignoreCase = true) }
        .filter { hasNotes == null || (hasNotes == (it.notes != null)) }
        .filter { !hideNoise || !isNoise(it) }
        .toList()

    val occurrences = HashMap<Int, Int>()
    if (dedupe) {
        val seen = LinkedHashMap<String, HttpRequestSummary>()
        for (s in filtered) {
            val key = "${s.method} ${s.host} ${s.path.substringBefore('?')}"
            val existing = seen[key]
            if (existing == null) {
                seen[key] = s
                occurrences[s.id] = 1
            } else {
                occurrences[existing.id] = (occurrences[existing.id] ?: 1) + 1
            }
        }
        filtered = seen.values.toList()
    }

    val matched = filtered.size
    if (matched == 0) {
        return "META: {\"total\":$total,\"idRange\":\"$minId..$maxId\",\"matched\":0,\"returned\":0}\n" +
            "No requests match the given filters."
    }

    val ordered = if (p.oldestFirst == true) filtered.sortedBy { it.id } else filtered.sortedByDescending { it.id }

    val offset = (p.offset ?: 0).coerceAtLeast(0)
    val count = (p.count ?: 100).coerceAtLeast(1)

    if (offset >= matched) {
        return "META: {\"total\":$total,\"idRange\":\"$minId..$maxId\",\"matched\":$matched,\"returned\":0,\"offset\":$offset}\n" +
            "Offset $offset is past the $matched matched rows."
    }

    val upper = (offset + count).coerceAtMost(matched)
    val page = ordered.subList(offset, upper)

    if ((p.format ?: "table").equals("json", ignoreCase = true)) {
        val rowJsons = page.map { Json.encodeToString(it) }
        val (joined, truncated, returned) = joinWithBudget(rowJsons, MAX_RESPONSE_CHARS, ",")
        val hasMore = offset + returned < matched
        val meta = "META: {\"total\":$total,\"idRange\":\"$minId..$maxId\",\"matched\":$matched," +
            "\"returned\":$returned,\"offset\":$offset,\"hasMore\":$hasMore,\"truncatedForSize\":$truncated" +
            (clampedToId?.let { ",\"clampedToId\":$it" } ?: "") + "}"
        return "$meta\n[$joined]"
    }

    val rows = page.map { s ->
        val occ = if (dedupe) " x${occurrences[s.id] ?: 1}" else ""
        summaryRow(s, pathMax) + occ
    }
    val (body, truncated, returned) = joinWithBudget(rows, MAX_RESPONSE_CHARS, "\n")
    val shown = page.take(returned)
    val hasMore = offset + returned < matched
    val atEnd = !hasMore
    val firstId = shown.first().id
    val lastId = shown.last().id

    val meta = StringBuilder("META: {")
    meta.append("\"total\":$total,\"idRange\":\"$minId..$maxId\",\"matched\":$matched,")
    meta.append("\"returned\":$returned,\"returnedIds\":\"$firstId..$lastId\",\"offset\":$offset,")
    if (fromId != null) meta.append("\"requestedFrom\":$fromId,")
    if (toIdParam != null) meta.append("\"requestedTo\":$toIdParam,")
    if (clampedToId != null) meta.append("\"clampedToId\":$clampedToId,")
    meta.append("\"hasMore\":$hasMore,\"atEnd\":$atEnd,\"truncatedForSize\":$truncated}")

    val header = "# id | method | host | path | status | len | mime"
    val out = StringBuilder()
    out.append(meta).append('\n').append(header).append('\n').append(body)
    when {
        truncated -> {
            val hint = if (p.oldestFirst == true) "fromId=${lastId + 1}" else "toId=${lastId - 1}"
            out.append("\n... output truncated for size after id $lastId — request the next chunk with $hint.")
        }
        atEnd -> out.append("\n--- END OF HISTORY (no more rows in this direction; last id $lastId, $total total) ---")
    }
    return out.toString()
}
