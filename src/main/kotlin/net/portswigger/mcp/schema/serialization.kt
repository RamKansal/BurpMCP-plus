package net.portswigger.mcp.schema

import burp.api.montoya.collaborator.Interaction as CollaboratorInteraction
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.websocket.Direction
import kotlinx.serialization.Serializable

fun AuditIssue.toSerializableForm(): IssueDetails {
    return IssueDetails(
        name = name(),
        detail = detail(),
        remediation = remediation(),
        httpService = HttpService(
            host = httpService().host(),
            port = httpService().port(),
            secure = httpService().secure()
        ),
        baseUrl = baseUrl(),
        severity = AuditIssueSeverity.valueOf(severity().name),
        confidence = AuditIssueConfidence.valueOf(confidence().name),
        requestResponses = requestResponses().map { it.toSerializableForm() },
        collaboratorInteractions = collaboratorInteractions().map {
            Interaction(
                interactionId = it.id().toString(),
                timestamp = it.timeStamp().toString()
            )
        },
        definition = AuditIssueDefinition(
            id = definition().name(),
            background = definition().background(),
            remediation = definition().remediation(),
            typeIndex = definition().typeIndex(),
        )
    )
}

fun burp.api.montoya.http.message.HttpRequestResponse.toSerializableForm(): HttpRequestResponse {
    return HttpRequestResponse(
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

fun ProxyHttpRequestResponse.toSerializableForm(): HttpRequestResponse {
    return HttpRequestResponse(
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

fun OrganizerItem.toSerializableForm(): OrganizerItemDetails {
    return OrganizerItemDetails(
        id = id(),
        status = status().displayName(),
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

fun ProxyWebSocketMessage.toSerializableForm(): WebSocketMessage {
    return WebSocketMessage(
        payload = payload()?.toString() ?: "<no payload>",
        direction =
            if (direction() == Direction.CLIENT_TO_SERVER)
                WebSocketMessageDirection.CLIENT_TO_SERVER
            else
                WebSocketMessageDirection.SERVER_TO_CLIENT,
        notes = annotations().notes()
    )
}

// ---------------------------------------------------------------------------
// LLM-friendly summary / detail forms for the flat-table HTTP history workflow.
// toSummary() = one lightweight row; toDetail() = full entry with header-safe
// body capping. The stable handle is entry.id() (Burp's "#" column), never an
// array index.
// ---------------------------------------------------------------------------

@Serializable
data class HttpRequestSummary(
    val id: Int,
    val method: String,
    val host: String,
    val path: String,
    val statusCode: Int,
    val statusMessage: String,
    val requestSize: Int,
    val responseSize: Int,
    val mimeType: String?,
    val hasParams: Boolean,
    val time: String,
    val notes: String?,
)

@Serializable
data class HttpRequestDetail(
    val id: Int,
    val request: String?,
    val response: String?,
    val host: String,
    val port: Int,
    val protocol: String,
    val truncatedBody: Boolean,
    val notes: String?,
)

@Serializable
data class WebSocketSummary(
    val index: Int,
    val direction: WebSocketMessageDirection,
    val payloadSize: Int,
    val payloadPreview: String,
    val notes: String?,
)

@Serializable
data class HistoryStats(
    val total: Int,
    val idRange: String,
    val byHost: Map<String, Int>,
    val byMethod: Map<String, Int>,
    val byStatusClass: Map<String, Int>,
    val byMimeClass: Map<String, Int>,
)

fun ProxyHttpRequestResponse.toSummary(): HttpRequestSummary {
    val req = request()
    val res = response()
    return HttpRequestSummary(
        id = id(),
        method = req?.method() ?: "",
        host = httpService()?.host() ?: req?.httpService()?.host() ?: "",
        path = req?.path() ?: "",
        statusCode = res?.statusCode()?.toInt() ?: 0,
        statusMessage = res?.reasonPhrase() ?: "",
        requestSize = req?.toByteArray()?.length() ?: 0,
        responseSize = res?.toByteArray()?.length() ?: 0,
        mimeType = mimeType()?.name,
        hasParams = req?.hasParameters() ?: false,
        time = time()?.toString() ?: "",
        notes = annotations().notes().takeIf { it.isNotBlank() },
    )
}

private fun splitPreludeBody(raw: String): Pair<String, String> {
    val crlf = raw.indexOf("\r\n\r\n")
    if (crlf >= 0) return raw.substring(0, crlf + 4) to raw.substring(crlf + 4)
    val lf = raw.indexOf("\n\n")
    if (lf >= 0) return raw.substring(0, lf + 2) to raw.substring(lf + 2)
    return raw to ""
}

/**
 * Reassembles a raw HTTP message keeping headers verbatim (never truncated) and
 * capping only the body. Returns (text, wasTruncated). With headersOnly=true the
 * body is dropped entirely and replaced with a one-line marker.
 */
private fun capMessage(raw: String, headersOnly: Boolean, maxBodyBytes: Int, bodyOffset: Int): Pair<String, Boolean> {
    val (prelude, body) = splitPreludeBody(raw)
    if (headersOnly) {
        return if (body.isNotEmpty()) {
            prelude + "[body omitted: ${body.length} bytes — refetch with include=all]" to true
        } else {
            prelude to false
        }
    }
    val start = bodyOffset.coerceIn(0, body.length)
    val end = (start + maxBodyBytes.coerceAtLeast(0)).coerceAtMost(body.length)
    val slice = body.substring(start, end)
    val truncated = start > 0 || end < body.length
    val marker = if (truncated) {
        "\n...[showing body bytes $start..$end of ${body.length} — refetch with bodyOffset=$end]"
    } else {
        ""
    }
    return prelude + slice + marker to truncated
}

fun ProxyHttpRequestResponse.toDetail(
    include: String = "all",
    maxBodyBytes: Int = 50_000,
    bodyOffset: Int = 0,
): HttpRequestDetail {
    val svc = httpService()
    val rawReq = request()?.toString() ?: "<no request>"
    val rawRes = response()?.toString() ?: "<no response>"

    var truncated = false
    fun cap(raw: String, headersOnly: Boolean): String {
        val (text, t) = capMessage(raw, headersOnly, maxBodyBytes, bodyOffset)
        if (t) truncated = true
        return text
    }

    val request: String?
    val response: String?
    when (include.lowercase()) {
        "request" -> { request = cap(rawReq, false); response = null }
        "response" -> { request = null; response = cap(rawRes, false) }
        "request_headers" -> { request = cap(rawReq, true); response = null }
        "response_headers" -> { request = null; response = cap(rawRes, true) }
        else -> { request = cap(rawReq, false); response = cap(rawRes, false) }
    }

    return HttpRequestDetail(
        id = id(),
        request = request,
        response = response,
        host = svc?.host() ?: "",
        port = svc?.port() ?: 0,
        protocol = if (svc?.secure() == true) "https" else "http",
        truncatedBody = truncated,
        notes = annotations().notes().takeIf { it.isNotBlank() },
    )
}

fun ProxyWebSocketMessage.toWebSocketSummary(index: Int): WebSocketSummary {
    val payload = payload()?.toString() ?: ""
    return WebSocketSummary(
        index = index,
        direction = if (direction() == Direction.CLIENT_TO_SERVER) {
            WebSocketMessageDirection.CLIENT_TO_SERVER
        } else {
            WebSocketMessageDirection.SERVER_TO_CLIENT
        },
        payloadSize = payload.length,
        payloadPreview = payload.take(150),
        notes = annotations().notes().takeIf { it.isNotBlank() },
    )
}

@Serializable
data class IssueDetails(
    val name: String?,
    val detail: String?,
    val remediation: String?,
    val httpService: HttpService?,
    val baseUrl: String?,
    val severity: AuditIssueSeverity,
    val confidence: AuditIssueConfidence,
    val requestResponses: List<HttpRequestResponse>,
    val collaboratorInteractions: List<Interaction>,
    val definition: AuditIssueDefinition
)

@Serializable
data class HttpService(
    val host: String,
    val port: Int,
    val secure: Boolean
)

@Serializable
enum class AuditIssueSeverity {
    HIGH,
    MEDIUM,
    LOW,
    INFORMATION,
    FALSE_POSITIVE;
}

@Serializable
enum class AuditIssueConfidence {
    CERTAIN,
    FIRM,
    TENTATIVE
}

@Serializable
data class HttpRequestResponse(
    val request: String?,
    val response: String?,
    val notes: String?
)

@Serializable
data class OrganizerItemDetails(
    val id: Int,
    val status: String,
    val request: String?,
    val response: String?,
    val notes: String?
)

@Serializable
data class Interaction(
    val interactionId: String,
    val timestamp: String
)

@Serializable
data class AuditIssueDefinition(
    val id: String,
    val background: String?,
    val remediation: String?,
    val typeIndex: Int
)


@Serializable
enum class WebSocketMessageDirection {
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT
}

@Serializable
data class WebSocketMessage(
    val payload: String?,
    val direction: WebSocketMessageDirection,
    val notes: String?
)

fun CollaboratorInteraction.toSerializableForm(): CollaboratorInteractionDetails {
    return CollaboratorInteractionDetails(
        id = id().toString(),
        type = type().name,
        timestamp = timeStamp().toString(),
        clientIp = clientIp().hostAddress,
        clientPort = clientPort(),
        customData = customData().orElse(null),
        dnsDetails = dnsDetails().orElse(null)?.let {
            CollaboratorDnsDetails(queryType = it.queryType().name)
        },
        httpDetails = httpDetails().orElse(null)?.let {
            CollaboratorHttpDetails(
                protocol = it.protocol().name,
                request = it.requestResponse()?.request()?.toString(),
                response = it.requestResponse()?.response()?.toString()
            )
        },
        smtpDetails = smtpDetails().orElse(null)?.let {
            CollaboratorSmtpDetails(
                protocol = it.protocol().name,
                conversation = it.conversation()
            )
        }
    )
}

@Serializable
data class CollaboratorInteractionDetails(
    val id: String,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val clientPort: Int,
    val customData: String?,
    val dnsDetails: CollaboratorDnsDetails?,
    val httpDetails: CollaboratorHttpDetails?,
    val smtpDetails: CollaboratorSmtpDetails?
)

@Serializable
data class CollaboratorDnsDetails(
    val queryType: String
)

@Serializable
data class CollaboratorHttpDetails(
    val protocol: String,
    val request: String?,
    val response: String?
)

@Serializable
data class CollaboratorSmtpDetails(
    val protocol: String,
    val conversation: String
)