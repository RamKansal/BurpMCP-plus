package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.PromptMessageContent
import io.modelcontextprotocol.kotlin.sdk.TextContent
import io.modelcontextprotocol.kotlin.sdk.Tool
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import net.portswigger.mcp.schema.asInputSchema
import kotlin.experimental.ExperimentalTypeInference

@OptIn(InternalSerializationApi::class)
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> List<PromptMessageContent>
) {
    val toolName = I::class.simpleName?.toLowerSnakeCase() ?: error("Couldn't find name for ${I::class}")

    addTool(
        name = toolName,
        description = description,
        inputSchema = I::class.asInputSchema(),
        handler = { request ->
            try {
                CallToolResult(
                    content = execute(
                        Json.decodeFromJsonElement(
                            I::class.serializer(),
                            request.arguments
                        )
                    )
                )
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("Error: ${e.message}")),
                    isError = true
                )
            }
        }
    )
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolString")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> String
) {
    mcpTool<I>(description, execute = {
        listOf(TextContent(execute(this)))
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolUnit")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> Unit
) {
    mcpTool<I>(description, execute = {
        execute(this)

        listOf(TextContent("Executed tool"))
    })
}

/**
 * Hard ceiling on the characters any single tool response may emit. Kept well under
 * the ~1 MB cap most MCP/LLM clients impose so a response is never silently dropped
 * or truncated mid-data by the transport. Truncation, when needed, happens here at
 * item boundaries (never mid-entry, never mid-header) with an explicit flag.
 */
const val MAX_RESPONSE_CHARS: Int = 500_000

/**
 * Joins [items] with [sep] without exceeding [budget] characters. Returns
 * (joinedText, truncated, includedCount). At least one item is always included
 * (so a single oversized item still surfaces, just on its own).
 */
fun joinWithBudget(
    items: List<String>,
    budget: Int = MAX_RESPONSE_CHARS,
    sep: String = "\n\n",
): Triple<String, Boolean, Int> {
    val sb = StringBuilder()
    var count = 0
    for (item in items) {
        val addition = if (count == 0) item.length else item.length + sep.length
        if (count > 0 && sb.length + addition > budget) {
            return Triple(sb.toString(), true, count)
        }
        if (count > 0) sb.append(sep)
        sb.append(item)
        count++
    }
    return Triple(sb.toString(), false, count)
}

fun paginationMeta(total: Int, offset: Int, count: Int, returned: Int, truncated: Boolean): String {
    val hasMore = offset + returned < total
    return "META: {\"total\":$total,\"offset\":$offset,\"count\":$count," +
        "\"returned\":$returned,\"hasMore\":$hasMore,\"truncatedForSize\":$truncated}"
}

inline fun <reified I : Paginated, J : Any> Server.mcpPaginatedTool(
    description: String,
    noinline mapper: (J) -> CharSequence = { it.toString() },
    crossinline execute: I.() -> List<J>
) {
    mcpTool<I>(description, execute = {

        val items = execute(this)
        val total = items.size

        when {
            total == 0 -> "No items found. Total: 0"

            offset >= total -> "Reached end of items. Total: $total"

            else -> {
                val upperLimit = (offset + count).coerceAtMost(total)
                val page = items.subList(offset, upperLimit).map { mapper(it).toString() }
                val (body, truncated, returned) = joinWithBudget(page)
                "${paginationMeta(total, offset, count, returned, truncated)}\n\n$body"
            }
        }
    })
}

inline fun <reified I : Paginated> Server.mcpPaginatedTool(
    description: String,
    crossinline execute: I.() -> Sequence<String>
) {
    mcpTool<I>(description, execute = {
        val all = execute(this).toList()
        val total = all.size

        when {
            total == 0 -> listOf(TextContent("No items found. Total: 0"))

            offset >= total -> listOf(TextContent("Reached end of items. Total: $total"))

            else -> {
                val upperLimit = (offset + count).coerceAtMost(total)
                val page = all.subList(offset, upperLimit)
                val (body, truncated, returned) = joinWithBudget(page)
                listOf(TextContent("${paginationMeta(total, offset, count, returned, truncated)}\n\n$body"))
            }
        }
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpNamedToolString")
inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: () -> List<PromptMessageContent>
) {
    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            CallToolResult(
                content = execute()
            )
        }
    )
}

inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: () -> String
) {
    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            CallToolResult(
                content = listOf(TextContent(execute()))
            )
        }
    )
}

fun String.toLowerSnakeCase(): String {
    return this
        .replace(Regex("([a-z0-9])([A-Z])"), "$1_$2")
        .replace(Regex("([A-Z])([A-Z][a-z])"), "$1_$2")
        .replace(Regex("[\\s-]+"), "_")
        .lowercase()
}

interface Paginated {
    val count: Int
    val offset: Int
}

