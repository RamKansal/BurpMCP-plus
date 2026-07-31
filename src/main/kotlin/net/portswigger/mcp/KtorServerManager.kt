package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.modelcontextprotocol.kotlin.sdk.Implementation
import io.modelcontextprotocol.kotlin.sdk.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.registerTools
import java.net.URI
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class KtorServerManager(private val api: MontoyaApi) : ServerManager {

    private var servers: List<EmbeddedServer<*, *>> = emptyList()
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    override fun start(config: McpConfig, callback: (ServerState) -> Unit) {
        callback(ServerState.Starting)

        executor.submit {
            try {
                servers.forEach { it.stop(1000, 5000) }
                servers = emptyList()

                val allHosts = config.getAllBindHosts().distinct()
                val allowedHostSet = buildAllowedHostSet(allHosts, config.allowExternalConnections)

                val mcpServer = Server(
                    serverInfo = Implementation("burp-suite", "1.1.2"), options = ServerOptions(
                        capabilities = ServerCapabilities(
                            tools = ServerCapabilities.Tools(listChanged = false)
                        )
                    )
                )

                servers = allHosts.map { bindHost ->
                    embeddedServer(Netty, port = config.port, host = bindHost) {
                        install(CORS) {
                            allowedHostSet.forEach { h -> allowHost(h) }

                            allowMethod(HttpMethod.Get)
                            allowMethod(HttpMethod.Post)

                            allowHeader(HttpHeaders.ContentType)
                            allowHeader(HttpHeaders.Accept)
                            allowHeader("Last-Event-ID")

                            allowCredentials = false
                            allowNonSimpleContentTypes = true
                            maxAgeInSeconds = 3600
                        }

                        intercept(ApplicationCallPipeline.Call) {
                            val origin = call.request.header("Origin")
                            val host = call.request.header("Host")
                            val referer = call.request.header("Referer")
                            val userAgent = call.request.header("User-Agent")
                            val allowExternal = config.allowExternalConnections

                            if (origin != null && !isValidOrigin(origin, allowExternal, allowedHostSet)) {
                                api.logging().logToOutput("Blocked DNS rebinding attack from origin: $origin")
                                call.respond(HttpStatusCode.Forbidden)
                                return@intercept
                            } else if (isBrowserRequest(userAgent)) {
                                api.logging().logToOutput("Blocked browser request without Origin header")
                                call.respond(HttpStatusCode.Forbidden)
                                return@intercept
                            }

                            if (host != null && !isValidHost(host, config.port, allowExternal, allowedHostSet)) {
                                api.logging().logToOutput("Blocked DNS rebinding attack from host: $host")
                                call.respond(HttpStatusCode.Forbidden)
                                return@intercept
                            }

                            if (referer != null && !isValidReferer(referer, allowExternal, allowedHostSet)) {
                                api.logging().logToOutput("Blocked suspicious request from referer: $referer")
                                call.respond(HttpStatusCode.Forbidden)
                                return@intercept
                            }

                            call.response.header("X-Frame-Options", "DENY")
                            call.response.header("X-Content-Type-Options", "nosniff")
                            call.response.header("Referrer-Policy", "same-origin")
                            call.response.header("Content-Security-Policy", "default-src 'none'")
                        }

                        mcp {
                            mcpServer
                        }

                        mcpServer.registerTools(api, config)
                    }.apply {
                        start(wait = false)
                    }
                }

                val boundAddresses = allHosts.joinToString(", ") { "$it:${config.port}" }
                api.logging().logToOutput("Started MCP server on: $boundAddresses")
                callback(ServerState.Running)

            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun stop(callback: (ServerState) -> Unit) {
        callback(ServerState.Stopping)

        executor.submit {
            try {
                servers.forEach { it.stop(1000, 5000) }
                servers = emptyList()
                api.logging().logToOutput("Stopped MCP server")
                callback(ServerState.Stopped)
            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun shutdown() {
        servers.forEach { it.stop(1000, 5000) }
        servers = emptyList()

        executor.shutdown()
        executor.awaitTermination(10, TimeUnit.SECONDS)
    }

    // Builds the set of host:port strings that are allowed for CORS/validation.
    // Always includes localhost + 127.0.0.1; adds all configured bind hosts when external is enabled.
    private fun buildAllowedHostSet(allHosts: List<String>, allowExternal: Boolean): Set<String> {
        val base = mutableSetOf("localhost", "127.0.0.1")
        if (allowExternal) {
            base.addAll(allHosts)
        } else {
            base.addAll(allHosts) // additional IPs explicitly configured are always trusted
        }
        return base
    }

    private fun isValidOrigin(origin: String, allowExternal: Boolean, allowedHosts: Set<String>): Boolean {
        if (allowExternal) return true
        return try {
            val hostname = URI(origin).toURL().host.lowercase()
            hostname in allowedHosts
        } catch (_: Exception) { false }
    }

    private fun isBrowserRequest(userAgent: String?): Boolean {
        if (userAgent == null) return false
        val ua = userAgent.lowercase()
        return listOf("mozilla/", "chrome/", "safari/", "webkit/", "gecko/", "firefox/", "edge/", "opera/", "browser")
            .any { ua.contains(it) }
    }

    private fun isValidHost(host: String, expectedPort: Int, allowExternal: Boolean, allowedHosts: Set<String>): Boolean {
        return try {
            val parts = host.split(":")
            val hostname = parts[0].lowercase()
            val port = if (parts.size > 1) parts[1].toIntOrNull() else null
            if (!allowExternal && hostname !in allowedHosts) return false
            if (port != null && port != expectedPort) return false
            true
        } catch (_: Exception) { false }
    }

    private fun isValidReferer(referer: String, allowExternal: Boolean, allowedHosts: Set<String>): Boolean {
        if (allowExternal) return true
        return try {
            val hostname = URI(referer).toURL().host.lowercase()
            hostname in allowedHosts
        } catch (_: Exception) { false }
    }
}