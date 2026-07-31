package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import java.lang.ref.WeakReference
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

private const val TARGET_SEPARATOR = "\n"

class McpConfig(storage: PersistedObject, private val logging: Logging) {

    var enabled by storage.boolean(true)
    var configEditingTooling by storage.boolean(false)
    var host by storage.string("127.0.0.1")
    var port by storage.int(9876)
    var requireHttpRequestApproval by storage.boolean(true)
    var requireDataAccessApproval by storage.boolean(true)

    private var _alwaysAllowHttpHistory by storage.boolean(false)
    var alwaysAllowHttpHistory: Boolean
        get() = _alwaysAllowHttpHistory
        set(value) {
            if (_alwaysAllowHttpHistory != value) {
                _alwaysAllowHttpHistory = value
                notifyDataAccessChanged()
            }
        }

    private var _alwaysAllowWebSocketHistory by storage.boolean(false)
    var alwaysAllowWebSocketHistory: Boolean
        get() = _alwaysAllowWebSocketHistory
        set(value) {
            if (_alwaysAllowWebSocketHistory != value) {
                _alwaysAllowWebSocketHistory = value
                notifyDataAccessChanged()
            }
        }

    private var _alwaysAllowOrganizer by storage.boolean(false)
    var alwaysAllowOrganizer: Boolean
        get() = _alwaysAllowOrganizer
        set(value) {
            if (_alwaysAllowOrganizer != value) {
                _alwaysAllowOrganizer = value
                notifyDataAccessChanged()
            }
        }

    var filterConfigCredentials by storage.boolean(true)
    var allowExternalConnections by storage.boolean(false)

    // ── Additional bind hosts ────────────────────────────────────────────────
    private var _additionalBindHosts by storage.stringList("")
    private val bindHostsChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()

    var additionalBindHosts: String
        get() = _additionalBindHosts
        set(value) {
            if (_additionalBindHosts != value) {
                _additionalBindHosts = value
                notifyBindHostsChanged()
            }
        }

    fun getAdditionalBindHostsList(): List<String> =
        if (_additionalBindHosts.isBlank()) emptyList()
        else _additionalBindHosts.split(TARGET_SEPARATOR).map { it.trim() }.filter { it.isNotEmpty() }

    fun getAllBindHosts(): List<String> = listOf(host) + getAdditionalBindHostsList()

    fun addBindHost(ip: String): Boolean {
        val trimmed = ip.trim()
        if (trimmed.isBlank()) return false
        val current = getAdditionalBindHostsList()
        if (current.contains(trimmed) || trimmed == host) return false
        additionalBindHosts = (current + trimmed).joinToString(TARGET_SEPARATOR)
        return true
    }

    fun removeBindHost(ip: String): Boolean {
        val current = getAdditionalBindHostsList()
        val new = current.filter { it != ip.trim() }
        if (new.size == current.size) return false
        additionalBindHosts = new.joinToString(TARGET_SEPARATOR)
        return true
    }

    fun clearAdditionalBindHosts() { additionalBindHosts = "" }

    fun addBindHostsChangeListener(listener: () -> Unit): ListenerHandle {
        val reg = ListenerRegistration(listener)
        bindHostsChangeListeners.add(reg)
        return ListenerHandle { bindHostsChangeListeners.remove(reg) }
    }

    private fun notifyBindHostsChanged() {
        cleanupStaleListeners(bindHostsChangeListeners)
        bindHostsChangeListeners.mapNotNull { it.listener.get() }.forEach {
            try { it() } catch (e: Exception) { logging.logToError("Bind hosts listener failed: ${e.message}") }
        }
    }

    // ── LAN IP detection ────────────────────────────────────────────────────
    fun detectLanIps(): List<String> = try {
        NetworkInterface.getNetworkInterfaces()?.toList()
            ?.flatMap { iface -> iface.inetAddresses.toList() }
            ?.filter { addr -> addr is Inet4Address && !addr.isLoopbackAddress && !addr.isLinkLocalAddress }
            ?.map { it.hostAddress }
            ?: emptyList()
    } catch (_: Exception) { emptyList() }

    private var _autoApproveTargets by storage.stringList("")
    private val targetsChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()
    private val dataAccessChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()

    var autoApproveTargets: String
        get() = _autoApproveTargets
        set(value) {
            if (_autoApproveTargets != value) {
                _autoApproveTargets = value
                notifyTargetsChanged()
            }
        }

    init {
        val current = getAutoApproveTargetsList()
        val valid = current.filter { TargetValidation.isValidTarget(it) }
        if (valid.size != current.size) {
            _autoApproveTargets = valid.joinToString(TARGET_SEPARATOR)
        }
    }

    fun addAutoApproveTarget(target: String): Boolean {
        val trimmed = target.trim()
        if (!TargetValidation.isValidTarget(trimmed)) return false
        val currentTargets = getAutoApproveTargetsList()
        if (currentTargets.contains(trimmed)) return false
        val newTargets = currentTargets + trimmed
        autoApproveTargets = newTargets.joinToString(TARGET_SEPARATOR)
        return true
    }

    fun removeAutoApproveTarget(target: String): Boolean {
        val currentTargets = getAutoApproveTargetsList()
        val newTargets = currentTargets.filter { it != target.trim() }
        if (newTargets.size != currentTargets.size) {
            autoApproveTargets = newTargets.joinToString(TARGET_SEPARATOR)
            return true
        }
        return false
    }

    fun getAutoApproveTargetsList(): List<String> {
        return if (_autoApproveTargets.isBlank()) {
            emptyList()
        } else {
            _autoApproveTargets.split(TARGET_SEPARATOR).map { it.trim() }.filter { it.isNotEmpty() }
        }
    }

    fun clearAutoApproveTargets() {
        autoApproveTargets = ""
    }

    fun addTargetsChangeListener(listener: () -> Unit): ListenerHandle {
        val registration = ListenerRegistration(listener)
        targetsChangeListeners.add(registration)
        return ListenerHandle { removeTargetsChangeListener(registration) }
    }

    private fun removeTargetsChangeListener(registration: ListenerRegistration) {
        targetsChangeListeners.remove(registration)
    }

    private fun notifyTargetsChanged() {
        cleanupStaleListeners(targetsChangeListeners)
        val listeners = targetsChangeListeners.mapNotNull { it.listener.get() }
        listeners.forEach { listener ->
            try {
                listener()
            } catch (e: Exception) {
                logging.logToError("Targets change listener failed: ${e.message}")
            }
        }
    }

    fun addDataAccessChangeListener(listener: () -> Unit): ListenerHandle {
        val registration = ListenerRegistration(listener)
        dataAccessChangeListeners.add(registration)
        return ListenerHandle { removeDataAccessChangeListener(registration) }
    }

    private fun removeDataAccessChangeListener(registration: ListenerRegistration) {
        dataAccessChangeListeners.remove(registration)
    }

    private fun notifyDataAccessChanged() {
        cleanupStaleListeners(dataAccessChangeListeners)
        val listeners = dataAccessChangeListeners.mapNotNull { it.listener.get() }
        listeners.forEach { listener ->
            try {
                listener()
            } catch (e: Exception) {
                logging.logToError("Data access change listener failed: ${e.message}")
            }
        }
    }

    private fun cleanupStaleListeners(listenerList: CopyOnWriteArrayList<ListenerRegistration>) {
        val staleListeners = listenerList.filter { it.listener.get() == null }
        listenerList.removeAll(staleListeners)
    }

    fun cleanup() {
        targetsChangeListeners.clear()
        dataAccessChangeListeners.clear()
        bindHostsChangeListeners.clear()
    }
}

fun PersistedObject.boolean(default: Boolean = false) =
    PersistedDelegate(getter = { key -> getBoolean(key) ?: default }, setter = { key, value -> setBoolean(key, value) })

fun PersistedObject.string(default: String) =
    PersistedDelegate(getter = { key -> getString(key) ?: default }, setter = { key, value -> setString(key, value) })

fun PersistedObject.int(default: Int) =
    PersistedDelegate(getter = { key -> getInteger(key) ?: default }, setter = { key, value -> setInteger(key, value) })

fun PersistedObject.stringList(default: String) =
    PersistedDelegate(getter = { key -> getString(key) ?: default }, setter = { key, value -> setString(key, value) })

class PersistedDelegate<T>(
    private val getter: (name: String) -> T, private val setter: (name: String, value: T) -> Unit
) : ReadWriteProperty<Any, T> {
    override fun getValue(thisRef: Any, property: KProperty<*>) = getter(property.name)
    override fun setValue(thisRef: Any, property: KProperty<*>, value: T) = setter(property.name, value)
}

class ListenerRegistration(listener: () -> Unit) {
    val listener: WeakReference<() -> Unit> = WeakReference(listener)
}

fun interface ListenerHandle {
    fun remove()
}