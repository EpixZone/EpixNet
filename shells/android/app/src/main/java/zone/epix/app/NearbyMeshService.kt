package zone.epix.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.epix_ffi.NativeRadioKind
import uniffi.epix_ffi.NativeRadioState
import uniffi.epix_ffi.NativeRadioStream
import uniffi.epix_ffi.NodeState

private fun NativeRadioStream.disconnectAndClose() {
    try { disconnect() } finally { close() }
}

internal data class NearbyUiState(
    val policy: String = "Nearby connections are off",
    val statuses: Map<NearbyKind, NearbyStatus> = emptyMap(),
    val connections: Map<NearbyKind, Int> = emptyMap(),
)

internal object NearbyMeshSettings {
    private const val STORE = "nearby-mesh"
    private val mutable = MutableStateFlow(NearbyUiState())
    val state = mutable.asStateFlow()
    private val owners = AtomicLong()
    fun claim(): Long = owners.incrementAndGet()
    fun publish(owner: Long, value: NearbyUiState) { if (owners.get() == owner) mutable.value = value }
    fun wanted(context: Context, kind: NearbyKind): Boolean =
        context.getSharedPreferences(STORE, Context.MODE_PRIVATE).getBoolean(kind.name, false)
    fun setWanted(context: Context, kind: NearbyKind, enabled: Boolean) {
        context.getSharedPreferences(STORE, Context.MODE_PRIVATE).edit().putBoolean(kind.name, enabled).apply()
    }
    fun anyWanted(context: Context) = NearbyKind.entries.any { wanted(context, it) }
    fun missing(context: Context, kind: NearbyKind): List<String> = nearbyPermissions(kind, Build.VERSION.SDK_INT)
        .filter { context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
}

/** Explicit opt-in keeps radio ownership outside any Activity or xite. */
internal class NearbyMeshService : Service(), NearbyTransport.Listener {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var owner = 0L
    private lateinit var transports: Map<NearbyKind, NearbyTransport>
    private val started = mutableSetOf<NearbyKind>()
    private val statuses = mutableMapOf<NearbyKind, NearbyStatus>()
    private val retryAt = mutableMapOf<NearbyKind, Long>()
    private val links = mutableMapOf<String, Link>()
    private var policy = "Starting nearby connections"
    private var ready = false
    private var destroyed = false
    private var enableCore = false
    private var enableRequest = 0L
    @Volatile private var generation = 0L
    private var poll: Job? = null
    private var lastPublished: NearbyUiState? = null

    private class Link(val connection: NearbyConnection) {
        @Volatile var native: NativeRadioStream? = null
        var job: Job? = null
        fun close() {
            runCatching { connection.close() }
            runCatching { native?.disconnectAndClose() }
            job?.cancel()
        }
    }

    override fun onCreate() {
        super.onCreate()
        owner = NearbyMeshSettings.claim()
        transports = mapOf(NearbyKind.BLE to BleMeshTransport(this), NearbyKind.WIFI_AWARE to WifiAwareMeshTransport(this))
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "Nearby mesh", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Shows when EpixNet is using nearby radios"
            },
        )
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            NearbyKind.entries.forEach { NearbyMeshSettings.setWanted(this, it, false) }
            stopSelf()
            return START_NOT_STICKY
        }
        if (!NearbyMeshSettings.anyWanted(this)) {
            stopSelf()
            return START_NOT_STICKY
        }
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                var types = ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                val wanted = NearbyKind.entries.filter { NearbyMeshSettings.wanted(this, it) }.toSet()
                val fine = checkSelfPermission("android.permission.ACCESS_FINE_LOCATION") == PackageManager.PERMISSION_GRANTED
                if (nearbyNeedsLocationService(wanted, Build.VERSION.SDK_INT, fine)) {
                    types = types or ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION
                }
                startForeground(NOTIFICATION_ID, notification(), types)
            } else {
                startForeground(NOTIFICATION_ID, notification())
            }
        } catch (_: RuntimeException) {
            policy = "Open EpixNet to start nearby connections"
            publish()
            stopSelf()
            return START_NOT_STICKY
        }
        if (intent?.getBooleanExtra(ENABLE_CORE, false) == true) {
            enableCore = true
            enableRequest++
        }
        retryAt.clear()
        if (poll == null) poll = scope.launch {
            while (true) {
                reconcile()
                delay(1000)
            }
        }
        return START_NOT_STICKY
    }

    private suspend fun reconcile() {
        if (!NearbyMeshSettings.anyWanted(this)) { stopSelf(); return }
        val node = EmbeddedNodeHost.node
        val requestedEnable = enableCore
        val request = enableRequest
        val result = try {
            withContext(Dispatchers.IO) {
                var consumed = false
                if (requestedEnable && node != null && node.state() == NodeState.SERVING) {
                    // A foreground user action can enable mesh, never override global Offline mode.
                    val state = node.nativeRadioStatus().state
                    if (state != NativeRadioState.OFFLINE && state != NativeRadioState.FEATURE_UNAVAILABLE) {
                        node.setNativeMeshEnabled(true)
                    }
                    consumed = true
                }
                (node?.nativeRadioStatus()?.state ?: NativeRadioState.STARTING) to consumed
            }
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            policy = "Nearby mesh could not start. Try again from EpixNet."
            stopRadios()
            publish()
            return
        }
        if (result.second && request == enableRequest) enableCore = false
        val nativeState = result.first
        ready = nativeState == NativeRadioState.READY
        policy = when (nativeState) {
            NativeRadioState.FEATURE_UNAVAILABLE -> "This build does not include mesh networking"
            NativeRadioState.OFFLINE -> "Paused: Offline mode blocks all network connections"
            NativeRadioState.MESH_DISABLED -> "Mesh is disabled. Tap Start nearby mesh to enable it."
            NativeRadioState.STARTING -> "Starting nearby mesh"
            NativeRadioState.READY -> "Nearby mesh is on. No Internet connection is needed."
        }
        if (!ready) {
            stopRadios()
        } else {
            for ((kind, transport) in transports) reconcileTransport(kind, transport)
        }
        publish()
    }

    private fun reconcileTransport(kind: NearbyKind, transport: NearbyTransport) {
        if (!NearbyMeshSettings.wanted(this, kind)) { stopTransport(kind); return }
        val capability = transport.capability()
        if (!capability.supported) {
            stopTransport(kind)
            statuses[kind] = NearbyStatus(NearbyState.UNSUPPORTED, capability.detail)
            return
        }
        if (NearbyMeshSettings.missing(this, kind).isNotEmpty()) {
            stopTransport(kind)
            statuses[kind] = NearbyStatus(NearbyState.PERMISSION_REQUIRED, "Permission is needed. Enable this radio in EpixNet again.")
            return
        }
        if (kind !in started && android.os.SystemClock.elapsedRealtime() >= (retryAt[kind] ?: 0L)) {
            started.add(kind)
            transport.start(this)
        }
    }

    override fun onStatus(kind: NearbyKind, status: NearbyStatus) {
        if (destroyed) return
        statuses[kind] = status
        if (status.state in setOf(NearbyState.FAILED, NearbyState.UNAVAILABLE, NearbyState.PERMISSION_REQUIRED)) {
            started.remove(kind)
            retryAt[kind] = android.os.SystemClock.elapsedRealtime() + 20_000
        }
        publish()
    }

    override fun onConnection(connection: NearbyConnection) {
        if (destroyed || !ready || !NearbyMeshSettings.wanted(this, connection.kind) ||
            NearbyMeshSettings.missing(this, connection.kind).isNotEmpty() || links.size >= 8 || connection.id in links
        ) {
            cleanup.launch { runCatching { connection.close() } }
            return
        }
        val link = Link(connection)
        links[connection.id] = link
        val admittedGeneration = generation
        publish()
        link.job = scope.launch(Dispatchers.IO) {
            try {
                val node = EmbeddedNodeHost.node ?: return@launch
                val native = node.openNativeRadio(when (connection.kind) {
                    NearbyKind.BLE -> NativeRadioKind.BLE
                    NearbyKind.WIFI_AWARE -> NativeRadioKind.WIFI_AWARE
                })
                link.native = native
                if (admittedGeneration != generation) return@launch
                pumpNearby(connection, object : NativeNearbyStream {
                    override fun write(bytes: ByteArray, timeoutMs: Int) = native.write(bytes, timeoutMs.toUInt())
                    override fun read(maxBytes: Int, timeoutMs: Int): NearbyRead =
                        native.read(maxBytes.toUInt(), timeoutMs.toUInt()).let { NearbyRead(it.data, it.closed) }
                    override fun close() = native.disconnectAndClose()
                })
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                // A lost or rejected bearer does not grant trust or interrupt another interface.
            } finally {
                link.close()
                withContext(NonCancellable + Dispatchers.Main) {
                    if (links[connection.id] === link) links.remove(connection.id)
                    publish()
                }
            }
        }
    }

    private fun stopTransport(kind: NearbyKind) {
        transports.getValue(kind).stop()
        started.remove(kind)
        val closing = links.values.filter { it.connection.kind == kind }
        closing.forEach { links.remove(it.connection.id) }
        closing.forEach { link -> cleanup.launch { link.close() } }
        statuses[kind] = NearbyStatus(NearbyState.STOPPED, "Off")
    }

    private fun stopRadios() {
        ready = false
        generation++
        NearbyKind.entries.forEach(::stopTransport)
    }

    private fun publish() {
        val next = NearbyUiState(policy, statuses.toMap(),
            NearbyKind.entries.associateWith { kind -> links.values.count { it.connection.kind == kind } })
        if (next == lastPublished) return
        lastPublished = next
        NearbyMeshSettings.publish(owner, next)
        if (poll != null && !destroyed) getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification())
    }

    private fun notification(): Notification {
        val open = PendingIntent.getActivity(this, 719, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 719, Intent(this, NearbyMeshService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_nearby)
            .setContentTitle("EpixNet nearby mesh")
            .setContentText(when {
                !ready -> policy
                links.size == 1 -> "1 nearby connection"
                else -> "${links.size} nearby connections"
            })
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .build()
    }

    override fun onDestroy() {
        destroyed = true
        stopRadios()
        policy = "Nearby connections are off"
        publish()
        scope.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    companion object {
        private const val CHANNEL = "epix-nearby-mesh"
        private const val NOTIFICATION_ID = 719
        private const val ENABLE_CORE = "enable_core_mesh"
        private const val ACTION_STOP = "zone.epix.app.STOP_NEARBY_MESH"
        // Socket closure must survive cancellation of a destroyed service's scope.
        private val cleanup = CoroutineScope(SupervisorJob() + Dispatchers.IO)

        fun resumeIfWanted(context: Context, explicit: Boolean = false): Boolean {
            if (!NearbyMeshSettings.anyWanted(context)) {
                context.stopService(Intent(context, NearbyMeshService::class.java))
                return true
            }
            return try {
                context.startForegroundService(Intent(context, NearbyMeshService::class.java)
                    .putExtra(ENABLE_CORE, explicit))
                true
            } catch (_: RuntimeException) { false }
        }
    }
}
