package zone.epix.app

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.aware.AttachCallback
import android.net.wifi.aware.DiscoverySession
import android.net.wifi.aware.DiscoverySessionCallback
import android.net.wifi.aware.PeerHandle
import android.net.wifi.aware.PublishConfig
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.SubscribeConfig
import android.net.wifi.aware.SubscribeDiscoverySession
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareNetworkInfo
import android.net.wifi.aware.WifiAwareNetworkSpecifier
import android.net.wifi.aware.WifiAwareSession
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import java.io.Closeable
import java.io.IOException
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Open, peer-specific Aware bearer. Reticulum authenticates and encrypts the stream above it.
 * Discovery nonces only suppress duplicate links; they do not authenticate a device.
 * No socket uses the process/default network, and no listener binds a wildcard address.
 */
internal class WifiAwareMeshTransport(context: Context) : NearbyTransport {
    override val kind = NearbyKind.WIFI_AWARE
    private val context = context.applicationContext
    private val main = Handler(Looper.getMainLooper())
    private val epoch = AtomicLong()
    private var active: Run? = null
    private val cleanup = ThreadPoolExecutor(0, 1, 30, TimeUnit.SECONDS, LinkedBlockingQueue<Runnable>()) { task ->
        Thread(task, "epix-aware-close").apply { isDaemon = true }
    }

    private class Run(val epoch: Long, val listener: NearbyTransport.Listener) {
        val nonce = AwareControl.nonce()
        val links = mutableMapOf<String, Link>()
        val workers = ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS, ArrayBlockingQueue(4),
            { task -> Thread(task, "epix-aware-io").apply { isDaemon = true } })
        var aware: WifiAwareSession? = null
        var publisher: PublishDiscoverySession? = null
        var subscriber: SubscribeDiscoverySession? = null
        var receiver: BroadcastReceiver? = null
        var nextMessage = 1
    }

    private class Link(
        val run: Run,
        val discovery: DiscoverySession,
        val peer: PeerHandle,
        val remote: String,
        val request: String,
        val server: Boolean,
    ) {
        val connectionId = AwareControl.nonce()
        val closed = AtomicBoolean(false)
        private val sockets = mutableListOf<Closeable>()
        var callback: ConnectivityManager.NetworkCallback? = null
        var network: Network? = null
        var peerAddress: Inet6Address? = null
        var properties: LinkProperties? = null
        var port = 0
        var ioStarted = false
        var connected = false
        var outgoing: AwareControl.Message? = null
        var sends = 0

        fun own(socket: Closeable): Boolean = synchronized(sockets) {
            if (closed.get()) {
                socket.close()
                false
            } else {
                sockets.add(socket)
                true
            }
        }

        fun closeSockets() {
            val owned = synchronized(sockets) { sockets.toList().also { sockets.clear() } }
            owned.forEach { runCatching { it.close() } }
        }
    }

    override fun capability(): NearbyCapability = when {
        Build.VERSION.SDK_INT < 29 -> NearbyCapability(false, "Wi-Fi Aware needs Android 10 or later")
        !context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE) ->
            NearbyCapability(false, "This device does not support Wi-Fi Aware")
        else -> NearbyCapability(true, "Wi-Fi Aware")
    }

    override fun start(listener: NearbyTransport.Listener) {
        val generation = epoch.incrementAndGet()
        main.post {
            if (epoch.get() != generation) return@post
            active?.let(::release)
            val run = Run(generation, listener)
            active = run
            begin(run)
        }
    }

    override fun stop() {
        val generation = epoch.incrementAndGet()
        main.post {
            if (epoch.get() != generation) return@post
            val run = active ?: return@post
            active = null
            release(run)
            status(run, NearbyState.STOPPED, "Wi-Fi Aware stopped")
        }
    }

    private fun alive(run: Run): Boolean = epoch.get() == run.epoch && active === run
    private fun alive(link: Link): Boolean = alive(link.run) && !link.closed.get()
    private fun manager(): WifiAwareManager? = context.getSystemService(WifiAwareManager::class.java)
    private fun connectivity(): ConnectivityManager = context.getSystemService(ConnectivityManager::class.java)

    private fun permitted(): Boolean {
        val nearby = if (Build.VERSION.SDK_INT >= 33) Manifest.permission.NEARBY_WIFI_DEVICES
            else Manifest.permission.ACCESS_FINE_LOCATION
        return listOf(nearby, Manifest.permission.ACCESS_WIFI_STATE, Manifest.permission.CHANGE_WIFI_STATE,
            Manifest.permission.CHANGE_NETWORK_STATE, Manifest.permission.INTERNET)
            .all { context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }
    }

    private fun begin(run: Run) {
        val capability = capability()
        if (!capability.supported) return finish(run, NearbyState.UNSUPPORTED, capability.detail)
        if (!permitted()) return finish(run, NearbyState.PERMISSION_REQUIRED, "Nearby Wi-Fi permission is required")
        status(run, NearbyState.STARTING, "Starting Wi-Fi Aware")
        guarded(run) {
            registerAvailability(run)
            val aware = manager()
            if (aware == null || !aware.isAvailable) {
                finish(run, NearbyState.UNAVAILABLE, "Wi-Fi Aware is currently unavailable")
            } else {
                aware.attach(attachment(run), main)
                later(run, 15_000) {
                    if (run.publisher == null || run.subscriber == null) {
                        finish(run, NearbyState.FAILED, "Wi-Fi Aware discovery did not start")
                    }
                }
                checkPermission(run)
            }
        }
    }

    private fun registerAvailability(run: Run) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (alive(run) && intent.action == WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED) {
                    finish(run, NearbyState.UNAVAILABLE, "Wi-Fi Aware availability changed; start nearby again")
                }
            }
        }
        val filter = IntentFilter(WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= 33) context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        else context.registerReceiver(receiver, filter)
        run.receiver = receiver
    }

    private fun checkPermission(run: Run) {
        later(run, 1_000) {
            if (!permitted()) finish(run, NearbyState.PERMISSION_REQUIRED, "Nearby Wi-Fi permission was removed")
            else checkPermission(run)
        }
    }

    private fun attachment(run: Run) = object : AttachCallback() {
        override fun onAttached(session: WifiAwareSession) {
            if (!alive(run)) {
                cleanup.execute { session.close() }
                return
            }
            run.aware = session
            try {
                val info = AwareControl.advert(run.nonce)
                session.publish(PublishConfig.Builder().setServiceName(AwareControl.SERVICE)
                    .setServiceSpecificInfo(info).build(), discovery(run, true), main)
                session.subscribe(SubscribeConfig.Builder().setServiceName(AwareControl.SERVICE)
                    .setServiceSpecificInfo(info).build(), discovery(run, false), main)
            } catch (_: SecurityException) {
                finish(run, NearbyState.PERMISSION_REQUIRED, "Nearby Wi-Fi permission is required")
            } catch (_: RuntimeException) {
                finish(run, NearbyState.FAILED, "Wi-Fi Aware could not start a connection")
            }
        }

        override fun onAttachFailed() {
            if (alive(run)) finish(run, NearbyState.FAILED, "Wi-Fi Aware attachment failed")
        }
    }

    private fun discovery(run: Run, server: Boolean) = object : DiscoverySessionCallback() {
        override fun onPublishStarted(session: PublishDiscoverySession) {
            if (!alive(run)) { cleanup.execute { session.close() }; return }
            run.publisher = session
            discoveryReady(run)
        }

        override fun onSubscribeStarted(session: SubscribeDiscoverySession) {
            if (!alive(run)) { cleanup.execute { session.close() }; return }
            run.subscriber = session
            discoveryReady(run)
        }

        override fun onServiceDiscovered(peer: PeerHandle?, info: ByteArray?, filters: MutableList<ByteArray>?) {
            if (!server && alive(run) && peer != null && info != null) discovered(run, peer, info)
        }

        override fun onMessageReceived(peer: PeerHandle?, bytes: ByteArray?) {
            if (alive(run) && peer != null && bytes != null) received(run, server, peer, bytes)
        }

        override fun onServiceLost(peer: PeerHandle, reason: Int) {
            if (alive(run)) run.links.values.filter { it.server == server && it.peer == peer }.forEach(::drop)
        }

        override fun onSessionConfigFailed() {
            if (alive(run)) finish(run, NearbyState.FAILED, "Wi-Fi Aware discovery failed")
        }

        override fun onSessionTerminated() {
            if (alive(run)) finish(run, NearbyState.UNAVAILABLE, "Wi-Fi Aware discovery ended")
        }
    }

    private fun discoveryReady(run: Run) {
        if (run.publisher != null && run.subscriber != null) {
            status(run, NearbyState.DISCOVERING, "Looking for nearby Wi-Fi Aware peers")
        }
    }

    private fun discovered(run: Run, peer: PeerHandle, info: ByteArray) {
        val remote = AwareControl.readAdvert(info) ?: return
        if (!AwareControl.initiates(run.nonce, remote)) return
        if (run.links.containsKey(remote) || run.links.size >= MAX_LINKS) return
        val session = run.subscriber ?: return
        val link = Link(run, session, peer, remote, AwareControl.requestId(), false)
        admit(link)
        send(link, AwareControl.Type.REQUEST)
    }

    private fun received(run: Run, server: Boolean, peer: PeerHandle, bytes: ByteArray) {
        val message = AwareControl.decode(bytes) ?: return
        if (message.recipient != run.nonce) return
        if (server && message.type == AwareControl.Type.REQUEST) {
            acceptRequest(run, peer, message)
            return
        }
        val link = run.links[message.sender] ?: return
        if (server || link.server || link.peer != peer || !message.matches(run.nonce, link.remote, link.request)) return
        when (message.type) {
            AwareControl.Type.READY -> if (link.callback == null) requestNetwork(link)
            AwareControl.Type.PORT -> {
                if (link.port != 0 && link.port != message.port) return
                link.port = message.port
                if (link.callback == null) requestNetwork(link)
                startSocket(link)
            }
            AwareControl.Type.REQUEST -> Unit
        }
    }

    private fun acceptRequest(run: Run, peer: PeerHandle, message: AwareControl.Message) {
        if (!AwareControl.initiates(message.sender, run.nonce)) return
        val existing = run.links[message.sender]
        if (existing != null) return // Timed control retransmission handles duplicate requests.
        if (run.links.size >= MAX_LINKS) return
        val session = run.publisher ?: return
        val link = Link(run, session, peer, message.sender, message.request, true)
        admit(link)
        requestNetwork(link)
        if (alive(link)) send(link, AwareControl.Type.READY)
    }

    private fun admit(link: Link) {
        link.run.links[link.remote] = link
        later(link.run, 25_000) { if (!link.connected) drop(link) }
        repeatControl(link)
    }

    private fun send(link: Link, type: AwareControl.Type) {
        link.outgoing = AwareControl.Message(type, link.run.nonce, link.remote, link.request, link.port)
        link.sends = 0
        transmit(link)
    }

    private fun transmit(link: Link) {
        if (!alive(link) || link.connected || link.sends >= 4) return
        val message = link.outgoing ?: return
        link.sends++
        guarded(link.run) {
            val id = link.run.nextMessage++
            link.discovery.sendMessage(link.peer, id, AwareControl.encode(message))
        }
    }

    private fun repeatControl(link: Link) {
        later(link.run, 2_000) {
            if (alive(link) && !link.connected) {
                transmit(link)
                repeatControl(link)
            }
        }
    }

    private fun requestNetwork(link: Link) {
        if (Build.VERSION.SDK_INT < 29 || !alive(link) || link.callback != null) return
        guarded(link.run) {
            // Port metadata requires a secured data path. This open bearer negotiates it through
            // the peer-bound discovery session instead; Reticulum secures application traffic.
            val specifier = WifiAwareNetworkSpecifier.Builder(link.discovery, link.peer).build()
            val request = NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
                .setNetworkSpecifier(specifier).build()
            val callback = networkCallbacks(link)
            link.callback = callback
            connectivity().requestNetwork(request, callback, main, 15_000)
        }
    }

    private fun networkCallbacks(link: Link) = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (!alive(link)) return
            link.network = network
            startSocket(link)
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            if (Build.VERSION.SDK_INT < 29 || !alive(link) || link.network != network) return
            val info = capabilities.transportInfo as? WifiAwareNetworkInfo ?: return
            link.peerAddress = info.peerIpv6Addr?.takeIf { it.isLinkLocalAddress && it.scopeId > 0 }
            startSocket(link)
        }

        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            if (!alive(link) || link.network != network) return
            link.properties = properties
            startSocket(link)
        }

        override fun onUnavailable() { if (alive(link)) drop(link) }
        override fun onLost(network: Network) { if (alive(link) && link.network == network) drop(link) }
    }

    private fun startSocket(link: Link) {
        if (!alive(link) || link.ioStarted) return
        val network = link.network ?: return
        val peer = link.peerAddress ?: return
        if (link.server && link.properties == null) return
        if (!link.server && link.port == 0) return
        link.ioStarted = true
        val properties = link.properties
        val port = link.port
        try {
            link.run.workers.execute { openSocket(link, network, peer, properties, port) }
        } catch (_: RejectedExecutionException) {
            drop(link)
        }
    }

    private fun openSocket(link: Link, network: Network, peer: Inet6Address, properties: LinkProperties?, port: Int) {
        try {
            val socket = if (link.server) listen(link, peer, checkNotNull(properties))
                else connect(link, network, peer, port)
            post(link.run) { deliver(link, socket) }
        } catch (_: IOException) {
            post(link.run) { drop(link) }
        } catch (_: SecurityException) {
            post(link.run) { finish(link.run, NearbyState.PERMISSION_REQUIRED, "Nearby Wi-Fi permission is required") }
        }
    }

    private fun listen(link: Link, peer: Inet6Address, properties: LinkProperties): Socket {
        val local = localAddress(properties)
        if (local.scopeId != peer.scopeId) throw IOException("Aware interface scope mismatch")
        val server = ServerSocket()
        if (!link.own(server)) throw IOException("Aware link closed")
        server.reuseAddress = false
        server.bind(InetSocketAddress(local, 0), 1)
        server.soTimeout = 10_000
        post(link.run) {
            if (alive(link)) {
                link.port = server.localPort
                send(link, AwareControl.Type.PORT)
            }
        }
        try {
            repeat(4) {
                val socket = server.accept()
                val address = socket.inetAddress as? Inet6Address
                if (address != null && address.address.contentEquals(peer.address) && address.scopeId == peer.scopeId) {
                    if (!link.own(socket)) throw IOException("Aware link closed")
                    return socket
                }
                socket.close()
            }
            throw IOException("Unexpected Aware peer")
        } finally {
            server.close()
        }
    }

    private fun localAddress(properties: LinkProperties): Inet6Address {
        val name = properties.interfaceName ?: throw IOException("No Aware interface")
        val device = NetworkInterface.getByName(name) ?: throw IOException("Aware interface is gone")
        val local = properties.linkAddresses.map { it.address }.filterIsInstance<Inet6Address>()
            .firstOrNull { it.isLinkLocalAddress } ?: throw IOException("No local Aware IPv6 address")
        val scoped = Inet6Address.getByAddress(null, local.address, device)
        if (scoped.scopeId <= 0) throw IOException("Unscoped Aware address")
        return scoped
    }

    private fun connect(link: Link, network: Network, peer: Inet6Address, port: Int): Socket {
        val socket = network.socketFactory.createSocket()
        if (!link.own(socket)) throw IOException("Aware link closed")
        socket.connect(InetSocketAddress(peer, port), 10_000)
        return socket
    }

    private fun deliver(link: Link, socket: Socket) {
        if (!alive(link) || link.connected) return
        link.connected = true
        val connection = NearbyConnection("aware-${link.connectionId}", kind, "Nearby Wi-Fi peer",
            socket.getInputStream(), socket.getOutputStream()) {
            link.closed.set(true)
            cleanup.execute { link.closeSockets() }
            main.post { drop(link) }
        }
        link.run.listener.onConnection(connection)
    }

    private fun drop(link: Link) {
        link.closed.set(true)
        if (link.run.links[link.remote] === link) link.run.links.remove(link.remote)
        val callback = link.callback
        link.callback = null
        cleanup.execute {
            link.closeSockets()
            if (callback != null) runCatching { connectivity().unregisterNetworkCallback(callback) }
        }
    }

    private fun release(run: Run) {
        main.removeCallbacksAndMessages(run)
        run.links.values.toList().forEach(::drop)
        run.receiver?.let { runCatching { context.unregisterReceiver(it) } }
        run.receiver = null
        cleanup.execute {
            runCatching { run.publisher?.close() }
            runCatching { run.subscriber?.close() }
            runCatching { run.aware?.close() }
            run.workers.shutdownNow()
        }
    }

    private fun finish(run: Run, state: NearbyState, detail: String) {
        if (!alive(run)) return
        epoch.incrementAndGet()
        active = null
        release(run)
        status(run, state, detail)
    }

    private fun status(run: Run, state: NearbyState, detail: String) {
        run.listener.onStatus(kind, NearbyStatus(state, detail))
    }

    private fun guarded(run: Run, action: () -> Unit) {
        if (!alive(run)) return
        try { action() }
        catch (_: SecurityException) { finish(run, NearbyState.PERMISSION_REQUIRED, "Nearby Wi-Fi permission is required") }
        catch (_: RuntimeException) { finish(run, NearbyState.FAILED, "Wi-Fi Aware could not start a connection") }
    }

    private fun post(run: Run, action: () -> Unit) {
        main.postAtTime({ if (alive(run)) action() }, run, SystemClock.uptimeMillis())
    }

    private fun later(run: Run, delay: Long, action: () -> Unit) {
        main.postAtTime({ if (alive(run)) action() }, run, SystemClock.uptimeMillis() + delay)
    }

    private companion object { const val MAX_LINKS = 4 }
}
