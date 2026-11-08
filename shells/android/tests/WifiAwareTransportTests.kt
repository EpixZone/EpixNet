package zone.epix.app

import android.content.Context
import android.content.Intent
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.aware.PeerHandle
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.SubscribeDiscoverySession
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareNetworkInfo
import android.net.wifi.aware.WifiAwareSession
import android.os.Build
import android.os.TestMain
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory

private var checks = 0
private fun verify(condition: Boolean, detail: String) { checks++; check(condition) { detail } }
private fun await(detail: String, condition: () -> Boolean) {
    val until = System.nanoTime() + 2_000_000_000
    while (!condition() && System.nanoTime() < until) { TestMain.drain(); Thread.sleep(2) }
    verify(condition(), detail)
}
private class RecordingListener : NearbyTransport.Listener {
    val statuses = mutableListOf<NearbyStatus>()
    val connections = mutableListOf<NearbyConnection>()
    private val thread = Thread.currentThread()
    override fun onStatus(kind: NearbyKind, status: NearbyStatus) {
        check(Thread.currentThread() === thread)
        check(kind == NearbyKind.WIFI_AWARE)
        statuses.add(status)
    }
    override fun onConnection(connection: NearbyConnection) {
        check(Thread.currentThread() === thread)
        connections.add(connection)
    }
}
private class Fixture {
    val context = Context()
    val transport = WifiAwareMeshTransport(context)
    val listener = RecordingListener()
    val session = WifiAwareSession()
    val publisher = PublishDiscoverySession()
    val subscriber = SubscribeDiscoverySession()
    lateinit var nonce: String
    fun start() { transport.start(listener); TestMain.drain() }
    fun attach() {
        checkNotNull(context.manager.attachCallback).onAttached(session)
        session.publisher.onPublishStarted(publisher)
        session.subscriber.onSubscribeStarted(subscriber)
        nonce = checkNotNull(AwareControl.readAdvert(session.publishConfig.info))
    }
    fun ready() { start(); attach() }
    fun stop() { transport.stop(); TestMain.drain() }
    fun request(peer: PeerHandle, remote: String, request: String = "0123456789abcdef") {
        session.publisher.onMessageReceived(peer, AwareControl.encode(
            AwareControl.Message(AwareControl.Type.REQUEST, remote, nonce, request)))
    }
}
private class TestSocket(holdConnect: Boolean = false) : Socket() {
    private val connectGate = CountDownLatch(if (holdConnect) 1 else 0)
    @Volatile var destination: SocketAddress? = null
    @Volatile var closedByAdapter = false
    override fun connect(endpoint: SocketAddress, timeout: Int) {
        check(timeout in 1..10000)
        destination = endpoint
        check(connectGate.await(2, TimeUnit.SECONDS)) { "fixture connect was not released" }
    }
    override fun getInputStream() = ByteArrayInputStream(byteArrayOf(1, 2, 3))
    override fun getOutputStream() = ByteArrayOutputStream()
    override fun close() { closedByAdapter = true; connectGate.countDown() }
}
private class ScopedFactory(holdConnect: Boolean = false) : SocketFactory() {
    val socket = TestSocket(holdConnect)
    @Volatile var calls = 0
    override fun createSocket(): Socket { calls++; return socket }
    override fun createSocket(host: String, port: Int): Socket = error("DNS is forbidden")
    override fun createSocket(host: String, port: Int, local: InetAddress, localPort: Int): Socket = error("DNS is forbidden")
    override fun createSocket(host: InetAddress, port: Int): Socket = error("connect must use an explicit timeout")
    override fun createSocket(host: InetAddress, port: Int, local: InetAddress, localPort: Int): Socket = error("default binding is forbidden")
}

private fun codecTests() {
    val low = "0".repeat(32)
    val high = "f".repeat(32)
    val request = "0123456789abcdef"
    verify(AwareControl.readAdvert(AwareControl.advert(low)) == low, "advert round trip")
    verify(AwareControl.initiates(low, high) && !AwareControl.initiates(high, low), "one initiator across symmetric discovery")
    verify(!AwareControl.initiates(low, low), "self nonce cannot initiate")
    verify(!AwareControl.initiates("invalid", high), "malformed nonce cannot select a role")
    for (type in AwareControl.Type.entries) {
        val message = AwareControl.Message(type, low, high, request, if (type == AwareControl.Type.PORT) 65535 else 0)
        val bytes = AwareControl.encode(message)
        verify(bytes.size <= AwareControl.MAX_BYTES && AwareControl.decode(bytes) == message, "$type bounded round trip")
        verify(message.matches(high, low, request), "$type exact correlation")
        verify(!message.matches(low, high, request), "$type rejects reversed peers")
        verify(!message.matches(high, low, "fedcba9876543210"), "$type rejects stale request")
    }
    val valid = "EPXA1|PORT|$low|$high|$request|12345"
    val bad = listOf("", valid.replace("EPXA1", "EPXA2"), "$valid|extra", valid.replace("12345", "0"),
        valid.replace("12345", "65536"), valid.replace("12345", "-1"), valid.replace("12345", "+12345"),
        valid.replace("12345", "012345"), valid.replace("PORT", "UNKNOWN"), valid.replace("PORT", "READY"),
        valid.replace(high, low), valid.replace(request, "short"), "$valid\n", valid.replace("12345", "é"))
    bad.forEach { verify(AwareControl.decode(it.toByteArray()) == null, "invalid control rejected: $it") }
    verify(AwareControl.decode(ByteArray(113) { 65 }) == null, "oversized control rejected before parsing")
    verify(AwareControl.readAdvert("EPXA2|$low".toByteArray()) == null, "foreign advert version rejected")
    verify(AwareControl.readAdvert("EPXA1|$low|extra".toByteArray()) == null, "advert extra fields rejected")
    verify(AwareControl.nonce() != AwareControl.nonce(), "run nonce is not static")
}

private fun lifecycleTests() {
    val unsupported = Fixture()
    unsupported.context.packageManager.aware = false
    unsupported.start()
    verify(!unsupported.transport.capability().supported && unsupported.context.manager.attachCallback == null,
        "hardware without Aware never calls attach")
    verify(unsupported.listener.statuses.last().state == NearbyState.UNSUPPORTED, "unsupported status")
    Build.VERSION.SDK_INT = 28
    verify(!Fixture().transport.capability().supported, "pre-29 API is unavailable")
    Build.VERSION.SDK_INT = 37
    val denied = Fixture()
    denied.context.permissionGranted = false
    denied.start()
    verify(denied.listener.statuses.last().state == NearbyState.PERMISSION_REQUIRED && denied.context.receiver == null,
        "permission denial does not start discovery")
    val pending = Fixture()
    pending.start()
    val old = checkNotNull(pending.context.manager.attachCallback)
    pending.stop()
    val stale = WifiAwareSession()
    old.onAttached(stale)
    await("late attached session is closed", { stale.closed })
    verify(pending.listener.connections.isEmpty(), "stopped attachment cannot deliver a connection")
    pending.ready()
    verify(pending.listener.statuses.last().state == NearbyState.DISCOVERING, "restart reaches discovery")
    verify(pending.session.publishConfig.name == AwareControl.SERVICE &&
        pending.session.publishConfig.info.contentEquals(pending.session.subscribeConfig.info),
        "both sessions use one run nonce and versioned service")
    pending.context.permissionGranted = false
    TestMain.advance(1000)
    await("revocation closes both discovery sessions", { pending.publisher.closed && pending.subscriber.closed })
    verify(pending.listener.statuses.last().state == NearbyState.PERMISSION_REQUIRED, "revocation reported")
    val lost = Fixture(); lost.ready()
    lost.context.receiver!!.onReceive(lost.context, Intent(WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED))
    await("availability disruption closes attachment", { lost.session.closed })
    verify(lost.listener.statuses.last().state == NearbyState.UNAVAILABLE, "availability change is fail closed")
}

private fun boundsTests() {
    val fixture = Fixture(); fixture.ready()
    for (id in 1..5) fixture.request(PeerHandle(id), id.toString(16).padStart(32, '0'))
    verify(fixture.context.connectivity.callbacks.size == 4, "four pending peers consume all slots")
    fixture.request(PeerHandle(99), "1".padStart(32, '0'), "ffffffffffffffff")
    verify(fixture.context.connectivity.callbacks.size == 4, "same nonce on a different native handle cannot add a link")
    val first = fixture.context.connectivity.callbacks.first()
    first.onUnavailable()
    await("failed request unregisters network callback", { first in fixture.context.connectivity.unregistered })
    fixture.request(PeerHandle(6), "6".padStart(32, '0'))
    verify(fixture.context.connectivity.callbacks.size == 5, "failed slot can be reused")
    repeat(10) { TestMain.advance(2000) }
    verify(fixture.publisher.sent.groupBy { it.peer.id }.values.all { it.size <= 4 }, "discovery control retries are bounded")
    TestMain.advance(6000)
    await("pending setup deadline unregisters all requests", { fixture.context.connectivity.unregistered.size == 5 })
    fixture.stop()
}

private fun scopedClientTests() {
    val fixture = Fixture(); fixture.ready()
    val peer = PeerHandle(7)
    val remote = "f".repeat(32)
    fixture.session.subscriber.onServiceDiscovered(peer, null, null)
    fixture.session.subscriber.onServiceDiscovered(null, AwareControl.advert(remote), null)
    fixture.session.subscriber.onMessageReceived(peer, null)
    fixture.session.publisher.onMessageReceived(null, byteArrayOf())
    verify(fixture.subscriber.sent.isEmpty() && fixture.context.connectivity.callbacks.isEmpty(),
        "absent discovery/control metadata cannot create a connection or crash the callback")
    fixture.session.subscriber.onServiceDiscovered(peer, AwareControl.advert(remote), mutableListOf())
    val request = checkNotNull(AwareControl.decode(fixture.subscriber.sent.single().bytes))
    val reply = AwareControl.Message(AwareControl.Type.READY, remote, fixture.nonce, request.request)
    fixture.session.subscriber.onMessageReceived(PeerHandle(8), AwareControl.encode(reply))
    val staleRequest = request.request.replaceRange(0, 1, if (request.request[0] == '0') "1" else "0")
    fixture.session.subscriber.onMessageReceived(peer, AwareControl.encode(reply.copy(request = staleRequest)))
    verify(fixture.context.connectivity.callbacks.isEmpty(), "wrong peer handle and stale request cannot request a network")
    fixture.session.subscriber.onMessageReceived(peer, AwareControl.encode(reply))
    val callback = fixture.context.connectivity.callbacks.single()
    verify(fixture.context.connectivity.requests.single().specifier.peer == peer, "network request binds discovered native peer")
    val factory = ScopedFactory()
    val network = Network(factory)
    callback.onAvailable(network)
    val address = Inet6Address.getByAddress(null, byteArrayOf(0xfe.toByte(), 0x80.toByte()) + ByteArray(13) + 1, 7)
    callback.onCapabilitiesChanged(network, NetworkCapabilities(WifiAwareNetworkInfo(address)))
    verify(factory.calls == 0, "client waits for correlated port control")
    val port = reply.copy(type = AwareControl.Type.PORT, port = 42391)
    fixture.session.subscriber.onMessageReceived(PeerHandle(9), AwareControl.encode(port))
    verify(factory.calls == 0, "foreign native peer cannot supply port")
    fixture.session.subscriber.onMessageReceived(peer, AwareControl.encode(port))
    await("scoped socket delivered", { fixture.listener.connections.size == 1 })
    val destination = factory.socket.destination as InetSocketAddress
    verify(factory.calls == 1 && destination.address == address && destination.port == port.port,
        "socket uses only returned Aware network, peer IPv6 and negotiated port")
    val connection = fixture.listener.connections.single()
    verify(connection.id != "aware-${request.request}", "connection identity is locally generated, not a peer request ID")
    connection.close(); connection.close()
    await("idempotent close releases stream socket", { factory.socket.closedByAdapter })
    fixture.stop()
    val server = Fixture(); server.ready()
    server.request(PeerHandle(10), "0".repeat(32))
    val serverCallback = server.context.connectivity.callbacks.single()
    val serverFactory = ScopedFactory()
    val serverNetwork = Network(serverFactory)
    serverCallback.onAvailable(serverNetwork)
    serverCallback.onCapabilitiesChanged(serverNetwork, NetworkCapabilities(WifiAwareNetworkInfo(address)))
    serverCallback.onLinkPropertiesChanged(serverNetwork, LinkProperties("epix-missing-aware", listOf(LinkAddress(address))))
    await("missing scoped interface unregisters setup", { server.context.connectivity.unregistered.size == 1 })
    verify(serverFactory.calls == 0 && server.listener.connections.isEmpty(), "missing Aware address never falls back to wildcard or default socket")
    server.stop()

    val stopping = Fixture(); stopping.ready()
    stopping.session.subscriber.onServiceDiscovered(peer, AwareControl.advert(remote), mutableListOf())
    val pending = checkNotNull(AwareControl.decode(stopping.subscriber.sent.single().bytes))
    stopping.session.subscriber.onMessageReceived(peer, AwareControl.encode(
        AwareControl.Message(AwareControl.Type.PORT, remote, stopping.nonce, pending.request, 42391)))
    val delayedFactory = ScopedFactory(holdConnect = true)
    val delayedNetwork = Network(delayedFactory)
    val delayed = stopping.context.connectivity.callbacks.single()
    delayed.onAvailable(delayedNetwork)
    delayed.onCapabilitiesChanged(delayedNetwork, NetworkCapabilities(WifiAwareNetworkInfo(address)))
    await("pending connect entered worker", { delayedFactory.socket.destination != null })
    stopping.stop()
    await("stop closes pending socket and unblocks worker", { delayedFactory.socket.closedByAdapter })
    TestMain.drain()
    verify(stopping.listener.connections.isEmpty(), "socket completing after stop cannot deliver a connection")
}

fun main() {
    codecTests(); lifecycleTests(); boundsTests(); scopedClientTests()
    println("PASS: $checks Wi-Fi Aware codec, lifecycle and scoped-socket checks (platform doubles; no hardware claim)")
}
