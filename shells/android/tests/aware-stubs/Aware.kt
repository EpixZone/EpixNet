package android.net.wifi.aware
import android.os.Handler
import java.net.Inet6Address
import java.util.concurrent.CopyOnWriteArrayList

class PeerHandle(val id: Int) {
    override fun equals(other: Any?) = other is PeerHandle && id == other.id
    override fun hashCode() = id
}
open class AttachCallback {
    open fun onAttached(session: WifiAwareSession) {}
    open fun onAttachFailed() {}
}
class WifiAwareManager {
    var isAvailable = true
    var attachCallback: AttachCallback? = null
    fun attach(callback: AttachCallback, handler: Handler) { attachCallback = callback }
    companion object { const val ACTION_WIFI_AWARE_STATE_CHANGED = "aware-changed" }
}
open class DiscoverySession {
    data class Sent(val peer: PeerHandle, val id: Int, val bytes: ByteArray)
    val sent = CopyOnWriteArrayList<Sent>()
    @Volatile var closed = false
    fun sendMessage(peer: PeerHandle, id: Int, bytes: ByteArray) { check(!closed); sent.add(Sent(peer, id, bytes)) }
    fun close() { closed = true }
}
class PublishDiscoverySession : DiscoverySession()
class SubscribeDiscoverySession : DiscoverySession()
open class DiscoverySessionCallback {
    open fun onPublishStarted(session: PublishDiscoverySession) {}
    open fun onSubscribeStarted(session: SubscribeDiscoverySession) {}
    open fun onServiceDiscovered(peer: PeerHandle?, info: ByteArray?, filters: MutableList<ByteArray>?) {}
    open fun onMessageReceived(peer: PeerHandle?, bytes: ByteArray?) {}
    open fun onServiceLost(peer: PeerHandle, reason: Int) {}
    open fun onSessionConfigFailed() {}
    open fun onSessionTerminated() {}
}
class PublishConfig(val name: String, val info: ByteArray) {
    class Builder {
        private var name = ""
        private var info = byteArrayOf()
        fun setServiceName(value: String) = apply { name = value }
        fun setServiceSpecificInfo(value: ByteArray) = apply { info = value }
        fun build() = PublishConfig(name, info)
    }
}
class SubscribeConfig(val name: String, val info: ByteArray) {
    class Builder {
        private var name = ""
        private var info = byteArrayOf()
        fun setServiceName(value: String) = apply { name = value }
        fun setServiceSpecificInfo(value: ByteArray) = apply { info = value }
        fun build() = SubscribeConfig(name, info)
    }
}
class WifiAwareSession {
    lateinit var publishConfig: PublishConfig
    lateinit var subscribeConfig: SubscribeConfig
    lateinit var publisher: DiscoverySessionCallback
    lateinit var subscriber: DiscoverySessionCallback
    @Volatile var closed = false
    fun publish(config: PublishConfig, callback: DiscoverySessionCallback, handler: Handler) {
        publishConfig = config; publisher = callback
    }
    fun subscribe(config: SubscribeConfig, callback: DiscoverySessionCallback, handler: Handler) {
        subscribeConfig = config; subscriber = callback
    }
    fun close() { closed = true }
}
class WifiAwareNetworkSpecifier(val session: DiscoverySession, val peer: PeerHandle) {
    class Builder(private val session: DiscoverySession, private val peer: PeerHandle) {
        fun build() = WifiAwareNetworkSpecifier(session, peer)
    }
}
class WifiAwareNetworkInfo(val peerIpv6Addr: Inet6Address?)
