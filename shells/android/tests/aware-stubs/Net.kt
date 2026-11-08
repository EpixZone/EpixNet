package android.net
import android.os.Handler
import android.net.wifi.aware.WifiAwareNetworkSpecifier
import java.net.InetAddress
import java.util.concurrent.CopyOnWriteArrayList
import javax.net.SocketFactory

class Network(val socketFactory: SocketFactory)
class NetworkCapabilities(var transportInfo: Any? = null) { companion object { const val TRANSPORT_WIFI_AWARE = 5 } }
class LinkAddress(val address: InetAddress)
class LinkProperties(var interfaceName: String? = null, val linkAddresses: List<LinkAddress> = emptyList())
class NetworkRequest(val specifier: WifiAwareNetworkSpecifier) {
    class Builder {
        private lateinit var specifier: WifiAwareNetworkSpecifier
        fun addTransportType(type: Int) = apply { check(type == NetworkCapabilities.TRANSPORT_WIFI_AWARE) }
        fun setNetworkSpecifier(value: WifiAwareNetworkSpecifier) = apply { specifier = value }
        fun build() = NetworkRequest(specifier)
    }
}
class ConnectivityManager {
    open class NetworkCallback {
        open fun onAvailable(network: Network) {}
        open fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {}
        open fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {}
        open fun onUnavailable() {}
        open fun onLost(network: Network) {}
    }
    val callbacks = CopyOnWriteArrayList<NetworkCallback>()
    val requests = CopyOnWriteArrayList<NetworkRequest>()
    val unregistered = CopyOnWriteArrayList<NetworkCallback>()
    fun requestNetwork(request: NetworkRequest, callback: NetworkCallback, handler: Handler, timeout: Int) {
        check(timeout in 1..15000)
        requests.add(request); callbacks.add(callback)
    }
    fun unregisterNetworkCallback(callback: NetworkCallback) { unregistered.add(callback) }
}
