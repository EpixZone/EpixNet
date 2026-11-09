package zone.epix.app

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket

/** Process-owned refusing endpoint while native startup has no SOCKS listener yet. */
internal object UnavailableTorProxy {
    val port: Int by lazy {
        val listener = ServerSocket()
        try {
            listener.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 16)
        } catch (error: Exception) {
            listener.close()
            throw error
        }
        // Gecko survives Activity recreation. Keep the socket owned for that
        // same process lifetime, including after preferences select native Tor.
        Thread({
            while (!listener.isClosed) {
                try { listener.accept().close() } catch (_: java.io.IOException) {
                    // A transient accept failure must not release the port to another app.
                    try { Thread.sleep(100) } catch (_: InterruptedException) { }
                }
            }
        }, "epix-unavailable-tor").apply { isDaemon = true; start() }
        listener.localPort
    }
}
