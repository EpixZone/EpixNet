package android.bluetooth

import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.le.BluetoothLeScanner
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicInteger

class BluetoothManager { val adapter = BluetoothAdapter() }
class BluetoothAdapter {
    @Volatile var enabled = true
    @Volatile var permissionDenied = false
    val isEnabled: Boolean get() { if (permissionDenied) throw SecurityException(); return enabled }
    var isMultipleAdvertisementSupported = true
    val bluetoothLeAdvertiser = BluetoothLeAdvertiser()
    val bluetoothLeScanner = BluetoothLeScanner()
    val servers = java.util.concurrent.CopyOnWriteArrayList<BluetoothServerSocket>()
    fun listenUsingInsecureL2capChannel(): BluetoothServerSocket = BluetoothServerSocket().also { servers.add(it) }
    companion object { const val ACTION_STATE_CHANGED = "android.bluetooth.adapter.action.STATE_CHANGED" }
}
class BluetoothDevice(val socket: BluetoothSocket = BluetoothSocket()) {
    @Volatile var requestedPsm = 0
    fun createInsecureL2capChannel(psm: Int): BluetoothSocket { requestedPsm = psm; return socket }
}
class BluetoothServerSocket {
    val psm = 129
    val incoming = LinkedBlockingQueue<BluetoothSocket>()
    @Volatile var closed = false
    fun accept(): BluetoothSocket {
        if (closed) throw IOException("Closed")
        val socket = try { incoming.take() } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("Closed", error)
        }
        if (closed) throw IOException("Closed")
        return socket
    }
    fun close() { closed = true; incoming.offer(BluetoothSocket()) }
}
class BluetoothSocket(
    val inputStream: InputStream = ByteArrayInputStream(byteArrayOf()),
    val outputStream: OutputStream = ByteArrayOutputStream(),
) {
    val closeCount = AtomicInteger()
    val connectCount = AtomicInteger()
    @Volatile var connectGate: CountDownLatch? = null
    fun connect() {
        connectCount.incrementAndGet()
        try { connectGate?.await() } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("Closed", error)
        }
        if (closeCount.get() > 0) throw IOException("Closed")
    }
    fun close() {
        closeCount.incrementAndGet()
        connectGate?.countDown()
        inputStream.close()
        outputStream.close()
    }
}
