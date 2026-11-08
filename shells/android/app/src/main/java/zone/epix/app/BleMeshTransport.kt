package zone.epix.app

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.os.SystemClock
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Wire discovery hints only. These values do not authenticate a peer or replace Rust framing. */
internal object BleMeshProtocol {
    const val SERVICE_UUID = "5c228a51-e2d4-4c6e-9639-3f7cc62b7109"
    const val ADVERTISEMENT_SIZE = 11
    const val HELLO_SIZE = 16
    private val magic = "EPIXBLE1".toByteArray(Charsets.US_ASCII)

    data class Advertisement(val psm: Int, val nonce: Long)

    fun advertisement(psm: Int, nonce: Long): ByteArray {
        require(psm in 1..65535)
        return ByteBuffer.allocate(ADVERTISEMENT_SIZE).put(1).putShort(psm.toShort()).putLong(nonce).array()
    }

    fun parseAdvertisement(bytes: ByteArray?): Advertisement? {
        if (bytes == null || bytes.size != ADVERTISEMENT_SIZE || bytes[0] != 1.toByte()) return null
        val buffer = ByteBuffer.wrap(bytes)
        buffer.get()
        val psm = buffer.short.toInt() and 0xffff
        return if (psm == 0) null else Advertisement(psm, buffer.long)
    }

    fun shouldDial(local: Long, remote: Long): Boolean = java.lang.Long.compareUnsigned(local, remote) < 0

    fun hello(nonce: Long): ByteArray = ByteBuffer.allocate(HELLO_SIZE).put(magic).putLong(nonce).array()

    fun readHello(input: InputStream): Long {
        val bytes = ByteArray(HELLO_SIZE)
        var offset = 0
        while (offset < bytes.size) {
            val count = input.read(bytes, offset, bytes.size - offset)
            if (count <= 0) throw EOFException("Incomplete nearby handshake")
            offset += count
        }
        if (!bytes.copyOfRange(0, magic.size).contentEquals(magic)) throw IOException("Unknown nearby protocol")
        return ByteBuffer.wrap(bytes, magic.size, 8).long
    }
}

/** Counts pending handshakes too, rejects duplicates, and cannot be reused after stop. */
internal class BlePeerGate(private val limit: Int = 4) {
    private val peers = mutableMapOf<Int, Long?>()
    private var nextId = 0
    private var stopped = false

    @Synchronized fun reserve(): Int? {
        if (stopped || peers.size >= limit) return null
        val id = nextId++
        peers[id] = null
        return id
    }

    @Synchronized fun identify(id: Int, nonce: Long): Boolean {
        if (stopped || !peers.containsKey(id) || peers.any { it.key != id && it.value == nonce }) return false
        peers[id] = nonce
        return true
    }

    @Synchronized fun release(id: Int) { peers.remove(id) }
    @Synchronized fun stop() { stopped = true; peers.clear() }
}

/** Discovery input is untrusted. Keep both retry frequency and retained hints bounded. */
internal class BleAttemptWindow(private val capacity: Int = 64, private val cooldownMs: Long = 15_000) {
    private val attempts = LinkedHashMap<Long, Long>()

    @Synchronized fun allow(nonce: Long, nowMs: Long): Boolean {
        val previous = attempts[nonce]
        if (previous != null && nowMs - previous < cooldownMs) return false
        attempts.remove(nonce)
        if (attempts.size >= capacity) attempts.remove(attempts.keys.first())
        attempts[nonce] = nowMs
        return true
    }
}

/**
 * Opt-in BLE discovery and LE L2CAP CoC bearer, Android 10 and newer.
 * The insecure CoC avoids pairing UI; Reticulum provides end-to-end authentication/encryption.
 * No Bluetooth address or name is persisted, logged, or presented as a trusted peer identity.
 */
internal class BleMeshTransport(context: Context) : NearbyTransport {
    override val kind = NearbyKind.BLE
    private val app = context.applicationContext
    private val main = Handler(Looper.getMainLooper())
    private val lock = Any()
    private val service = ParcelUuid(UUID.fromString(BleMeshProtocol.SERVICE_UUID))
    private val control = ThreadPoolExecutor(0, 1, 30, TimeUnit.SECONDS, LinkedBlockingQueue<Runnable>()) { task ->
        Thread(task, "epix-ble-control").apply { isDaemon = true }
    }
    private val deadlines = ScheduledThreadPoolExecutor(1) { task ->
        Thread(task, "epix-ble-deadline").apply { isDaemon = true }
    }.apply {
        removeOnCancelPolicy = true
        setKeepAliveTime(30, TimeUnit.SECONDS)
        allowCoreThreadTimeOut(true)
    }
    private var generation = 0L
    private var current: Run? = null

    private class Run(val generation: Long, val listener: NearbyTransport.Listener) {
        val nonce = SecureRandom().nextLong()
        val peers = BlePeerGate()
        val attempts = BleAttemptWindow()
        val sockets = mutableMapOf<Int, BluetoothSocket>()
        val workers = ThreadPoolExecutor(5, 5, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue<Runnable>(4)) { task ->
            Thread(task, "epix-ble-io").apply { isDaemon = true }
        }
        var server: BluetoothServerSocket? = null
        var scanner: BluetoothLeScanner? = null
        var advertiser: BluetoothLeAdvertiser? = null
        var scan: ScanCallback? = null
        var advertising: AdvertiseCallback? = null
        var receiver: BroadcastReceiver? = null
    }

    override fun capability(): NearbyCapability = when {
        Build.VERSION.SDK_INT < 29 -> NearbyCapability(false, "Bluetooth mesh needs Android 10 or newer.")
        !app.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE) -> NearbyCapability(false, "This device does not support Bluetooth LE.")
        else -> NearbyCapability(true, "Bluetooth LE discovery and L2CAP streams are supported.")
    }

    override fun start(listener: NearbyTransport.Listener) {
        val previous: Run?
        val run: Run
        synchronized(lock) {
            previous = current
            run = Run(++generation, listener)
            current = run
        }
        status(run, NearbyState.STARTING, "Starting Bluetooth discovery…")
        control.execute {
            previous?.let(::cleanup)
            if (active(run)) setup(run) else cleanup(run)
        }
    }

    override fun stop() {
        val run: Run?
        val stoppedGeneration: Long
        synchronized(lock) {
            run = current
            current = null
            stoppedGeneration = ++generation
            run?.peers?.stop()
        }
        if (run == null) return
        control.execute { cleanup(run) }
        main.post {
            if (synchronized(lock) { generation == stoppedGeneration }) {
                run.listener.onStatus(kind, NearbyStatus(NearbyState.STOPPED, "Bluetooth discovery is off."))
            }
        }
    }

    private fun active(run: Run): Boolean = synchronized(lock) { current === run }

    private fun status(run: Run, state: NearbyState, detail: String) {
        main.post {
            if (synchronized(lock) { generation == run.generation }) run.listener.onStatus(kind, NearbyStatus(state, detail))
        }
    }

    private fun fail(run: Run, state: NearbyState, detail: String) {
        synchronized(lock) {
            if (current !== run) return
            current = null
            run.peers.stop()
        }
        control.execute { cleanup(run) }
        status(run, state, detail)
    }

    private fun setup(run: Run) {
        val support = capability()
        if (Build.VERSION.SDK_INT < 29 || !support.supported) {
            fail(run, NearbyState.UNSUPPORTED, support.detail)
            return
        }
        try {
            val adapter = app.getSystemService(BluetoothManager::class.java)?.adapter
            if (adapter == null || !adapter.isEnabled) {
                fail(run, NearbyState.UNAVAILABLE, "Turn on Bluetooth in Android settings to use nearby mesh.")
                return
            }
            val advertiser = adapter.bluetoothLeAdvertiser
            val scanner = adapter.bluetoothLeScanner
            if (!adapter.isMultipleAdvertisementSupported || advertiser == null || scanner == null) {
                fail(run, NearbyState.UNSUPPORTED, "This device cannot advertise Bluetooth LE connections.")
                return
            }
            watchAdapter(run, adapter)
            run.server = adapter.listenUsingInsecureL2capChannel()
            run.advertiser = advertiser
            run.scanner = scanner
            if (!active(run)) return
            advertise(run, advertiser, run.server!!.psm)
            scan(run, scanner)
            run.workers.execute { accept(run) }
        } catch (_: SecurityException) {
            fail(run, NearbyState.PERMISSION_REQUIRED, "Allow nearby Bluetooth permissions to start discovery.")
        } catch (_: IOException) {
            fail(run, NearbyState.FAILED, "Bluetooth could not open a nearby listener. Try again.")
        } catch (_: RuntimeException) {
            fail(run, NearbyState.UNAVAILABLE, "Bluetooth is unavailable. Check Android settings and try again.")
        }
    }

    private fun watchAdapter(run: Run, adapter: BluetoothAdapter) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action != BluetoothAdapter.ACTION_STATE_CHANGED || !active(run)) return
                try {
                    if (!adapter.isEnabled) fail(run, NearbyState.UNAVAILABLE, "Bluetooth was turned off. Nearby connections have closed.")
                } catch (_: SecurityException) {
                    fail(run, NearbyState.PERMISSION_REQUIRED, "Bluetooth permission was removed. Nearby connections have closed.")
                }
            }
        }
        val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= 33) app.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
        else app.registerReceiver(receiver, filter)
        run.receiver = receiver
    }

    private fun advertise(run: Run, advertiser: BluetoothLeAdvertiser, psm: Int) {
        val callback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                if (active(run)) status(run, NearbyState.DISCOVERING, "Looking for nearby EpixNet devices…")
            }

            override fun onStartFailure(errorCode: Int) {
                fail(run, NearbyState.FAILED, "Bluetooth advertising could not start (code $errorCode). Try again.")
            }
        }
        run.advertising = callback
        // 128-bit service UUID plus flags fits 31 bytes. The 11-byte payload and its
        // 128-bit service-data field fit separately in the 31-byte scan response.
        val data = AdvertiseData.Builder().addServiceUuid(service).setIncludeDeviceName(false).build()
        val response = AdvertiseData.Builder().addServiceData(service, BleMeshProtocol.advertisement(psm, run.nonce)).build()
        val settings = AdvertiseSettings.Builder().setConnectable(true).setTimeout(0)
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM).build()
        advertiser.startAdvertising(settings, data, response, callback)
    }

    private fun scan(run: Run, scanner: BluetoothLeScanner) {
        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult?) {
                if (Build.VERSION.SDK_INT < 29 || result == null || !active(run)) return
                val hint = BleMeshProtocol.parseAdvertisement(result.scanRecord?.getServiceData(service)) ?: return
                if (!BleMeshProtocol.shouldDial(run.nonce, hint.nonce)) return
                if (!run.attempts.allow(hint.nonce, SystemClock.elapsedRealtime())) return
                val slot = run.peers.reserve() ?: return
                if (!run.peers.identify(slot, hint.nonce)) { run.peers.release(slot); return }
                submit(run, slot) {
                    val socket = result.device.createInsecureL2capChannel(hint.psm)
                    if (!attach(run, slot, socket)) return@submit
                    handshake(run, slot, socket, hint.nonce, connect = true)
                }
            }

            override fun onScanFailed(errorCode: Int) {
                fail(run, NearbyState.FAILED, "Bluetooth scanning could not start (code $errorCode). Try again.")
            }
        }
        run.scan = callback
        scanner.startScan(listOf(ScanFilter.Builder().setServiceUuid(service).build()),
            ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(), callback)
    }

    private fun accept(run: Run) {
        try {
            while (active(run)) {
                val socket = run.server?.accept() ?: break
                val slot = run.peers.reserve()
                if (slot == null || !attach(run, slot, socket)) {
                    closeQuietly(socket)
                    continue
                }
                submit(run, slot) { handshake(run, slot, socket, expectedNonce = null, connect = false) }
            }
        } catch (_: SecurityException) {
            fail(run, NearbyState.PERMISSION_REQUIRED, "Bluetooth permission was removed. Nearby connections have closed.")
        } catch (_: IOException) {
            fail(run, NearbyState.UNAVAILABLE, "Bluetooth listener stopped. Try nearby discovery again.")
        } catch (_: RuntimeException) {
            fail(run, NearbyState.UNAVAILABLE, "Bluetooth listener became unavailable. Try again.")
        }
    }

    private fun submit(run: Run, slot: Int, operation: () -> Unit) {
        try {
            run.workers.execute {
                try {
                    if (active(run)) operation() else release(run, slot)
                } catch (_: SecurityException) {
                    release(run, slot)
                    fail(run, NearbyState.PERMISSION_REQUIRED, "Bluetooth permission was removed. Nearby connections have closed.")
                } catch (_: IOException) {
                    release(run, slot)
                } catch (_: RuntimeException) {
                    release(run, slot)
                }
            }
        } catch (_: RejectedExecutionException) {
            release(run, slot)
        }
    }

    private fun attach(run: Run, slot: Int, socket: BluetoothSocket): Boolean {
        synchronized(lock) {
            if (current === run) {
                run.sockets[slot] = socket
                return true
            }
        }
        run.peers.release(slot)
        closeQuietly(socket)
        return false
    }

    private fun handshake(run: Run, slot: Int, socket: BluetoothSocket, expectedNonce: Long?, connect: Boolean) {
        val finished = AtomicBoolean(false)
        val deadline: ScheduledFuture<*> = deadlines.schedule({
            if (finished.compareAndSet(false, true)) closeQuietly(socket)
        }, 10, TimeUnit.SECONDS)
        try {
            if (connect) socket.connect()
            val input = socket.inputStream
            val output = socket.outputStream
            output.write(BleMeshProtocol.hello(run.nonce))
            output.flush()
            val remote = BleMeshProtocol.readHello(input)
            val valid = if (expectedNonce != null) remote == expectedNonce
                else BleMeshProtocol.shouldDial(remote, run.nonce)
            if (!valid || !run.peers.identify(slot, remote) || !active(run)) throw IOException("Unexpected nearby handshake")
            // Cancel before handing the streams to the coordinator, which owns its IO pumps.
            if (!finished.compareAndSet(false, true)) throw IOException("Nearby handshake timed out")
            deadline.cancel(false)
            val connection = NearbyConnection("ble-${run.generation}-$slot", kind, "Bluetooth peer ${slot + 1}", input, output) {
                release(run, slot)
            }
            main.post {
                if (active(run)) {
                    try { run.listener.onConnection(connection) }
                    catch (_: RuntimeException) { control.execute { connection.close() } }
                } else control.execute { connection.close() }
            }
        } finally {
            finished.set(true)
            deadline.cancel(false)
        }
    }

    private fun release(run: Run, slot: Int) {
        val socket = synchronized(lock) { run.sockets.remove(slot) }
        run.peers.release(slot)
        socket?.let(::closeQuietly)
    }

    private fun cleanup(run: Run) {
        run.peers.stop()
        try { run.server?.close() } catch (_: IOException) { /* Already closed or unavailable. */ }
        catch (_: RuntimeException) { /* Radio service or permission already removed. */ }
        val sockets = synchronized(lock) { run.sockets.values.toList().also { run.sockets.clear() } }
        sockets.forEach(::closeQuietly)
        run.workers.shutdownNow()
        try { run.scan?.let { run.scanner?.stopScan(it) } }
        catch (_: SecurityException) { /* Permission was removed before cleanup. */ }
        catch (_: RuntimeException) { /* Radio service is already unavailable. */ }
        try { run.advertising?.let { run.advertiser?.stopAdvertising(it) } }
        catch (_: SecurityException) { /* Permission was removed before cleanup. */ }
        catch (_: RuntimeException) { /* Radio service is already unavailable. */ }
        try { run.receiver?.let(app::unregisterReceiver) } catch (_: IllegalArgumentException) { /* Already unregistered. */ }
        run.receiver = null
    }

    private fun closeQuietly(socket: BluetoothSocket) {
        try { socket.close() } catch (_: IOException) { /* Closing is idempotent. */ }
        catch (_: RuntimeException) { /* Radio service or permission already removed. */ }
    }
}
