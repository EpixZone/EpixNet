package zone.epix.app

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.ScanRecord
import android.bluetooth.le.ScanResult
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.ParcelUuid
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

private var checks = 0
private val mainThread = Thread.currentThread()
private fun expect(condition: Boolean, message: String) { check(condition) { message }; checks++ }
private fun await(message: String, predicate: () -> Boolean) {
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(6)
    while (System.nanoTime() < deadline) {
        Handler.drain()
        if (predicate()) { checks++; return }
        Thread.sleep(5)
    }
    error("Timed out: $message")
}
private fun rejects(message: String, block: () -> Unit) {
    try { block(); error("Expected rejection: $message") } catch (_: IOException) { checks++ }
}

private class Listener : NearbyTransport.Listener {
    val statuses = mutableListOf<NearbyState>()
    val connections = mutableListOf<NearbyConnection>()
    override fun onStatus(kind: NearbyKind, status: NearbyStatus) {
        expect(Thread.currentThread() === mainThread, "Status runs on main")
        expect(kind == NearbyKind.BLE, "BLE status kind")
        statuses.add(status.state)
    }
    override fun onConnection(connection: NearbyConnection) {
        expect(Thread.currentThread() === mainThread, "Connection runs on main")
        connections.add(connection)
    }
}

private class Fixture {
    val context = Context()
    val adapter = context.manager.adapter
    val transport = BleMeshTransport(context)
    val listener = Listener()
    val service = ParcelUuid(UUID.fromString(BleMeshProtocol.SERVICE_UUID))
    fun start() {
        transport.start(listener)
        await("scanning started") { adapter.bluetoothLeScanner.started.isNotEmpty() }
    }
    fun hint() = BleMeshProtocol.parseAdvertisement(adapter.bluetoothLeAdvertiser.started.last().response.serviceData[service])!!
    fun advertise(remote: Long, socket: BluetoothSocket, psm: Int = 171) {
        val record = ScanRecord(mapOf(service to BleMeshProtocol.advertisement(psm, remote)))
        adapter.bluetoothLeScanner.started.last().onScanResult(1, ScanResult(BluetoothDevice(socket), record))
    }
    fun stop() {
        transport.stop()
        await("resources stopped") { adapter.servers.all { it.closed } && context.receivers.isEmpty() }
    }
}

private class BlockingInput : InputStream() {
    val entered = CountDownLatch(1)
    private val closed = CountDownLatch(1)
    override fun read(): Int {
        entered.countDown()
        try { closed.await() } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("Closed", error)
        }
        return -1
    }
    override fun read(bytes: ByteArray, offset: Int, length: Int): Int = read()
    override fun close() { closed.countDown() }
}

private fun protocol() {
    for (psm in listOf(1, 128, 255, 65535)) for (nonce in listOf(0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE)) {
        val bytes = BleMeshProtocol.advertisement(psm, nonce)
        expect(bytes.size == 11, "Fixed advertisement size")
        expect(BleMeshProtocol.parseAdvertisement(bytes) == BleMeshProtocol.Advertisement(psm, nonce), "Unsigned PSM/nonce round trip")
    }
    val valid = BleMeshProtocol.advertisement(129, 0x0102030405060708L)
    expect(valid.contentEquals(byteArrayOf(1, 0, 0x81.toByte(), 1, 2, 3, 4, 5, 6, 7, 8)), "Network byte order")
    expect(BleMeshProtocol.parseAdvertisement(null) == null, "Absent scan response ignored")
    for (size in listOf(0, 1, 10, 12, 31, 1000)) expect(BleMeshProtocol.parseAdvertisement(ByteArray(size)) == null, "Reject malformed size $size")
    expect(BleMeshProtocol.parseAdvertisement(valid.copyOf().apply { this[0] = 2 }) == null, "Reject other protocol version")
    expect(BleMeshProtocol.parseAdvertisement(valid.copyOf().apply { this[1] = 0; this[2] = 0 }) == null, "Reject zero PSM")
    expect(!BleMeshProtocol.shouldDial(1, 1), "Do not dial self")
    for (a in listOf(0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE)) for (b in listOf(0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE)) {
        if (a != b) expect(BleMeshProtocol.shouldDial(a, b) != BleMeshProtocol.shouldDial(b, a), "Exactly one dialer across unsigned boundary")
    }
    val stream = ByteArrayInputStream(BleMeshProtocol.hello(-1) + byteArrayOf(42))
    expect(BleMeshProtocol.readHello(stream) == -1L, "Handshake nonce")
    expect(stream.read() == 42, "Handshake leaves subsequent mesh bytes untouched")
    rejects("truncated hello") { BleMeshProtocol.readHello(ByteArrayInputStream(BleMeshProtocol.hello(2).copyOf(15))) }
    rejects("other protocol") { BleMeshProtocol.readHello(ByteArrayInputStream(BleMeshProtocol.hello(2).apply { this[0] = 0 })) }
    rejects("zero progress") { BleMeshProtocol.readHello(object : InputStream() {
        override fun read() = 0
        override fun read(bytes: ByteArray, offset: Int, length: Int) = 0
    }) }
}

private fun gatesAndClose() {
    val gate = BlePeerGate()
    val slots = (1..4).map { gate.reserve()!! }
    expect(gate.reserve() == null, "Four pending peers fill capacity")
    expect(gate.identify(slots[0], 8), "First peer accepted")
    expect(!gate.identify(slots[1], 8), "Duplicate peer refused")
    gate.release(slots[0])
    expect(gate.identify(slots[1], 8), "Released peer can reconnect")
    gate.stop()
    expect(gate.reserve() == null && !gate.identify(slots[1], 8), "Stopped generation cannot accept delayed peer")
    val concurrent = BlePeerGate()
    val accepted = AtomicInteger()
    val threads = (1..40).map { Thread { if (concurrent.reserve() != null) accepted.incrementAndGet() }.apply { start() } }
    threads.forEach { it.join() }
    expect(accepted.get() == 4, "Concurrent reservations respect hard capacity")
    val retries = BleAttemptWindow(capacity = 2, cooldownMs = 100)
    expect(retries.allow(1, 0) && !retries.allow(1, 99) && retries.allow(1, 100), "Per-peer retry cooldown")
    expect(retries.allow(2, 101) && retries.allow(3, 102) && retries.allow(1, 103), "Bounded hint cache evicts oldest")
    val closes = AtomicInteger()
    val connection = NearbyConnection("temporary", NearbyKind.BLE, "Bluetooth peer 1", ByteArrayInputStream(byteArrayOf()), ByteArrayOutputStream()) { closes.incrementAndGet() }
    (1..20).map { Thread { connection.close() }.apply { start() } }.forEach { it.join() }
    expect(closes.get() == 1, "Concurrent connection close invokes owner once")
}

private fun unavailableAndPermissions() {
    Build.VERSION.SDK_INT = 28
    val old = Fixture()
    expect(!old.transport.capability().supported, "API28 is unsupported before requesting permissions")
    old.transport.start(old.listener)
    await("unsupported result") { NearbyState.UNSUPPORTED in old.listener.statuses }
    expect(old.adapter.servers.isEmpty() && old.context.receivers.isEmpty(), "Unsupported API does not touch radio")
    old.stop()
    Build.VERSION.SDK_INT = 37
    val absent = Fixture()
    absent.context.packageManager.ble = false
    expect(!absent.transport.capability().supported, "Feature absent is unsupported")
    val off = Fixture()
    off.adapter.enabled = false
    off.transport.start(off.listener)
    await("radio off result") { NearbyState.UNAVAILABLE in off.listener.statuses }
    expect(!off.adapter.enabled && off.adapter.servers.isEmpty(), "Transport never enables radio")
    off.stop()
    val denied = Fixture()
    denied.adapter.permissionDenied = true
    denied.transport.start(denied.listener)
    await("permission result") { NearbyState.PERMISSION_REQUIRED in denied.listener.statuses }
    expect(denied.adapter.servers.isEmpty(), "No listener without permission")
    denied.stop()
    val partial = Fixture()
    partial.adapter.bluetoothLeScanner.failSecurity = true
    partial.transport.start(partial.listener)
    await("partial setup cleanup") { NearbyState.PERMISSION_REQUIRED in partial.listener.statuses && partial.adapter.servers.all { it.closed } && partial.context.receivers.isEmpty() }
    expect(partial.adapter.bluetoothLeAdvertiser.stopped.size == 1, "Advertising stopped after scan permission failure")
    partial.stop()
}

private fun delayedCallbacksAndStop() {
    val f = Fixture()
    f.adapter.bluetoothLeAdvertiser.autoSuccess = false
    f.start()
    val oldAdvertising = f.adapter.bluetoothLeAdvertiser.started.single()
    val oldScan = f.adapter.bluetoothLeScanner.started.single()
    expect(oldAdvertising.data.uuids == listOf(f.service), "Only our private service advertised")
    expect(oldAdvertising.data.serviceData.isEmpty(), "Service data kept out of primary 31-byte packet")
    expect(18 + oldAdvertising.response.serviceData.getValue(f.service).size <= 31, "128-bit scan response fits legacy advertising")
    expect(f.adapter.bluetoothLeScanner.filters.single().service == f.service, "Discovery filter is scoped to our service")
    f.stop()
    val statusCount = f.listener.statuses.size
    oldAdvertising.callback.onStartSuccess(oldAdvertising.settings)
    oldAdvertising.callback.onStartFailure(1)
    oldScan.onScanFailed(2)
    Handler.drain()
    expect(f.listener.statuses.size == statusCount, "Stopped callbacks cannot revive discovery/failure")
    f.adapter.bluetoothLeAdvertiser.autoSuccess = true
    f.transport.start(f.listener)
    await("second generation") { f.adapter.servers.size == 2 && NearbyState.DISCOVERING in f.listener.statuses }
    oldScan.onScanFailed(3)
    Handler.drain()
    expect(!f.adapter.servers.last().closed, "Old generation failure cannot stop replacement")
    f.stop()
}

private fun streamAndBounds() {
    val f = Fixture()
    f.start()
    val local = f.hint().nonce
    val remote = if (local == -1L) 0 else local + 1
    val bytes = BleMeshProtocol.hello(remote) + byteArrayOf(77)
    val socket = BluetoothSocket(ByteArrayInputStream(bytes))
    if (BleMeshProtocol.shouldDial(local, remote)) f.advertise(remote, socket)
    else f.adapter.servers.single().incoming.add(socket)
    await("stream handed off") { f.listener.connections.size == 1 }
    val connection = f.listener.connections.single()
    expect(connection.input.read() == 77, "Delivered stream begins at Rust payload")
    expect((socket.outputStream as ByteArrayOutputStream).toByteArray().contentEquals(BleMeshProtocol.hello(local)), "Fixed bearer hello sent before payload")
    connection.close()
    expect(socket.closeCount.get() > 0, "Consumer close releases socket")
    val blocked = (1..4).map { BluetoothSocket(BlockingInput()).also { f.adapter.servers.single().incoming.add(it) } }
    blocked.forEach { expect((it.inputStream as BlockingInput).entered.await(2, TimeUnit.SECONDS), "Pending handshake admitted") }
    val excess = BluetoothSocket(BlockingInput())
    f.adapter.servers.single().incoming.add(excess)
    await("fifth connection refused") { excess.closeCount.get() > 0 }
    f.stop()
    expect(blocked.all { it.closeCount.get() > 0 }, "Stop closes all blocked handshakes")
    expect(f.adapter.bluetoothLeScanner.stopped.size == 1 && f.adapter.bluetoothLeAdvertiser.stopped.size == 1, "Stop ends scan and advertisement")
    expect(f.listener.connections.size == 1, "No delayed stream delivery after stop")
}

private fun adapterLossAndMismatchedHello() {
    val f = Fixture()
    f.start()
    val pending = BluetoothSocket(BlockingInput())
    f.adapter.servers.single().incoming.add(pending)
    expect((pending.inputStream as BlockingInput).entered.await(2, TimeUnit.SECONDS), "Incoming handshake blocked")
    f.adapter.enabled = false
    f.context.broadcast(BluetoothAdapter.ACTION_STATE_CHANGED)
    await("radio loss cleanup") { NearbyState.UNAVAILABLE in f.listener.statuses && pending.closeCount.get() > 0 && f.context.receivers.isEmpty() }
    expect(f.listener.connections.isEmpty(), "Availability loss never delivers incomplete stream")
    f.stop()
    val wrong = Fixture()
    wrong.start()
    val local = wrong.hint().nonce
    val socket = BluetoothSocket(ByteArrayInputStream(BleMeshProtocol.hello(local)))
    wrong.adapter.servers.single().incoming.add(socket)
    await("self hello rejected") { socket.closeCount.get() > 0 }
    expect(wrong.listener.connections.isEmpty(), "Self/incorrect hello is not a mesh connection")
    wrong.stop()
}

private fun pendingDialAndDeadline() {
    val f = Fixture()
    f.start()
    val local = f.hint().nonce
    // Every unsigned value except MAX has a larger dial target. The MAX case
    // exercises the same timeout on an accepted stream without a random fixture failure.
    val pending = BluetoothSocket(BlockingInput())
    if (local != -1L) {
        pending.connectGate = CountDownLatch(1)
        f.advertise(local + 1, pending)
        await("outgoing connect entered") { pending.connectCount.get() == 1 }
    } else f.adapter.servers.single().incoming.add(pending)
    f.stop()
    expect(pending.closeCount.get() > 0, "Stop aborts outstanding connect as well as read")
    expect(f.listener.connections.isEmpty(), "Cancelled dial not delivered")

    val timeout = Fixture()
    timeout.start()
    val blocked = BluetoothSocket(BlockingInput())
    timeout.adapter.servers.single().incoming.add(blocked)
    expect((blocked.inputStream as BlockingInput).entered.await(2, TimeUnit.SECONDS), "Deadline test reached actual blocking read")
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(14)
    while (blocked.closeCount.get() == 0 && System.nanoTime() < deadline) Thread.sleep(20)
    expect(blocked.closeCount.get() > 0, "Ten-second handshake deadline aborts stalled peer")
    Handler.drain()
    expect(timeout.listener.connections.isEmpty(), "Timed out stream not delivered")
    timeout.stop()
}

fun main() {
    val workerErrors = java.util.concurrent.CopyOnWriteArrayList<Throwable>()
    Thread.setDefaultUncaughtExceptionHandler { _, error -> workerErrors.add(error) }
    protocol()
    gatesAndClose()
    unavailableAndPermissions()
    delayedCallbacksAndStop()
    streamAndBounds()
    adapterLossAndMismatchedHello()
    pendingDialAndDeadline()
    await("all IO workers released") { Thread.getAllStackTraces().keys.none { it.name == "epix-ble-io" && it.isAlive } }
    expect(workerErrors.isEmpty(), "No worker exceptions: $workerErrors")
    println("BLE transport regressions passed: $checks checks")
}
