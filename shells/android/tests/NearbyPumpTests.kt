package zone.epix.app

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

private var checks = 0
private fun expect(value: Boolean, message: String) { check(value) { message }; checks++ }
private suspend fun await(message: String, condition: () -> Boolean) {
    try { withTimeout(2500) { while (!condition()) delay(5) } }
    catch (error: kotlinx.coroutines.TimeoutCancellationException) { throw IllegalStateException("Timed out: $message", error) }
    expect(condition(), message)
}

private class PipeInput : InputStream() {
    private val queue = LinkedBlockingQueue<ByteArray>()
    private var remaining = byteArrayOf()
    val reads = AtomicInteger()
    val closes = AtomicInteger()
    @Volatile private var closed = false
    fun data(bytes: ByteArray) { require(bytes.isNotEmpty()); queue.add(bytes) }
    fun eof() { queue.add(byteArrayOf()) }
    override fun read(): Int = ByteArray(1).let { if (read(it, 0, 1) < 0) -1 else it[0].toInt() and 255 }
    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
        reads.incrementAndGet()
        if (closed) return -1
        if (remaining.isEmpty()) remaining = queue.take()
        if (remaining.isEmpty()) return -1
        val count = minOf(length, remaining.size)
        remaining.copyInto(bytes, offset, 0, count)
        remaining = remaining.copyOfRange(count, remaining.size)
        return count
    }
    override fun close() { closes.incrementAndGet(); closed = true; eof() }
}

private class PipeOutput(private val blocked: Boolean = false) : OutputStream() {
    private val buffer = ByteArrayOutputStream()
    private val released = CountDownLatch(if (blocked) 1 else 0)
    val writes = AtomicInteger()
    val closes = AtomicInteger()
    @Volatile var closed = false
    fun bytes(): ByteArray = synchronized(buffer) { buffer.toByteArray() }
    fun release() { released.countDown() }
    override fun write(value: Int) { write(byteArrayOf(value.toByte()), 0, 1) }
    override fun write(bytes: ByteArray, offset: Int, length: Int) {
        writes.incrementAndGet()
        released.await()
        if (closed) throw IOException("Socket closed")
        synchronized(buffer) { buffer.write(bytes, offset, length) }
    }
    override fun close() { closes.incrementAndGet(); closed = true; released.countDown() }
}

private class Native : NativeNearbyStream {
    private val queue = LinkedBlockingQueue<NearbyRead>()
    val written = java.util.concurrent.CopyOnWriteArrayList<ByteArray>()
    val writes = AtomicInteger()
    val closes = AtomicInteger()
    val reads = AtomicInteger()
    @Volatile var writeGate: CountDownLatch? = null
    @Volatile var writeFailure = false
    @Volatile var closed = false
    fun incoming(bytes: ByteArray, closed: Boolean = false) { queue.add(NearbyRead(bytes, closed)) }
    override fun write(bytes: ByteArray, timeoutMs: Int) {
        writes.incrementAndGet()
        check(bytes.size <= 4096 && timeoutMs in 1..5000)
        if (writeGate?.await(timeoutMs.toLong(), TimeUnit.MILLISECONDS) == false) throw IOException("Native backpressure timeout")
        if (writeFailure || closed) throw IOException("Native write failed")
        written.add(bytes.copyOf())
    }
    override fun read(maxBytes: Int, timeoutMs: Int): NearbyRead {
        reads.incrementAndGet()
        check(maxBytes in 1..4096 && timeoutMs in 1..5000)
        return queue.poll(timeoutMs.toLong(), TimeUnit.MILLISECONDS) ?: NearbyRead(byteArrayOf(), closed)
    }
    override fun close() {
        closes.incrementAndGet()
        closed = true
        writeGate?.countDown()
        queue.offer(NearbyRead(byteArrayOf(), true))
    }
}

private class Fixture(blockedOutput: Boolean = false) {
    val input = PipeInput()
    val output = PipeOutput(blockedOutput)
    val native = Native()
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val connection = NearbyConnection("test", NearbyKind.BLE, "Temporary peer", input, output) {
        input.close()
        output.close()
    }
    fun start(chunkSize: Int = 4096): Deferred<Unit> = scope.async { pumpNearby(connection, native, chunkSize) }
    suspend fun forceCleanup(job: Deferred<Unit>) {
        // Rescue a failing before-test without leaving a blocked worker in the test process.
        connection.close()
        native.close()
        job.cancel()
        runCatching { withTimeout(2500) { job.join() } }
        scope.cancel()
    }
    fun closedOnce() {
        expect(input.closes.get() == 1 && output.closes.get() == 1, "Both platform streams closed once")
        expect(native.closes.get() == 1, "Native stream closed once")
    }
}

private suspend fun cancellationWhileWriting() {
    val f = Fixture(blockedOutput = true)
    f.native.incoming(byteArrayOf(1, 2))
    val job = f.start()
    try {
        await("output write reached") { f.output.writes.get() == 1 }
        job.cancel()
        await("cancellation closes a blocked output stream") { f.output.closed && f.native.closed }
        withTimeout(2500) { job.join() }
        f.closedOnce()
    } finally { f.forceCleanup(job) }
}

private suspend fun eofWhileWriting(nativeFailure: Boolean) {
    val f = Fixture(blockedOutput = true)
    f.native.incoming(byteArrayOf(9))
    val job = f.start()
    try {
        await("output blocked before read-side failure") { f.output.writes.get() == 1 }
        if (nativeFailure) { f.native.writeFailure = true; f.input.data(byteArrayOf(7)) } else f.input.eof()
        await("read-side failure closes blocked opposite direction") { f.output.closed && f.native.closed }
        val error = runCatching { withTimeout(2500) { job.await() } }.exceptionOrNull()
        expect(error is IOException || error is CancellationException, "Read-side failure is observable")
        f.closedOnce()
    } finally { f.forceCleanup(job) }
}

private suspend fun nativeCloseAndByteOrder() {
    repeat(12) {
        val f = Fixture()
        f.native.incoming(byteArrayOf()) // A timeout is not EOF.
        f.native.incoming(byteArrayOf(1, 2))
        f.native.incoming(byteArrayOf(3, 4), closed = true)
        val job = f.start()
        try {
            withTimeout(2500) { job.await() }
            expect(f.output.bytes().contentEquals(byteArrayOf(1, 2, 3, 4)), "Final bytes delivered in order before native EOF")
            f.closedOnce()
        } finally { f.forceCleanup(job) }
    }
}

private suspend fun backpressure() {
    val f = Fixture()
    val gate = CountDownLatch(1)
    f.native.writeGate = gate
    val payload = ByteArray(12289) { (it % 251).toByte() }
    f.input.data(payload)
    val job = f.start()
    try {
        await("native write is blocked") { f.native.writes.get() == 1 }
        delay(50)
        expect(f.input.reads.get() == 1, "Backpressure prevents additional platform reads")
        gate.countDown()
        await("payload passed in bounded chunks") { f.native.written.sumOf { it.size } == payload.size }
        expect(f.native.written.all { it.size <= 4096 }, "Native write chunks are bounded")
        expect(f.native.written.flatMap { it.asList() }.toByteArray().contentEquals(payload), "No bytes lost or reordered by chunking")
        f.native.incoming(byteArrayOf(), closed = true)
        withTimeout(2500) { job.await() }
        f.closedOnce()
    } finally { f.forceCleanup(job) }
}

private suspend fun oversizedAndPrecancelled() {
    val f = Fixture()
    f.native.incoming(ByteArray(4097))
    val job = f.start()
    try {
        val error = runCatching { withTimeout(2500) { job.await() } }.exceptionOrNull()
        expect(error is IOException, "Oversized native return rejected")
        expect(f.output.bytes().isEmpty(), "Oversized bytes never sent to peer")
        f.closedOnce()
    } finally { f.forceCleanup(job) }

    val cancelled = Fixture()
    cancelled.scope.cancel()
    // UNDISPATCHED deliberately enters the production function in a cancelled context.
    val beforeStart = cancelled.scope.async(start = CoroutineStart.UNDISPATCHED) {
        pumpNearby(cancelled.connection, cancelled.native)
    }
    try {
        withTimeout(2500) { beforeStart.join() }
        cancelled.closedOnce()
    } finally { cancelled.forceCleanup(beforeStart) }
}

private fun permissions() {
    val fine = listOf("android.permission.ACCESS_FINE_LOCATION")
    val bluetooth = setOf("android.permission.BLUETOOTH_SCAN", "android.permission.BLUETOOTH_CONNECT", "android.permission.BLUETOOTH_ADVERTISE")
    for (sdk in listOf(26, 27, 28)) for (kind in NearbyKind.entries) expect(nearbyPermissions(kind, sdk).isEmpty(), "Unsupported SDK requests no radio permission")
    for (sdk in listOf(29, 30)) expect(nearbyPermissions(NearbyKind.BLE, sdk) == fine, "Old BLE discovery requires fine location")
    for (sdk in listOf(31, 32, 33, 36, 37)) expect(nearbyPermissions(NearbyKind.BLE, sdk).toSet() == bluetooth, "Modern BLE requests all three nearby permissions")
    for (sdk in listOf(29, 30)) expect(nearbyPermissions(NearbyKind.WIFI_AWARE, sdk) == fine, "Pre31 Aware requires fine location")
    for (sdk in listOf(31, 32)) expect(nearbyPermissions(NearbyKind.WIFI_AWARE, sdk).toSet() == setOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"), "Android12 Aware must request fine and coarse location together")
    for (sdk in listOf(33, 36, 37)) expect(nearbyPermissions(NearbyKind.WIFI_AWARE, sdk) == listOf("android.permission.NEARBY_WIFI_DEVICES"), "Modern Aware uses nearby Wi-Fi permission")
    val coarse = "android.permission.ACCESS_COARSE_LOCATION"
    for (sdk in listOf(31, 32)) {
        expect(nearbyPermissionRequest(fine, sdk).toSet() == setOf(fine.single(), coarse), "Fine upgrade includes previously granted coarse permission")
        expect(nearbyPermissionRequest(fine + coarse + coarse, sdk).size == 2, "Permission request has no duplicates")
    }
    expect(nearbyPermissionRequest(emptyList(), 31).isEmpty(), "No prompt after all permissions granted")
    expect(nearbyPermissionRequest(bluetooth, 31).toSet() == bluetooth, "Modern Bluetooth does not ask for location")
    for (sdk in listOf(26, 28, 29, 30, 31, 32, 33, 34, 36, 37)) for (kind in NearbyKind.entries) {
        val expected = when (kind) { NearbyKind.BLE -> sdk in 29..30; NearbyKind.WIFI_AWARE -> sdk in 29..32 }
        expect(nearbyNeedsLocationService(setOf(kind), sdk, true) == expected, "Location FGS used only on legacy discovery APIs")
        expect(!nearbyNeedsLocationService(setOf(kind), sdk, false), "Location FGS never activated without fine grant")
        expect(!nearbyNeedsLocationService(emptySet(), sdk, true), "Disabled discovery never activates location FGS")
    }
}

fun main() = runBlocking {
    permissions()
    cancellationWhileWriting()
    eofWhileWriting(nativeFailure = false)
    eofWhileWriting(nativeFailure = true)
    nativeCloseAndByteOrder()
    backpressure()
    oversizedAndPrecancelled()
    println("Nearby pump and permission regressions passed: $checks checks")
}
