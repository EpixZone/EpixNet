package zone.epix.app

import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

private var checks = 0
private fun verify(value: Boolean, message: String) {
    checks++
    check(value) { message }
}

private class Fixture {
    val queue = mutableListOf<() -> Unit>()
    val writes = mutableListOf<Pair<String, Boolean>>()
    val settings = BrowserSettingsStore(
        enqueue = { queue.add(it) },
        persist = { path, value -> writes.add(path to value) },
    )
    fun runFirst() = queue.removeAt(0).invoke()
    fun runLast() = queue.removeAt(queue.lastIndex).invoke()
}

private fun reorderedUpdatesUseLatestPreference() {
    val fixture = Fixture()
    fixture.settings.update("app/files", true)
    fixture.settings.update("app/files", false)
    verify(fixture.writes.isEmpty() && fixture.queue.size == 2, "updates record state without doing caller-thread file IO")
    fixture.runLast()
    fixture.runFirst()
    verify(fixture.writes == listOf("app/files" to false, "app/files" to false),
        "an older queued write running last cannot restore an old preference")
    fixture.settings.update("app/files", true)
    fixture.settings.update("app/files", false)
    fixture.settings.update("app/files", true)
    while (fixture.queue.isNotEmpty()) fixture.runFirst()
    verify(fixture.writes.takeLast(3).all { it == "app/files" to true },
        "rapid toggles persist the latest recorded value for every queued callback")
}

private fun bootSnapshotCannotOverwriteToggle() {
    val fixture = Fixture()
    fixture.settings.update("app/files", false)
    fixture.settings.writeLatest("app/files", true)
    verify(fixture.writes.single() == "app/files" to false,
        "startup uses the recorded preference even before its queued write runs")
    fixture.runFirst()
    fixture.settings.writeLatest("app/files", true)
    verify(fixture.writes.size == 3 && fixture.writes.all { it == "app/files" to false },
        "a late boot snapshot cannot overwrite an already persisted toggle")
    fixture.settings.update("app/files", true)
    fixture.settings.writeLatest("app/files", false)
    fixture.runFirst()
    verify(fixture.writes.takeLast(2).all { it == "app/files" to true },
        "a replacement Activity's current preference supersedes both old directions")
}

private fun separatePathsAndInitialFallback() {
    val fixture = Fixture()
    fixture.settings.writeLatest("fresh/files", true)
    verify(fixture.writes.single() == "fresh/files" to true,
        "startup without an Activity preference still writes its supplied default")
    fixture.settings.update("first/files", false)
    fixture.settings.update("second/files", true)
    fixture.runLast()
    fixture.runFirst()
    verify(fixture.writes.takeLast(2) == listOf("second/files" to true, "first/files" to false),
        "settings for separate data directories cannot overwrite one another")
    fixture.settings.writeLatest("first/files", true)
    fixture.settings.writeLatest("second/files", false)
    verify(fixture.writes.takeLast(2) == listOf("first/files" to false, "second/files" to true),
        "each directory retains its own latest preference across boot writes")
}

private fun blockedDiskWriteDoesNotBlockUpdate() {
    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)
    val updateFinished = CountDownLatch(1)
    val queue = Collections.synchronizedList(mutableListOf<() -> Unit>())
    val writes = Collections.synchronizedList(mutableListOf<Boolean>())
    val errors = Collections.synchronizedList(mutableListOf<Throwable>())
    val settings = BrowserSettingsStore(
        enqueue = { queue.add(it) },
        persist = { _, value ->
            if (writes.isEmpty()) {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS)) { "blocked write was not released" }
            }
            writes.add(value)
        },
    )
    val writer = Thread {
        try { settings.writeLatest("app/files", true) } catch (error: Throwable) { errors.add(error) }
    }
    val updater = Thread {
        try {
            settings.update("app/files", false)
            updateFinished.countDown()
        } catch (error: Throwable) { errors.add(error) }
    }
    var enteredWrite = false
    var returnedWhileBlocked = false
    try {
        writer.start()
        enteredWrite = entered.await(2, TimeUnit.SECONDS)
        if (enteredWrite) {
            updater.start()
            returnedWhileBlocked = updateFinished.await(2, TimeUnit.SECONDS)
        }
    } finally {
        release.countDown()
        writer.join(5_000)
        updater.join(5_000)
    }
    verify(!writer.isAlive && !updater.isAlive && errors.isEmpty(), "blocked-IO test joins both owned workers")
    verify(enteredWrite && returnedWhileBlocked, "preference update returns while disk persistence is blocked")
    queue.toList().forEach { it() }
    verify(writes == listOf(true, false), "the queued latest value follows the already-running old write")
    settings.writeLatest("app/files", true)
    verify(writes.last() == false, "a later stale boot snapshot still reads the latest preference")
}

fun main() {
    reorderedUpdatesUseLatestPreference()
    bootSnapshotCannotOverwriteToggle()
    separatePathsAndInitialFallback()
    blockedDiskWriteDoesNotBlockUpdate()
    println("PASS: $checks Android process-owned browser-settings regression checks")
}
