package zone.epix.app

private var checks = 0
private fun verify(value: Boolean, message: String) {
    checks++
    check(value) { message }
}

private fun pendingReplies() {
    val operations = PendingOperations()
    val queued = mutableListOf<() -> Unit>()
    var canceled = 0
    var completed = 0
    val operation = operations.register { canceled++ }
    queued.add { operation.complete { completed++ } }
    operations.cancelAll()
    queued.forEach { it() }
    operation.cancel()
    verify(canceled == 1 && completed == 0 && !operation.pending,
        "destruction before queued work settles once and rejects its late success")
    val late = operations.register { canceled++ }
    late.complete { completed++ }
    verify(canceled == 2 && completed == 0 && !late.pending,
        "registration after destruction is immediately canceled")

    val live = PendingOperations()
    var success = 0
    var rejected = 0
    val reply = live.register { rejected++ }
    reply.complete { success++ }
    reply.complete { success++ }
    reply.cancel()
    live.cancelAll()
    verify(success == 1 && rejected == 0 && !reply.pending,
        "completion cannot be replaced by a second response or teardown")
}

private fun ownerIdentityAndReentrancy() {
    data class Owner(val name: String)
    val operations = PendingOperations()
    val first = Owner("same value")
    val second = Owner("same value")
    val canceled = mutableListOf<String>()
    val a = operations.register(first) { canceled.add("a") }
    val b = operations.register(second) { canceled.add("b") }
    val shared = operations.register { canceled.add("shared") }
    operations.cancelOwner(first)
    verify(!a.pending && b.pending && shared.pending && canceled == listOf("a"),
        "closing one session matches owner identity, not equality or ownerless messages")
    operations.cancelAll()
    verify(!b.pending && !shared.pending && canceled == listOf("a", "b", "shared"),
        "activity teardown also settles remaining sessions and ownerless messages")

    val nested = PendingOperations()
    var nestedReplies = 0
    lateinit var outer: PendingOperations.Operation
    outer = nested.register {
        nestedReplies++
        outer.cancel()
        outer.complete { error("reentrant success must be ignored") }
        nested.register { nestedReplies++ }
    }
    nested.cancelAll()
    verify(!outer.pending && nestedReplies == 2,
        "a cancel callback can reenter disposal and register a late request without double replies")

    val exceptions = PendingOperations()
    var survivor = 0
    val throwing = exceptions.register { throw IllegalStateException("closed engine") }
    val next = exceptions.register { survivor++ }
    exceptions.cancelAll()
    throwing.cancel()
    verify(!throwing.pending && !next.pending && survivor == 1,
        "one broken engine callback cannot prevent remaining cleanup")
}

private class PermissionReply : GeckoSession.PermissionDelegate.Callback {
    var granted = 0
    var rejected = 0
    override fun grant() { granted++ }
    override fun reject() { rejected++ }
}

private fun stalePermissions() {
    val shell = PermissionShell()
    val first = GeckoSession()
    val second = GeckoSession()
    shell.owned.add(first)
    shell.owned.add(second)
    val a = PermissionReply()
    val b = PermissionReply()
    shell.onAndroidPermissionsRequest(first, arrayOf("camera"), a)
    val aCode = shell.requests.single()
    shell.onAndroidPermissionsRequest(second, arrayOf("microphone"), b)
    val bCode = shell.requests.last()
    verify(aCode != bCode && a.rejected == 1, "a replacement permission request rejects its predecessor and uses a new code")
    shell.onRequestPermissionsResult(aCode, arrayOf("camera"), intArrayOf(PackageManager.PERMISSION_GRANTED))
    verify(b.granted == 0 && b.rejected == 0 && shell.pendingGeckoPermission === b,
        "the old permission answer cannot settle the replacement callback")
    shell.onRequestPermissionsResult(bCode, arrayOf("microphone"), intArrayOf(PackageManager.PERMISSION_GRANTED))
    shell.onRequestPermissionsResult(bCode, arrayOf("microphone"), intArrayOf(PackageManager.PERMISSION_GRANTED))
    verify(b.granted == 1 && b.rejected == 0 && shell.pendingGeckoPermission == null,
        "the current permission answer grants once and clears ownership")

    val replacement = PermissionShell()
    val current = GeckoSession()
    replacement.owned.add(current)
    val c = PermissionReply()
    replacement.onAndroidPermissionsRequest(current, arrayOf("camera"), c)
    val cCode = replacement.requests.single()
    verify(cCode != aCode && cCode != bCode, "request IDs remain distinct across activity instances")
    replacement.onRequestPermissionsResult(aCode, arrayOf("camera"), intArrayOf(PackageManager.PERMISSION_GRANTED))
    verify(c.granted == 0 && c.rejected == 0, "an old activity's reply cannot settle the replacement activity")
    replacement.owned.remove(current)
    replacement.onRequestPermissionsResult(cCode, arrayOf("camera"), intArrayOf(PackageManager.PERMISSION_GRANTED))
    verify(c.granted == 0 && c.rejected == 1 && replacement.permissionSession == null,
        "a closed session cannot receive a permission grant")

    val denied = PermissionReply()
    replacement.onAndroidPermissionsRequest(current, arrayOf("camera"), denied)
    verify(denied.rejected == 1 && replacement.requests.size == 1,
        "a stale session cannot launch a new Android permission request")
    replacement.owned.add(current)
    replacement.failRequest = true
    val failed = PermissionReply()
    replacement.onAndroidPermissionsRequest(current, arrayOf("camera"), failed)
    verify(failed.rejected == 1 && replacement.pendingGeckoPermission == null && replacement.permissionRequestCode == null,
        "an Android request failure rejects and clears the pending callback")
}

fun main() {
    pendingReplies()
    ownerIdentityAndReentrancy()
    stalePermissions()
    println("PASS: $checks Android pending-operation and permission regression checks")
}
