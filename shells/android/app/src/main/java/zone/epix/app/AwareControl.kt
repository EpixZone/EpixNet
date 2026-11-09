package zone.epix.app

import java.security.SecureRandom

/** Discovery metadata is routing information, never a peer identity or authorization. */
internal object AwareControl {
    const val SERVICE = "epixnet-mesh-v1"
    private const val PREFIX = "EPXA1"
    const val MAX_BYTES = 112
    private val noncePattern = Regex("[0-9a-f]{32}")
    private val requestPattern = Regex("[0-9a-f]{16}")
    private val random = SecureRandom()

    enum class Type { REQUEST, READY, PORT }

    data class Message(
        val type: Type,
        val sender: String,
        val recipient: String,
        val request: String,
        val port: Int = 0,
    ) {
        fun matches(local: String, remote: String, expectedRequest: String): Boolean =
            recipient == local && sender == remote && request == expectedRequest
    }

    fun nonce(): String = token(16)
    fun requestId(): String = token(8)
    private fun token(length: Int): String = ByteArray(length).also(random::nextBytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }

    fun advert(nonce: String): ByteArray {
        require(noncePattern.matches(nonce))
        return "$PREFIX|$nonce".toByteArray(Charsets.US_ASCII)
    }

    fun readAdvert(bytes: ByteArray): String? {
        val parts = ascii(bytes)?.split('|') ?: return null
        return parts.takeIf { it.size == 2 && it[0] == PREFIX }
            ?.get(1)?.takeIf(noncePattern::matches)
    }

    /** Exactly one subscriber initiates when both devices publish and subscribe. */
    fun initiates(local: String, remote: String): Boolean =
        noncePattern.matches(local) && noncePattern.matches(remote) && local < remote

    fun encode(message: Message): ByteArray {
        val bytes = listOf(PREFIX, message.type.name, message.sender, message.recipient,
            message.request, message.port.toString()).joinToString("|").toByteArray(Charsets.US_ASCII)
        require(decode(bytes) == message)
        return bytes
    }

    fun decode(bytes: ByteArray): Message? {
        val parts = ascii(bytes)?.split('|') ?: return null
        if (parts.size != 6 || parts[0] != PREFIX) return null
        val type = Type.entries.firstOrNull { it.name == parts[1] } ?: return null
        if (!noncePattern.matches(parts[2]) || !noncePattern.matches(parts[3])) return null
        if (parts[2] == parts[3] || !requestPattern.matches(parts[4])) return null
        val port = parts[5].toIntOrNull() ?: return null
        if (parts[5] != port.toString()) return null
        if (type == Type.PORT && port !in 1..65535) return null
        if (type != Type.PORT && port != 0) return null
        return Message(type, parts[2], parts[3], parts[4], port)
    }

    private fun ascii(bytes: ByteArray): String? {
        if (bytes.isEmpty() || bytes.size > MAX_BYTES) return null
        if (bytes.any { it.toInt() !in 32..126 }) return null
        return bytes.toString(Charsets.US_ASCII)
    }
}
