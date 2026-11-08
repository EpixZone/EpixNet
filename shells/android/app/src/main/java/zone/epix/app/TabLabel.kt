package zone.epix.app

import java.net.URI
import java.net.IDN
import java.util.Locale

internal data class TabLabel(val title: String, val subtitle: String)

/** Display text only. Does not rewrite navigation targets or change browser state. */
internal fun tabLabel(pageTitle: String, pageUrl: String, nodeBase: String): TabLabel {
    val address = tabAddress(pageUrl, nodeBase)
    val title = pageTitle.replace(Regex("\\s+"), " ").trim().ifEmpty { address.title }
    return TabLabel(title, address.subtitle)
}

private fun tabAddress(pageUrl: String, nodeBase: String): TabLabel {
    val value = pageUrl.trim()
    if (value.isEmpty()) return TabLabel("New tab", "Blank page")
    val candidate = if (isXite(value.substringBefore('/').substringBefore('?').substringBefore('#'))) {
        "epix://$value"
    } else {
        value
    }
    val uri = parseUri(candidate) ?: return unavailableAddress()
    return when (uri.scheme?.lowercase(Locale.ROOT)) {
        "http", "https", "epix" -> networkAddress(uri, parseUri(nodeBase))
        "about" -> aboutAddress(uri)
        "data" -> TabLabel("Local page", "Local page")
        "file", "content" -> TabLabel("Local file", "Local file")
        "blob" -> TabLabel("Temporary page", "Temporary page")
        "moz-extension" -> TabLabel("Extension page", "Extension page")
        else -> unavailableAddress()
    }
}

private fun parseUri(value: String): URI? = runCatching { URI(value) }.getOrNull()

private fun unavailableAddress() = TabLabel("Untitled tab", "Address unavailable")

private fun aboutAddress(uri: URI): TabLabel {
    val page = uri.rawSchemeSpecificPart.orEmpty().substringBefore('?').substringBefore('#')
    if (page.equals("blank", ignoreCase = true) || page.equals("newtab", ignoreCase = true)) {
        return TabLabel("New tab", "Blank page")
    }
    val subtitle = if (Regex("[a-zA-Z0-9-]{1,40}").matches(page)) {
        "about:${page.lowercase(Locale.ROOT)}"
    } else {
        "Browser page"
    }
    return TabLabel("Browser page", subtitle)
}

private fun networkAddress(uri: URI, node: URI?): TabLabel {
    val address = networkUri(uri) ?: return unavailableAddress()
    val host = address.host.lowercase(Locale.ROOT)
    if (address.port !in -1..65535) return unavailableAddress()
    val path = address.rawPath.orEmpty().trimEnd('/')
    if (node != null && sameOrigin(address, node)) return nodeAddress(path)

    if (node != null && sameProtocolAndPort(address, node)) {
        isolatedXite(host)?.let { xite ->
            val ownPrefix = "/$xite"
            val suffix = if (path == ownPrefix) "" else if (path.startsWith("$ownPrefix/")) {
                path.removePrefix(ownPrefix)
            } else {
                path
            }
            return TabLabel(xite, xite + suffix)
        }
    }

    val authority = if (address.port == -1 || address.port == defaultPort(address.scheme)) host else "$host:${address.port}"
    return TabLabel(host, authority + path)
}

/** URI does not recognize Unicode DNS hosts until converted to their ASCII form. */
private fun networkUri(uri: URI): URI? {
    if (uri.host != null) return uri
    val authority = uri.rawAuthority?.substringAfterLast('@') ?: return null
    val host = authority.substringBefore(':')
    val port = authority.removePrefix(host)
    if (port.isNotEmpty() && !Regex(":[0-9]{1,5}").matches(port)) return null
    val ascii = runCatching { IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES) }.getOrNull() ?: return null
    val parsed = parseUri("${uri.scheme}://$ascii$port${uri.rawPath.orEmpty()}") ?: return null
    return parsed.takeIf { it.host != null }
}

private fun nodeAddress(path: String): TabLabel {
    val route = path.removePrefix("/")
    val first = route.substringBefore('/')
    if (isXite(first)) {
        val xite = first.lowercase(Locale.ROOT)
        return TabLabel(xite, xite + route.removePrefix(first))
    }
    val title = when (first.lowercase(Locale.ROOT)) {
        "" -> "Dashboard"
        "config" -> "Settings"
        "backup" -> "Backup and restore"
        "plugins" -> "Plugins"
        "stats" -> "Statistics"
        "login" -> "Sign in"
        else -> "EpixNet"
    }
    return TabLabel(title, "EpixNet$path")
}

private fun isXite(value: String): Boolean =
    Regex("epix1[a-z0-9]{20,}|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+epix", RegexOption.IGNORE_CASE)
        .matches(value)

private fun isolatedXite(host: String): String? = host
    .takeIf { it.startsWith("epix-") && it.endsWith(".localhost") }
    ?.removePrefix("epix-")
    ?.removeSuffix(".localhost")
    ?.takeIf { Regex("epix1[a-z0-9]{20,}").matches(it) }

private fun sameOrigin(left: URI, right: URI): Boolean =
    left.host != null && left.host.equals(right.host, ignoreCase = true) && sameProtocolAndPort(left, right)

private fun sameProtocolAndPort(left: URI, right: URI): Boolean =
    left.scheme != null && left.scheme.equals(right.scheme, ignoreCase = true) &&
        effectivePort(left) == effectivePort(right)

private fun effectivePort(uri: URI): Int = if (uri.port == -1) defaultPort(uri.scheme) else uri.port

private fun defaultPort(scheme: String?): Int = when (scheme?.lowercase(Locale.ROOT)) {
    "http" -> 80
    "https" -> 443
    else -> -1
}
