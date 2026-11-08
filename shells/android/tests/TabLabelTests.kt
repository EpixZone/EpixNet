package zone.epix.app

private const val NODE = "http://127.0.0.1:42222"
private const val ADDRESS = "epix1g34lhhtdeh24d622g6m755n0j23ae5n5zugs50"
private var checks = 0

private fun expect(actual: Any?, expected: Any?, context: String) {
    check(actual == expected) { "$context: expected <$expected>, got <$actual>" }
    checks++
}

private fun privacySafeAddresses() {
    val cases = listOf(
        "https://alice:private-password@example.com/news?wrapper_nonce=private-nonce#private-fragment" to
            TabLabel("example.com", "example.com/news"),
        "$NODE/talk.epix/topic/123?wrapper_nonce=private-nonce#private-fragment" to
            TabLabel("talk.epix", "talk.epix/topic/123"),
        "data:text/html;base64,private-payload" to TabLabel("Local page", "Local page"),
        "file:///home/private-person/private-file.txt?key=private-key" to TabLabel("Local file", "Local file"),
        "content://private-account/private-file" to TabLabel("Local file", "Local file"),
        "blob:https://example.com/private-identifier" to TabLabel("Temporary page", "Temporary page"),
        "moz-extension://private-identifier/index.html?key=private-key" to
            TabLabel("Extension page", "Extension page"),
        "about:reader?url=https://private-account@example.com/private-path" to
            TabLabel("Browser page", "about:reader"),
        "https://private-password@example.com/%broken?key=private-key" to
            TabLabel("Untitled tab", "Address unavailable"),
        "javascript:private-payload" to TabLabel("Untitled tab", "Address unavailable"),
    )
    for ((url, expected) in cases) {
        val actual = tabLabel("", url, NODE)
        expect(actual, expected, "safe address")
        check(!actual.toString().contains("private-")) { "Private URL component was exposed" }
        checks++
    }
}

private fun xitePathsAndNodePages() {
    val cases = listOf(
        "$NODE/$ADDRESS/posts/a%20b%2Fc.html?token=hidden" to
            TabLabel(ADDRESS, "$ADDRESS/posts/a%20b%2Fc.html"),
        "epix://talk.epix/thread/42?token=hidden" to TabLabel("talk.epix", "talk.epix/thread/42"),
        "talk.epix/thread/42?token=hidden" to TabLabel("talk.epix", "talk.epix/thread/42"),
        "http://epix-$ADDRESS.localhost:42222/$ADDRESS/posts/42?wrapper_nonce=hidden" to
            TabLabel(ADDRESS, "$ADDRESS/posts/42"),
        "$NODE/" to TabLabel("Dashboard", "EpixNet"),
        "$NODE/Config?returnTo=hidden" to TabLabel("Settings", "EpixNet/Config"),
        "$NODE/Backup?token=hidden" to TabLabel("Backup and restore", "EpixNet/Backup"),
        "$NODE/Plugins" to TabLabel("Plugins", "EpixNet/Plugins"),
        "$NODE/Stats" to TabLabel("Statistics", "EpixNet/Stats"),
        "$NODE/Login?password=hidden" to TabLabel("Sign in", "EpixNet/Login"),
        "$NODE/EpixNet-Internal/Status?token=hidden" to TabLabel("EpixNet", "EpixNet/EpixNet-Internal/Status"),
    )
    for ((url, expected) in cases) expect(tabLabel("", url, NODE), expected, "xite or node route")
    expect(
        tabLabel("", "http://127.0.0.1:42223/Config", NODE),
        TabLabel("127.0.0.1", "127.0.0.1:42223/Config"),
        "a different local service is not labelled as this node",
    )
    expect(
        tabLabel("", "http://127.0.0.1.evil.example:42222/Config", NODE),
        TabLabel("127.0.0.1.evil.example", "127.0.0.1.evil.example:42222/Config"),
        "a hostname prefix is not this node",
    )
}

private fun readableTitlesAndOrigins() {
    expect(tabLabel("", "", NODE), TabLabel("New tab", "Blank page"), "empty initial tab")
    expect(tabLabel("  ", "about:blank", NODE), TabLabel("New tab", "Blank page"), "blank title")
    expect(tabLabel("", "about:blank?private-token#fragment", NODE), TabLabel("New tab", "Blank page"), "opaque about URL")
    expect(tabLabel(" A\n  readable\t title ", "https://example.com", NODE).title, "A readable title", "title whitespace")
    expect(tabLabel("Literal <title>", "https://example.com", NODE).title, "Literal <title>", "text remains plain display text")
    val first = tabLabel("Same title", "$NODE/talk.epix/one", NODE)
    val second = tabLabel("Same title", "$NODE/blog.epix/two", NODE)
    expect(first.title, second.title, "page title preserved")
    expect(first.subtitle, "talk.epix/one", "first tab identity")
    expect(second.subtitle, "blog.epix/two", "second tab identity")
    expect(tabLabel("", "https://Example.COM:443/a", NODE).subtitle, "example.com/a", "default HTTPS port")
    expect(tabLabel("", "https://example.com:8443/a", NODE).subtitle, "example.com:8443/a", "nondefault port remains visible")
    expect(tabLabel("", "http://[::1]:42223/a?secret=hidden", NODE).subtitle, "[::1]:42223/a", "IPv6 display")
    expect(tabLabel("", "https://münich.example:8443/a?token=hidden", NODE).subtitle, "xn--mnich-kva.example:8443/a", "international DNS host")
    expect(tabLabel("", "https://example.com:999999/a?secret=hidden", NODE), TabLabel("Untitled tab", "Address unavailable"), "invalid port")
    val longTitle = "A long document title ".repeat(20).trim()
    expect(tabLabel(longTitle, "https://example.com/a", NODE).title, longTitle, "view controls title ellipsis")
}

fun main() {
    privacySafeAddresses()
    xitePathsAndNodePages()
    readableTitlesAndOrigins()
    println("PASS: $checks tab label checks")
}
