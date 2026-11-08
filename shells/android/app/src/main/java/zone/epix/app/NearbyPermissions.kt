package zone.epix.app

/** Runtime permissions only; capability checks happen before any prompt. */
internal fun nearbyPermissions(kind: NearbyKind, sdk: Int): List<String> = when {
    sdk < 29 -> emptyList()
    kind == NearbyKind.BLE && sdk >= 31 -> listOf(
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_ADVERTISE",
    )
    kind == NearbyKind.WIFI_AWARE && sdk >= 33 -> listOf("android.permission.NEARBY_WIFI_DEVICES")
    kind == NearbyKind.WIFI_AWARE && sdk >= 31 -> listOf(
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
    )
    else -> listOf("android.permission.ACCESS_FINE_LOCATION")
}

/** Android 12 ignores some fine-only requests, including upgrades from an existing coarse grant. */
internal fun nearbyPermissionRequest(missing: Collection<String>, sdk: Int): List<String> {
    val permissions = missing.toMutableSet()
    if (sdk >= 31 && "android.permission.ACCESS_FINE_LOCATION" in permissions) {
        permissions.add("android.permission.ACCESS_COARSE_LOCATION")
    }
    return permissions.toList()
}

/** Keep legacy discovery's while-in-use grant active through the visible foreground service. */
internal fun nearbyNeedsLocationService(wanted: Set<NearbyKind>, sdk: Int, hasFineLocation: Boolean): Boolean =
    hasFineLocation && sdk >= 29 && wanted.any { kind ->
        when (kind) {
            NearbyKind.BLE -> sdk <= 30
            NearbyKind.WIFI_AWARE -> sdk <= 32
        }
    }
