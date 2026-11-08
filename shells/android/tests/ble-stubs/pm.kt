package android.content.pm

class PackageManager {
    var ble = true
    fun hasSystemFeature(name: String) = name == FEATURE_BLUETOOTH_LE && ble
    companion object { const val FEATURE_BLUETOOTH_LE = "android.hardware.bluetooth_le" }
}
