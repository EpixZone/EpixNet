package android.content.pm
class PackageManager {
    var aware = true
    fun hasSystemFeature(feature: String) = aware
    companion object {
        const val FEATURE_WIFI_AWARE = "aware"
        const val PERMISSION_GRANTED = 0
    }
}
