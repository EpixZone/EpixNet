package android.content
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.wifi.aware.WifiAwareManager

class Intent(val action: String?)
class IntentFilter(val action: String)
abstract class BroadcastReceiver { abstract fun onReceive(context: Context, intent: Intent) }
class Context {
    val applicationContext get() = this
    val packageManager = PackageManager()
    val manager = WifiAwareManager()
    val connectivity = ConnectivityManager()
    var permissionGranted = true
    var receiver: BroadcastReceiver? = null
    fun checkSelfPermission(permission: String) = if (permissionGranted) 0 else -1
    fun <T> getSystemService(type: Class<T>): T = type.cast(when(type) {
        WifiAwareManager::class.java -> manager
        ConnectivityManager::class.java -> connectivity
        else -> error("unexpected service")
    })
    fun registerReceiver(value: BroadcastReceiver, filter: IntentFilter) { receiver = value }
    fun registerReceiver(value: BroadcastReceiver, filter: IntentFilter, flags: Int) { receiver = value }
    fun unregisterReceiver(value: BroadcastReceiver) { check(receiver === value); receiver = null }
    companion object { const val RECEIVER_NOT_EXPORTED = 4 }
}
