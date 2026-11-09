package android.content

import android.bluetooth.BluetoothManager
import android.content.pm.PackageManager
import java.util.concurrent.CopyOnWriteArrayList

class Context {
    val applicationContext: Context get() = this
    val packageManager = PackageManager()
    val manager = BluetoothManager()
    val receivers = CopyOnWriteArrayList<BroadcastReceiver>()
    @Suppress("UNCHECKED_CAST", "UNUSED_PARAMETER")
    fun <T> getSystemService(type: Class<T>): T? = manager as T
    @Suppress("UNUSED_PARAMETER")
    fun registerReceiver(receiver: BroadcastReceiver, filter: IntentFilter, flags: Int = 0): Intent? {
        receivers.add(receiver)
        return null
    }
    fun unregisterReceiver(receiver: BroadcastReceiver) { receivers.remove(receiver) }
    fun broadcast(action: String) { receivers.forEach { it.onReceive(this, Intent(action)) } }
    companion object { const val RECEIVER_EXPORTED = 2 }
}
class Intent(val action: String)
class IntentFilter(val action: String)
abstract class BroadcastReceiver { abstract fun onReceive(context: Context?, intent: Intent?) }
