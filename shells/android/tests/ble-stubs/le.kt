@file:Suppress("UNUSED_PARAMETER")
package android.bluetooth.le

import android.bluetooth.BluetoothDevice
import android.os.ParcelUuid
import java.util.concurrent.CopyOnWriteArrayList

open class AdvertiseCallback {
    open fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {}
    open fun onStartFailure(errorCode: Int) {}
}
class AdvertiseData(val uuids: List<ParcelUuid>, val serviceData: Map<ParcelUuid, ByteArray>) {
    class Builder {
        private val uuids = mutableListOf<ParcelUuid>()
        private val data = mutableMapOf<ParcelUuid, ByteArray>()
        fun addServiceUuid(uuid: ParcelUuid) = apply { uuids.add(uuid) }
        fun addServiceData(uuid: ParcelUuid, bytes: ByteArray) = apply { data[uuid] = bytes }
        fun setIncludeDeviceName(enabled: Boolean) = this
        fun build() = AdvertiseData(uuids.toList(), data.toMap())
    }
}
class AdvertiseSettings {
    class Builder {
        fun setConnectable(enabled: Boolean) = this
        fun setTimeout(timeout: Int) = this
        fun setAdvertiseMode(mode: Int) = this
        fun setTxPowerLevel(level: Int) = this
        fun build() = AdvertiseSettings()
    }
    companion object { const val ADVERTISE_MODE_BALANCED = 1; const val ADVERTISE_TX_POWER_MEDIUM = 2 }
}
class BluetoothLeAdvertiser {
    data class Started(val settings: AdvertiseSettings, val data: AdvertiseData, val response: AdvertiseData, val callback: AdvertiseCallback)
    val started = CopyOnWriteArrayList<Started>()
    val stopped = CopyOnWriteArrayList<AdvertiseCallback>()
    @Volatile var autoSuccess = true
    fun startAdvertising(settings: AdvertiseSettings, data: AdvertiseData, response: AdvertiseData, callback: AdvertiseCallback) {
        started.add(Started(settings, data, response, callback))
        if (autoSuccess) callback.onStartSuccess(settings)
    }
    fun stopAdvertising(callback: AdvertiseCallback) { stopped.add(callback) }
}
open class ScanCallback {
    open fun onScanResult(callbackType: Int, result: ScanResult?) {}
    open fun onScanFailed(errorCode: Int) {}
}
class ScanResult(val device: BluetoothDevice, val scanRecord: ScanRecord?)
class ScanRecord(private val data: Map<ParcelUuid, ByteArray>) { fun getServiceData(uuid: ParcelUuid) = data[uuid] }
class ScanFilter(val service: ParcelUuid?) {
    class Builder {
        private var service: ParcelUuid? = null
        fun setServiceUuid(uuid: ParcelUuid) = apply { service = uuid }
        fun build() = ScanFilter(service)
    }
}
class ScanSettings {
    class Builder {
        fun setScanMode(mode: Int) = this
        fun build() = ScanSettings()
    }
    companion object { const val SCAN_MODE_LOW_LATENCY = 2 }
}
class BluetoothLeScanner {
    val started = CopyOnWriteArrayList<ScanCallback>()
    val stopped = CopyOnWriteArrayList<ScanCallback>()
    @Volatile var failSecurity = false
    var filters: List<ScanFilter> = emptyList()
    fun startScan(filters: List<ScanFilter>, settings: ScanSettings, callback: ScanCallback) {
        if (failSecurity) throw SecurityException()
        this.filters = filters
        started.add(callback)
    }
    fun stopScan(callback: ScanCallback) { stopped.add(callback) }
}
