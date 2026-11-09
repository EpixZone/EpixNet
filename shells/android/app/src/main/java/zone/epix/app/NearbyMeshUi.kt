package zone.epix.app

import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Activity-owned permission prompts and controls. The service owns all radio work. */
internal class NearbyMeshUi(
    private val activity: AppCompatActivity,
    private val scope: CoroutineScope,
    private val showDialog: (AlertDialog, () -> Unit) -> Unit,
) {
    private var dialog: AlertDialog? = null
    private var pendingEnable = emptySet<NearbyKind>()
    private var observer: Job? = null
    private var updating = false
    private val switches = mutableMapOf<NearbyKind, Switch>()
    private val details = mutableMapOf<NearbyKind, TextView>()
    private var summary: TextView? = null
    private var failure: String? = null
    private val permissionPrompt = activity.registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) {
        val kinds = pendingEnable
        pendingEnable = emptySet()
        if (!activity.isDestroyed && !activity.isFinishing) enableGranted(kinds)
    }

    fun show() {
        dialog?.let { it.show(); return }
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(12), dp(24), dp(12))
        }
        content.addView(label("Connect directly to nearby EpixNet devices without Internet. Your device can relay mesh traffic while connected. Enable the radios you want to use."))
        if (Build.VERSION.SDK_INT in 29..32) {
            val discovery = if (Build.VERSION.SDK_INT <= 30) "nearby discovery" else "Wi-Fi Aware discovery"
            content.addView(label("Android requires location permission for $discovery on this version. Nearby mesh does not read your position."))
        }
        summary = label("").apply { setPadding(0, dp(16), 0, dp(12)) }
        content.addView(summary)
        for (kind in NearbyKind.entries) {
            val capability = capability(kind)
            val toggle = Switch(activity).apply {
                text = if (kind == NearbyKind.BLE) "Bluetooth" else "Wi-Fi Aware"
                textSize = 17f
                minimumHeight = dp(56)
                isEnabled = capability.supported
                setOnCheckedChangeListener { _, checked ->
                    if (!updating) {
                        failure = null
                        if (checked) requestEnable(setOf(kind)) else {
                            NearbyMeshSettings.setWanted(activity, kind, false)
                            NearbyMeshService.resumeIfWanted(activity)
                            render(NearbyMeshSettings.state.value)
                        }
                    }
                }
            }
            switches[kind] = toggle
            content.addView(toggle, LinearLayout.LayoutParams(-1, -2))
            details[kind] = label(capability.detail).apply { setPadding(0, 0, 0, dp(16)) }
            content.addView(details.getValue(kind))
        }
        content.addView(Button(activity).apply {
            text = "Start nearby mesh"
            isAllCaps = false
            minimumHeight = dp(48)
            setOnClickListener {
                val wanted = NearbyKind.entries.filter { NearbyMeshSettings.wanted(activity, it) }.toSet()
                if (wanted.isEmpty()) {
                    failure = "Choose Bluetooth or Wi-Fi Aware first."
                    render(NearbyMeshSettings.state.value)
                } else requestEnable(wanted)
            }
        }, LinearLayout.LayoutParams(-1, -2))
        content.addView(Button(activity).apply {
            text = "Android radio settings"
            isAllCaps = false
            minimumHeight = dp(48)
            setOnClickListener {
                runCatching { activity.startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS)) }
                    .onFailure { activity.startActivity(Intent(Settings.ACTION_SETTINGS)) }
            }
        }, LinearLayout.LayoutParams(-1, -2))
        val sheet = AlertDialog.Builder(activity).setTitle("Nearby mesh")
            .setView(ScrollView(activity).apply { addView(content) })
            .setPositiveButton("Done", null).create()
        dialog = sheet
        showDialog(sheet) {
            observer?.cancel()
            observer = null
            dialog = null
            summary = null
            switches.clear()
            details.clear()
        }
        render(NearbyMeshSettings.state.value)
        observer = scope.launch { NearbyMeshSettings.state.collect(::render) }
    }

    private fun requestEnable(kinds: Set<NearbyKind>) {
        if (pendingEnable.isNotEmpty()) return
        val supported = kinds.filter { capability(it).supported }.toSet()
        if (supported.isEmpty()) return
        val permissions = nearbyPermissionRequest(
            supported.flatMap { NearbyMeshSettings.missing(activity, it) }, Build.VERSION.SDK_INT,
        ).toMutableSet()
        if (Build.VERSION.SDK_INT >= 33 && activity.checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED) {
            permissions.add("android.permission.POST_NOTIFICATIONS")
        }
        if (permissions.isEmpty()) enableGranted(supported) else {
            pendingEnable = supported
            runCatching { permissionPrompt.launch(permissions.toTypedArray()) }.onFailure {
                pendingEnable = emptySet()
                failure = "Permission could not be requested. Try again from EpixNet."
                render(NearbyMeshSettings.state.value)
            }
        }
    }

    private fun enableGranted(kinds: Set<NearbyKind>) {
        failure = null
        for (kind in kinds) {
            val granted = capability(kind).supported && NearbyMeshSettings.missing(activity, kind).isEmpty()
            NearbyMeshSettings.setWanted(activity, kind, granted)
            if (!granted) failure = "Nearby permission was not granted. You can allow it in Android's app settings."
        }
        if (!NearbyMeshService.resumeIfWanted(activity, explicit = true)) {
            failure = "Nearby connections could not start. Keep EpixNet open and try again."
        }
        render(NearbyMeshSettings.state.value)
    }

    private fun render(state: NearbyUiState) {
        updating = true
        summary?.text = failure ?: state.policy
        for (kind in NearbyKind.entries) {
            val supported = capability(kind)
            switches[kind]?.isEnabled = supported.supported
            switches[kind]?.isChecked = NearbyMeshSettings.wanted(activity, kind)
            val count = state.connections[kind] ?: 0
            details[kind]?.text = when {
                !supported.supported -> supported.detail
                !NearbyMeshSettings.wanted(activity, kind) -> "Off"
                NearbyMeshSettings.missing(activity, kind).isNotEmpty() -> "Nearby permission is needed"
                count > 0 -> if (count == 1) "1 nearby connection" else "$count nearby connections"
                else -> state.statuses[kind]?.detail ?: "Starting"
            }
        }
        updating = false
    }

    private fun capability(kind: NearbyKind): NearbyCapability = when {
        Build.VERSION.SDK_INT < 29 -> NearbyCapability(false, "Nearby radio connections require Android 10 or later")
        kind == NearbyKind.BLE -> NearbyCapability(
            activity.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE),
            "Bluetooth Low Energy is not supported on this device",
        )
        else -> NearbyCapability(
            activity.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE),
            "Wi-Fi Aware is not supported on this device",
        )
    }

    private fun label(value: String) = TextView(activity).apply {
        text = value
        textSize = 14f
        gravity = Gravity.START
    }
    private fun dp(value: Int) = (value * activity.resources.displayMetrics.density + 0.5f).toInt()
}
