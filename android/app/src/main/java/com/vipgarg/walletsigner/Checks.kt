package com.vipgarg.walletsigner

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.provider.Settings
import android.telephony.TelephonyManager

/** One start-up check (ARCHITECTURE-MOBILE.md §5.1). */
data class Check(
    val title: String,
    val ok: Boolean,
    val detail: String,
    /** A failed critical check blocks the app. */
    val critical: Boolean,
)

/**
 * Checks that the tablet is offline, not open to screen-reading or
 * debugging tools, not modified (verified boot, via key attestation) and not
 * casting its screen. Screen recording is watched continuously
 * (MainActivity / Safety).
 */
fun runChecks(context: Context): List<Check> {
    val cr = context.contentResolver
    val checks = mutableListOf<Check>()

    val airplane = Settings.Global.getInt(cr, Settings.Global.AIRPLANE_MODE_ON, 0) == 1
    checks += Check(
        "Airplane mode",
        airplane,
        if (airplane) "On." else "Turn airplane mode on and keep it on.",
        critical = true,
    )

    val cm = context.getSystemService(ConnectivityManager::class.java)
    val connected = cm?.activeNetwork != null
    checks += Check(
        "No network connection",
        !connected,
        if (connected) "The tablet is connected to a network. Turn off Wi-Fi, Bluetooth and mobile data." else "Not connected.",
        critical = true,
    )

    val adb = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1
    checks += Check(
        "USB debugging off",
        !adb,
        if (adb) "USB debugging is on. Turn it off in Developer options after installing the app." else "Off.",
        critical = true,
    )

    val accessibility = Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
    val accessibilityOn = !accessibility.isNullOrBlank()
    checks += Check(
        "No accessibility services",
        !accessibilityOn,
        if (accessibilityOn) "An accessibility service is on. These can read and tap the screen. Turn them all off." else "None active.",
        critical = true,
    )

    val tm = context.getSystemService(TelephonyManager::class.java)
    val simPresent = tm != null && tm.simState != TelephonyManager.SIM_STATE_ABSENT &&
        tm.simState != TelephonyManager.SIM_STATE_UNKNOWN
    checks += Check(
        "No SIM card",
        !simPresent,
        if (simPresent) "Remove the SIM card." else "None.",
        critical = true,
    )

    val (untampered, tamperDetail) = TamperCheck.run()
    checks += Check(
        "System not modified (verified boot)",
        untampered,
        tamperDetail,
        critical = true,
    )

    checks += Check(
        "Screen not cast or mirrored",
        !Safety.externalDisplay,
        if (Safety.externalDisplay) "The screen is being shown on another display. Stop casting." else "Not cast.",
        critical = true,
    )

    val devOptions = Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
    checks += Check(
        "Developer options off",
        !devOptions,
        if (devOptions) "Developer options are on. Turn them off after installing the app." else "Off.",
        critical = false,
    )

    val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    checks += Check(
        "Security chip (StrongBox)",
        strongBox,
        if (strongBox) "Available." else "Not available: keys rely on the processor's secure area (TEE) and the vault password. Acceptable for an offline device.",
        critical = false,
    )
    return checks
}
