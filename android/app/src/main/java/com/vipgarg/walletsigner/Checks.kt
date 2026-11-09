package com.vipgarg.walletsigner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import java.security.MessageDigest
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

    checks += signingCheck(context)

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

/** SHA-256 of this app's signing certificate (lowercase hex), or null. */
fun signingCertSha256(context: Context): String? = runCatching {
    val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
    val si = info.signingInfo ?: return null
    if (si.hasMultipleSigners()) return null
    val cert = si.apkContentsSigners?.singleOrNull() ?: return null
    MessageDigest.getInstance("SHA-256").digest(cert.toByteArray()).joinToString("") { "%02x".format(it) }
}.getOrNull()

private fun grouped(hex: String) = hex.uppercase().chunked(4).joinToString(" ")

/**
 * The app checks it was signed with the owner's key (pinned in the repo,
 * android/signing-cert.sha256). Android itself refuses updates signed with
 * another key; this also catches a wrong build installed fresh, and shows
 * the fingerprint to compare with the owner's own record. A tampered app
 * could skip this check, so the owner's comparison stays the real test.
 */
private fun signingCheck(context: Context): Check {
    val actual = signingCertSha256(context)
    val expected = BuildConfig.EXPECTED_SIGNING_CERT
    val debuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    val kind = if (debuggable) " This is a debug build." else ""
    return when {
        actual == null -> Check("App signed with your key", false, "Couldn't read this app's signing certificate.", critical = true)
        expected.isEmpty() -> Check(
            "App signed with your key",
            false,
            "Not pinned yet.$kind Signing certificate SHA-256:\n${grouped(actual)}\nCompare it with the one shown when you made the key (keytool -list -v). Once it matches, it gets pinned and checked on every start.",
            critical = false,
        )
        actual == expected -> Check(
            "App signed with your key",
            !debuggable,
            if (debuggable) "Matches the pinned key, but this is a debug build." else "Matches the pinned key: ${grouped(actual).take(9)}…${grouped(actual).takeLast(9)}",
            critical = false,
        )
        else -> Check(
            "App signed with your key",
            false,
            "This app was signed with a DIFFERENT key than the pinned one. Don't use it: uninstall it and install the APK from your own build.\nThis app: ${grouped(actual)}",
            critical = true,
        )
    }
}
