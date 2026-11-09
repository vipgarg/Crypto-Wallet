package com.vipgarg.walletsigner

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/**
 * Live safety state watched while the app is open (ARCHITECTURE-MOBILE.md
 * §5.1). When either is true the app hides every screen.
 */
object Safety {
    /** Android 15+: this app's window is being recorded. */
    var screenRecorded by mutableStateOf(false)

    /** A presentation display (casting, mirroring) is connected. */
    var externalDisplay by mutableStateOf(false)

    val blocked: Boolean get() = screenRecorded || externalDisplay
}
