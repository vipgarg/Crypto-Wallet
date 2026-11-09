package com.vipgarg.walletsigner

import android.hardware.display.DisplayManager
import android.os.Build
import android.os.Bundle
import android.view.Display
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import java.util.function.Consumer

class MainActivity : ComponentActivity() {
    private var recordingCallback: Consumer<Int>? = null

    private val displayListener = object : DisplayManager.DisplayListener {
        override fun onDisplayAdded(displayId: Int) = refreshDisplays()
        override fun onDisplayRemoved(displayId: Int) = refreshDisplays()
        override fun onDisplayChanged(displayId: Int) = refreshDisplays()
    }

    private fun displayManager() = getSystemService(DisplayManager::class.java)

    private fun refreshDisplays() {
        val dm = displayManager() ?: return
        Safety.externalDisplay = dm.getDisplays(DisplayManager.DISPLAY_CATEGORY_PRESENTATION)
            .any { it.displayId != Display.DEFAULT_DISPLAY }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, screen recording or recent-apps preview of any screen.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        setContent { SignerApp(WalletStore(filesDir)) }
    }

    override fun onStart() {
        super.onStart()
        // Screen recording of this app (Android 15+).
        if (Build.VERSION.SDK_INT >= 35) {
            val cb = Consumer<Int> { state ->
                Safety.screenRecorded = state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE
            }
            recordingCallback = cb
            val initial = windowManager.addScreenRecordingCallback(mainExecutor, cb)
            Safety.screenRecorded = initial == WindowManager.SCREEN_RECORDING_STATE_VISIBLE
        }
        // Casting / mirroring to another display.
        displayManager()?.registerDisplayListener(displayListener, null)
        refreshDisplays()
    }

    override fun onStop() {
        if (Build.VERSION.SDK_INT >= 35) {
            recordingCallback?.let { windowManager.removeScreenRecordingCallback(it) }
        }
        recordingCallback = null
        displayManager()?.unregisterDisplayListener(displayListener)
        super.onStop()
    }
}
