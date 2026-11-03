package com.vipgarg.walletsigner

import android.Manifest
import android.content.pm.PackageManager
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Reads one QR code with the camera (offline: CameraX + ZXing, no network).
 * The camera runs only while this is on screen; it stops as soon as a code
 * starting with [prefix] is read, or when the screen is left.
 */
@Composable
fun QrScanner(prefix: String, wrongHint: String, onResult: (String) -> Unit, onCancel: () -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var granted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED,
        )
    }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }
    LaunchedEffect(Unit) { if (!granted) launcher.launch(Manifest.permission.CAMERA) }

    if (!granted) {
        Text("Camera permission is needed to read the QR code. The camera is used only on this screen; this app has no internet access.")
        OutlinedButton(onClick = { launcher.launch(Manifest.permission.CAMERA) }) { Text("Allow camera") }
        OutlinedButton(onClick = onCancel) { Text("Cancel") }
        return
    }

    var notice by remember { mutableStateOf<String?>(null) }
    val done = remember { AtomicBoolean(false) }
    val analysisExecutor = remember { Executors.newSingleThreadExecutor() }
    val mainExecutor = remember { ContextCompat.getMainExecutor(context) }
    val providerFuture = remember { ProcessCameraProvider.getInstance(context) }

    DisposableEffect(Unit) {
        onDispose {
            done.set(true)
            providerFuture.addListener({ runCatching { providerFuture.get().unbindAll() } }, mainExecutor)
            analysisExecutor.shutdown()
        }
    }

    AndroidView(
        factory = { ctx ->
            val previewView = PreviewView(ctx)
            providerFuture.addListener({
                val provider = providerFuture.get()
                val preview = Preview.Builder().build()
                preview.setSurfaceProvider(previewView.surfaceProvider)
                val analysis = ImageAnalysis.Builder()
                    .setResolutionSelector(
                        ResolutionSelector.Builder()
                            .setResolutionStrategy(
                                ResolutionStrategy(
                                    Size(1920, 1080),
                                    ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER,
                                ),
                            )
                            .build(),
                    )
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                val reader = MultiFormatReader().apply {
                    setHints(
                        mapOf(
                            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                            DecodeHintType.TRY_HARDER to true,
                        ),
                    )
                }
                analysis.setAnalyzer(analysisExecutor) { image ->
                    try {
                        if (done.get()) return@setAnalyzer
                        val plane = image.planes[0]
                        val buf = plane.buffer
                        val data = ByteArray(buf.remaining())
                        buf.get(data)
                        val source = PlanarYUVLuminanceSource(
                            data, plane.rowStride, image.height, 0, 0, image.width, image.height, false,
                        )
                        val text = reader.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text.trim()
                        if (text.startsWith(prefix) && text.length <= 8000) {
                            if (done.compareAndSet(false, true)) {
                                mainExecutor.execute {
                                    runCatching { provider.unbindAll() }
                                    onResult(text)
                                }
                            }
                        } else {
                            mainExecutor.execute { notice = wrongHint }
                        }
                    } catch (_: NotFoundException) {
                        // No QR code in this frame.
                    } catch (_: Exception) {
                        // Unreadable frame; try the next one.
                    } finally {
                        reader.reset()
                        image.close()
                    }
                }
                val selector = if (provider.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA)) {
                    CameraSelector.DEFAULT_BACK_CAMERA
                } else {
                    CameraSelector.DEFAULT_FRONT_CAMERA
                }
                provider.unbindAll()
                provider.bindToLifecycle(lifecycleOwner, selector, preview, analysis)
            }, mainExecutor)
            previewView
        },
        modifier = Modifier.fillMaxWidth().height(420.dp),
    )
    Text(notice ?: "Point the camera at the QR code on the PC screen.", color = if (notice != null) Color(0xFF7A5600) else Color.Unspecified)
    OutlinedButton(onClick = onCancel) { Text("Cancel (turns the camera off)") }
}
