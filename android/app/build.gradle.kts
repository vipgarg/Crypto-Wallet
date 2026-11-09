plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// SHA-256 of the owner's signing certificate, pinned in android/signing-cert.sha256
// once the owner has compared it with their own record. The app checks
// itself against it at start-up; empty until pinned.
val pinnedSigningCert: String = rootProject.file("signing-cert.sha256").let { f ->
    if (!f.exists()) return@let ""
    val v = f.readLines().map { it.trim() }.firstOrNull { it.isNotEmpty() && !it.startsWith("#") }
        ?.replace(":", "")?.lowercase() ?: ""
    require(v.matches(Regex("^[0-9a-f]{64}$"))) { "signing-cert.sha256 must hold 64 hex characters" }
    v
}

android {
    namespace = "com.vipgarg.walletsigner"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.vipgarg.walletsigner"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-testnet"
        // The tablet is 64-bit ARM; the Rust core is built for it by CI.
        ndk { abiFilters += "arm64-v8a" }
        buildConfigField("String", "EXPECTED_SIGNING_CERT", "\"$pinnedSigningCert\"")
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        // Signed in CI with the owner's key (see docs/signer-app.md). Not
        // minified: the Rust bridge (UniFFI + JNA) is called by name.
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.3")
    // Camera QR reading, offline only (no network code is used).
    implementation("androidx.camera:camera-camera2:1.4.1")
    implementation("androidx.camera:camera-lifecycle:1.4.1")
    implementation("androidx.camera:camera-view:1.4.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("com.google.zxing:core:3.5.3")
    // Used by the UniFFI-generated Kotlin bindings to call the Rust core.
    implementation("net.java.dev.jna:jna:5.15.0@aar")
}
