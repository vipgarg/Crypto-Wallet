plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
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
    }

    buildTypes {
        debug {
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
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.3")
    // Used by the UniFFI-generated Kotlin bindings to call the Rust core.
    implementation("net.java.dev.jna:jna:5.15.0@aar")
}
