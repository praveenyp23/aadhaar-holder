plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    // Kotlin 2.0+ Compose compiler plugin (replaces composeOptions.kotlinCompilerExtensionVersion)
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.mdocholder.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.mdocholder.app"
        minSdk = 29  // raised from 26: multipaz-compose (DC API presentment UI) requires API 29+
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Multipaz longfellow native lib (libzkp.so) ships only for these ABIs.
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
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
        viewBinding = true
        compose = true
    }
}

dependencies {
    implementation("com.airbnb.android:lottie-compose:6.6.3")
    // Common module
    implementation(project(":common"))

    // Multipaz W3C Digital Credentials API provider + known doc types (Aadhaar).
    // multipaz-dcapi bundles the Credential Manager matcher and pulls Play Services
    // Identity Credentials + androidx.credentials transitively. No Compose-Multiplatform.
    implementation("org.multipaz:multipaz-dcapi:0.99.0")
    implementation("org.multipaz:multipaz-doctypes:0.99.0")
    // Multipaz presentment UI (consent prompt) + CredentialManagerPresentmentActivity base class.
    implementation("org.multipaz:multipaz-compose:0.99.0")
    
    // AndroidX Core & Lifecycle
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.7.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    
    // Jetpack Compose
    implementation("androidx.compose.ui:ui:1.6.0")
    implementation("androidx.compose.ui:ui-tooling-preview:1.6.0")
    implementation("androidx.compose.material3:material3:1.1.2")
    implementation("androidx.compose.material:material:1.6.0")
    implementation("androidx.activity:activity-compose:1.8.0")
    
    // Material Design (for traditional views if needed)
    implementation("com.google.android.material:material:1.11.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    
    // CBOR support
    implementation("co.nstant.in:cbor:0.9")
    
    // BouncyCastle for cryptography
    implementation("org.bouncycastle:bcprov-jdk18on:1.77")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.77")
    
    // Gson for JSON
    implementation("com.google.code.gson:gson:2.10.1")
    
    // QR Code generation and scanning
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    // Testing
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4:1.6.0")
    debugImplementation("androidx.compose.ui:ui-tooling:1.6.0")
}
