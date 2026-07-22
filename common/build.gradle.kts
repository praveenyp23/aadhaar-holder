plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.mdoc.common"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
    }
    
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.2.21")
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")

    // Multipaz core + Google longfellow-zk integration (Zero-Knowledge Proofs).
    // Built with Kotlin 2.2 — this is why the project toolchain was upgraded.
    // Native libzkp.so ships for arm64-v8a and x86_64 only.
    api("org.multipaz:multipaz:0.99.0")
    api("org.multipaz:multipaz-longfellow:0.99.0")

    // CBOR support
    implementation("co.nstant.in:cbor:0.9")
    
    // BouncyCastle for cryptography
    implementation("org.bouncycastle:bcprov-jdk18on:1.77")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.77")
    
    // Kotlin Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    
    // Gson for JSON
    implementation("com.google.code.gson:gson:2.10.1")
    
    // ZXing for QR codes
    implementation("com.google.zxing:core:3.5.3")
    
    // OkHttp for network calls
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    
    // Nimbus JOSE+JWT for JWE/JWS operations
    implementation("com.nimbusds:nimbus-jose-jwt:9.37.3")
}