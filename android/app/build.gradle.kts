plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.alfonsoteran.slip39trio"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.alfonsoteran.slip39trio"
        minSdk = 30          // setUserAuthenticationParameters() needs API 30
        targetSdk = 35
        versionCode = 1
        versionName = "0.0.1-experimental"
    }

    // The vendored SLIP-39 code uses Java 17 features (records, pattern matching).
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("com.alfonsoteran.slip39trio:core")      // ../core, via includeBuild
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
}
