pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "slip39-trio-android"

// Pure-JVM crypto core (BIP39 + SLIP-39), testable without the Android SDK.
// Substitutes the dependency "com.alfonsoteran.slip39trio:core" used by :app.
includeBuild("core")

include(":app")
