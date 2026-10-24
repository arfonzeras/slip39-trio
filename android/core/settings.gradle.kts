// core is a standalone build so it can be tested without the Android SDK.
// The Android app includes it as a composite build (see ../settings.gradle.kts).
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}
rootProject.name = "core"
