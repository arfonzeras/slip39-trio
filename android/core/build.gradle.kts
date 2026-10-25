// Pure-JVM crypto core (BIP39 + SLIP-39 + ceremonies). No Android dependencies, so the
// official vectors run on any machine with `./gradlew -p android/core test`.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.21"
    `java-library`
}

group = "com.alfonsoteran.slip39trio"
version = "0.0.1-experimental"

repositories { mavenCentral() }

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<JavaCompile>().configureEach { options.release.set(17) }

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
}

tasks.test {
    testLogging { events("passed", "failed"); showStandardStreams = false }
}
