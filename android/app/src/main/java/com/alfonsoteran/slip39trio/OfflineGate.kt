// SPDX-License-Identifier: Apache-2.0
package com.alfonsoteran.slip39trio

import android.content.Context
import android.net.ConnectivityManager
import android.provider.Settings

/**
 * Offline gate: refuse to touch a share while the phone has any network path.
 *
 * Hygiene control, NOT a security boundary (docs/THREAT_MODEL.md, L2):
 * it blocks live exfiltration and remote sessions during the sensitive window,
 * but cannot stop malware that stores the secret and sends it after reconnecting.
 */
object OfflineGate {

    class NotOfflineException(msg: String) : SecurityException(msg)

    fun check(context: Context) {
        val airplane = Settings.Global.getInt(
            context.contentResolver, Settings.Global.AIRPLANE_MODE_ON, 0
        ) == 1
        if (!airplane) throw NotOfflineException("Enable airplane mode first.")

        // Airplane mode still allows Wi-Fi to be switched back on manually, so check networks too.
        val cm = context.getSystemService(ConnectivityManager::class.java)
        @Suppress("DEPRECATION") // allNetworks is the simplest complete snapshot available on API 30+
        val networks = cm.allNetworks
        if (networks.isNotEmpty()) {
            throw NotOfflineException("A network is still active (Wi-Fi or other). Turn it off.")
        }
        // TODO (roadmap): Bluetooth and NFC checks.
    }
}
