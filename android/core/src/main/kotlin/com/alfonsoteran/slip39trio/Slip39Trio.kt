// SPDX-License-Identifier: Apache-2.0
package com.alfonsoteran.slip39trio

/**
 * The two ceremonies of slip39-trio, on top of [Bip39] and [Slip39].
 *
 * EXPERIMENTAL, UNAUDITED. Run only on an offline, freshly reset device (docs/THREAT_MODEL.md, L1).
 *
 * About the optional SLIP-39 passphrase: a WRONG passphrase does not produce an error. It
 * recovers a DIFFERENT, perfectly valid mnemonic (a different, empty wallet). This is how
 * SLIP-39 is designed (plausible deniability). Always check the recovered wallet's first
 * address against the one you wrote down at setup.
 */
object Slip39Trio {

    /** Share A goes to the Mac, B stays in this phone's Keystore vault, C is written on paper. */
    data class Shares(val a: String, val b: String, val c: String) {
        override fun toString() = "Shares(<redacted>)"   // never print shares by accident
    }

    fun split(bip39Mnemonic: String, passphrase: String = "", slip39: Slip39 = DrongoSlip39): Shares {
        val entropy = Bip39.mnemonicToEntropy(Bip39.normalize(bip39Mnemonic))
        try {
            val s = slip39.split(entropy, passphrase)
            return Shares(s[0], s[1], s[2])
        } finally {
            entropy.fill(0)
        }
    }

    /** Recovers the BIP39 mnemonic from exactly two different shares. */
    fun recover(first: String, second: String, passphrase: String = "", slip39: Slip39 = DrongoSlip39): String {
        val entropy = slip39.combine(listOf(first, second), passphrase)
        try {
            return Bip39.entropyToMnemonic(entropy).joinToString(" ")
        } finally {
            entropy.fill(0)
        }
    }
}
