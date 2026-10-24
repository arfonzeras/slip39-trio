// SPDX-License-Identifier: Apache-2.0
package com.alfonsoteran.slip39trio

import com.sparrowwallet.drongo.wallet.slip39.GroupParams
import com.sparrowwallet.drongo.wallet.slip39.Shamir
import com.sparrowwallet.drongo.wallet.slip39.Slip39MnemonicCode

/** SLIP-0039 operations slip39-trio needs: one group, 2-of-3 members. */
interface Slip39 {
    /** Splits [masterSecret] (BIP39 entropy) into 3 mnemonic shares, any 2 of which recover it. */
    fun split(masterSecret: ByteArray, passphrase: String = ""): List<String>

    /** Recovers the master secret from shares. Caller wipes the result with fill(0). */
    fun combine(shares: List<String>, passphrase: String = ""): ByteArray
}

/**
 * Backend: the SLIP-39 code from Sparrow Wallet's Drongo library (Apache-2.0),
 * vendored under android/core/src/main/java/com/sparrowwallet/drongo/.
 * It must keep passing the official Trezor vectors (Slip39OfficialVectorsTest).
 *
 * Known limit (docs/THREAT_MODEL.md): like the Python reference implementation, the field
 * arithmetic uses lookup tables and is not hardened against side-channel attacks.
 */
object DrongoSlip39 : Slip39 {

    const val THRESHOLD = 2
    const val SHARE_COUNT = 3

    /** Reference-implementation defaults: extendable backup flag on, iteration exponent 1. */
    private const val EXTENDABLE = true
    private const val ITERATION_EXPONENT = 1

    private val WORD_SET: Set<String> by lazy { Slip39MnemonicCode.INSTANCE.wordList.toHashSet() }

    override fun split(masterSecret: ByteArray, passphrase: String): List<String> {
        val groups = Shamir.generateMnemonics(
            1, listOf(GroupParams(THRESHOLD, SHARE_COUNT)),
            masterSecret, passphraseBytes(passphrase), EXTENDABLE, ITERATION_EXPONENT
        )
        return groups.single().also { check(it.size == SHARE_COUNT) }
    }

    override fun combine(shares: List<String>, passphrase: String): ByteArray {
        require(shares.isNotEmpty()) { "No shares given" }
        val normalized = shares.mapIndexed { n, share -> normalizeShare(share, n + 1) }
        return Shamir.combineMnemonics(normalized, passphraseBytes(passphrase))
    }

    /**
     * Lowercases, collapses whitespace and rejects unknown words up front. Drongo would map
     * an unknown word to index -1 and only fail later on the checksum; failing here gives a
     * clearer error. Messages name positions, never words.
     */
    private fun normalizeShare(share: String, n: Int): String {
        val words = share.trim().lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }
        words.forEachIndexed { i, w ->
            require(w in WORD_SET) { "Share $n, word ${i + 1} is not in the SLIP-39 word list" }
        }
        return words.joinToString(" ")
    }

    /** SLIP-39 passphrases must be printable ASCII (32..126). */
    private fun passphraseBytes(passphrase: String): ByteArray {
        require(passphrase.all { it.code in 32..126 }) { "The passphrase must be printable ASCII" }
        return passphrase.toByteArray(Charsets.US_ASCII)
    }
}
