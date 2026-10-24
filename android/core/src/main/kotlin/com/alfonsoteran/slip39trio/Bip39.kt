// SPDX-License-Identifier: Apache-2.0
package com.alfonsoteran.slip39trio

import java.security.MessageDigest

/**
 * Minimal BIP39 (English) entropy <-> mnemonic conversion with checksum validation.
 *
 * Only what slip39-trio needs: no seed derivation (PBKDF2 to a BIP32 seed) and no BIP39
 * passphrase ("25th word") handling — those stay in the user's wallet.
 * Verified against the official vectors from trezor/python-mnemonic (see tests).
 *
 * Error messages give word POSITIONS, never the words themselves, so a log line or a
 * crash report cannot leak part of a seed.
 */
object Bip39 {

    private val WORDS: List<String> by lazy {
        val stream = Bip39::class.java.getResourceAsStream("/com/alfonsoteran/slip39trio/bip39-english.txt")
            ?: error("BIP39 word list missing from resources")
        val list = stream.bufferedReader(Charsets.UTF_8).use { it.readLines() }.filter { it.isNotBlank() }
        check(list.size == 2048) { "BIP39 word list must have 2048 words, found ${list.size}" }
        list
    }

    private val INDEX: Map<String, Int> by lazy { WORDS.withIndex().associate { it.value to it.index } }

    /** Valid entropy sizes in bytes: 128, 160, 192, 224 and 256 bits. */
    val ENTROPY_SIZES = setOf(16, 20, 24, 28, 32)

    /** Splits user input into normalized words: trimmed, lowercase, any whitespace as separator. */
    fun normalize(text: String): List<String> =
        text.trim().lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }

    fun entropyToMnemonic(entropy: ByteArray): List<String> {
        require(entropy.size in ENTROPY_SIZES) { "Entropy must be 16, 20, 24, 28 or 32 bytes" }
        val entBits = entropy.size * 8
        val csBits = entBits / 32
        val hash = sha256(entropy)
        val bits = BooleanArray(entBits + csBits)
        try {
            for (i in 0 until entBits) bits[i] = bit(entropy, i)
            for (i in 0 until csBits) bits[entBits + i] = bit(hash, i)
            return (0 until bits.size / 11).map { w ->
                var idx = 0
                for (j in 0 until 11) idx = (idx shl 1) or (if (bits[w * 11 + j]) 1 else 0)
                WORDS[idx]
            }
        } finally {
            bits.fill(false)
            hash.fill(0)
        }
    }

    /** Returns the entropy behind [words]. Throws if a word is unknown or the checksum fails. Caller wipes the result. */
    fun mnemonicToEntropy(words: List<String>): ByteArray {
        require(words.size in setOf(12, 15, 18, 21, 24)) { "A BIP39 mnemonic has 12, 15, 18, 21 or 24 words, got ${words.size}" }
        val bits = BooleanArray(words.size * 11)
        val csBits = bits.size / 33
        val entBits = bits.size - csBits
        val entropy = ByteArray(entBits / 8)
        var hash = ByteArray(0)
        try {
            words.forEachIndexed { w, word ->
                val idx = INDEX[word] ?: throw IllegalArgumentException("Word ${w + 1} is not in the BIP39 English word list")
                for (j in 0 until 11) bits[w * 11 + j] = ((idx shr (10 - j)) and 1) == 1
            }
            for (i in 0 until entBits) if (bits[i]) entropy[i / 8] = (entropy[i / 8].toInt() or (0x80 ushr (i % 8))).toByte()
            hash = sha256(entropy)
            var ok = true
            for (i in 0 until csBits) ok = ok and (bits[entBits + i] == bit(hash, i))
            if (!ok) {
                entropy.fill(0)
                throw IllegalArgumentException("BIP39 checksum mismatch: a word is wrong or out of order")
            }
            return entropy
        } finally {
            bits.fill(false)
            hash.fill(0)
        }
    }

    private fun bit(bytes: ByteArray, i: Int): Boolean = ((bytes[i / 8].toInt() shr (7 - i % 8)) and 1) == 1

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
}
