// SPDX-License-Identifier: Apache-2.0
package com.alfonsoteran.slip39trio

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/**
 * Release gate #1 (SECURITY.md). Vectors are copied verbatim from:
 *  - SLIP-39: github.com/trezor/python-shamir-mnemonic, vectors.json (passphrase "TREZOR")
 *  - BIP39:   github.com/trezor/python-mnemonic, vectors.json ("english" section only)
 * Never hand-edit these files.
 */
class OfficialVectorsTest {

    private fun resource(name: String): String =
        javaClass.getResourceAsStream("/vectors/$name")!!.bufferedReader().use { it.readText() }

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun slip39_allOfficialVectors_throughOurAdapter() {
        val vectors = Json.parseToJsonElement(resource("slip39-vectors.json")).jsonArray
        var valid = 0
        var invalid = 0
        for (entry in vectors) {
            val v = entry.jsonArray
            val description = v[0].jsonPrimitive.content
            val mnemonics = v[1].jsonArray.map { it.jsonPrimitive.content }
            val expected = v[2].jsonPrimitive.content
            if (expected.isNotEmpty()) {
                val secret = DrongoSlip39.combine(mnemonics, "TREZOR")
                assertArrayEquals("valid vector failed: $description", hex(expected), secret)
                valid++
            } else {
                val accepted = runCatching { DrongoSlip39.combine(mnemonics, "TREZOR") }.isSuccess
                if (accepted) fail("invalid vector was accepted: $description")
                invalid++
            }
        }
        // Guard against a truncated or empty vectors file silently passing.
        assertEquals("unexpected number of SLIP-39 vectors", 45, valid + invalid)
        assertEquals("unexpected number of valid SLIP-39 vectors", 15, valid)
    }

    @Test
    fun bip39_allEnglishVectors() {
        val vectors = Json.parseToJsonElement(resource("bip39-vectors.json")).jsonObject["english"]!!.jsonArray
        vectors.forEachIndexed { i, entry ->
            val v = entry.jsonArray
            val entropy = hex(v[0].jsonPrimitive.content)
            val mnemonic = v[1].jsonPrimitive.content
            assertEquals("vector $i: entropy -> mnemonic", mnemonic, Bip39.entropyToMnemonic(entropy).joinToString(" "))
            assertArrayEquals("vector $i: mnemonic -> entropy", entropy, Bip39.mnemonicToEntropy(Bip39.normalize(mnemonic)))
        }
        assertEquals("unexpected number of BIP39 vectors", 24, vectors.size)
    }
}
