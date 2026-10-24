// SPDX-License-Identifier: Apache-2.0
package com.alfonsoteran.slip39trio

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/** Properties of the 2-of-3 ceremony. Uses throwaway random seeds only. */
class Slip39TrioTest {

    private val rng = SecureRandom()

    private fun randomMnemonic(bytes: Int): String =
        Bip39.entropyToMnemonic(ByteArray(bytes).also(rng::nextBytes)).joinToString(" ")

    private fun rejects(block: () -> Unit) {
        assertThrows(Throwable::class.java) { block() }
    }

    @Test
    fun anyTwoSharesRecover_forEveryBip39Length() {
        for (size in Bip39.ENTROPY_SIZES) {
            repeat(3) {
                val mnemonic = randomMnemonic(size)
                val s = Slip39Trio.split(mnemonic)
                assertEquals("shares must differ", 3, setOf(s.a, s.b, s.c).size)
                assertEquals("A+B, $size bytes", mnemonic, Slip39Trio.recover(s.a, s.b))
                assertEquals("A+C, $size bytes", mnemonic, Slip39Trio.recover(s.a, s.c))
                assertEquals("B+C, $size bytes", mnemonic, Slip39Trio.recover(s.b, s.c))
                assertEquals("order must not matter", mnemonic, Slip39Trio.recover(s.c, s.a))
            }
        }
    }

    @Test
    fun oneShareAloneIsRejected() {
        val s = Slip39Trio.split(randomMnemonic(16))
        for (share in listOf(s.a, s.b, s.c)) rejects { DrongoSlip39.combine(listOf(share)) }
    }

    @Test
    fun sameShareTwiceIsRejected() {
        val s = Slip39Trio.split(randomMnemonic(32))
        rejects { Slip39Trio.recover(s.a, s.a) }
    }

    @Test
    fun sharesFromDifferentSplitsDoNotMix() {
        val m = randomMnemonic(16)
        val first = Slip39Trio.split(m)
        val second = Slip39Trio.split(m)   // same seed, new random identifier and polynomial
        rejects { Slip39Trio.recover(first.a, second.b) }
    }

    @Test
    fun shareWordCounts() {
        // SLIP-39: 20 words for a 128-bit secret, 33 words for a 256-bit secret.
        val s128 = Slip39Trio.split(randomMnemonic(16))
        val s256 = Slip39Trio.split(randomMnemonic(32))
        assertTrue(listOf(s128.a, s128.b, s128.c).all { it.split(" ").size == 20 })
        assertTrue(listOf(s256.a, s256.b, s256.c).all { it.split(" ").size == 33 })
    }

    @Test
    fun messyInputIsNormalized() {
        val m = randomMnemonic(16)
        val s = Slip39Trio.split("  " + m.uppercase().replace(" ", "\n\t ") + " ")
        val messyA = "  " + s.a.uppercase().replace(" ", "   ") + "\n"
        assertEquals(m, Slip39Trio.recover(messyA, s.b))
    }

    @Test
    fun corruptedShareIsRejected() {
        // RS1024 is guaranteed to detect up to 3 wrong words in a share.
        val s = Slip39Trio.split(randomMnemonic(16))
        val words = s.a.split(" ").toMutableList()
        words[10] = if (words[10] == "academic") "acid" else "academic"   // both are SLIP-39 words
        rejects { Slip39Trio.recover(words.joinToString(" "), s.b) }
    }

    @Test
    fun unknownWordErrorDoesNotLeakTheWord() {
        val s = Slip39Trio.split(randomMnemonic(16))
        val words = s.b.split(" ").toMutableList()
        words[4] = "notaslip39word"
        val e = assertThrows(IllegalArgumentException::class.java) { Slip39Trio.recover(s.a, words.joinToString(" ")) }
        assertEquals("Share 2, word 5 is not in the SLIP-39 word list", e.message)
    }

    @Test
    fun invalidBip39IsRejectedBeforeSplitting() {
        // All-zero entropy ends in "about"; twelve "abandon" is a well-known checksum failure.
        assertThrows(IllegalArgumentException::class.java) { Slip39Trio.split(List(12) { "abandon" }.joinToString(" ")) }
        assertThrows(IllegalArgumentException::class.java) { Slip39Trio.split(List(11) { "abandon" }.joinToString(" ") + " zzzz") }
        assertThrows(IllegalArgumentException::class.java) { Slip39Trio.split("abandon abandon abandon") }
    }

    @Test
    fun passphrase_rightOneRecovers_wrongOneGivesADifferentValidSeed() {
        val m = randomMnemonic(16)
        val s = Slip39Trio.split(m, passphrase = "correct horse")
        assertEquals(m, Slip39Trio.recover(s.a, s.b, passphrase = "correct horse"))
        // Documented SLIP-39 behaviour: no error, just another wallet. See Slip39Trio KDoc.
        assertNotEquals(m, Slip39Trio.recover(s.a, s.b, passphrase = "wrong"))
        assertNotEquals(m, Slip39Trio.recover(s.a, s.b))
    }

    @Test
    fun nonAsciiPassphraseIsRejected() {
        assertThrows(IllegalArgumentException::class.java) { Slip39Trio.split(randomMnemonic(16), passphrase = "contraseña") }
    }

    @Test
    fun sharesNeverPrintByAccident() {
        assertEquals("Shares(<redacted>)", Slip39Trio.split(randomMnemonic(16)).toString())
    }
}
