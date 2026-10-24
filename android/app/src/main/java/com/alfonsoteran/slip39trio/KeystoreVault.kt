// SPDX-License-Identifier: Apache-2.0
package com.alfonsoteran.slip39trio

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Share B at rest: AES-256-GCM with a non-exportable Android Keystore key.
 *
 *  - Strong biometric required for EVERY use (timeout 0, cipher bound to BiometricPrompt).
 *  - Key invalidated if a new biometric is enrolled (THREAT_MODEL L7).
 *  - StrongBox (dedicated secure chip) when the phone has one, TEE otherwise.
 *  - Ciphertext stored in noBackupFilesDir, file format: [12-byte IV][ciphertext+tag].
 *
 * Every call ends in exactly one onDone(...) — success, error or user cancel.
 *
 * EXPERIMENTAL, UNAUDITED.
 */
class KeystoreVault(private val activity: FragmentActivity) {

    class BiometricsChangedException :
        SecurityException("Biometrics changed since share B was sealed: the key is gone by design. Recover with shares A + C.")

    private val alias = "slip39-trio-share-b"
    private val file = File(activity.noBackupFilesDir, "share-b.bin")

    // ---------- key ----------

    private fun spec(strongBox: Boolean) =
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .setIsStrongBoxBacked(strongBox)
            .build()

    private fun existingKey(): SecretKey? {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return ks.getKey(alias, null) as? SecretKey
    }

    private fun deleteKey() {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
    }

    /** Always a fresh key for a new seal, so an old (possibly invalidated) key is never reused. */
    private fun newKey(): SecretKey {
        deleteKey()
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        return try {
            gen.init(spec(strongBox = true)); gen.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            gen.init(spec(strongBox = false)); gen.generateKey()
        }
    }

    // ---------- public API ----------

    fun isSealed(): Boolean = file.exists()

    /** Encrypts share B after the offline gate and a biometric prompt. Always wipes [share]. */
    fun seal(share: ByteArray, onDone: (Result<Unit>) -> Unit) {
        val done: (Result<Unit>) -> Unit = { r -> share.fill(0); onDone(r) }
        val cipher = try {
            OfflineGate.check(activity)
            check(!file.exists()) { "Share B is already sealed on this phone" }
            Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, newKey()) }  // Keystore picks a random IV
        } catch (e: Exception) {
            return done(Result.failure(e))
        }
        authenticate(cipher, "Seal share B", done) { authed ->
            val ct = authed.doFinal(share)
            val tmp = File(file.path + ".tmp")
            tmp.writeBytes(authed.iv + ct)
            check(tmp.renameTo(file)) { "Could not write share B" }
        }
    }

    /** Decrypts share B. On success the caller MUST wipe the returned array with fill(0) when done. */
    fun reveal(onDone: (Result<ByteArray>) -> Unit) {
        val (cipher, ct) = try {
            OfflineGate.check(activity)
            check(file.exists()) { "No share B sealed on this phone" }
            val key = existingKey() ?: throw BiometricsChangedException()
            val blob = file.readBytes()
            require(blob.size > IV_BYTES + TAG_BYTES) { "Share B file is corrupted" }
            val c = Cipher.getInstance(TRANSFORMATION)
            try {
                c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BYTES * 8, blob, 0, IV_BYTES))
            } catch (e: KeyPermanentlyInvalidatedException) {
                throw BiometricsChangedException()
            }
            c to blob.copyOfRange(IV_BYTES, blob.size)
        } catch (e: Exception) {
            return onDone(Result.failure(e))
        }
        authenticate(cipher, "Reveal share B", onDone) { authed ->
            val pt = authed.doFinal(ct)
            try {
                OfflineGate.check(activity)   // re-check before the caller displays anything
            } catch (e: Exception) {
                pt.fill(0); throw e
            }
            pt
        }
    }

    // ---------- biometrics ----------

    /** Runs [work] with the authenticated cipher and reports the result (or any error) through [onDone]. */
    private fun <T> authenticate(cipher: Cipher, title: String, onDone: (Result<T>) -> Unit, work: (Cipher) -> T) {
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle("Approve only if YOU just started this action")
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setNegativeButtonText("Cancel")
            .build()

        BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val c = result.cryptoObject?.cipher
                    onDone(if (c == null) Result.failure(SecurityException("No authenticated cipher")) else runCatching { work(c) })
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onDone(Result.failure(SecurityException("Biometric authentication ended: $errString ($errorCode)")))
                }
                // onAuthenticationFailed (one wrong finger) is not final: the prompt stays open.
            }
        ).authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
        const val TAG_BYTES = 16
    }
}
