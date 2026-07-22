package com.example.mdoc.holder.ble

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Session crypto for OpenID4VP-over-BLE: X25519 ECDH → HKDF-SHA256 (SKWallet / SKVerifier) →
 * AES-256-GCM. The Verifier encrypts with SKVerifier, the Wallet with SKWallet; the 12-byte IV is
 * the wallet's nonce from the Identify request; AAD is empty; the ciphertext is `ct || tag`.
 */
object BleCrypto {

    class KeyPair(val priv: X25519PrivateKeyParameters, val publicRaw: ByteArray)

    fun newKeyPair(): KeyPair {
        val priv = X25519PrivateKeyParameters(SecureRandom())
        return KeyPair(priv, priv.generatePublicKey().encoded)
    }

    fun sharedSecret(myPriv: X25519PrivateKeyParameters, peerPublicRaw: ByteArray): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(myPriv)
        val out = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X25519PublicKeyParameters(peerPublicRaw, 0), out, 0)
        return out
    }

    /** HKDF-SHA256(sharedSecret, info) → 32-byte key. info is "SKWallet" or "SKVerifier". */
    fun deriveKey(sharedSecret: ByteArray, info: String): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(sharedSecret, null, info.toByteArray()))
        val key = ByteArray(32)
        hkdf.generateBytes(key, 0, 32)
        return key
    }

    fun encrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return cipher.doFinal(plaintext) // ct || 16-byte tag
    }

    fun decrypt(key: ByteArray, iv: ByteArray, ciphertextAndTag: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return cipher.doFinal(ciphertextAndTag)
    }

    fun randomNonce(): ByteArray = ByteArray(12).also { SecureRandom().nextBytes(it) }

    fun toHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
    fun fromHex(s: String): ByteArray =
        ByteArray(s.length / 2) { ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte() }
}
