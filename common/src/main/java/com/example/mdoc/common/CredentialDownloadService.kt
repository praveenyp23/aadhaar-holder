package com.example.mdoc.common

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID
import java.util.concurrent.TimeUnit

class CredentialDownloadService {

    companion object {
        private const val TAG = "CRED_DOWNLOAD"
        private const val BASE_URL = "https://pehchaanstage.uidai.gov.in/csm/api/v1"
        private const val DEVICE_ID = "mdoc-holder-app"
        private val JSON_MEDIA = "application/json".toMediaType()
        const val DEVICE_KEY_ALIAS = "mdoc_device_key"
        // UIDAI encryption key (RSA-OAEP-256) for encrypting credential requests
        private const val UIDAI_ENC_KID = "YzpBmDr3UdrnKYtxi6xSLRuFiSSLQhnrtellnDm5mqA"
        private const val UIDAI_ENC_N = "r_plRUuMw5MUgSCnZzO2-Lxrx4jSI-x4aoc0sbEusjsNH7eiIh8jmCG2QJkaOG312Or3y6RRt_i3g3T95h4gjjgwpc5t0e6q74uo6azJOKcSRPWNjqbBK0A3qP7umAG3VgW7tPjXs7yM99ILse4rPNCuPMNWtwhg3AfiPuco9-nZZZCZRrQE8D4a6FDnszgeAEUf-zr-3xZO2YJKw7WSlbIBPJ2QMy22Etcu8VcrDII-ahJREbTsnKEIKGLD2YmMaUP-7M_RC9GunfK8mJxMdzelVvANl7pLDHvSQPVTcyRZ1JM-JT0bjdFvQO0vv1a2_o-0lu-SnLB6B2Imka61hw"
        private const val UIDAI_ENC_E = "AQAB"

        // UIDAI signature key (RS256) for verifying credential responses
        private const val UIDAI_SIG_KID = "CEZk74VBmnDD1yx0JCmNU8TdiXAfqUO2ujJfgiLhTN8"
        private const val UIDAI_SIG_N = "yITY_ZOJaJEVfp4ozm-5erBXMk7fWuDBHOzPy0JT8aKsJca4OXHsqZR6ZjPOyUQZByTymGbp2OSxgM0CWUmDTfIn_ify_rGip6y-uXXZDQXq0lxC2O-l0tfxUR9DguqY3Kcbj6h8MhpivQgmkHbJ1Dx03Xs0KRb_0zt7Oz--MivGdaWSZ2k6XQ_ryWiak2RuaTsDMSV2Quw6cu6_Ng9vxxirwu-A9W8uvPy3zGh_V6oihoWGRiLtm8WDCEm3J56486R-FWMDdFWriKPi_7TD4sAhdnv-EkuqYtBNarPp_31moQBBJX2FAEhfuvKgMgEhXFzMptSi0IlPYDH9tGYkgw"
        private const val UIDAI_SIG_E = "AQAB"
    }

    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    private val gson = Gson()


    data class DownloadResult(
        val success: Boolean,
        val mdocBase64: String? = null,
        val error: String? = null
    )

    /**
     * Downloads a credential from UIDAI Pehchaan.
     * @param uid 12-digit Aadhaar number
     * @return DownloadResult with base64-encoded mdoc on success
     */
    suspend fun downloadCredential(uid: String): DownloadResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Starting credential download for UID: ${uid.take(4)}****")

            // Step 1: Generate device RSA key pair for response encryption
            val rsaKeyPairGen = KeyPairGenerator.getInstance("RSA")
            rsaKeyPairGen.initialize(2048)
            val deviceKeyPair = rsaKeyPairGen.generateKeyPair()
            val devicePubKey = deviceKeyPair.public as RSAPublicKey
            val devicePrivKey = deviceKeyPair.private as RSAPrivateKey
            Log.d(TAG, "Generated device RSA key pair for response encryption")

            // Step 2: Get nonce
            val nonce = getNonce()
            Log.d(TAG, "Got nonce: $nonce")

            // Step 3: Generate ECDSA key in Android KeyStore with nonce as attestation challenge
            // Use fixed alias so we can retrieve the private key later for ECDH during presentation
            val attestationAlias = DEVICE_KEY_ALIAS
            // Generating a key under an existing alias replaces it atomically, so we never delete the
            // old key first — a failure here can't leave the keystore without a device key.
            val attestationCertChain = generateAttestationKey(attestationAlias, nonce)
            Log.d(TAG, "Generated attestation key with ${attestationCertChain.size} certs in chain")

            // Step 4: Build credential request JSON
            val credentialRequest = buildCredentialRequest(devicePubKey, attestationCertChain)
            Log.d(TAG, "Built credential request (${credentialRequest.length} chars)")

            // Step 5: Encrypt the request with UIDAI's encryption key
            val encryptedRequest = encryptCredentialRequest(credentialRequest)
            Log.d(TAG, "Encrypted credential request (${encryptedRequest.length} chars)")

            // Step 6: Call getCredential
            val signedResponse = getCredential(uid, encryptedRequest)
            Log.d(TAG, "Got signed credential response (${signedResponse.length} chars)")

            // Step 7: Verify JWS and extract encrypted credential payload
            val encryptedPayload = verifyAndExtractPayload(signedResponse)
            Log.d(TAG, "Extracted encrypted credential payload")

            // Step 8: Decrypt the credential payload
            val decryptedPayload = decryptCredentialPayload(encryptedPayload, devicePrivKey)
            Log.d(TAG, "Decrypted credential payload (${decryptedPayload.length} chars)")

            // Step 9: Extract the base64 mdoc from the decrypted payload
            val mdocB64 = extractMdocFromPayload(decryptedPayload)
            Log.d(TAG, "Extracted mdoc base64 (${mdocB64.length} chars)")

            // Keep the attestation key in KeyStore — it's the MSO deviceKey private key
            // needed for ECDH during presentation
            Log.d(TAG, "Device key kept in KeyStore with alias: $attestationAlias")

            DownloadResult(success = true, mdocBase64 = mdocB64)
        } catch (e: Exception) {
            Log.e(TAG, "Credential download failed", e)
            DownloadResult(success = false, error = e.message ?: "Unknown error")
        }
    }

    /**
     * Generates an ECDSA key pair in Android KeyStore with the nonce as
     * attestation challenge, and returns the attestation certificate chain
     * as a list of base64-encoded DER certificates.
     */
    private fun generateAttestationKey(alias: String, nonce: String): List<String> {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )

        val paramBuilder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_AGREE_KEY
        )
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
            .setAttestationChallenge(nonce.toByteArray(Charsets.UTF_8))

        keyPairGenerator.initialize(paramBuilder.build())
        keyPairGenerator.generateKeyPair()

        // Retrieve the attestation certificate chain
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val certChain = entry.certificateChain

        Log.d(TAG, "Attestation cert chain length: ${certChain.size}")

        return certChain.map { cert ->
            Base64.encodeToString(cert.encoded, Base64.NO_WRAP)
        }
    }

    private fun getNonce(): String {
        val requestId = UUID.randomUUID().toString()
        val body = gson.toJson(mapOf("deviceId" to DEVICE_ID))

        val request = Request.Builder()
            .url("$BASE_URL/getNonce")
            .addHeader("X-Request-ID", requestId)
            .addHeader("Content-Type", "application/json")
            .post(body.toRequestBody(JSON_MEDIA))
            .build()

        val response = client.newCall(request).execute()
        val responseBody = response.body?.string() ?: throw Exception("Empty getNonce response")
        Log.d(TAG, "getNonce response: $responseBody")

        if (!response.isSuccessful) {
            throw Exception("getNonce failed: HTTP ${response.code} - $responseBody")
        }

        val json = JsonParser.parseString(responseBody).asJsonObject
        val status = json.get("status")?.asString
        if (status != "SUCCESS") {
            throw Exception("getNonce failed: status=$status")
        }

        return json.getAsJsonObject("response").get("nonce").asString
    }

    private fun buildCredentialRequest(devicePubKey: RSAPublicKey, attestationCertChain: List<String>): String {
        val credId = "1_${UUID.randomUUID()}"

        // Build the response encryption JWK
        val deviceRsaKey = RSAKey.Builder(devicePubKey)
            .keyID(UUID.randomUUID().toString().replace("-", "").uppercase())
            .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.RSA_OAEP_256)
            .build()

        // Build attestation cert chain array (array of arrays, matching request_dummy.json format)
        val certChainArray = com.google.gson.JsonArray()
        for (certB64 in attestationCertChain) {
            certChainArray.add(certB64)
        }
        val attestationArray = com.google.gson.JsonArray()
        attestationArray.add(certChainArray)

        val requestJson = JsonObject().apply {
            addProperty("credential_identifier", credId)
            addProperty("credential_configuration_id", "")

            // Proof with Android KeyStore attestation
            add("proof", JsonObject().apply {
                addProperty("proof_type", "attestation")
                add("attestation", JsonObject().apply {
                    add("android_keystore_attestation", attestationArray)
                })
            })

            // Credential response encryption
            add("credential_response_encryption", JsonObject().apply {
                add("jwk", JsonParser.parseString(deviceRsaKey.toJSONString()))
                addProperty("enc", "A256GCM")
                addProperty("zip", "none")
                addProperty("sig", "")
                add("credential_key_cert_chain", com.google.gson.JsonArray())
            })

            addProperty("credential_type", "mdoc")
        }

        return requestJson.toString()
    }

    private fun encryptCredentialRequest(plaintextRequest: String): String {
        // Build UIDAI encryption RSA public key
        val uidaiEncKey = RSAKey.Builder(
            com.nimbusds.jose.util.Base64URL(UIDAI_ENC_N),
            com.nimbusds.jose.util.Base64URL(UIDAI_ENC_E)
        )
            .keyID(UIDAI_ENC_KID)
            .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.RSA_OAEP_256)
            .build()

        // Create JWE with RSA-OAEP-256 + A256GCM
        val header = JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
            .keyID(UIDAI_ENC_KID)
            .build()

        val jweObject = JWEObject(header, Payload(plaintextRequest))
        jweObject.encrypt(RSAEncrypter(uidaiEncKey))

        val jweCompact = jweObject.serialize()

        // Base64-encode the JWE compact serialization
        return Base64.encodeToString(jweCompact.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    }

    private fun getCredential(uid: String, encryptedRequest: String): String {
        val requestId = UUID.randomUUID().toString()
        val body = gson.toJson(mapOf(
            "deviceId" to DEVICE_ID,
            "uid" to uid,
            "encryptedCredentialRequest" to encryptedRequest
        ))

        val request = Request.Builder()
            .url("$BASE_URL/getCredential")
            .addHeader("X-Request-Id", requestId)
            .addHeader("Content-Type", "application/json")
            .post(body.toRequestBody(JSON_MEDIA))
            .build()

        val response = client.newCall(request).execute()
        val responseBody = response.body?.string() ?: throw Exception("Empty getCredential response")
        Log.d(TAG, "getCredential response status: ${response.code}")

        if (!response.isSuccessful) {
            throw Exception("getCredential failed: HTTP ${response.code} - ${responseBody.take(500)}")
        }

        val json = JsonParser.parseString(responseBody).asJsonObject
        val status = json.get("status")?.asString
        if (status != "SUCCESS") {
            val errorMsg = json.get("error")?.asString ?: responseBody.take(500)
            throw Exception("getCredential failed: status=$status, error=$errorMsg")
        }

        return json.getAsJsonObject("response").get("signedCredentialResponse").asString
    }

    private fun verifyAndExtractPayload(jwsString: String): String {
        // Parse the JWS
        val signedJWT = SignedJWT.parse(jwsString)

        // Build UIDAI signature RSA public key
        val uidaiSigKey = RSAKey.Builder(
            com.nimbusds.jose.util.Base64URL(UIDAI_SIG_N),
            com.nimbusds.jose.util.Base64URL(UIDAI_SIG_E)
        )
            .keyID(UIDAI_SIG_KID)
            .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .build()

        // Verify signature
        val verifier = RSASSAVerifier(uidaiSigKey)
        if (!signedJWT.verify(verifier)) {
            throw Exception("JWS signature verification failed")
        }
        Log.d(TAG, "JWS signature verified successfully")

        // Extract encrypted_credential_payload from JWT claims
        val claims = signedJWT.jwtClaimsSet
        val encryptedPayload = claims.getStringClaim("encrypted_credential_payload")
            ?: throw Exception("No encrypted_credential_payload in JWS claims")

        return encryptedPayload
    }

    private fun decryptCredentialPayload(jweString: String, privateKey: RSAPrivateKey): String {
        val jweObject = JWEObject.parse(jweString)
        jweObject.decrypt(RSADecrypter(privateKey))
        return jweObject.payload.toString()
    }

    private fun extractMdocFromPayload(decryptedPayload: String): String {
        // The decrypted payload could be:
        // 1. Direct base64-encoded mdoc bytes
        // 2. JSON containing the mdoc
        // 3. CBOR data

        return try {
            // Try parsing as JSON first
            val json = JsonParser.parseString(decryptedPayload).asJsonObject
            // Look for common field names
            json.get("credential")?.asString
                ?: json.get("mdoc")?.asString
                ?: json.get("data")?.asString
                ?: json.get("credential_payload")?.asString
                ?: throw Exception("No known credential field in JSON payload")
        } catch (e: Exception) {
            if (e.message?.contains("No known credential field") == true) throw e
            // Not JSON - treat the payload itself as the base64 mdoc
            // Verify it's valid base64
            try {
                val decoded = Base64.decode(decryptedPayload.trim(), Base64.DEFAULT)
                if (decoded.isNotEmpty()) {
                    decryptedPayload.trim()
                } else {
                    throw Exception("Decoded payload is empty")
                }
            } catch (b64e: Exception) {
                // Could be raw CBOR bytes - encode as base64
                Base64.encodeToString(
                    decryptedPayload.toByteArray(Charsets.ISO_8859_1),
                    Base64.NO_WRAP
                )
            }
        }
    }
}
