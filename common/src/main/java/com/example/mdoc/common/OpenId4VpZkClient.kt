@file:OptIn(kotlin.time.ExperimentalTime::class)

package com.example.mdoc.common

import android.net.Uri
import android.util.Base64
import android.util.Log
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.Simple
import org.multipaz.cbor.buildCborArray
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto

/**
 * Minimal OpenID4VP holder client for presenting a longfellow **ZK proof** of Aadhaar attributes to
 * an online verifier (e.g. the OWF Multipaz verifier at verifier.multipaz.org).
 *
 * This deliberately does NOT use Multipaz's full `OpenID4VP.generateResponse` / `PresentmentSource`
 * machinery (which is tied to Multipaz's document-store/SecureArea framework). Instead it reproduces
 * just the two interoperability-critical pieces — the OpenID4VP session transcript and the vp_token
 * shape — and reuses [ZkPresentationManager] for the proof.
 *
 * Security (high-assurance profile):
 *  - The request is a signed ES256 JWS carrying the verifier certificate in `x5c`. The holder
 *    verifies the signature and **pins** that certificate to the bundled trusted verifier cert
 *    (two-layer check) before acting on the request; an unsigned request from a pinned verifier is
 *    refused.
 *  - Both `direct_post` (unencrypted) and `direct_post.jwt` (encrypted response, JARM) are supported.
 *    For `direct_post.jwt` the response `{ vp_token }` is encrypted as a JWE (ECDH-ES / A256GCM) to
 *    the verifier's ephemeral key, and that key's thumbprint is folded into the session transcript.
 *  - OpenID4VP 1.0 handover (`OpenID4VPHandover`).
 * The W3C Digital Credentials API path is not implemented.
 */
object OpenId4VpZkClient {

    private const val TAG = "MDOC_ZK_OID4VP"

    private val http = OkHttpClient()

    /** Details parsed from the verifier's authorization request, for display + the response step. */
    data class RequestInfo(
        val clientId: String,
        val nonce: String,
        val responseUri: String,
        val responseMode: String,
        val credentialId: String,
        val docType: String?,
        val requestedClaims: List<ZkPresentationManager.AttributeRef>,
        val zkRequested: Boolean,
        val state: String?,
        /** The verifier's response-encryption public JWK (from client_metadata) for direct_post.jwt; null if unencrypted. */
        val encJwkJson: String? = null
    )

    /** Outcome of submitting the response. */
    data class SubmitResult(
        val httpCode: Int,
        val redirectUri: String?,
        val body: String
    )

    /**
     * Resolves the verifier QR/deeplink to its authorization request and parses what's being asked.
     * Networked — call off the main thread (it already hops to [Dispatchers.IO]).
     *
     * @param qrText the scanned QR contents, e.g. `openid4vp://?request_uri=...&client_id=...`.
     */
    suspend fun fetchRequest(
        qrText: String,
        trustedVerifierCert: X509Certificate? = null
    ): RequestInfo = withContext(Dispatchers.IO) {
        Log.d(TAG, "Scanned QR (${qrText.length} chars): ${qrText.take(600)}")
        val uri = Uri.parse(qrText.trim())
        Log.d(TAG, "QR parsed: scheme=${uri.scheme} authority=${uri.authority} " +
            "path=${uri.path} queryParams=${runCatching { uri.queryParameterNames }.getOrNull()}")
        val inlineRequest = uri.getQueryParameter("request")
        val requestUri = uri.getQueryParameter("request_uri")
        val outerClientId = uri.getQueryParameter("client_id")

        val requestJwt = when {
            inlineRequest != null -> inlineRequest
            requestUri != null -> {
                val method = uri.getQueryParameter("request_uri_method")?.lowercase() ?: "get"
                Log.d(TAG, "Fetching request_uri ($method): $requestUri")
                val reqBuilder = Request.Builder().url(requestUri)
                if (method == "post") reqBuilder.post(FormBody.Builder().build())
                http.newCall(reqBuilder.build()).execute().use { resp ->
                    val body = resp.body?.string().orEmpty()
                    check(resp.isSuccessful) { "request_uri returned HTTP ${resp.code}" }
                    body
                }
            }
            else -> throw IllegalArgumentException("QR has neither 'request' nor 'request_uri'")
        }

        parseRequestJwt(requestJwt, outerClientId, trustedVerifierCert)
    }

    /**
     * Parses the OpenID4VP request object (a JWT) into a [RequestInfo]. When [trustedVerifierCert] is
     * provided, the request MUST be a signed JWS: its signature is verified against the certificate in
     * the `x5c` header, and that certificate is pinned (must byte-match the trusted verifier certificate).
     */
    private fun parseRequestJwt(
        requestJwt: String, outerClientId: String?, trustedVerifierCert: X509Certificate?
    ): RequestInfo {
        val json = if (trustedVerifierCert != null) {
            val signed = SignedJWT.parse(requestJwt.trim())
            val chain = signed.header.x509CertChain
                ?: error("Request is not signed (no x5c) — refusing an unsigned request from a pinned verifier.")
            val leaf = CertificateFactory.getInstance("X.509")
                .generateCertificate(chain[0].decode().inputStream()) as X509Certificate
            // (1) signature valid against the key in the request's certificate
            require(signed.verify(ECDSAVerifier(leaf.publicKey as ECPublicKey))) {
                "Request signature is invalid."
            }
            // (2) that certificate is the trusted verifier (pin: byte-identical to the bundled cert)
            require(leaf.encoded.contentEquals(trustedVerifierCert.encoded)) {
                "Request signer certificate is not the trusted verifier (certificate pin mismatch)."
            }
            Log.d(TAG, "Request signature verified and verifier certificate pinned OK")
            JSONObject(signed.jwtClaimsSet.toString())
        } else {
            JSONObject(JWTParser.parse(requestJwt.trim()).jwtClaimsSet.toString())
        }

        val nonce = json.optString("nonce").ifEmpty { error("request missing 'nonce'") }
        val clientId = json.optString("client_id").ifEmpty { outerClientId.orEmpty() }
        val responseMode = json.optString("response_mode", "direct_post")
        val responseUri = json.optString("response_uri")
            .ifEmpty { json.optString("redirect_uri") }
        require(responseUri.isNotEmpty()) { "request missing 'response_uri'" }
        val state = json.optString("state").ifEmpty { null }

        // DCQL: locate the (first) mdoc / mdoc-zk credential query.
        val dcql = json.optJSONObject("dcql_query")
            ?: error("request has no 'dcql_query' (this client only supports DCQL requests)")
        val credentials = dcql.optJSONArray("credentials") ?: JSONArray()
        var credentialId = ""
        var docType: String? = null
        var zkRequested = false
        val claimsOut = mutableListOf<ZkPresentationManager.AttributeRef>()

        for (i in 0 until credentials.length()) {
            val cred = credentials.getJSONObject(i)
            val format = cred.optString("format")
            if (format != "mso_mdoc" && format != "mso_mdoc_zk") continue
            credentialId = cred.optString("id", "cred1")
            zkRequested = format == "mso_mdoc_zk" || cred.optJSONObject("meta")?.has("zk_system_type") == true
            docType = cred.optJSONObject("meta")?.optString("doctype_value")?.ifEmpty { null }
            val claimsArr = cred.optJSONArray("claims") ?: JSONArray()
            for (j in 0 until claimsArr.length()) {
                val c = claimsArr.getJSONObject(j)
                val ref = claimToAttributeRef(c) ?: continue
                claimsOut.add(ref)
            }
            break
        }
        require(credentialId.isNotEmpty()) { "no mso_mdoc / mso_mdoc_zk credential query found" }

        Log.d(TAG, "Parsed request: clientId=$clientId zk=$zkRequested docType=$docType claims=${claimsOut.size} mode=$responseMode")
        val encJwkJson = json.optJSONObject("client_metadata")
            ?.optJSONObject("jwks")?.optJSONArray("keys")?.optJSONObject(0)?.toString()
        return RequestInfo(
            clientId = clientId,
            nonce = nonce,
            responseUri = responseUri,
            responseMode = responseMode,
            credentialId = credentialId,
            docType = docType,
            requestedClaims = claimsOut,
            zkRequested = zkRequested,
            state = state,
            encJwkJson = encJwkJson
        )
    }

    /** Extracts (namespace, element) from a DCQL mdoc claim, handling 1.0 `path` and legacy forms. */
    private fun claimToAttributeRef(claim: JSONObject): ZkPresentationManager.AttributeRef? {
        val path = claim.optJSONArray("path")
        if (path != null && path.length() >= 2) {
            return ZkPresentationManager.AttributeRef(path.getString(0), path.getString(1))
        }
        val ns = claim.optString("namespace")
        val name = claim.optString("claim_name")
        if (ns.isNotEmpty() && name.isNotEmpty()) {
            return ZkPresentationManager.AttributeRef(ns, name)
        }
        return null
    }

    /**
     * Generates a ZK proof disclosing [selected] attributes and posts it to the verifier.
     *
     * @param req the parsed request from [fetchRequest].
     * @param mdocBytes stored credential bytes.
     * @param docType credential docType (falls back to the one in the request).
     * @param selected the attributes to disclose in the proof.
     */
    suspend fun presentZk(
        req: RequestInfo,
        mdocBytes: ByteArray,
        docType: String,
        selected: List<ZkPresentationManager.AttributeRef>,
        devicePrivateKey: java.security.PrivateKey
    ): SubmitResult = withContext(Dispatchers.IO) {
        require(req.responseMode == "direct_post" || req.responseMode == "direct_post.jwt") {
            "Unsupported response_mode '${req.responseMode}'."
        }

        // For an encrypted (direct_post.jwt) response, bind the verifier's encryption-key thumbprint
        // (RFC 7638) into the session transcript — byte-identical to what the verifier computes.
        val encJwk: ECKey? = req.encJwkJson?.let { ECKey.parse(it) }
        val readerThumbprint: ByteArray? = encJwk?.computeThumbprint()?.decode()
        val sessionTranscript = computeSessionTranscript(
            clientId = req.clientId,
            nonce = req.nonce,
            responseUri = req.responseUri,
            readerJwkThumbprint = readerThumbprint
        )

        val zkResult = ZkPresentationManager.generateZkDocument(
            mdocBytes = mdocBytes,
            docType = req.docType ?: docType,
            selected = selected,
            encodedSessionTranscript = sessionTranscript,
            devicePrivateKey = devicePrivateKey
        )
        val deviceResponse = ZkPresentationManager.buildZkDeviceResponse(zkResult.zkDocument)
        val deviceResponseB64Url = Base64.encodeToString(
            deviceResponse, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )

        // vp_token is a JSON object keyed by the DCQL credential id; value is the base64url DeviceResponse.
        val vpToken = JSONObject().apply { put(req.credentialId, deviceResponseB64Url) }

        val formBuilder = FormBody.Builder()
        if (req.responseMode == "direct_post.jwt" && encJwk != null) {
            // Encrypt { vp_token, state? } as a JWE (ECDH-ES / A256GCM) to the verifier's key.
            val responseJson = JSONObject().put("vp_token", vpToken)
            req.state?.let { responseJson.put("state", it) }
            val header = JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                .keyID(encJwk.keyID).build()
            val jwe = JWEObject(header, Payload(responseJson.toString()))
            jwe.encrypt(ECDHEncrypter(encJwk))
            formBuilder.add("response", jwe.serialize())
            Log.d(TAG, "POSTing encrypted direct_post.jwt response to ${req.responseUri}")
        } else {
            formBuilder.add("vp_token", vpToken.toString())
            req.state?.let { formBuilder.add("state", it) }
            Log.d(TAG, "POSTing vp_token (${deviceResponseB64Url.length} chars) to ${req.responseUri}")
        }

        http.newCall(Request.Builder().url(req.responseUri).post(formBuilder.build()).build())
            .execute().use { resp ->
                val body = resp.body?.string().orEmpty()
                val redirect = runCatching { JSONObject(body).optString("redirect_uri").ifEmpty { null } }
                    .getOrNull()
                Log.d(TAG, "Verifier responded HTTP ${resp.code}; redirect=$redirect")
                SubmitResult(resp.code, redirect, body)
            }
    }

    /**
     * Builds the ISO 18013-7 / OpenID4VP session transcript:
     * `[ null, null, [ "OpenID4VPHandover", SHA256( [clientId, nonce, thumbprint|null, responseUri] ) ] ]`.
     */
    private suspend fun computeSessionTranscript(
        clientId: String,
        nonce: String,
        responseUri: String,
        readerJwkThumbprint: ByteArray?
    ): ByteArray {
        val handoverInfo = Cbor.encode(
            buildCborArray {
                add(clientId)
                add(nonce)
                if (readerJwkThumbprint == null) add(Simple.NULL) else add(Bstr(readerJwkThumbprint))
                add(responseUri)
            }
        )
        val handoverInfoDigest = Crypto.digest(Algorithm.SHA256, handoverInfo)
        return Cbor.encode(
            buildCborArray {
                add(Simple.NULL) // DeviceEngagementBytes
                add(Simple.NULL) // EReaderKeyBytes
                add(
                    buildCborArray {
                        add("OpenID4VPHandover")
                        add(handoverInfoDigest)
                    }
                )
            }
        )
    }
}
