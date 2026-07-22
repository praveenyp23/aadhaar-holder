package com.example.mdoc.common

import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jwt.SignedJWT
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey

/**
 * Holder-side authentication of a verifier's OpenID4VP Authorization Request.
 *
 * The verifier signs the request as an ES256 JWS carrying its certificate in the `x5c` header. The
 * holder performs a two-layer check:
 *  1. **Signature** — the JWS verifies against the public key in the leaf `x5c` certificate, proving
 *     the request was produced by the holder of that certificate's private key.
 *  2. **Pinning** — that leaf certificate is byte-identical to the verifier certificate bundled in
 *     this app, proving it is the specific verifier we trust (not merely any well-formed signer).
 *
 * Only the request payload (the OpenID4VP claims JSON) is returned, and only when both checks pass;
 * any failure throws. This is used identically by the online (relay) and BLE/NFC transports.
 */
object VerifierRequestAuth {

    /** A signed request is a compact JWS; it always starts with the base64url of `{"alg":...`. */
    fun looksSigned(s: String): Boolean = s.trimStart().startsWith("eyJ")

    /**
     * Verifies the signed request and pins its certificate against [trustedCert], returning the
     * request payload (claims JSON) exactly as it was signed. Throws on any signature/pin failure.
     */
    fun verifyAndExtractClaims(requestJwt: String, trustedCert: X509Certificate): String {
        val signed = SignedJWT.parse(requestJwt)
        val chain = signed.header.x509CertChain
        require(!chain.isNullOrEmpty()) { "request JWT has no x5c certificate" }
        val leaf = CertificateFactory.getInstance("X.509")
            .generateCertificate(chain[0].decode().inputStream()) as X509Certificate
        require(signed.verify(ECDSAVerifier(leaf.publicKey as ECPublicKey))) {
            "request signature did not verify"
        }
        require(leaf.encoded.contentEquals(trustedCert.encoded)) {
            "verifier certificate is not the trusted one (pin mismatch)"
        }
        // The exact payload string that was signed (preserves the dcql_query structure verbatim).
        return signed.payload.toString()
    }
}
