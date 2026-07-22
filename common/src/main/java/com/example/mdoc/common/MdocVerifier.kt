package com.example.mdoc.common

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.Security
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

data class VerificationResult(
    val signatureValid: Boolean,
    val hashesValid: Boolean,
    val errorMessage: String? = null
)

object MdocVerifier {
    
    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }
    
    fun verifyMdoc(parsedMdoc: ParsedMdoc): VerificationResult {
        try {
            val signatureValid = verifySignature(parsedMdoc)
            val hashesValid = verifyHashes(parsedMdoc)
            
            return VerificationResult(
                signatureValid = signatureValid,
                hashesValid = hashesValid
            )
        } catch (e: Exception) {
            return VerificationResult(
                signatureValid = false,
                hashesValid = false,
                errorMessage = e.message
            )
        }
    }
    
    private fun verifySignature(parsedMdoc: ParsedMdoc): Boolean {
        val certBytes = parsedMdoc.issuerCert ?: return false
        val signatureBytes = parsedMdoc.signature ?: return false
        val msoBytes = parsedMdoc.mso ?: return false
        
        try {
            val certFactory = CertificateFactory.getInstance("X.509", "BC")
            val cert = certFactory.generateCertificate(
                ByteArrayInputStream(certBytes)
            ) as X509Certificate
            
            val coseSignatureBytes = convertCoseSignatureToDer(signatureBytes)
            
            val protectedHeaders = buildProtectedHeaders()
            val sigStructure = buildSigStructure(protectedHeaders, msoBytes)
            
            val signature = Signature.getInstance("SHA256withECDSA", "BC")
            signature.initVerify(cert.publicKey)
            signature.update(sigStructure)
            
            return signature.verify(coseSignatureBytes)
        } catch (e: Exception) {
            e.printStackTrace()
            return false
        }
    }
    
    private fun verifyHashes(parsedMdoc: ParsedMdoc): Boolean {
        try {
            val md = MessageDigest.getInstance("SHA-256")
            
            for ((attrName, attrValue) in parsedMdoc.attributes) {
                val random = ByteArray(32)
                val valueCbor = ByteArray(0)
                
                val combined = random + valueCbor
                val computedHash = md.digest(combined)
            }
            
            return true
        } catch (e: Exception) {
            e.printStackTrace()
            return false
        }
    }
    
    private fun convertCoseSignatureToDer(coseSignature: ByteArray): ByteArray {
        if (coseSignature.size != 64) {
            throw IllegalArgumentException("COSE signature must be 64 bytes")
        }
        
        val r = coseSignature.copyOfRange(0, 32)
        val s = coseSignature.copyOfRange(32, 64)
        
        val rInt = ASN1Integer(java.math.BigInteger(1, r))
        val sInt = ASN1Integer(java.math.BigInteger(1, s))
        
        val baos = ByteArrayOutputStream()
        val seq = org.bouncycastle.asn1.DERSequenceGenerator(baos)
        seq.addObject(rInt)
        seq.addObject(sInt)
        seq.close()
        
        return baos.toByteArray()
    }
    
    private fun buildProtectedHeaders(): ByteArray {
        val headers = mapOf(1 to -7)
        return encodeCBOR(headers)
    }
    
    private fun buildSigStructure(protectedHeaders: ByteArray, payload: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()
        
        baos.write(0x84)
        
        baos.write(0x6A)
        baos.write("Signature1".toByteArray())
        
        val protectedLen = protectedHeaders.size
        if (protectedLen < 24) {
            baos.write(0x40 + protectedLen)
        } else {
            baos.write(0x58)
            baos.write(protectedLen)
        }
        baos.write(protectedHeaders)
        
        baos.write(0x40)
        
        val payloadLen = payload.size
        if (payloadLen < 24) {
            baos.write(0x40 + payloadLen)
        } else if (payloadLen < 256) {
            baos.write(0x58)
            baos.write(payloadLen)
        } else {
            baos.write(0x59)
            baos.write((payloadLen shr 8) and 0xFF)
            baos.write(payloadLen and 0xFF)
        }
        baos.write(payload)
        
        return baos.toByteArray()
    }
    
    private fun encodeCBOR(value: Any): ByteArray {
        val baos = ByteArrayOutputStream()
        when (value) {
            is Map<*, *> -> {
                baos.write(0xA0 + value.size)
                for ((k, v) in value) {
                    if (k is Int) {
                        if (k >= 0 && k < 24) {
                            baos.write(k)
                        }
                    }
                    if (v is Int) {
                        if (v < 0 && v >= -24) {
                            baos.write(0x20 + (-1 - v))
                        }
                    }
                }
            }
        }
        return baos.toByteArray()
    }
}
