package com.example.mdoc.common

import android.util.Log
import kotlinx.io.bytestring.ByteString
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.buildCborArray
import org.multipaz.cbor.buildCborMap
import org.multipaz.mdoc.devicesigned.DeviceAuth
import org.multipaz.mdoc.devicesigned.buildDeviceNamespaces
import org.multipaz.mdoc.issuersigned.IssuerNamespaces
import org.multipaz.mdoc.response.DeviceResponse
import org.multipaz.mdoc.response.DeviceResponseGenerator
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.zkp.ZkDocument
import org.multipaz.mdoc.zkp.ZkSystemSpec
import org.multipaz.mdoc.zkp.longfellow.LongfellowZkSystem
import org.multipaz.cose.CoseSign1
import org.multipaz.request.MdocRequestedClaim
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import java.math.BigInteger
import java.security.PrivateKey
import java.security.Signature
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Generates Zero-Knowledge proofs (Google longfellow-zk, via Multipaz) of selected attributes of
 * the Aadhaar mdoc, so the holder can disclose attribute-wise without revealing the rest of the
 * credential or even the issuer signature.
 *
 * This sits alongside the existing (non-ZK) ISO 18013-5 presentation path — it does not touch it.
 *
 * The longfellow prover proves *exactly* the issuer-signed data elements present in the
 * [MdocDocument] we hand it. So "share attribute-wise" is implemented by filtering the credential's
 * issuer-signed items down to the user's selection before generating the proof, and then picking the
 * bundled circuit whose `num_attributes` equals the number of selected elements.
 *
 * Important limitations (upstream, as of multipaz-longfellow 0.99.0):
 *  - Device binding is NOT proven (`deviceSigned` is empty in the ZK document). The proof attests the
 *    issuer signature + the selected issuer-signed claims only.
 *  - The issuer MSO must be ECDSA P-256 + SHA-256 (Aadhaar qualifies).
 *  - The number of selected attributes must match a bundled circuit's `num_attributes`.
 */
object ZkPresentationManager {

    private const val TAG = "MDOC_ZK"

    /** A single disclosable data element in the credential. */
    data class AttributeRef(val namespace: String, val element: String)

    /** Result of a successful proof generation. */
    data class ZkResult(
        val zkDocument: ZkDocument,
        val systemSpec: ZkSystemSpec,
        val numAttributes: Int,
        val docType: String
    )

    /** Thrown when the selected attribute count has no matching bundled circuit. */
    class NoMatchingCircuitException(
        val requestedCount: Int,
        val availableCounts: List<Int>
    ) : Exception(
        "No longfellow circuit supports $requestedCount attribute(s). " +
            "Bundled circuits support these attribute counts: ${availableCounts.sorted()}."
    )

    /** Thrown when a selected attribute exceeds the longfellow size limits. */
    class AttributeTooLargeException(val offenders: List<String>) : Exception(
        "These attributes are too large for a zero-knowledge proof: ${offenders.joinToString()}."
    )

    // longfellow mdoc circuit limits: CBOR element value <= 64 bytes, whole IssuerSignedItem <= 119 bytes.
    const val MAX_VALUE_BYTES = 64
    const val MAX_ITEM_BYTES = 119

    /** Size check for one attribute against the longfellow limits. */
    data class SizeCheck(
        val ref: AttributeRef,
        val valueBytes: Int,
        val itemBytes: Int
    ) {
        val provable: Boolean get() = valueBytes <= MAX_VALUE_BYTES && itemBytes <= MAX_ITEM_BYTES
    }

    /** Encoded value size and full IssuerSignedItem size for every element in the credential. */
    private fun sizeMap(mdocBytes: ByteArray): Map<AttributeRef, Pair<Int, Int>> {
        val out = mutableMapOf<AttributeRef, Pair<Int, Int>>()
        val nameSpaces = Cbor.decode(mdocBytes)["issuerSigned"]["nameSpaces"]
        for ((nsKey, arr) in nameSpaces.asMap) {
            val ns = nsKey.asTstr
            for (item in arr.asArray) {
                val decoded = item.asTaggedEncodedCbor          // decoded IssuerSignedItem
                val itemBytes = Cbor.encode(decoded).size       // full IssuerSignedItem size
                val element = decoded["elementIdentifier"].asTstr
                val valueBytes = Cbor.encode(decoded["elementValue"]).size
                out[AttributeRef(ns, element)] = valueBytes to itemBytes
            }
        }
        return out
    }

    /** For each requested attribute, whether it fits the longfellow size limits. */
    fun checkSizes(mdocBytes: ByteArray, selected: List<AttributeRef>): List<SizeCheck> {
        val sizes = sizeMap(mdocBytes)
        return selected.map { ref ->
            val (v, i) = sizes[ref] ?: (Int.MAX_VALUE to Int.MAX_VALUE)
            SizeCheck(ref, v, i)
        }
    }

    /**
     * The longfellow ZK system, with the circuits recommended by the Longfellow authors loaded.
     * Construction loads native circuit assets, so it is created once and reused.
     */
    private val zkSystem: LongfellowZkSystem by lazy {
        LongfellowZkSystem().apply { addDefaultCircuits() }
    }

    /** All distinct attribute counts supported by the bundled circuits (for UI guidance). */
    fun availableAttributeCounts(): List<Int> =
        zkSystem.systemSpecs
            .mapNotNull { it.getParam<Long>("num_attributes")?.toInt() }
            .distinct()
            .sorted()

    /**
     * Lists every disclosable (namespace, element) pair in the stored credential.
     *
     * @param mdocBytes the stored credential: a CBOR map containing an `issuerSigned` entry.
     */
    fun listAttributes(mdocBytes: ByteArray): List<AttributeRef> {
        val issuerNamespaces = parseIssuerNamespaces(mdocBytes)
        return issuerNamespaces.data.flatMap { (namespace, elements) ->
            elements.keys.map { AttributeRef(namespace, it) }
        }
    }

    /**
     * Generates a ZK proof disclosing only [selected] attributes.
     *
     * This is CPU-heavy native work (hundreds of ms to ~1s) — call it off the main thread.
     *
     * @param mdocBytes the stored credential bytes (CBOR map with `issuerSigned`).
     * @param docType the credential docType (e.g. the Aadhaar doctype).
     * @param selected the attributes the user chose to disclose.
     * @param encodedSessionTranscript the ISO 18013-5 SessionTranscript bytes for this session
     *        (BLE proximity or OpenID4VP) — must be byte-identical to what the verifier uses.
     * @param devicePrivateKey the MSO's DeviceKey private key (the `mdoc_device_key` from the
     *        KeyStore). The longfellow circuit verifies a real device signature over the session
     *        transcript against the DeviceKey embedded in the MSO — i.e. it proves holder binding.
     * @param timestamp presentation time; fractional seconds are dropped by longfellow.
     */
    @OptIn(ExperimentalTime::class)
    suspend fun generateZkDocument(
        mdocBytes: ByteArray,
        docType: String,
        selected: List<AttributeRef>,
        encodedSessionTranscript: ByteArray,
        devicePrivateKey: PrivateKey,
        timestamp: Instant = Clock.System.now()
    ): ZkResult {
        require(selected.isNotEmpty()) { "Select at least one attribute to disclose." }

        // Reject oversized attributes up front with a clear message (avoids the opaque prover error).
        val tooLarge = checkSizes(mdocBytes, selected).filterNot { it.provable }.map { it.ref.element }
        if (tooLarge.isNotEmpty()) throw AttributeTooLargeException(tooLarge)

        val credential = Cbor.decode(mdocBytes)
        val issuerSigned = credential["issuerSigned"]
        val issuerAuth = issuerSigned["issuerAuth"].asCoseSign1
        val resolvedDocType = credential.getOrNull("docType")?.asTstr ?: docType

        // Build the requested claims and pick the matching circuit by attribute count.
        val requestedClaims = selected.map { ref ->
            MdocRequestedClaim(
                docType = resolvedDocType,
                namespaceName = ref.namespace,
                dataElementName = ref.element,
                intentToRetain = false
            )
        }
        val spec = zkSystem.getMatchingSystemSpec(zkSystem.systemSpecs, requestedClaims)
            ?: throw NoMatchingCircuitException(selected.size, availableAttributeCounts())
        Log.d(TAG, "Selected circuit '${spec.id}' for ${selected.size} attribute(s)")

        // Filter the issuer-signed items down to the user's selection.
        val allIssuerNamespaces = IssuerNamespaces.fromDataItem(issuerSigned["nameSpaces"])
        val filteredIssuerNamespaces = allIssuerNamespaces.filter(requestedClaims)

        val sessionTranscript: DataItem = Cbor.decode(encodedSessionTranscript)

        // The longfellow mdoc circuit verifies the device signature against the MSO's DeviceKey,
        // so we MUST produce a genuine ECDSA deviceSignature over DeviceAuthentication using the
        // real device key. This is what proves holder binding inside the ZK proof.
        val deviceAuth = DeviceAuth.Ecdsa(
            buildDeviceSignature(sessionTranscript, resolvedDocType, devicePrivateKey)
        )

        val document = MdocDocument(
            docType = resolvedDocType,
            issuerAuth = issuerAuth,
            issuerNamespaces = filteredIssuerNamespaces,
            deviceAuth = deviceAuth,
            deviceNamespaces = buildDeviceNamespaces {},
            errors = emptyMap()
        )

        Log.d(TAG, "Generating ZK proof (docType='$resolvedDocType', ${selected.size} attrs)…")
        val zkDocument = zkSystem.generateProof(
            zkSystemSpec = spec,
            document = document,
            sessionTranscript = sessionTranscript,
            timestamp = timestamp
        )
        Log.d(TAG, "ZK proof generated: ${zkDocument.proof.size} bytes")

        return ZkResult(
            zkDocument = zkDocument,
            systemSpec = spec,
            numAttributes = selected.size,
            docType = resolvedDocType
        )
    }

    /**
     * Wraps a [ZkDocument] in a spec-compliant ISO 18013-5 `DeviceResponse` whose `zkDocuments`
     * entry carries the proof (sibling to the normal `documents` entry). The returned bytes are
     * what gets encrypted and sent to the reader over BLE, or carried in an OpenID4VP vp_token.
     */
    fun buildZkDeviceResponse(zkDocument: ZkDocument): ByteArray =
        DeviceResponseGenerator(DeviceResponse.STATUS_OK.toLong())
            .addZkDocument(zkDocument)
            .generate()

    /**
     * Builds a COSE_Sign1 `deviceSignature` over
     * `DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]`
     * (empty device namespaces), signed ES256 with the real device key. The longfellow circuit
     * verifies this against the DeviceKey embedded in the MSO — proving holder binding in ZK.
     */
    private fun buildDeviceSignature(
        sessionTranscript: DataItem,
        docType: String,
        devicePrivateKey: PrivateKey
    ): CoseSign1 {
        val protectedHeaders = Cbor.encode(buildCborMap { put(1L, -7L) }) // {1: -7} = ES256
        val emptyDeviceNameSpaces = Cbor.encode(buildCborMap {})          // {}
        val deviceAuthentication = buildCborArray {
            add("DeviceAuthentication")
            add(sessionTranscript)
            add(docType)
            add(Tagged(Tagged.ENCODED_CBOR, Bstr(emptyDeviceNameSpaces)))
        }
        val deviceAuthBytes = Cbor.encode(
            Tagged(Tagged.ENCODED_CBOR, Bstr(Cbor.encode(deviceAuthentication)))
        )
        // COSE Sig_structure for COSE_Sign1: ["Signature1", protected, external_aad, payload]
        val sigStructure = Cbor.encode(buildCborArray {
            add("Signature1")
            add(Bstr(protectedHeaders))
            add(Bstr(ByteArray(0)))
            add(Bstr(deviceAuthBytes))
        })
        val derSignature = Signature.getInstance("SHA256withECDSA").run {
            initSign(devicePrivateKey)
            update(sigStructure)
            sign()
        }
        val rawSignature = derToRawEcdsa(derSignature, 32) // P-256 → 32-byte r,s
        val coseSign1 = buildCborArray {
            add(Bstr(protectedHeaders))
            add(buildCborMap {})  // empty unprotected headers
            add(Simple.NULL)      // detached payload
            add(Bstr(rawSignature))
        }
        return coseSign1.asCoseSign1
    }

    /** Converts a DER ECDSA signature to fixed-width r||s as COSE expects. */
    private fun derToRawEcdsa(der: ByteArray, coordLen: Int): ByteArray {
        val seq = ASN1Sequence.getInstance(der)
        val r = (seq.getObjectAt(0) as ASN1Integer).positiveValue
        val s = (seq.getObjectAt(1) as ASN1Integer).positiveValue
        return toFixed(r, coordLen) + toFixed(s, coordLen)
    }

    private fun toFixed(v: BigInteger, len: Int): ByteArray {
        val bytes = v.toByteArray()
        val src = if (bytes.size > len) bytes.copyOfRange(bytes.size - len, bytes.size) else bytes
        val out = ByteArray(len)
        System.arraycopy(src, 0, out, len - src.size, src.size)
        return out
    }

    /** Parses the issuer-signed namespaces from the stored credential bytes. */
    private fun parseIssuerNamespaces(mdocBytes: ByteArray): IssuerNamespaces {
        val credential = Cbor.decode(mdocBytes)
        val issuerSigned = credential["issuerSigned"]
        return IssuerNamespaces.fromDataItem(issuerSigned["nameSpaces"])
    }
}
