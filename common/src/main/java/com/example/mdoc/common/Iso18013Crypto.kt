package com.example.mdoc.common

import android.util.Base64
import android.util.Log
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.*
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.Array as CborArray
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ISO/IEC 18013-5:2021 cryptographic operations: ECDH, session encryption,
 * CBOR encoding for Device Engagement, DeviceResponse, and session management.
 */
object Iso18013Crypto {
    private const val TAG = "Iso18013Crypto"

    // ── Key Generation ────────────────────────────────────────────────────

    fun generateEphemeralKeyPair(): KeyPair {
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        return gen.generateKeyPair()
    }

    // ── CBOR helpers ──────────────────────────────────────────────────────

    fun cborEncode(item: DataItem): ByteArray {
        val out = ByteArrayOutputStream()
        CborEncoder(out).encode(item)
        return out.toByteArray()
    }

    fun cborDecode(data: ByteArray): List<DataItem> =
        CborDecoder(ByteArrayInputStream(data)).decode()

    private fun bigIntTo32Bytes(bi: BigInteger): ByteArray {
        val raw = bi.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size > 32  -> raw.copyOfRange(raw.size - 32, raw.size)
            else           -> ByteArray(32 - raw.size) + raw
        }
    }

    // ── COSE_Key encoding / decoding ──────────────────────────────────────

    fun encodeEcPublicKeyAsCoseKey(pub: ECPublicKey): ByteArray {
        val m = CborMap()
        m.put(UnsignedInteger(1), UnsignedInteger(2))                       // kty: EC2
        m.put(NegativeInteger(-1L), UnsignedInteger(1))                     // crv: P-256
        m.put(NegativeInteger(-2L), ByteString(bigIntTo32Bytes(pub.w.affineX))) // x
        m.put(NegativeInteger(-3L), ByteString(bigIntTo32Bytes(pub.w.affineY))) // y
        return cborEncode(m)
    }

    fun decodeCoseKeyToEcPublicKey(item: DataItem): ECPublicKey {
        val m = item as CborMap
        val x = BigInteger(1, (m.get(NegativeInteger(-2L)) as ByteString).bytes)
        val y = BigInteger(1, (m.get(NegativeInteger(-3L)) as ByteString).bytes)
        // Use standard JCA to reconstruct EC public key (avoids Android BC provider conflicts)
        val kf = KeyFactory.getInstance("EC")
        // Generate a temp key pair to get the ECParameterSpec for P-256
        val tempGen = KeyPairGenerator.getInstance("EC")
        tempGen.initialize(ECGenParameterSpec("secp256r1"))
        val tempPub = tempGen.generateKeyPair().public as ECPublicKey
        val ecParams: ECParameterSpec = tempPub.params
        val point = ECPoint(x, y)
        return kf.generatePublic(ECPublicKeySpec(point, ecParams)) as ECPublicKey
    }

    // ── Device Engagement ─────────────────────────────────────────────────

    fun buildDeviceEngagement(eDeviceKeyPub: ECPublicKey, bleUuid: UUID): ByteArray {
        val de = CborMap()

        // version
        de.put(UnsignedInteger(0), UnicodeString("1.0"))

        // security: [cipherSuiteId, eDeviceKeyBytes]
        val security = CborArray()
        security.add(UnsignedInteger(1))  // cipher suite 1
        val coseKeyBytes = encodeEcPublicKeyAsCoseKey(eDeviceKeyPub)
        val taggedKey = ByteString(coseKeyBytes)
        taggedKey.tag = Tag(24)
        security.add(taggedKey)
        de.put(UnsignedInteger(1), security)

        // deviceRetrievalMethods: [ BLE method ]
        val methods = CborArray()
        val ble = CborArray()
        ble.add(UnsignedInteger(2))   // type = BLE
        ble.add(UnsignedInteger(1))   // version 1
        val opts = CborMap()
        opts.put(UnsignedInteger(0), SimpleValue.TRUE)               // key 0: supportsPeripheralServerMode = true
        opts.put(UnsignedInteger(1), SimpleValue.FALSE)              // key 1: supportsCentralClientMode = false
        opts.put(UnsignedInteger(10), ByteString(uuidToBytes(bleUuid)))  // key 10: peripheralServerModeUuid
        ble.add(opts)
        methods.add(ble)
        de.put(UnsignedInteger(2), methods)

        return cborEncode(de)
    }

    fun uuidToBytes(uuid: UUID): ByteArray {
        val bb = java.nio.ByteBuffer.allocate(16)
        bb.putLong(uuid.mostSignificantBits)
        bb.putLong(uuid.leastSignificantBits)
        return bb.array()
    }

    // ── QR code URI ───────────────────────────────────────────────────────

    fun buildQrEngagementUri(encodedDeviceEngagement: ByteArray): String {
        val b64url = Base64.encodeToString(
            encodedDeviceEngagement,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )
        return "mdoc:$b64url"
    }

    // ── Session Transcript ────────────────────────────────────────────────

    /**
     * @param handover  null → QR engagement;  CBOR array → NFC handover
     */
    fun buildSessionTranscript(
        encodedDeviceEngagement: ByteArray,
        encodedEReaderKey: ByteArray,
        handover: DataItem?
    ): ByteArray {
        val arr = CborArray()
        val de = ByteString(encodedDeviceEngagement); de.tag = Tag(24)
        arr.add(de)
        val er = ByteString(encodedEReaderKey); er.tag = Tag(24)
        arr.add(er)
        arr.add(handover ?: SimpleValue.NULL)
        return cborEncode(arr)
    }

    // ── Session Encryption ────────────────────────────────────────────────

    fun performEcdh(priv: PrivateKey, pub: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(priv)
        ka.doPhase(pub, true)
        return ka.generateSecret()
    }

    private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, len: Int): ByteArray {
        val gen = HKDFBytesGenerator(SHA256Digest())
        gen.init(HKDFParameters(ikm, salt, info))
        val out = ByteArray(len)
        gen.generateBytes(out, 0, len)
        return out
    }

    data class SessionKeys(val skDevice: ByteArray, val skReader: ByteArray, val eMacKey: ByteArray)

    fun deriveSessionKeys(sharedSecret: ByteArray, encodedSessionTranscript: ByteArray): SessionKeys {
        // ISO 18013-5: salt = SHA-256( CBOR_encode( Tag(24, bstr(encodedSessionTranscript)) ) )
        val tagged = ByteString(encodedSessionTranscript)
        tagged.tag = Tag(24)
        val sessionTranscriptBytes = cborEncode(tagged)
        val salt = MessageDigest.getInstance("SHA-256").digest(sessionTranscriptBytes)
        return SessionKeys(
            skDevice = hkdfSha256(sharedSecret, salt, "SKDevice".toByteArray(), 32),
            skReader = hkdfSha256(sharedSecret, salt, "SKReader".toByteArray(), 32),
            eMacKey  = hkdfSha256(sharedSecret, salt, "EMacKey".toByteArray(), 32)
        )
    }

    /**
     * 12-byte IV per ISO 18013-5 §9.1.1.5:
     *  bytes 0-3: 0x00000000
     *  bytes 4-7: 0x00000001 for device→reader, 0x00000000 for reader→device
     *  bytes 8-11: message counter (big-endian)
     */
    fun buildIv(counter: Int, deviceToReader: Boolean): ByteArray {
        val iv = ByteArray(12)
        if (deviceToReader) iv[7] = 0x01  // bytes 4-7 = 0x00000001
        // bytes 8-11 = counter big-endian
        iv[8]  = ((counter shr 24) and 0xFF).toByte()
        iv[9]  = ((counter shr 16) and 0xFF).toByte()
        iv[10] = ((counter shr 8) and 0xFF).toByte()
        iv[11] = (counter and 0xFF).toByte()
        return iv
    }

    fun aesGcmEncrypt(key: ByteArray, iv: ByteArray, plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return c.doFinal(plain)
    }

    fun aesGcmDecrypt(key: ByteArray, iv: ByteArray, cipher: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return c.doFinal(cipher)
    }

    // ── Parse first SessionEstablishment message from reader ──────────

    data class SessionEstablishment(val eReaderKeyEncoded: ByteArray, val eReaderKeyPublic: ECPublicKey, val encryptedData: ByteArray)

    fun parseSessionEstablishment(raw: ByteArray): SessionEstablishment {
        val items = cborDecode(raw)
        val m = items[0] as CborMap
        val eReaderKeyTagged = m.get(UnicodeString("eReaderKey"))

        // Extract eReaderKey bytes preserving original CBOR encoding to avoid
        // map key reordering during decode→re-encode (which would change
        // SessionTranscript hash and break EMacKey derivation).
        val eReaderKeyBytes: ByteArray
        val pub: ECPublicKey
        when (eReaderKeyTagged) {
            is ByteString -> {
                // Tagged(24, bstr) — inner bytes are the COSE_Key CBOR
                eReaderKeyBytes = eReaderKeyTagged.bytes
                pub = decodeCoseKeyToEcPublicKey(cborDecode(eReaderKeyBytes)[0])
            }
            is CborMap -> {
                // Inline COSE_Key map — extract original bytes from raw CBOR
                // to preserve exact encoding (key ordering, int sizes, etc.)
                eReaderKeyBytes = extractCborValueBytes(raw, "eReaderKey")
                    ?: cborEncode(eReaderKeyTagged)  // fallback to re-encode
                pub = decodeCoseKeyToEcPublicKey(eReaderKeyTagged)
            }
            else -> throw IllegalArgumentException("Unexpected eReaderKey type: ${eReaderKeyTagged?.javaClass}")
        }

        Log.d(TAG, "eReaderKey raw bytes (${eReaderKeyBytes.size}): ${eReaderKeyBytes.joinToString("") { "%02x".format(it) }}")
        val data = (m.get(UnicodeString("data")) as ByteString).bytes
        return SessionEstablishment(eReaderKeyBytes, pub, data)
    }

    /**
     * Extract the raw CBOR bytes of a text-keyed value from a CBOR map,
     * preserving the original encoding exactly as the sender wrote it.
     */
    private fun extractCborValueBytes(rawCbor: ByteArray, keyName: String): ByteArray? {
        // Encode the key to search for: CBOR text string "eReaderKey"
        val keyBytes = cborEncode(UnicodeString(keyName))
        val pos = findBytes(rawCbor, keyBytes)
        if (pos < 0) return null
        // The value starts right after the key
        val valueStart = pos + keyBytes.size
        if (valueStart >= rawCbor.size) return null
        // Decode one CBOR item starting at valueStart to determine its length
        try {
            val valueItem = CborDecoder(ByteArrayInputStream(rawCbor, valueStart, rawCbor.size - valueStart)).decode()[0]
            val reEncoded = cborEncode(valueItem)
            // The original bytes have the same logical content; measure
            // the actual encoded length from the raw stream
            // Use a counting decoder approach: the raw value occupies from valueStart
            // to wherever the next sibling key/value or end of map is
            // Simpler: since CBOR is self-delimiting, we can determine the exact byte
            // span by using a fresh CborDecoder with offset tracking
            val stream = ByteArrayInputStream(rawCbor, valueStart, rawCbor.size - valueStart)
            val decoder = CborDecoder(stream)
            decoder.decode() // consumes exactly one item
            val bytesConsumed = (rawCbor.size - valueStart) - stream.available()
            return rawCbor.copyOfRange(valueStart, valueStart + bytesConsumed)
        } catch (e: Exception) {
            Log.w(TAG, "extractCborValueBytes failed for key '$keyName'", e)
            return null
        }
    }

    // ── Parse subsequent SessionData messages ─────────────────────────

    data class SessionData(val encryptedData: ByteArray?, val status: Long?)

    fun parseSessionData(raw: ByteArray): SessionData {
        val m = cborDecode(raw)[0] as CborMap
        val dataItem = m.get(UnicodeString("data"))
        val data = if (dataItem is ByteString) dataItem.bytes else null
        val statusItem = m.get(UnicodeString("status"))
        val status = when (statusItem) {
            is UnsignedInteger -> statusItem.value.toLong()
            else -> null
        }
        return SessionData(data, status)
    }

    /** Encode a holder → reader session data message. */
    fun encodeSessionData(encryptedData: ByteArray?, status: Long? = null): ByteArray {
        val m = CborMap()
        if (encryptedData != null) m.put(UnicodeString("data"), ByteString(encryptedData))
        if (status != null) m.put(UnicodeString("status"), UnsignedInteger(status))
        return cborEncode(m)
    }

    // ── DeviceRequest parser ──────────────────────────────────────────

    /**
     * Manually build the CBOR encoding of:
     *   DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]
     * by concatenating raw CBOR bytes, avoiding cbor-java's CborMap key reordering.
     * This ensures the SessionTranscript bytes in DeviceAuthentication are identical
     * to what the reader computes.
     */
    private fun buildDeviceAuthenticationManual(
        encodedSessionTranscript: ByteArray,
        docType: String,
        encodedDeviceNameSpaces: ByteArray
    ): ByteArray {
        val out = ByteArrayOutputStream()
        // CBOR array header: 4 items = 0x84
        out.write(0x84)
        // [0] text string "DeviceAuthentication"
        out.write(cborEncode(UnicodeString("DeviceAuthentication")))
        // [1] SessionTranscript - embed raw CBOR bytes directly (already a valid CBOR array)
        out.write(encodedSessionTranscript)
        // [2] docType text string
        out.write(cborEncode(UnicodeString(docType)))
        // [3] DeviceNameSpacesBytes = Tag(24, bstr(encodedDeviceNameSpaces))
        val taggedNsBytes = ByteString(encodedDeviceNameSpaces)
        taggedNsBytes.tag = Tag(24)
        out.write(cborEncode(taggedNsBytes))
        return out.toByteArray()
    }

    data class DocRequest(val docType: String, val requestedNamespaces: Map<String, List<String>>)

    /**
     * Parse a DeviceRequest to extract all requested docTypes and their namespaces/elements.
     * DeviceRequest = { "version": "1.0", "docRequests": [ { "itemsRequest": Tag(24, bstr({...})), ... } ] }
     */
    fun parseDeviceRequest(encodedDeviceRequest: ByteArray): List<DocRequest> {
        val result = mutableListOf<DocRequest>()
        try {
            val dr = cborDecode(encodedDeviceRequest)[0] as CborMap
            val docRequests = dr.get(UnicodeString("docRequests")) as? CborArray ?: return result
            for (item in docRequests.dataItems) {
                val docReq = item as? CborMap ?: continue
                val itemsRequestTagged = docReq.get(UnicodeString("itemsRequest"))
                val itemsRequestBytes: ByteArray = when (itemsRequestTagged) {
                    is ByteString -> itemsRequestTagged.bytes
                    else -> continue
                }
                val itemsRequest = cborDecode(itemsRequestBytes)[0] as? CborMap ?: continue
                val docType = (itemsRequest.get(UnicodeString("docType")) as? UnicodeString)?.string ?: continue
                val nameSpacesMap = itemsRequest.get(UnicodeString("nameSpaces")) as? CborMap
                val nsMap = mutableMapOf<String, List<String>>()
                nameSpacesMap?.keys?.forEach { nsKey ->
                    val nsName = (nsKey as? UnicodeString)?.string ?: return@forEach
                    val elementsMap = nameSpacesMap.get(nsKey) as? CborMap
                    val elements = mutableListOf<String>()
                    elementsMap?.keys?.forEach { elemKey ->
                        (elemKey as? UnicodeString)?.string?.let { elements.add(it) }
                    }
                    nsMap[nsName] = elements
                }
                result.add(DocRequest(docType, nsMap))
                Log.d(TAG, "parseDeviceRequest: docType='$docType' namespaces=${nsMap.keys}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "parseDeviceRequest failed", e)
        }
        return result
    }

    // ── DeviceResponse builder ────────────────────────────────────────

    private fun findBytes(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }

    /**
     * Wraps the existing mdoc issuerSigned in a proper DeviceResponse
     * with deviceMac computed using the session's EMacKey.
     */
    /**
     * Build DeviceResponse, filtering issuerSigned->nameSpaces to only requested namespaces/elements.
     * @param requestedNamespaces Map<namespace, List<element>>
     */
    fun buildDeviceResponse(
        mdocBytes: ByteArray,
        docType: String,
        encodedSessionTranscript: ByteArray,
        eMacKey: ByteArray,
        requestedNamespaces: Map<String, List<String>> = emptyMap()
    ): ByteArray {
        Log.d(TAG, "═══════════════════════════════════════════════════════")
        Log.d(TAG, "buildDeviceResponse START")
        Log.d(TAG, "═══════════════════════════════════════════════════════")
        Log.d(TAG, "INPUT: docType='$docType'")
        Log.d(TAG, "INPUT: requestedNamespaces=$requestedNamespaces")
        Log.d(TAG, "INPUT: encodedSessionTranscript (${encodedSessionTranscript.size} bytes):")
        Log.d(TAG, "  HEX: ${encodedSessionTranscript.joinToString("") { "%02x".format(it) }}")
        Log.d(TAG, "INPUT: eMacKey (${eMacKey.size} bytes): ${eMacKey.joinToString("") { "%02x".format(it) }}")
        
        val mdocMap = cborDecode(mdocBytes)[0] as CborMap
        val issuerSigned = mdocMap.get(UnicodeString("issuerSigned")) as? CborMap
            ?: throw IllegalStateException("mdoc has no issuerSigned")

        // Compare original issuerAuth bytes with re-encoded to detect cbor-java mutations
        val origIssuerAuth = issuerSigned.get(UnicodeString("issuerAuth"))
        val origIssuerAuthBytes = cborEncode(origIssuerAuth!!)
        Log.d(TAG, "buildDeviceResponse: origIssuerAuth class=${origIssuerAuth.javaClass.simpleName} tag=${origIssuerAuth.tag}")
        Log.d(TAG, "buildDeviceResponse: origIssuerAuth re-encoded ${origIssuerAuthBytes.size} bytes")
        Log.d(TAG, "buildDeviceResponse: origIssuerAuth HEX (first 80): ${origIssuerAuthBytes.take(80).joinToString("") { "%02x".format(it) }}")

        val origNameSpaces = issuerSigned.get(UnicodeString("nameSpaces")) as? CborMap
            ?: throw IllegalStateException("issuerSigned has no nameSpaces")

        val filteredNameSpaces = CborMap()
        for ((ns, elements) in requestedNamespaces) {
            val nsKey = UnicodeString(ns)
            val arr = origNameSpaces.get(nsKey) as? CborArray ?: continue
            Log.d(TAG, "buildDeviceResponse: ns='$ns' has ${arr.dataItems.size} items")
            // Each item is Tag(24) ByteString wrapping IssuerSignedItem
            val filteredArr = CborArray()
            for ((idx, item) in arr.dataItems.withIndex()) {
                Log.d(TAG, "buildDeviceResponse: item[$idx] class=${item.javaClass.simpleName} tag=${item.tag} majorType=${item.majorType}")
                // Decode IssuerSignedItem to check elementIdentifier
                val tagItem = item as? ByteString ?: continue
                Log.d(TAG, "buildDeviceResponse: item[$idx] bytesLen=${tagItem.bytes.size} firstBytes=${tagItem.bytes.take(8).joinToString("") { "%02x".format(it) }}")
                val inner = try { cborDecode(tagItem.bytes)[0] as? CborMap } catch (_: Exception) { null } ?: continue
                val eid = inner.get(UnicodeString("elementIdentifier")) as? UnicodeString ?: continue
                Log.d(TAG, "buildDeviceResponse: item[$idx] eid='${eid.string}'")
                if (elements.contains(eid.string)) {
                    filteredArr.add(item)
                    Log.d(TAG, "buildDeviceResponse: INCLUDED item eid='${eid.string}'")
                }
            }
            if (filteredArr.dataItems.isNotEmpty()) {
                filteredNameSpaces.put(nsKey, filteredArr)
            }
        }

        // If nothing matched, fallback to original (for debugging)
        val finalNameSpaces = if (filteredNameSpaces.keys.isNotEmpty()) filteredNameSpaces else origNameSpaces

        // Build filtered issuerSigned
        val filteredIssuerSigned = CborMap()
        for (k in issuerSigned.keys) {
            filteredIssuerSigned.put(k, issuerSigned.get(k))
        }
        filteredIssuerSigned.put(UnicodeString("nameSpaces"), finalNameSpaces)

        val resp = CborMap()
        resp.put(UnicodeString("version"), UnicodeString("1.0"))

        // documents array
        val doc = CborMap()
        doc.put(UnicodeString("docType"), UnicodeString(docType))
        doc.put(UnicodeString("issuerSigned"), filteredIssuerSigned)

        // deviceSigned
        val emptyNs = CborMap()
        val emptyNsBytes = cborEncode(emptyNs)
        val taggedNs = ByteString(emptyNsBytes); taggedNs.tag = Tag(24)

        // DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]
        // IMPORTANT: We must NOT decode and re-encode the SessionTranscript, because
        // cbor-java's CborMap reorders keys canonically. Instead, embed the raw bytes
        // of SessionTranscript directly into the DeviceAuthentication array.
        val encodedDevAuth = buildDeviceAuthenticationManual(encodedSessionTranscript, docType, emptyNsBytes)
        
        Log.d(TAG, "───────────────────────────────────────────────────────")
        Log.d(TAG, "DeviceAuthentication structure:")
        Log.d(TAG, "  [0] = \"DeviceAuthentication\"")
        Log.d(TAG, "  [1] = SessionTranscript (decoded from encodedSessionTranscript)")
        Log.d(TAG, "  [2] = docType = \"$docType\"")
        Log.d(TAG, "  [3] = Tag(24, bstr(emptyMap)) = DeviceNameSpacesBytes")
        Log.d(TAG, "encodedDevAuth (${encodedDevAuth.size} bytes): ${encodedDevAuth.joinToString("") { "%02x".format(it) }}")

        // protected header {1:5} = alg HMAC-256/256
        val protHdr = CborMap(); protHdr.put(UnsignedInteger(1), UnsignedInteger(5))
        val encodedProtHdr = cborEncode(protHdr)
        Log.d(TAG, "protectedHeaders {1:5}: ${encodedProtHdr.joinToString("") { "%02x".format(it) }}")

        // MAC_structure = ["MAC0", protectedHeaders, externalAad, payload]
        // payload must be a bstr containing the CBOR-encoded DeviceAuthenticationBytes
        // DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
        val taggedDevAuth = ByteString(encodedDevAuth); taggedDevAuth.tag = Tag(24)
        val deviceAuthBytes = cborEncode(taggedDevAuth) // CBOR encoding of Tag(24, bstr)
        
        Log.d(TAG, "DeviceAuthenticationBytes = Tag(24, bstr(encodedDevAuth)):")
        Log.d(TAG, "  (${deviceAuthBytes.size} bytes): ${deviceAuthBytes.joinToString("") { "%02x".format(it) }}")

        val macStructure = CborArray()
        macStructure.add(UnicodeString("MAC0"))
        macStructure.add(ByteString(encodedProtHdr))
        macStructure.add(ByteString(ByteArray(0)))                // external_aad
        macStructure.add(ByteString(deviceAuthBytes))             // payload = bstr wrapping DeviceAuthenticationBytes
        
        val encodedMacStructure = cborEncode(macStructure)
        Log.d(TAG, "MAC_structure = [\"MAC0\", protHdr_bstr, h'', deviceAuthBytes_bstr]:")
        Log.d(TAG, "  (${encodedMacStructure.size} bytes): ${encodedMacStructure.joinToString("") { "%02x".format(it) }}")

        val macTag = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(eMacKey, "HmacSHA256"))
            doFinal(encodedMacStructure)
        }
        
        Log.d(TAG, "Computed MAC tag (32 bytes): ${macTag.joinToString("") { "%02x".format(it) }}")
        Log.d(TAG, "───────────────────────────────────────────────────────")

        // COSE_Mac0 = [protected, unprotected, payload(null), tag]
        val coseMac0 = CborArray()
        coseMac0.add(ByteString(encodedProtHdr))
        coseMac0.add(CborMap())
        coseMac0.add(SimpleValue.NULL)
        coseMac0.add(ByteString(macTag))

        val deviceAuth = CborMap()
        deviceAuth.put(UnicodeString("deviceMac"), coseMac0)

        val deviceSigned = CborMap()
        deviceSigned.put(UnicodeString("nameSpaces"), taggedNs)
        deviceSigned.put(UnicodeString("deviceAuth"), deviceAuth)
        doc.put(UnicodeString("deviceSigned"), deviceSigned)

        val docs = CborArray(); docs.add(doc)
        resp.put(UnicodeString("documents"), docs)
        resp.put(UnicodeString("status"), UnsignedInteger(0))

        val encoded = cborEncode(resp)

        // Dump DeviceResponse and original mdoc to files for analysis
        try {
            val ctx = android.app.Application::class.java.getMethod("getProcessName").let {
                // Use any accessible context - write to external cache
                val dir = java.io.File("/sdcard/Download")
                dir.mkdirs()
                // Write DeviceResponse
                java.io.File(dir, "device_response.bin").writeBytes(encoded)
                Log.d(TAG, "Wrote DeviceResponse (${encoded.size} bytes) to /sdcard/Download/device_response.bin")
                // Write original mdoc
                java.io.File(dir, "original_mdoc.bin").writeBytes(mdocBytes)
                Log.d(TAG, "Wrote original mdoc (${mdocBytes.size} bytes) to /sdcard/Download/original_mdoc.bin")
                // Write DeviceResponse as base64 in logcat (split into chunks)
                val b64 = android.util.Base64.encodeToString(encoded, android.util.Base64.NO_WRAP)
                val chunkSize = 800
                for (i in 0 until b64.length step chunkSize) {
                    Log.d(TAG, "DEVRESP_B64[$i]: ${b64.substring(i, minOf(i + chunkSize, b64.length))}")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to dump files: ${e.message}")
        }
        try {
            val check = cborDecode(encoded)[0] as CborMap
            val docsArr = check.get(UnicodeString("documents")) as CborArray
            val doc0 = docsArr.dataItems[0] as CborMap
            val respDocType = (doc0.get(UnicodeString("docType")) as UnicodeString).string
            val respIss = doc0.get(UnicodeString("issuerSigned")) as CborMap

            // Compare issuerAuth in DeviceResponse with original
            val respAuth = respIss.get(UnicodeString("issuerAuth"))
            val respAuthBytes = cborEncode(respAuth!!)
            Log.d(TAG, "buildDeviceResponse: respIssuerAuth re-encoded ${respAuthBytes.size} bytes")
            Log.d(TAG, "buildDeviceResponse: respIssuerAuth HEX (first 80): ${respAuthBytes.take(80).joinToString("") { "%02x".format(it) }}")
            Log.d(TAG, "buildDeviceResponse: issuerAuth bytes MATCH original: ${origIssuerAuthBytes.contentEquals(respAuthBytes)}")

            // Check issuerAuth structure details
            if (respAuth is co.nstant.`in`.cbor.model.Array) {
                val items = (respAuth as co.nstant.`in`.cbor.model.Array).dataItems
                Log.d(TAG, "buildDeviceResponse: issuerAuth array size=${items.size}")
                for ((i, item) in items.withIndex()) {
                    Log.d(TAG, "buildDeviceResponse: issuerAuth[$i] class=${item.javaClass.simpleName} tag=${item.tag} majorType=${item.majorType}")
                    if (item is ByteString) {
                        Log.d(TAG, "buildDeviceResponse: issuerAuth[$i] bytesLen=${item.bytes.size} first8=${item.bytes.take(8).joinToString("") { "%02x".format(it) }}")
                    }
                }
            }

            // Also compare original raw mdoc issuerAuth position
            // Find "issuerAuth" key in raw mdoc bytes
            val issuerAuthMarker = "issuerAuth".toByteArray()
            val markerPos = findBytes(mdocBytes, issuerAuthMarker)
            if (markerPos >= 0) {
                val afterKey = markerPos + issuerAuthMarker.size
                Log.d(TAG, "buildDeviceResponse: raw mdoc issuerAuth at offset $afterKey, next bytes: ${mdocBytes.sliceArray(afterKey until minOf(afterKey + 20, mdocBytes.size)).joinToString("") { "%02x".format(it) }}")
            }

            val respNs = respIss.get(UnicodeString("nameSpaces"))
            Log.d(TAG, "buildDeviceResponse VERIFY: docType='$respDocType'")
            Log.d(TAG, "buildDeviceResponse VERIFY: nameSpaces class=${respNs?.javaClass?.simpleName} tag=${respNs?.tag}")
        } catch (e: Exception) {
            Log.e(TAG, "buildDeviceResponse VERIFY failed: ${e.message}", e)
        }

        return encoded
    }

    // ── Extract docType from mdoc ─────────────────────────────────────

    fun extractDocType(mdocBytes: ByteArray): String {
        try {
            val mdoc = cborDecode(mdocBytes)[0] as CborMap

            // direct docType key?
            (mdoc.get(UnicodeString("docType")) as? UnicodeString)?.let {
                Log.d(TAG, "extractDocType: found direct docType = ${it.string}")
                return it.string
            }

            val iss = mdoc.get(UnicodeString("issuerSigned")) as? CborMap ?: return ""
            // from MSO
            val auth = iss.get(UnicodeString("issuerAuth")) as? CborArray ?: return ""
            Log.d(TAG, "extractDocType: issuerAuth has ${auth.dataItems.size} items")
            if (auth.dataItems.size >= 3) {
                val payload = auth.dataItems[2]
                Log.d(TAG, "extractDocType: payload class=${payload.javaClass.simpleName} tag=${payload.tag}")
                if (payload is ByteString && payload.bytes.isNotEmpty()) {
                    Log.d(TAG, "extractDocType: payload bytes=${payload.bytes.size}")
                    val msoItems = cborDecode(payload.bytes)
                    if (msoItems.isNotEmpty() && msoItems[0] is CborMap) {
                        val dt = (msoItems[0] as CborMap).get(UnicodeString("docType"))
                        if (dt is UnicodeString) {
                            Log.d(TAG, "extractDocType: MSO docType = ${dt.string}")
                            return dt.string
                        }
                    }
                } else {
                    Log.d(TAG, "extractDocType: payload is not ByteString or empty, trying namespace fallback")
                }
            }
            // fallback: first namespace
            val ns = iss.get(UnicodeString("nameSpaces")) as? CborMap ?: return ""
            for (k in ns.keys) if (k is UnicodeString) {
                Log.d(TAG, "extractDocType: namespace fallback = ${k.string}")
                return k.string
            }
        } catch (e: Exception) {
            Log.e(TAG, "extractDocType failed", e)
        }
        return ""
    }

    // ── IACA Certificate Verification ─────────────────────────────────

    data class IacaVerificationResult(
        val success: Boolean,
        val message: String,
        val docSignerSubject: String? = null,
        val iacaSubject: String? = null
    )

    /**
     * Verify the document signer certificate from the mdoc's issuerAuth
     * against the provided IACA root certificate.
     */
    fun verifyIacaCertChain(mdocBytes: ByteArray, iacaCertPem: String): IacaVerificationResult {
        try {
            val mdoc = cborDecode(mdocBytes)[0] as CborMap
            val iss = mdoc.get(UnicodeString("issuerSigned")) as? CborMap
                ?: return IacaVerificationResult(false, "No issuerSigned in mdoc")

            val auth = iss.get(UnicodeString("issuerAuth")) as? CborArray
                ?: return IacaVerificationResult(false, "No issuerAuth in issuerSigned")

            // issuerAuth is COSE_Sign1: [protected, unprotected, payload, signature]
            if (auth.dataItems.size < 4) {
                return IacaVerificationResult(false, "issuerAuth has ${auth.dataItems.size} items, expected 4")
            }

            // Extract document signer cert from unprotected header (label 33 = x5chain)
            val unprotected = auth.dataItems[1] as? CborMap
            var docSignerCertBytes: ByteArray? = null

            if (unprotected != null) {
                // Try label 33 (integer key for x5chain)
                val x5chainItem = unprotected.get(UnsignedInteger(33))
                    ?: unprotected.get(NegativeInteger(33))
                Log.d(TAG, "verifyIaca: x5chain item class=${x5chainItem?.javaClass?.simpleName}")

                when (x5chainItem) {
                    is ByteString -> {
                        docSignerCertBytes = x5chainItem.bytes
                        Log.d(TAG, "verifyIaca: single cert, ${docSignerCertBytes.size} bytes")
                    }
                    is CborArray -> {
                        // Array of certs — first one is the document signer
                        val first = x5chainItem.dataItems.firstOrNull()
                        if (first is ByteString) {
                            docSignerCertBytes = first.bytes
                            Log.d(TAG, "verifyIaca: cert chain with ${x5chainItem.dataItems.size} cert(s), first=${docSignerCertBytes.size} bytes")
                        }
                    }
                }
            }

            if (docSignerCertBytes == null) {
                return IacaVerificationResult(false, "No x5chain (label 33) found in issuerAuth unprotected header")
            }

            // Parse document signer certificate
            val certFactory = java.security.cert.CertificateFactory.getInstance("X.509")
            val docSignerCert = certFactory.generateCertificate(
                java.io.ByteArrayInputStream(docSignerCertBytes)
            ) as java.security.cert.X509Certificate
            Log.d(TAG, "verifyIaca: docSigner subject=${docSignerCert.subjectX500Principal}")
            Log.d(TAG, "verifyIaca: docSigner issuer=${docSignerCert.issuerX500Principal}")

            // Parse IACA root certificate from PEM
            val iacaPem = iacaCertPem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\\s".toRegex(), "")
            val iacaCertBytes = Base64.decode(iacaPem, Base64.DEFAULT)
            val iacaCert = certFactory.generateCertificate(
                java.io.ByteArrayInputStream(iacaCertBytes)
            ) as java.security.cert.X509Certificate
            Log.d(TAG, "verifyIaca: IACA subject=${iacaCert.subjectX500Principal}")

            // Check 1: Verify document signer cert was issued by IACA
            try {
                docSignerCert.verify(iacaCert.publicKey)
                Log.d(TAG, "verifyIaca: Signature verification PASSED")
            } catch (e: Exception) {
                Log.e(TAG, "verifyIaca: Signature verification FAILED", e)
                return IacaVerificationResult(
                    false,
                    "Doc signer cert NOT signed by IACA: ${e.message}",
                    docSignerCert.subjectX500Principal.toString(),
                    iacaCert.subjectX500Principal.toString()
                )
            }

            // Check 2: Verify IACA cert validity (not expired)
            try {
                iacaCert.checkValidity()
            } catch (e: Exception) {
                return IacaVerificationResult(
                    false,
                    "IACA cert expired/not yet valid: ${e.message}",
                    docSignerCert.subjectX500Principal.toString(),
                    iacaCert.subjectX500Principal.toString()
                )
            }

            // Check 3: Verify doc signer cert validity
            try {
                docSignerCert.checkValidity()
            } catch (e: Exception) {
                return IacaVerificationResult(
                    false,
                    "Doc signer cert expired/not yet valid: ${e.message}",
                    docSignerCert.subjectX500Principal.toString(),
                    iacaCert.subjectX500Principal.toString()
                )
            }

            // Check 4: Verify COSE_Sign1 signature over the MSO
            try {
                val protectedHdr = auth.dataItems[0] as ByteString
                val payload = auth.dataItems[2] as ByteString
                val signature = auth.dataItems[3] as ByteString

                // Build Sig_structure = ["Signature1", protectedHeaders, externalAad, payload]
                val sigStructure = CborArray()
                sigStructure.add(UnicodeString("Signature1"))
                sigStructure.add(protectedHdr)
                sigStructure.add(ByteString(ByteArray(0)))
                sigStructure.add(payload)
                val sigStructureBytes = cborEncode(sigStructure)

                // Convert COSE signature (raw R||S) to DER format
                val rawSig = signature.bytes
                val r = BigInteger(1, rawSig.copyOfRange(0, rawSig.size / 2))
                val s = BigInteger(1, rawSig.copyOfRange(rawSig.size / 2, rawSig.size))
                val derSig = derEncodeSignature(r, s)

                val sig = Signature.getInstance("SHA256withECDSA")
                sig.initVerify(docSignerCert.publicKey)
                sig.update(sigStructureBytes)
                val valid = sig.verify(derSig)
                Log.d(TAG, "verifyIaca: COSE_Sign1 signature valid=$valid")
                if (!valid) {
                    return IacaVerificationResult(
                        false,
                        "COSE_Sign1 signature over MSO is INVALID",
                        docSignerCert.subjectX500Principal.toString(),
                        iacaCert.subjectX500Principal.toString()
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "verifyIaca: COSE_Sign1 check failed", e)
                return IacaVerificationResult(
                    false,
                    "COSE_Sign1 verification error: ${e.message}",
                    docSignerCert.subjectX500Principal.toString(),
                    iacaCert.subjectX500Principal.toString()
                )
            }

            return IacaVerificationResult(
                true,
                "All checks PASSED: IACA → DocSigner → COSE_Sign1",
                docSignerCert.subjectX500Principal.toString(),
                iacaCert.subjectX500Principal.toString()
            )
        } catch (e: Exception) {
            Log.e(TAG, "verifyIaca: unexpected error", e)
            return IacaVerificationResult(false, "Unexpected error: ${e.message}")
        }
    }

    private fun derEncodeSignature(r: BigInteger, s: BigInteger): ByteArray {
        val rBytes = r.toByteArray()
        val sBytes = s.toByteArray()
        val rLen = rBytes.size
        val sLen = sBytes.size
        val seqLen = 2 + rLen + 2 + sLen
        val out = ByteArrayOutputStream()
        out.write(0x30) // SEQUENCE
        out.write(seqLen)
        out.write(0x02) // INTEGER
        out.write(rLen)
        out.write(rBytes)
        out.write(0x02) // INTEGER
        out.write(sLen)
        out.write(sBytes)
        return out.toByteArray()
    }
}
