package com.example.mdoc.holder.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import com.example.mdoc.common.VerifierRequestAuth
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.ArrayDeque

/**
 * OpenID4VP-over-BLE wallet (GATT central). Scans for the verifier's OpenID4VP service, performs the
 * X25519 handshake (Identify), reads and decrypts the authorization request, and — after the app
 * supplies a vp_token via [submit] — encrypts and streams it back in chunks.
 *
 * Happy-path implementation of the openid4vp_ble draft (assumes the request fits one long read and
 * no chunk retransmission is needed). The proof itself is produced by the hosting activity.
 */
@SuppressLint("MissingPermission")
class BleWalletClient(
    private val context: Context,
    private val verifierPublicKeyHex: String,
    /** Bundled verifier certificate to pin the signed request against (null = accept unsigned). */
    private val trustedVerifierCert: X509Certificate?,
    private val onStatus: (String) -> Unit,
    private val onProgress: (Int) -> Unit,
    private val onRequestReady: (requestJson: String, transcript: ByteArray) -> Unit,
    private val onDone: (success: Boolean, message: String) -> Unit
) {
    private companion object { const val TAG = "ZK_BLE_WALLET" }

    private val keyPair = BleCrypto.newKeyPair()
    private val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
    private var skWallet: ByteArray? = null
    private var skVerifier: ByteArray? = null

    private var scanner = (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter.bluetoothLeScanner
    private var gatt: BluetoothGatt? = null
    private val chars = HashMap<java.util.UUID, BluetoothGattCharacteristic>()

    private var requestSize = 0
    private val requestBuffer = java.io.ByteArrayOutputStream()
    private var mtu = 23
    private var totalChunks = 0
    private val writeQueue = ArrayDeque<ByteArray>()
    private val notifyQueue = ArrayDeque<BluetoothGattCharacteristic>()
    private var submitChar: BluetoothGattCharacteristic? = null
    private val CCCD = java.util.UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    fun start() {
        onStatus("Looking for the verifier nearby")
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(BleProtocol.SERVICE_UUID)).build()
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        scanner?.startScan(listOf(filter), settings, scanCallback)
    }

    fun stop() {
        runCatching { scanner?.stopScan(scanCallback) }
        runCatching { gatt?.close() }
        gatt = null
    }

    @Volatile private var connecting = false
    @Volatile private var handshakeStarted = false

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            if (connecting) return // BLE can deliver several adv packets; only connect once
            connecting = true
            scanner?.stopScan(this)
            onStatus("Connecting")
            connect(result.device)
        }
        override fun onScanFailed(errorCode: Int) { onDone(false, "Bluetooth scan failed ($errorCode)") }
    }

    private fun connect(device: BluetoothDevice) {
        gatt = device.connectGatt(context, false, gattCallback)
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                g.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
                // LE 2M PHY doubles radio throughput with no protocol change (falls back to 1M if unsupported).
                g.setPreferredPhy(BluetoothDevice.PHY_LE_2M_MASK, BluetoothDevice.PHY_LE_2M_MASK, BluetoothDevice.PHY_OPTION_NO_PREFERRED)
                g.requestMtu(512)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) onStatus("Disconnected")
        }

        override fun onMtuChanged(g: BluetoothGatt, negotiated: Int, status: Int) {
            mtu = negotiated
            Log.d(TAG, "mtu=$mtu")
            g.discoverServices()
        }

        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
            Log.d(TAG, "servicesDiscovered status=$status")
            if (handshakeStarted) return // guard against a duplicate discovery callback
            handshakeStarted = true
            val service = g.getService(BleProtocol.SERVICE_UUID) ?: return onDone(false, "Verifier service not found")
            listOf(
                BleProtocol.REQUEST_SIZE, BleProtocol.REQUEST, BleProtocol.IDENTIFY,
                BleProtocol.CONTENT_SIZE, BleProtocol.SUBMIT_VC, BleProtocol.TRANSFER_SUMMARY_REQUEST,
                BleProtocol.TRANSFER_SUMMARY_REPORT, BleProtocol.DISCONNECT
            ).forEach { u -> service.getCharacteristic(u)?.let { chars[u] = it } }
            submitChar = chars[BleProtocol.SUBMIT_VC]
            // Completion is detected via the Transfer Summary Request write-ack, so no CCCD needed.
            startHandshake(g)
        }

        override fun onCharacteristicWrite(g: BluetoothGatt, ch: BluetoothGattCharacteristic, status: Int) {
            when (ch.uuid) {
                BleProtocol.IDENTIFY -> readValue(chars[BleProtocol.REQUEST_SIZE]!!)
                BleProtocol.CONTENT_SIZE -> pumpWriteQueue()
                BleProtocol.SUBMIT_VC -> pumpWriteQueue()
                // The verifier only acks this after it has received all chunks and verified.
                BleProtocol.TRANSFER_SUMMARY_REQUEST -> finish(true, "")
            }
        }

        // Old callback (Android < 33) delegates to the shared handler.
        @Suppress("DEPRECATION")
        override fun onCharacteristicRead(g: BluetoothGatt, ch: BluetoothGattCharacteristic, status: Int) {
            handleRead(ch.uuid, ch.value ?: ByteArray(0), status)
        }

        // New callback (Android 33+) with the value provided directly.
        override fun onCharacteristicRead(g: BluetoothGatt, ch: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
            handleRead(ch.uuid, value, status)
        }

        @Suppress("DEPRECATION")
        override fun onCharacteristicChanged(g: BluetoothGatt, ch: BluetoothGattCharacteristic) {
            if (ch.uuid == BleProtocol.DISCONNECT || ch.uuid == BleProtocol.TRANSFER_SUMMARY_REPORT) {
                finish(true, "")
            }
        }
        override fun onCharacteristicChanged(g: BluetoothGatt, ch: BluetoothGattCharacteristic, value: ByteArray) {
            if (ch.uuid == BleProtocol.DISCONNECT || ch.uuid == BleProtocol.TRANSFER_SUMMARY_REPORT) {
                finish(true, "")
            }
        }
    }

    @Volatile private var completed = false
    private fun finish(success: Boolean, message: String) {
        if (completed) return
        completed = true
        Log.d(TAG, "finish success=$success")
        onDone(success, message)
    }

    private fun handleRead(uuid: java.util.UUID, value: ByteArray, status: Int) {
        Log.d(TAG, "read ${uuid.toString().takeLast(4)} status=$status len=${value.size} (expected=$requestSize)")
        when (uuid) {
            BleProtocol.REQUEST_SIZE -> {
                requestSize = bytesToInt(value)
                requestBuffer.reset() // start a fresh (possibly multi-page) request read
                readValue(chars[BleProtocol.REQUEST]!!)
            }
            BleProtocol.REQUEST -> {
                try {
                    // A BLE characteristic value maxes at 512 bytes, so a larger request (more attributes)
                    // is served in pages: keep reading REQUEST until we've collected requestSize bytes.
                    if (value.isNotEmpty()) requestBuffer.write(value)
                    if (requestBuffer.size() < requestSize && value.isNotEmpty()) {
                        readValue(chars[BleProtocol.REQUEST]!!) // fetch the next page
                        return
                    }
                    val full = requestBuffer.toByteArray()
                    if (full.size < requestSize) {
                        onDone(false, "Incomplete request over Bluetooth (${full.size}/$requestSize).")
                        return
                    }
                    val verifierPub = BleCrypto.fromHex(verifierPublicKeyHex)
                    val decoded = BleCrypto.decrypt(skVerifier!!, nonce, full).decodeToString()
                    // When a verifier certificate is pinned, the request MUST be signed: verify the
                    // signature and pin the certificate, then use the verified payload. An unsigned
                    // request is refused (same strict rule as the online path) — no silent fallback.
                    val requestJson = if (trustedVerifierCert != null) {
                        require(VerifierRequestAuth.looksSigned(decoded)) {
                            "Verifier sent an unsigned request — refusing (a signed request from the pinned verifier is required)."
                        }
                        val claims = VerifierRequestAuth.verifyAndExtractClaims(decoded, trustedVerifierCert)
                        Log.d(TAG, "Request signature verified and verifier certificate pinned OK")
                        claims
                    } else decoded
                    val transcript = sessionTranscript(verifierPub, requestJson)
                    onStatus("Request received")
                    onRequestReady(requestJson, transcript)
                } catch (e: Exception) {
                    Log.e(TAG, "request decrypt/parse failed", e)
                    onDone(false, "Couldn't read the request over Bluetooth: ${e.message}")
                }
            }
        }
    }

    /** Called by the activity after consent + proof: encrypts the vp_token and streams it. */
    fun submit(vpTokenBytes: ByteArray) {
        val enc = BleCrypto.encrypt(skWallet!!, nonce, vpTokenBytes)
        writeQueue.clear()
        // Chunk size = min(MTU-3, 512). 512 is the max BLE attribute-value length; MTU can exceed it.
        val chunkSize = minOf(mtu - 3, 512).coerceAtLeast(100)
        val chunks = BleProtocol.encodeChunks(enc, chunkSize)
        chunks.forEach { writeQueue.add(it) }
        totalChunks = chunks.size
        writeQueue.add(byteArrayOf(1)) // Transfer Summary Request marks the end
        Log.d(TAG, "submitting ${enc.size} bytes in ${chunks.size} chunks (mtu=$mtu)")
        onProgress(0)
        writeValue(chars[BleProtocol.CONTENT_SIZE]!!, intToBytes(enc.size)) // kicks off the queue on write-ack
    }

    /**
     * Streams one chunk per write-ack. No-response writes have no ATT-level flow control, so flooding
     * them overruns the verifier's receive buffer and silently drops chunks (transfer stalls at the
     * end). Pacing to [onCharacteristicWrite] is reliable.
     */
    private fun pumpWriteQueue() {
        val next = writeQueue.poll() ?: return
        if (totalChunks > 0) {
            val done = totalChunks - (writeQueue.size - 1).coerceAtLeast(0) // -1 for the queued sentinel
            if (done % 8 == 0 || writeQueue.isEmpty()) onProgress((100 * done / totalChunks).coerceIn(0, 100))
        }
        if (writeQueue.isEmpty()) {
            writeValue(chars[BleProtocol.TRANSFER_SUMMARY_REQUEST]!!, next) // reliable with-response end marker
        } else {
            writeValue(submitChar!!, next, noResponse = true)
        }
    }

    private fun enableNextNotify(g: BluetoothGatt) {
        val ch = notifyQueue.poll() ?: return startHandshake(g)
        g.setCharacteristicNotification(ch, true)
        val cccd = ch.getDescriptor(CCCD) ?: return enableNextNotify(g)
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            g.writeDescriptor(cccd, android.bluetooth.BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
        } else {
            @Suppress("DEPRECATION")
            run {
                cccd.value = android.bluetooth.BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                g.writeDescriptor(cccd)
            }
        }
    }

    private fun startHandshake(g: BluetoothGatt) {
        onStatus("Exchanging keys")
        val verifierPub = BleCrypto.fromHex(verifierPublicKeyHex)
        val shared = BleCrypto.sharedSecret(keyPair.priv, verifierPub)
        skWallet = BleCrypto.deriveKey(shared, "SKWallet")
        skVerifier = BleCrypto.deriveKey(shared, "SKVerifier")
        writeValue(chars[BleProtocol.IDENTIFY]!!, keyPair.publicRaw + nonce)
    }

    /** Returns true if the stack accepted the write; false means its buffer is full (back-pressure). */
    private fun writeValue(
        ch: BluetoothGattCharacteristic,
        value: ByteArray,
        noResponse: Boolean = false
    ): Boolean {
        val g = gatt ?: return false
        val type = if (noResponse) BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
        else BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        return if (android.os.Build.VERSION.SDK_INT >= 33) {
            g.writeCharacteristic(ch, value, type) == android.bluetooth.BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            run { ch.value = value; ch.writeType = type; g.writeCharacteristic(ch) }
        }
    }

    private fun readValue(ch: BluetoothGattCharacteristic) { gatt?.readCharacteristic(ch) }

    private fun sessionTranscript(verifierPub: ByteArray, requestJson: String): ByteArray {
        val obj = org.json.JSONObject(requestJson)
        val clientId = obj.optString("client_id")
        val n = obj.optString("nonce")
        val info = (clientId + n + BleCrypto.toHex(verifierPub) + BleCrypto.toHex(keyPair.publicRaw)).toByteArray()
        val digest = MessageDigest.getInstance("SHA-256").digest(info)
        return org.multipaz.cbor.Cbor.encode(org.multipaz.cbor.buildCborArray {
            add(org.multipaz.cbor.Simple.NULL); add(org.multipaz.cbor.Simple.NULL)
            add(org.multipaz.cbor.buildCborArray { add("OpenID4VPBLEHandover"); add(digest) })
        })
    }

    private fun bytesToInt(b: ByteArray) =
        ((b[0].toInt() and 0xFF) shl 24) or ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or (b[3].toInt() and 0xFF)
    private fun intToBytes(v: Int) = byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())
}
