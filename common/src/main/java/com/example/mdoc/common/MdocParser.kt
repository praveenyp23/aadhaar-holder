package com.example.mdoc.common

import android.util.Base64
import android.util.Log
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.*
import java.io.ByteArrayInputStream
import java.math.BigInteger

data class ParsedMdoc(
    val rawBase64: String,
    val namespace: String,
    val attributes: Map<String, Any>,
    val issuerCert: ByteArray?,
    val signature: ByteArray?,
    val mso: ByteArray?,
    val valueDigests: Map<String, ByteArray>
)

object MdocParser {
    private const val TAG = "MDOC_PARSER"
    
    @Suppress("UNCHECKED_CAST")
    fun parseBase64Mdoc(base64String: String): ParsedMdoc? {
        return try {
            Log.d(TAG, "Starting CBOR parsing of ${base64String.length} byte base64 credential")
            
            val decodedBytes = Base64.decode(base64String, Base64.DEFAULT)
            Log.d(TAG, "Decoded to ${decodedBytes.size} bytes")
            
            val inputStream = ByteArrayInputStream(decodedBytes)
            val dataItems = CborDecoder(inputStream).decode()
            
            Log.d(TAG, "CBOR decoded ${dataItems.size} items")
            
            if (dataItems.isEmpty() || dataItems[0] !is co.nstant.`in`.cbor.model.Map) {
                Log.e(TAG, "First item is not a Map or data items is empty")
                return null
            }
            
            val mainMap = dataItems[0] as co.nstant.`in`.cbor.model.Map
            Log.d(TAG, "Main map has ${mainMap.keys.size} keys")
            
            val issuerSignedKey = UnicodeString("issuerSigned")
            val issuerSigned = mainMap[issuerSignedKey] as? co.nstant.`in`.cbor.model.Map
            if (issuerSigned == null) {
                Log.e(TAG, "issuerSigned key not found or not a Map")
                return null
            }
            
            Log.d(TAG, "issuerSigned map has ${issuerSigned.keys.size} keys")
            
            val nameSpacesKey = UnicodeString("nameSpaces")
            val nameSpacesMap = issuerSigned[nameSpacesKey] as? co.nstant.`in`.cbor.model.Map
            if (nameSpacesMap == null) {
                Log.e(TAG, "nameSpaces key not found or not a Map")
                return null
            }
            
            Log.d(TAG, "nameSpaces map has ${nameSpacesMap.keys.size} namespaces")
            
            var namespace = ""
            val attributes = mutableMapOf<String, Any>()
            
            for (nsKey in nameSpacesMap.keys) {
                val nsValue = nameSpacesMap[nsKey]
                if (nsKey is UnicodeString && nsValue is co.nstant.`in`.cbor.model.Array) {
                    namespace = nsKey.string
                    val itemsArray = nsValue as co.nstant.`in`.cbor.model.Array
                    Log.d(TAG, "Processing namespace: $namespace with ${itemsArray.dataItems.size} items")
                    
                    for (item in itemsArray.dataItems) {
                        // Items are ByteStrings containing CBOR-encoded IssuerSignedItem
                        if (item is ByteString) {
                            try {
                                // Decode the ByteString as CBOR
                                val decodedItem = ByteArrayInputStream(item.bytes)
                                val decodedDataItems = CborDecoder(decodedItem).decode()
                                
                                if (decodedDataItems.isNotEmpty() && decodedDataItems[0] is co.nstant.`in`.cbor.model.Map) {
                                    val itemMap = decodedDataItems[0] as co.nstant.`in`.cbor.model.Map
                                    val elementIdKey = UnicodeString("elementIdentifier")
                                    val elementValueKey = UnicodeString("elementValue")
                                    
                                    val identifier = (itemMap[elementIdKey] as? UnicodeString)?.string
                                    val value = itemMap[elementValueKey]
                                    
                                    if (identifier != null && value != null) {
                                        attributes[identifier] = extractValue(value)
                                        Log.d(TAG, "  Field: $identifier")
                                    }
                                }
                            } catch (e: Exception) {
                                Log.w(TAG, "Error decoding item in namespace $namespace", e)
                            }
                        } else if (item is co.nstant.`in`.cbor.model.Map) {
                            // Fallback: handle direct Maps if present
                            val itemMap = item as co.nstant.`in`.cbor.model.Map
                            val elementIdKey = UnicodeString("elementIdentifier")
                            val elementValueKey = UnicodeString("elementValue")
                            
                            val identifier = (itemMap[elementIdKey] as? UnicodeString)?.string
                            val value = itemMap[elementValueKey]
                            
                            if (identifier != null && value != null) {
                                attributes[identifier] = extractValue(value)
                                Log.d(TAG, "  Field: $identifier")
                            }
                        }
                    }
                }
            }
            
            Log.d(TAG, "Successfully extracted ${attributes.size} attributes")
            
            val issuerAuthKey = UnicodeString("issuerAuth")
            val issuerAuth = issuerSigned[issuerAuthKey] as? co.nstant.`in`.cbor.model.Array
            
            var issuerCert: ByteArray? = null
            var signature: ByteArray? = null
            var mso: ByteArray? = null
            
            if (issuerAuth != null && issuerAuth.dataItems.size >= 4) {
                val unprotectedHeaders = issuerAuth.dataItems[1] as? co.nstant.`in`.cbor.model.Map
                if (unprotectedHeaders != null) {
                    val x5chainKey = UnsignedInteger(33L)
                    val certData = unprotectedHeaders[x5chainKey]
                    issuerCert = when (certData) {
                        is co.nstant.`in`.cbor.model.Array -> {
                            val certArray = certData.dataItems
                            if (certArray.isNotEmpty() && certArray[0] is ByteString) {
                                (certArray[0] as ByteString).bytes
                            } else null
                        }
                        else -> null
                    }
                }
                
                val payloadItem = issuerAuth.dataItems[2]
                mso = when (payloadItem) {
                    is ByteString -> payloadItem.bytes
                    else -> null
                }
                
                val signatureItem = issuerAuth.dataItems[3]
                signature = when (signatureItem) {
                    is ByteString -> signatureItem.bytes
                    else -> null
                }
            }
            
            val valueDigests = extractValueDigests(mso)
            
            ParsedMdoc(
                rawBase64 = base64String,
                namespace = namespace,
                attributes = attributes,
                issuerCert = issuerCert,
                signature = signature,
                mso = mso,
                valueDigests = valueDigests
            )
        } catch (e: Exception) {
            Log.e(TAG, "Parsing failed with exception", e)
            e.printStackTrace()
            null
        }
    }
    
    @Suppress("UNCHECKED_CAST")
    private fun extractValue(dataItem: DataItem): Any {
        return when (dataItem) {
            is UnicodeString -> dataItem.string
            is UnsignedInteger -> dataItem.value.toLong()
            is NegativeInteger -> dataItem.value.toLong()
            is ByteString -> Base64.encodeToString(dataItem.bytes, Base64.NO_WRAP)
            is SimpleValue -> when {
                dataItem.simpleValueType == SimpleValueType.TRUE -> true
                dataItem.simpleValueType == SimpleValueType.FALSE -> false
                else -> "null"
            }
            is co.nstant.`in`.cbor.model.Array -> {
                val list = mutableListOf<Any>()
                for (item in dataItem.dataItems) {
                    list.add(extractValue(item))
                }
                list
            }
            is co.nstant.`in`.cbor.model.Map -> {
                val map = mutableMapOf<String, Any>()
                for (key in dataItem.keys) {
                    val value = dataItem[key]
                    val keyString = when (key) {
                        is UnicodeString -> key.string
                        is UnsignedInteger -> key.value.toString()
                        else -> key.toString()
                    }
                    if (value != null) {
                        map[keyString] = extractValue(value)
                    }
                }
                map
            }
            else -> dataItem.toString()
        }
    }
    
    @Suppress("UNCHECKED_CAST")
    private fun extractValueDigests(msoBytes: ByteArray?): Map<String, ByteArray> {
        // TODO: Implement proper CBOR MSO parsing for value digests
        return emptyMap()
    }
}
