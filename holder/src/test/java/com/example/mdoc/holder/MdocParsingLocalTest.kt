package com.example.mdoc.holder

import org.junit.Test
import java.io.File
import java.io.ByteArrayInputStream
import java.util.Base64
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.*

class MdocParsingLocalTest {
    
    @Test
    fun testMdocParsingFromFile() {
        // Read credential from absolute path
        val credentialFile = File("d:\\mdoc-poc\\MdocApps\\holder\\src\\main\\assets\\mdoc_b64.txt")
        
        if (!credentialFile.exists()) {
            println("\nERROR: Credential file not found at ${credentialFile.absolutePath}")
            return
        }
        
        val mdocBase64 = credentialFile.readText().trim()
        
        println("\n========== MDOC PARSING RESULTS ==========")
        println("Credential file: ${credentialFile.absolutePath}")
        println("File size: ${credentialFile.length()} bytes")
        println("Base64 string length: ${mdocBase64.length} characters")
        println()
        
        try {
            // Decode base64
            val decodedBytes = Base64.getDecoder().decode(mdocBase64)
            println("Decoded to ${decodedBytes.size} bytes")
            
            // Show first few bytes in hex
            println("First 20 bytes (hex): ${decodedBytes.take(20).joinToString(" ") { "%02x".format(it) }}")
            println()
            
            // Parse CBOR
            val inputStream = ByteArrayInputStream(decodedBytes)
            val dataItems = CborDecoder(inputStream).decode()
            println("CBOR has ${dataItems.size} items")
            
            // Check what the first item actually is
            if (dataItems.isNotEmpty()) {
                val firstItem = dataItems[0]
                println("First item type: ${firstItem.javaClass.simpleName}")
                
                // If it's a CBOR Map, process it
                if (firstItem is co.nstant.`in`.cbor.model.Map) {
                    println("Processing CBOR Map...")
                    extractFromMap(firstItem)
                }
            }
        } catch (e: Exception) {
            println("EXCEPTION during parsing:")
            e.printStackTrace()
        }
        
        println("\n========== END PARSING ==========\n")
    }
    
    private fun extractFromMap(mainMap: co.nstant.`in`.cbor.model.Map) {
        println("Main map keys: ${mainMap.keys.size}")
        
        val issuerSignedKey = UnicodeString("issuerSigned")
        val issuerSigned = mainMap[issuerSignedKey] as? co.nstant.`in`.cbor.model.Map
        
        if (issuerSigned != null) {
            println("issuerSigned found, keys: ${issuerSigned.keys.size}")
            
            val nameSpacesKey = UnicodeString("nameSpaces")
            val nameSpacesMap = issuerSigned[nameSpacesKey] as? co.nstant.`in`.cbor.model.Map
            
            if (nameSpacesMap != null) {
                println("nameSpaces found with ${nameSpacesMap.keys.size} namespaces")
                println()
                
                val fieldsMap = mutableMapOf<String, String>()
                
                for (nsKey in nameSpacesMap.keys) {
                    if (nsKey is UnicodeString) {
                        val nsName = nsKey.string
                        val itemsArray = nameSpacesMap[nsKey] as? co.nstant.`in`.cbor.model.Array
                        
                        if (itemsArray != null) {
                            println("Namespace: $nsName (${itemsArray.dataItems.size} encoded items)")
                            
                            // Each item is a ByteString containing CBOR-encoded IssuerSignedItem
                            for ((index, item) in itemsArray.dataItems.withIndex()) {
                                if (item is ByteString) {
                                    try {
                                        // Decode the ByteString as CBOR
                                        val decodedItem = ByteArrayInputStream(item.bytes)
                                        val decodedDataItems = CborDecoder(decodedItem).decode()
                                        
                                        if (decodedDataItems.isNotEmpty()) {
                                            val issuerSignedItem = decodedDataItems[0] as? co.nstant.`in`.cbor.model.Map
                                            if (issuerSignedItem != null) {
                                                val elementIdKey = UnicodeString("elementIdentifier")
                                                val elementValueKey = UnicodeString("elementValue")
                                                
                                                val identifier = (issuerSignedItem[elementIdKey] as? UnicodeString)?.string
                                                val value = issuerSignedItem[elementValueKey]
                                                
                                                if (identifier != null && value != null) {
                                                    val stringValue = when (value) {
                                                        is UnicodeString -> value.string
                                                        is ByteString -> "[ByteString: ${value.bytes.size} bytes]"
                                                        is SimpleValue -> value.toString()
                                                        else -> value.toString()
                                                    }
                                                    fieldsMap[identifier] = stringValue
                                                }
                                            }
                                        }
                                    } catch (e: Exception) {
                                        // Silently skip decode errors for this item
                                    }
                                }
                            }
                        }
                    }
                }
                
                println("\nTotal Fields Extracted: ${fieldsMap.size}")
                if (fieldsMap.isNotEmpty()) {
                    println("\nField List:")
                    fieldsMap.forEach { (key, value) ->
                        val display = if (value.length > 100) {
                            value.substring(0, 100) + "..."
                        } else {
                            value
                        }
                        println("  [$key] = $display")
                    }
                }
            }
        }
    }
}
