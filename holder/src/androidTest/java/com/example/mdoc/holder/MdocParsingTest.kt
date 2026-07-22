package com.example.mdoc.holder

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test
import org.junit.runner.RunWith
import android.util.Log

@RunWith(AndroidJUnit4::class)
class MdocParsingTest {
    
    @Test
    fun testMdocParsing() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        
        // Read the credential file
        val mdocBase64 = context.assets.open("mdoc_b64.txt").bufferedReader().use { it.readText().trim() }
        println("\n=== MDOC PARSING TEST ===")
        println("Credential size: ${mdocBase64.length} bytes")
        println()
        
        // Extract fields
        val (docType, fields) = MdocFieldExtractor.extractAllFields(mdocBase64)
        
        println("Document Type: $docType")
        println("Total Fields Extracted: ${fields.size}")
        println()
        
        if (fields.isEmpty()) {
            println("ERROR: No fields were extracted!")
        } else {
            println("Fields:")
            fields.forEach { (key, value) ->
                val displayValue = if (value.length > 80) {
                    value.substring(0, 80) + "..."
                } else {
                    value
                }
                println("  $key = $displayValue")
            }
        }
        
        println("\n=== END PARSING TEST ===\n")
        
        // Assert we got fields
        assert(fields.isNotEmpty()) { "No fields were extracted from credential!" }
    }
}
