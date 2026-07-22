package com.example.mdoc.holder

import android.os.Bundle
import android.view.View
import com.journeyapps.barcodescanner.CaptureActivity

/**
 * ZXing capture screen with the viewfinder overlay hidden. The default [CaptureActivity] draws a
 * framing box and an animated red laser line; we hide that view for a clean camera preview.
 */
class ZkScanActivity : CaptureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val vfId = resources.getIdentifier("zxing_viewfinder_view", "id", packageName)
        if (vfId != 0) findViewById<View?>(vfId)?.visibility = View.GONE
    }
}
