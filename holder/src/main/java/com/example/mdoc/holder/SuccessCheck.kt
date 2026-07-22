package com.example.mdoc.holder

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp

/**
 * Banking-style animated success mark: a ring sweeps closed, then a checkmark draws in, with a
 * subtle scale settle. Purely drawn (no assets).
 */
@Composable
fun SuccessCheck(
    modifier: Modifier = Modifier,
    sizeDp: Int = 96,
    color: Color = Color(0xFF15A24A)
) {
    val ring = remember { Animatable(0f) }
    val check = remember { Animatable(0f) }
    val scale = remember { Animatable(0.6f) }

    LaunchedEffect(Unit) {
        scale.animateTo(1f, tween(420, easing = FastOutSlowInEasing))
    }
    LaunchedEffect(Unit) {
        ring.animateTo(1f, tween(520, easing = FastOutSlowInEasing))
        check.animateTo(1f, tween(360, easing = FastOutSlowInEasing))
    }

    Canvas(modifier = modifier.size(sizeDp.dp)) {
        val s = size.minDimension
        val stroke = Stroke(width = s * 0.075f, cap = StrokeCap.Round)
        val sc = scale.value
        val cx = size.width / 2f
        val cy = size.height / 2f

        // Ring sweeping closed from the top.
        drawArc(
            color = color,
            startAngle = -90f,
            sweepAngle = 360f * ring.value,
            useCenter = false,
            topLeft = Offset(cx - s * 0.44f * sc, cy - s * 0.44f * sc),
            size = androidx.compose.ui.geometry.Size(s * 0.88f * sc, s * 0.88f * sc),
            style = stroke
        )

        // Checkmark: p0 -> p1 -> p2, drawn progressively.
        val p0 = Offset(cx - s * 0.20f * sc, cy + s * 0.02f * sc)
        val p1 = Offset(cx - s * 0.05f * sc, cy + s * 0.17f * sc)
        val p2 = Offset(cx + s * 0.22f * sc, cy - s * 0.15f * sc)
        val t = check.value
        if (t > 0f) {
            val firstLen = 0.4f
            if (t <= firstLen) {
                val f = t / firstLen
                drawLine(color, p0, lerp(p0, p1, f), strokeWidth = s * 0.075f, cap = StrokeCap.Round)
            } else {
                drawLine(color, p0, p1, strokeWidth = s * 0.075f, cap = StrokeCap.Round)
                val f = (t - firstLen) / (1f - firstLen)
                drawLine(color, p1, lerp(p1, p2, f), strokeWidth = s * 0.075f, cap = StrokeCap.Round)
            }
        }
    }
}

private fun lerp(a: Offset, b: Offset, f: Float) = Offset(a.x + (b.x - a.x) * f, a.y + (b.y - a.y) * f)
