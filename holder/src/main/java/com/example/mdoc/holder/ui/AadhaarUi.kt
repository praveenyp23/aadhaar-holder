package com.example.mdoc.holder.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import com.airbnb.lottie.compose.LottieAnimation
import com.airbnb.lottie.compose.LottieCompositionSpec
import com.airbnb.lottie.compose.rememberLottieComposition
import com.example.mdoc.common.MdocCardData
import com.mdocholder.app.R

/**
 * Aadhaar design system, matched to the official UIDAI "Pehchaan" app: deep navy (#083459), warm
 * cream backgrounds (#FAF4EE), the ivory Aadhaar card with brown text, Manrope type and Lottie success.
 */
object Aadhaar {
    val Navy = Color(0xFF083459)       // Pehchaan Primary500
    val NavyDark = Color(0xFF010F2A)   // Pehchaan Topbar
    val Bg = Color(0xFFFAF4EE)         // Pehchaan BackgroundPrimary
    val BgWarm = Color(0xFFFEF6EE)     // Pehchaan onboarding / splash
    val Surface = Color(0xFFFFFFFF)
    val CardBeige = Color(0xFFF5EBE0)
    val Ink = Color(0xFF23313C)        // Pehchaan Cardtitle / Cardtext
    val InkStrong = Color(0xFF010F2A)
    val Muted = Color(0xFF757575)
    val Line = Color(0xFFE6E2DE)
    val Success = Color(0xFF2EAE7D)
    val Green = Success
    val GreenSoft = Color(0xFFE7F6EC)
    val SaffronSoft = Color(0xFFFFF1E6)
    val Red = Color(0xFFDA251D)
    val Saffron = Color(0xFFFDB913)    // AadhaarYellow
    val Orange = Color(0xFFE84A2E)
    val Link = Color(0xFF0057FF)
    // Aadhaar card ink (brown, as on the physical card)
    val CardBrown = Color(0xFF726044)
    val CardBrownDark = Color(0xFF5E4C30)
    val CardGold = Color(0xFFC4A26D)
    val cardGradient = listOf(
        Color(0xFFFFFDF1), Color(0xFFFFFDF1), Color(0xFFFDFAFA), Color(0xFFFFF6E9), Color(0xFFFFFBF6)
    )
}

val Manrope = FontFamily(
    Font(R.font.manrope_light, FontWeight.Light),
    Font(R.font.manrope_regular, FontWeight.Normal),
    Font(R.font.manrope_medium, FontWeight.Medium),
    Font(R.font.manrope_semibold, FontWeight.SemiBold),
    Font(R.font.manrope_bold, FontWeight.Bold)
)

@Composable
fun AadhaarTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = lightColorScheme(
            primary = Aadhaar.Navy, onPrimary = Color.White,
            secondary = Aadhaar.Saffron, onSecondary = Aadhaar.InkStrong,
            tertiary = Aadhaar.Success,
            background = Aadhaar.Bg, onBackground = Aadhaar.Ink,
            surface = Aadhaar.Surface, onSurface = Aadhaar.Ink,
            surfaceVariant = Aadhaar.CardBeige, error = Aadhaar.Red
        ),
        shapes = Shapes(
            small = RoundedCornerShape(10.dp),
            medium = RoundedCornerShape(16.dp),
            large = RoundedCornerShape(20.dp)
        )
    ) {
        // Default every Text to Manrope. Do NOT force a color here, or button/dark-surface text would
        // inherit dark ink and vanish; leave color to LocalContentColor (white inside navy buttons).
        CompositionLocalProvider(LocalTextStyle provides TextStyle(fontFamily = Manrope)) {
            content()
        }
    }
}

@Composable
fun AadhaarEmblem(size: Int = 34, modifier: Modifier = Modifier) {
    Image(
        painter = painterResource(id = R.drawable.ic_aadhaar_splash),
        contentDescription = "Aadhaar",
        modifier = modifier.size(size.dp)
    )
}

/** Dark navy header band with the real Aadhaar emblem and Hindi tagline. */
@Composable
fun BrandTopBar(title: String, subtitle: String? = null, modifier: Modifier = Modifier) {
    Box(
        modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(bottomStart = 24.dp, bottomEnd = 24.dp))
            .background(Brush.verticalGradient(listOf(Aadhaar.NavyDark, Aadhaar.Navy)))
            .padding(horizontal = 20.dp, vertical = 18.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(46.dp).clip(RoundedCornerShape(12.dp)).background(Color.White).padding(6.dp),
                contentAlignment = Alignment.Center
            ) { AadhaarEmblem(size = 34) }
            Spacer(Modifier.width(12.dp))
            Column {
                Text(title, color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                Text(subtitle ?: "मेरा आधार, मेरी पहचान", color = Color.White.copy(alpha = 0.78f), fontSize = 12.sp)
            }
        }
    }
}

/**
 * The digital Aadhaar card, matched to the Pehchaan app: the [R.drawable.h_back] artwork already carries
 * the tricolor band, "APPROVED BY UIDAI" strip and the AADHAAR logo (bottom-right), so we don't add an
 * emblem. Tap to flip — front shows the square photo + name/DOB/gender, back shows the addresses. The
 * Aadhaar number is intentionally omitted (not present in this credential).
 */
@Composable
fun DigitalAadhaarCard(
    card: MdocCardData,
    address: String,
    regionalAddress: String,
    modifier: Modifier = Modifier
) {
    var flipped by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(false) }
    val rotation by androidx.compose.animation.core.animateFloatAsState(
        targetValue = if (flipped) 180f else 0f,
        animationSpec = androidx.compose.animation.core.tween(520),
        label = "cardFlip"
    )
    Box(modifier.fillMaxWidth(0.92f).aspectRatio(0.78f)) {
        Box(
            Modifier.matchParentSize()
                .graphicsLayer(rotationY = rotation, cameraDistance = 14f)
                .clip(RoundedCornerShape(16.dp))
                .background(Color(0xFFFFFDF1))
                .clickable { flipped = !flipped }
                .pointerInput(Unit) {
                    detectHorizontalDragGestures(onDragEnd = { flipped = !flipped }) { change, _ -> change.consume() }
                }
        ) {
            if (rotation <= 90f) {
                Box(Modifier.matchParentSize()) {
                    Image(painterResource(R.drawable.h_back), null, Modifier.fillMaxSize(), contentScale = ContentScale.Crop)
                    CardFront(card)
                }
            } else {
                // Counter-rotate the whole back face (art + text) so "APPROVED BY UIDAI" and the logo read correctly.
                Box(Modifier.matchParentSize().graphicsLayer(rotationY = 180f)) {
                    Image(painterResource(R.drawable.h_back), null, Modifier.fillMaxSize(), contentScale = ContentScale.Crop)
                    CardBack(card.name, address, regionalAddress)
                }
            }
        }
        // Fixed flip arrows (not part of the rotating face)
        Text("‹", Modifier.align(Alignment.CenterStart).padding(start = 4.dp).clickable { flipped = !flipped },
            fontSize = 34.sp, fontWeight = FontWeight.Bold, color = Aadhaar.CardBrownDark.copy(alpha = 0.5f))
        Text("›", Modifier.align(Alignment.CenterEnd).padding(end = 4.dp).clickable { flipped = !flipped },
            fontSize = 34.sp, fontWeight = FontWeight.Bold, color = Aadhaar.CardBrownDark.copy(alpha = 0.5f))
    }
}

/** Formats a raw DOB (yyyy-MM-dd or dd-MM-yyyy) to "08-Apr-2002". */
private fun formatDob(raw: String): String {
    val months = arrayOf("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    val g = Regex("\\d+").findAll(raw).map { it.value }.toList()
    if (g.size < 3) return raw
    val year: Int; val month: Int; val day: Int
    if (g[0].length == 4) { year = g[0].toInt(); month = g[1].toIntOrNull() ?: 0; day = g[2].toIntOrNull() ?: 0 }
    else { day = g[0].toIntOrNull() ?: 0; month = g[1].toIntOrNull() ?: 0; year = g[2].toIntOrNull() ?: 0 }
    if (month !in 1..12 || day !in 1..31) return raw
    return "%02d-%s-%04d".format(day, months[month - 1], year)
}

@Composable
private fun CardFront(card: MdocCardData) {
    Column(
        Modifier.fillMaxSize().padding(horizontal = 26.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        val bmp = remember(card.residentImageBytes) {
            card.residentImageBytes?.let { runCatching { BitmapFactory.decodeByteArray(it, 0, it.size) }.getOrNull() }
        }
        Box(Modifier.size(118.dp).clip(RoundedCornerShape(6.dp)).border(2.dp, Color.White, RoundedCornerShape(6.dp))) {
            if (bmp != null) {
                Image(bmp.asImageBitmap(), contentDescription = "Photo",
                    modifier = Modifier.fillMaxSize().clip(RoundedCornerShape(6.dp)), contentScale = ContentScale.Crop)
            } else {
                Box(Modifier.fillMaxSize().background(Color.Gray.copy(alpha = 0.15f)), contentAlignment = Alignment.Center) {
                    Text("No photo", fontSize = 10.sp, color = Aadhaar.CardBrown)
                }
            }
        }
        Spacer(Modifier.height(16.dp))
        if (card.name.isNotBlank()) {
            Text(card.name, textAlign = TextAlign.Center, style = TextStyle(
                fontFamily = Manrope, fontWeight = FontWeight.Bold, fontSize = 21.sp,
                brush = Brush.linearGradient(listOf(Aadhaar.CardBrownDark, Aadhaar.CardGold))
            ))
            Spacer(Modifier.height(12.dp))
        }
        if (card.dateOfBirth.isNotBlank())
            Text("DOB: ${formatDob(card.dateOfBirth)}", color = Aadhaar.CardBrown, fontWeight = FontWeight.Bold, fontSize = 14.sp)
        if (card.gender.isNotBlank()) {
            Spacer(Modifier.height(4.dp))
            Text("Gender: ${card.gender}", color = Aadhaar.CardBrown, fontWeight = FontWeight.Bold, fontSize = 14.sp)
        }
    }
}

@Composable
private fun CardBack(name: String, address: String, regionalAddress: String) {
    // Top-left, just below the "APPROVED BY UIDAI" strip; text flows left-to-right (not centered).
    Column(
        Modifier.fillMaxSize().padding(start = 24.dp, end = 20.dp, top = 56.dp, bottom = 20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        if (name.isNotBlank()) {
            Text(name, color = Aadhaar.CardBrownDark, fontWeight = FontWeight.Bold, fontSize = 17.sp,
                textAlign = TextAlign.Start)
        }
        Text(if (address.isNotBlank()) address else "Address not available",
            color = Aadhaar.CardBrown, fontWeight = FontWeight.Medium, fontSize = 12.sp, lineHeight = 17.sp,
            textAlign = TextAlign.Start)
        if (regionalAddress.isNotBlank()) {
            Text(regionalAddress, color = Aadhaar.CardBrown, fontWeight = FontWeight.Medium, fontSize = 12.sp,
                lineHeight = 17.sp, textAlign = TextAlign.Start)
        }
    }
}

@Composable
fun PrimaryButton(text: String, modifier: Modifier = Modifier, enabled: Boolean = true, onClick: () -> Unit) {
    Button(
        onClick = onClick, enabled = enabled,
        modifier = modifier.fillMaxWidth().height(52.dp),
        shape = RoundedCornerShape(10.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Aadhaar.Navy, disabledContainerColor = Aadhaar.Navy.copy(alpha = 0.35f))
    ) { Text(text, fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color.White) }
}

@Composable
fun SaffronButton(text: String, modifier: Modifier = Modifier, enabled: Boolean = true, onClick: () -> Unit) {
    // Pehchaan uses the navy primary for the main CTA.
    Button(
        onClick = onClick, enabled = enabled,
        modifier = modifier.fillMaxWidth().height(52.dp),
        shape = RoundedCornerShape(10.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Aadhaar.Navy, disabledContainerColor = Aadhaar.Navy.copy(alpha = 0.35f))
    ) { Text(text, fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color.White) }
}

@Composable
fun OutlineActionButton(text: String, modifier: Modifier = Modifier, onClick: () -> Unit) {
    OutlinedButton(
        onClick = onClick,
        modifier = modifier.fillMaxWidth().height(50.dp),
        shape = RoundedCornerShape(10.dp),
        border = androidx.compose.foundation.BorderStroke(1.5.dp, Aadhaar.Navy),
        colors = ButtonDefaults.outlinedButtonColors(contentColor = Aadhaar.Navy)
    ) { Text(text, fontSize = 14.sp, fontWeight = FontWeight.Bold) }
}

@Composable
fun ActionListItem(title: String, subtitle: String, badge: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Card(
        onClick = onClick,
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Aadhaar.Surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(42.dp).clip(RoundedCornerShape(12.dp)).background(Aadhaar.BgWarm),
                contentAlignment = Alignment.Center
            ) { Text(badge, fontSize = 18.sp) }
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(title, fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Aadhaar.Ink)
                Text(subtitle, fontSize = 12.sp, color = Aadhaar.Muted)
            }
            Text("›", fontSize = 24.sp, color = Aadhaar.Muted)
        }
    }
}

@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(text.uppercase(), modifier = modifier, fontSize = 10.sp, fontWeight = FontWeight.Bold,
        color = Aadhaar.Muted, letterSpacing = 1.5.sp)
}

/** Pehchaan's Lottie success tick (res/raw/success_anim.json). */
@Composable
fun LottieSuccess(size: Int = 150, modifier: Modifier = Modifier) {
    val composition by rememberLottieComposition(LottieCompositionSpec.RawRes(R.raw.success_anim))
    LottieAnimation(composition = composition, iterations = 1, modifier = modifier.size(size.dp))
}
