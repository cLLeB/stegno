package com.stegno.app

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.stegno_core.MethodInfo
import uniffi.stegno_core.listMethods

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            var dark by remember { mutableStateOf<Boolean?>(null) }
            val isDark = dark ?: isSystemInDarkTheme()
            MaterialTheme(colorScheme = if (isDark) StegnoDark else StegnoLight) {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    StegnoApp(::readUri, ::writeUri, isDark) { dark = !isDark }
                }
            }
        }
    }

    private fun readUri(uri: Uri): ByteArray =
        contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IllegalStateException("Cannot read file")

    private fun writeUri(uri: Uri, bytes: ByteArray) {
        contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
            ?: throw IllegalStateException("Cannot write file")
    }
}

/* ---------------- Brand theme (deep blue) ---------------- */
private val BlueDeep = Color(0xFF1F56D6)
private val BlueDeeper = Color(0xFF163F9E)
private val StegnoLight = lightColorScheme(
    primary = BlueDeep, secondary = BlueDeeper,
    // Softened surfaces (not glaring white) with a distinctly darker outline so
    // borders on fields, cards and dropdowns stay clearly visible.
    background = Color(0xFFE5E9F2), surface = Color(0xFFF2F5FB),
    surfaceVariant = Color(0xFFE7ECF6), outline = Color(0xFF94A1BF),
    outlineVariant = Color(0xFFBDC7DB),
    primaryContainer = Color(0xFFDCE7FB), onPrimaryContainer = BlueDeep,
    onSurface = Color(0xFF15203A), onBackground = Color(0xFF15203A),
)
private val StegnoDark = darkColorScheme(
    // Near-black surfaces with a faint blue tint.
    primary = Color(0xFF4D8BFF), secondary = Color(0xFF2F6BF0),
    background = Color(0xFF030509), surface = Color(0xFF0A0E17),
    surfaceVariant = Color(0xFF111725), outline = Color(0xFF303C58),
    outlineVariant = Color(0xFF1C2439),
    primaryContainer = Color(0xFF0E1A2E), onPrimaryContainer = Color(0xFF4D8BFF),
    onSurface = Color(0xFFE9EEF8), onBackground = Color(0xFFE9EEF8),
)

/* ---------------- Root ---------------- */
private data class Sub(val id: String, val label: String)
private data class Grp(val label: String, val subs: List<Sub>)

// Hide is one unified composer; everything analytical lives behind one group.
private val GROUPS = listOf(
    Grp("🔒 Hide", listOf(Sub("hide", "🔒 Hide"))),
    Grp("🔑 Reveal", listOf(Sub("reveal", "🔑 Reveal"))),
    Grp("🔬 Analyze", listOf(
        Sub("inspect", "🔍 Inspect"), Sub("lab", "🧪 Lab"),
        Sub("keys", "🔐 Key-shares"), Sub("clean", "🧼 Clean"))),
)

@Composable
fun StegnoApp(
    readUri: (Uri) -> ByteArray,
    writeUri: (Uri, ByteArray) -> Unit,
    isDark: Boolean,
    onToggleTheme: () -> Unit,
) {
    var group by remember { mutableStateOf(0) }
    var panel by remember { mutableStateOf("hide") }
    var methods by remember { mutableStateOf<List<MethodInfo>>(emptyList()) }

    LaunchedEffect(Unit) {
        methods = runCatching { withContext(Dispatchers.Default) { listMethods() } }.getOrDefault(emptyList())
    }

    Column(Modifier.fillMaxSize()) {
        // Top: just the name and the theme toggle.
        Row(
            Modifier.fillMaxWidth().padding(start = 18.dp, end = 12.dp, top = 14.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Stegno", color = MaterialTheme.colorScheme.primary, fontSize = 22.sp,
                fontWeight = FontWeight.ExtraBold, modifier = Modifier.weight(1f))
            Surface(
                onClick = onToggleTheme, shape = CircleShape,
                color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
            ) { Box(Modifier.size(40.dp), contentAlignment = Alignment.Center) { Text(if (isDark) "☀️" else "🌙", fontSize = 17.sp) } }
        }

        // Three simple groups.
        TabRow(selectedTabIndex = group, containerColor = MaterialTheme.colorScheme.background) {
            GROUPS.forEachIndexed { i, g ->
                Tab(selected = group == i, onClick = { group = i; panel = g.subs.first().id },
                    text = { Text(g.label, fontWeight = FontWeight.SemiBold) })
            }
        }

        // Sub-options for the selected group (only when there is more than one).
        val current = GROUPS[group]
        if (current.subs.size > 1) {
            Row(
                Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 8.dp),
            ) {
                current.subs.forEach { s ->
                    FilterChip(selected = panel == s.id, onClick = { panel = s.id },
                        label = { Text(s.label) }, modifier = Modifier.padding(end = 8.dp))
                }
            }
        }

        // Content, sliding in on each switch.
        AnimatedContent(
            targetState = panel,
            transitionSpec = {
                (slideInHorizontally(tween(280)) { it / 4 } + fadeIn(tween(280))) togetherWith fadeOut(tween(140))
            },
            modifier = Modifier.weight(1f),
            label = "panel",
        ) { p ->
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
                when (p) {
                    "hide" -> HideTab(methods, readUri, writeUri)
                    "reveal" -> RevealTab(readUri, writeUri)
                    "keys" -> KeysTab(readUri, writeUri)
                    "inspect" -> InspectTab(readUri)
                    "lab" -> LabTab(methods, readUri, writeUri)
                    else -> CleanTab(readUri, writeUri)
                }
                Spacer(Modifier.height(18.dp))
                Text(
                    "Runs on your device. No uploads. · ${methods.size} methods",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.outline,
                )
                Spacer(Modifier.height(24.dp))
            }
        }
    }
}
