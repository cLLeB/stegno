package com.stegno.app

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
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

/* ---------------- Brand theme ---------------- */
internal val Indigo = Color(0xFF6366F1)
internal val Violet = Color(0xFF8B5CF6)
private val StegnoLight = lightColorScheme(
    primary = Indigo, secondary = Violet,
    background = Color(0xFFE9E7F3), surface = Color(0xFFF7F6FC),
    surfaceVariant = Color(0xFFEFEEF7), outline = Color(0xFFBCB9D6),
    onSurface = Color(0xFF1C1B2E), onBackground = Color(0xFF1C1B2E),
)
private val StegnoDark = darkColorScheme(
    primary = Color(0xFF818CF8), secondary = Color(0xFFA78BFA),
    background = Color(0xFF0D0C14), surface = Color(0xFF17161F),
    surfaceVariant = Color(0xFF1E1C28), outline = Color(0xFF3A3750),
    onSurface = Color(0xFFECEAF5), onBackground = Color(0xFFECEAF5),
)

/* ---------------- Root ---------------- */
private data class TabDef(val label: String, val emoji: String)

@Composable
fun StegnoApp(
    readUri: (Uri) -> ByteArray,
    writeUri: (Uri, ByteArray) -> Unit,
    isDark: Boolean,
    onToggleTheme: () -> Unit,
) {
    var tab by remember { mutableStateOf(0) }
    var methods by remember { mutableStateOf<List<MethodInfo>>(emptyList()) }

    LaunchedEffect(Unit) {
        methods = runCatching { withContext(Dispatchers.Default) { listMethods() } }.getOrDefault(emptyList())
    }

    val tabs = listOf(
        TabDef("Hide", "🖼️"), TabDef("Reveal", "🔑"), TabDef("Share", "👥"),
        TabDef("Split", "🧩"), TabDef("Keys", "🔐"), TabDef("Inspect", "🔍"),
        TabDef("Lab", "🧪"), TabDef("Clean", "🧼"),
    )

    Column(Modifier.fillMaxSize()) {
        Hero(isDark, onToggleTheme)
        ScrollableTabRow(
            selectedTabIndex = tab,
            edgePadding = 12.dp,
            containerColor = MaterialTheme.colorScheme.background,
        ) {
            tabs.forEachIndexed { i, t ->
                Tab(selected = tab == i, onClick = { tab = i },
                    text = { Text("${t.emoji} ${t.label}", fontWeight = FontWeight.SemiBold) })
            }
        }
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)
        ) {
            when (tab) {
                0 -> HideTab(methods, readUri, writeUri)
                1 -> RevealTab(readUri, writeUri)
                2 -> ShareTab(readUri, writeUri)
                3 -> SplitTab(methods, readUri, writeUri)
                4 -> KeysTab()
                5 -> InspectTab(readUri)
                6 -> LabTab(methods, readUri, writeUri)
                else -> CleanTab(readUri, writeUri)
            }
            Spacer(Modifier.height(18.dp))
            Text(
                "Runs entirely on your device — no uploads, no servers. · ${methods.size} methods",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.outline,
            )
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun Hero(isDark: Boolean, onToggleTheme: () -> Unit) {
    Box(
        Modifier
            .fillMaxWidth()
            .background(Brush.linearGradient(listOf(Indigo, Violet)))
            .padding(horizontal = 18.dp, vertical = 20.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(44.dp).background(Color.White.copy(alpha = 0.18f), RoundedCornerShape(13.dp)),
                contentAlignment = Alignment.Center
            ) { Text("🔒", fontSize = 22.sp) }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text("Stegno", color = Color.White, fontSize = 21.sp, fontWeight = FontWeight.ExtraBold)
                Text("Hide encrypted messages in photos, text & files.",
                    color = Color.White.copy(alpha = 0.9f), fontSize = 12.5.sp)
            }
            Surface(
                onClick = onToggleTheme, shape = RoundedCornerShape(11.dp),
                color = Color.White.copy(alpha = 0.18f)
            ) { Box(Modifier.size(38.dp), contentAlignment = Alignment.Center) { Text(if (isDark) "☀️" else "🌙", fontSize = 17.sp) } }
        }
    }
}
