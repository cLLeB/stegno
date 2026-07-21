package com.stegno.app

import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.material3.MenuAnchorType
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import uniffi.stegno_core.CoverInfo
import uniffi.stegno_core.PassphraseStrength

/* ---------------- Shared building blocks ---------------- */

@Composable
internal fun SectionCard(title: String, hint: String, content: @Composable ColumnScope.() -> Unit) {
    Card(
        Modifier.fillMaxWidth().padding(bottom = 16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(18.dp),
    ) {
        Column(Modifier.padding(18.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(hint, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            Spacer(Modifier.height(12.dp))
            content()
        }
    }
}

@Composable
internal fun PickButton(label: String, onClick: () -> Unit) {
    OutlinedButton(onClick = onClick, Modifier.fillMaxWidth().padding(top = 8.dp), shape = RoundedCornerShape(12.dp)) {
        Text(label)
    }
}

@Composable
internal fun PrimaryButton(label: String, enabled: Boolean, busy: Boolean, onClick: () -> Unit) {
    Button(
        onClick = onClick, enabled = enabled && !busy,
        modifier = Modifier.fillMaxWidth().padding(top = 16.dp), shape = RoundedCornerShape(12.dp)
    ) {
        if (busy) { CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp, color = Color.White); Spacer(Modifier.width(8.dp)) }
        Text(label, fontWeight = FontWeight.Bold)
    }
}

@Composable
internal fun Banner(ok: Boolean, text: String) {
    val c = if (ok) Color(0xFF0CA678) else Color(0xFFE23B3B)
    Surface(
        Modifier.fillMaxWidth().padding(top = 14.dp), shape = RoundedCornerShape(12.dp),
        color = c.copy(alpha = 0.14f)
    ) { Text((if (ok) "✅ " else "⚠️ ") + text, Modifier.padding(13.dp), color = c, fontWeight = FontWeight.SemiBold) }
}

@Composable
internal fun Field(label: String) {
    Text(label.uppercase(), style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.outline, fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(top = 12.dp, bottom = 4.dp))
}

/** One metric row: a label on the left, a value on the right. */
@Composable
internal fun StatRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(top = 6.dp)) {
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline)
        Text(value, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
    }
}

/** A read-only, monospace value the user can copy with one tap. */
@Composable
internal fun CopyRow(value: String, label: String? = null) {
    val clip = LocalClipboardManager.current
    Surface(
        Modifier.fillMaxWidth().padding(top = 8.dp), shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Row(Modifier.padding(start = 12.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f).padding(vertical = 10.dp)) {
                label?.let { Text(it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline) }
                Text(value, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, maxLines = 3)
            }
            TextButton(onClick = { clip.setText(AnnotatedString(value)) }) { Text("Copy") }
        }
    }
}

/** Decode PNG/JPEG bytes into a Compose bitmap, or null if undecodable. */
internal fun decodeImage(bytes: ByteArray): ImageBitmap? =
    runCatching { BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.asImageBitmap() }.getOrNull()

/** Render decoded image bytes inside a rounded card. */
@Composable
internal fun ImagePreview(bytes: ByteArray) {
    val bmp = remember(bytes) { decodeImage(bytes) } ?: return
    Surface(
        Modifier.fillMaxWidth().padding(top = 10.dp), shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Image(bmp, contentDescription = null, modifier = Modifier.fillMaxWidth().padding(6.dp))
    }
}

internal fun run(scope: CoroutineScope, onDone: () -> Unit, block: suspend () -> Unit) {
    scope.launch { try { block() } finally { onDone() } }
}

/** A two-way switch rendered as a pair of chips. */
@Composable
internal fun SegToggle(labels: List<String>, selected: Int, enabled: Boolean = true, onSelect: (Int) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(top = 4.dp)) {
        labels.forEachIndexed { i, label ->
            FilterChip(
                selected = selected == i, onClick = { onSelect(i) }, enabled = enabled,
                label = { Text(label) }, modifier = Modifier.padding(end = 8.dp),
            )
        }
    }
}

/** Live passphrase feedback: a coloured bar plus the engine's own verdict. */
@Composable
internal fun StrengthMeter(strength: PassphraseStrength?) {
    val s = strength ?: return
    val labels = listOf("Very weak", "Weak", "Fair", "Strong", "Excellent")
    val col = when {
        s.score >= 3u -> Color(0xFF0CA678)
        s.score >= 2u -> Color(0xFFE8770C)
        else -> Color(0xFFE23B3B)
    }
    LinearProgressIndicator(
        progress = { (s.score.toInt() + 1) / 5f },
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp), color = col,
    )
    Text(
        "${labels[s.score.toInt()]} · ~${s.entropyBits.toInt()} bits · cracks in ${s.crackTimeDisplay}" +
            if (s.warning.isNotEmpty()) " · ${s.warning}" else "",
        style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline,
        modifier = Modifier.padding(top = 4.dp),
    )
}

/* ---------------- Files: names, carriers, saving ---------------- */

/** A named blob waiting to be written through the system file picker. */
internal data class OutFile(val name: String, val bytes: ByteArray)

/**
 * The name the user knows the document by. Falls back to the last path segment
 * because some providers expose no OpenableColumns cursor at all.
 */
internal fun displayNameOf(context: Context, uri: Uri): String {
    val provided = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { c -> if (c.moveToFirst() && !c.isNull(0)) c.getString(0) else null }
    }.getOrNull()
    return provided ?: uri.lastPathSegment?.substringAfterLast('/') ?: "file"
}

internal fun stemOf(name: String): String = name.substringBeforeLast('.', name)

/** Original extension including the dot, or "" when there isn't one. */
internal fun extOf(name: String): String =
    name.substringAfterLast('.', "").let { if (it.isEmpty()) "" else ".$it" }

/**
 * What a stego file made from this cover should be called. Photos are re-encoded
 * to PNG (lossless is mandatory for LSB survival) so they take the engine's
 * extension; every other carrier keeps its own container, so a PDF cover stays a
 * PDF and a clip stays playable under its original extension.
 */
internal fun stegoNameFor(coverName: String?, info: CoverInfo?, fallbackStem: String): String {
    val stem = coverName?.let(::stemOf) ?: fallbackStem
    if (info?.preservesContainer == true && coverName != null) return "$stem-hidden${extOf(coverName)}"
    return "$stem-hidden.${info?.extension ?: "png"}"
}

/** Human label for a carrier kind, for the capacity readout. */
internal val KIND_LABEL = mapOf(
    "image" to "photo", "audio" to "audio", "text" to "text",
    "video" to "video (frame-level)", "bytes" to "file (appended)",
)

internal fun kindLabel(kind: String?): String = KIND_LABEL[kind] ?: "file"

/**
 * Writes a queue of files through SAF one prompt at a time — the platform gives
 * us no way to save several documents in a single dialog.
 */
@Composable
internal fun rememberFileSaver(
    writeUri: (Uri, ByteArray) -> Unit,
    onComplete: (Int) -> Unit,
    onError: (String) -> Unit,
): (List<OutFile>) -> Unit {
    var queue by remember { mutableStateOf<List<OutFile>>(emptyList()) }
    var index by remember { mutableStateOf(0) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        val i = index
        if (uri == null || i >= queue.size) return@rememberLauncherForActivityResult
        val total = queue.size
        try {
            writeUri(uri, queue[i].bytes)
            if (i + 1 < total) index = i + 1 else { queue = emptyList(); onComplete(total) }
        } catch (e: Exception) {
            queue = emptyList()
            onError(e.message ?: "Could not save the file")
        }
    }
    LaunchedEffect(queue, index) {
        if (index in queue.indices) launcher.launch(queue[index].name)
    }
    return { files -> if (files.isNotEmpty()) { index = 0; queue = files } }
}

/* ---------------- Dropdowns ---------------- */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun MethodDropdown(
    methods: List<uniffi.stegno_core.MethodInfo>,
    selected: String,
    enabled: Boolean = true,
    showMedia: Boolean = false,
    onSelect: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    fun caption(m: uniffi.stegno_core.MethodInfo) =
        if (showMedia) "${m.displayName} · ${m.media.lowercase()}" else m.displayName
    val label = methods.firstOrNull { it.id == selected }?.let(::caption) ?: selected
    ExposedDropdownMenuBox(expanded = expanded && enabled, onExpandedChange = { if (enabled) expanded = it }) {
        OutlinedTextField(
            value = label, onValueChange = {}, readOnly = true, enabled = enabled,
            modifier = Modifier.fillMaxWidth().menuAnchor(MenuAnchorType.PrimaryNotEditable),
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded && enabled) },
        )
        ExposedDropdownMenu(expanded = expanded && enabled, onDismissRequest = { expanded = false }) {
            methods.forEach { m ->
                DropdownMenuItem(text = { Text(caption(m)) }, onClick = { onSelect(m.id); expanded = false })
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun LabeledDropdown(labels: List<String>, selected: Int, enabled: Boolean = true, onSelect: (Int) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded && enabled, onExpandedChange = { if (enabled) expanded = it }) {
        OutlinedTextField(
            value = labels[selected], onValueChange = {}, readOnly = true, enabled = enabled,
            modifier = Modifier.fillMaxWidth().menuAnchor(MenuAnchorType.PrimaryNotEditable),
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded && enabled) },
        )
        ExposedDropdownMenu(expanded = expanded && enabled, onDismissRequest = { expanded = false }) {
            labels.forEachIndexed { i, l ->
                DropdownMenuItem(text = { Text(l) }, onClick = { onSelect(i); expanded = false })
            }
        }
    }
}

/** Dims a block of controls that do not apply to the current selection. */
@Composable
internal fun Dimmed(active: Boolean, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.alpha(if (active) 1f else 0.45f)) { content() }
}
