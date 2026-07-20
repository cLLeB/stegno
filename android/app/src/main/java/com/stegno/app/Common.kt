package com.stegno.app

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.material3.MenuAnchorType
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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

/* ---------------- Dropdowns ---------------- */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun MethodDropdown(methods: List<uniffi.stegno_core.MethodInfo>, selected: String, onSelect: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    val label = methods.firstOrNull { it.id == selected }?.displayName ?: selected
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
            value = label, onValueChange = {}, readOnly = true,
            modifier = Modifier.fillMaxWidth().menuAnchor(MenuAnchorType.PrimaryNotEditable),
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            methods.forEach { m ->
                DropdownMenuItem(text = { Text(m.displayName) }, onClick = { onSelect(m.id); expanded = false })
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun LabeledDropdown(labels: List<String>, selected: Int, onSelect: (Int) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
            value = labels[selected], onValueChange = {}, readOnly = true,
            modifier = Modifier.fillMaxWidth().menuAnchor(MenuAnchorType.PrimaryNotEditable),
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            labels.forEachIndexed { i, l ->
                DropdownMenuItem(text = { Text(l) }, onClick = { onSelect(i); expanded = false })
            }
        }
    }
}
