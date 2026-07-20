package com.stegno.app

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.stegno_core.SecretShare
import uniffi.stegno_core.sssCombine
import uniffi.stegno_core.sssSplit

/** "3-1a2b3c…" - the x-coordinate, a dash, then the y bytes in hex. */
private fun SecretShare.encode(): String =
    "${x.toInt()}-" + y.joinToString("") { "%02x".format(it) }

private fun parseShare(line: String): SecretShare? {
    val t = line.trim()
    val dash = t.indexOf('-')
    if (dash <= 0) return null
    val x = t.substring(0, dash).toIntOrNull()?.takeIf { it in 1..255 } ?: return null
    val hex = t.substring(dash + 1).trim()
    if (hex.isEmpty() || hex.length % 2 != 0) return null
    val bytes = runCatching {
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }.getOrNull() ?: return null
    return SecretShare(x.toUByte(), bytes)
}

@Composable
internal fun KeysTab() {
    val scope = rememberCoroutineScope()
    var mode by remember { mutableStateOf(0) } // 0 = split, 1 = combine

    SectionCard("Split a secret into key-shares",
        "Any threshold of shares rebuilds a secret.") {
        Row(Modifier.fillMaxWidth().padding(bottom = 4.dp)) {
            listOf("Split", "Combine").forEachIndexed { i, label ->
                FilterChip(selected = mode == i, onClick = { mode = i }, label = { Text(label) },
                    modifier = Modifier.padding(end = 8.dp))
            }
        }
        if (mode == 0) SplitPane() else CombinePane(scope)
    }
}

@Composable
private fun ColumnScope.SplitPane() {
    val scope = rememberCoroutineScope()
    var secret by remember { mutableStateOf("") }
    var threshold by remember { mutableStateOf(2) }
    var shares by remember { mutableStateOf(3) }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<List<SecretShare>?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    Field("Secret")
    OutlinedTextField(secret, { secret = it }, Modifier.fillMaxWidth(), minLines = 2,
        placeholder = { Text("The passphrase or note to split") })

    Field("Threshold (needed to rebuild)")
    LabeledDropdown((2..8).map { "$it shares" }, threshold - 2) {
        threshold = it + 2; if (shares < threshold) shares = threshold
    }
    Field("Total shares to create")
    LabeledDropdown((threshold..8).map { "$it shares" }, shares - threshold) { shares = it + threshold }

    PrimaryButton(if (busy) "Splitting…" else "Split into shares", secret.isNotEmpty(), busy) {
        busy = true; error = null; result = null
        run(scope, { busy = false }) {
            try {
                result = withContext(Dispatchers.Default) {
                    sssSplit(secret.toByteArray(), threshold.toUByte(), shares.toUByte())
                }
            } catch (e: Exception) { error = e.message ?: "Failed" }
        }
    }
    error?.let { Banner(false, it) }
    result?.let { list ->
        Text("Give each person one share. Any $threshold of $shares rebuild the secret.",
            style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline,
            modifier = Modifier.padding(top = 12.dp))
        list.forEachIndexed { i, s -> CopyRow(s.encode(), "Share ${i + 1}") }
    }
}

@Composable
private fun ColumnScope.CombinePane(scope: kotlinx.coroutines.CoroutineScope) {
    var text by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<Pair<Boolean, String>?>(null) }

    Field("Paste shares (one per line)")
    OutlinedTextField(text, { text = it }, Modifier.fillMaxWidth(), minLines = 4,
        placeholder = { Text("3-1a2b3c…\n5-9f8e7d…") })
    PrimaryButton(if (busy) "Rebuilding…" else "Reconstruct secret", text.isNotBlank(), busy) {
        busy = true; out = null
        run(scope, { busy = false }) {
            val parsed = text.lines().mapNotNull { parseShare(it) }
            if (parsed.size < 2) { out = false to "Need at least 2 valid shares."; return@run }
            try {
                val bytes = withContext(Dispatchers.Default) { sssCombine(parsed) }
                out = true to String(bytes)
            } catch (e: Exception) { out = false to (e.message ?: "Could not reconstruct - wrong or too few shares.") }
        }
    }
    out?.let { (ok, msg) ->
        if (ok) {
            Banner(true, "Reconstructed the secret.")
            Surface(Modifier.fillMaxWidth().padding(top = 10.dp), shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant) {
                Text(msg, Modifier.padding(13.dp), fontWeight = FontWeight.SemiBold)
            }
        } else Banner(false, msg)
    }
}
