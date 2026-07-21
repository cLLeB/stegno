package com.stegno.app

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.stegno_core.FileRecord
import uniffi.stegno_core.Revealed
import uniffi.stegno_core.Secret
import uniffi.stegno_core.SecretShare
import uniffi.stegno_core.sssCombineSecret
import uniffi.stegno_core.sssSplitSecret

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
internal fun KeysTab(readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    var mode by remember { mutableStateOf(0) } // 0 = split, 1 = combine

    SectionCard(
        "Key-shares",
        "Any threshold of shares rebuilds a secret. A shared file comes back under its own name.",
    ) {
        SegToggle(listOf("Split", "Combine"), mode) { mode = it }
        if (mode == 0) SplitPane(readUri) else CombinePane(writeUri)
    }
}

@Composable
private fun ColumnScope.SplitPane(readUri: (Uri) -> ByteArray) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var isText by remember { mutableStateOf(true) }
    var secret by remember { mutableStateOf("") }
    var file by remember { mutableStateOf<FileRecord?>(null) }
    var threshold by remember { mutableStateOf(2) }
    var shares by remember { mutableStateOf(3) }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<List<SecretShare>?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        try {
            file = FileRecord(displayNameOf(context, uri), readUri(uri)); error = null
        } catch (e: Exception) {
            error = e.message ?: "Could not read that file"
        }
    }

    Field("Secret")
    SegToggle(listOf("Text", "File"), if (isText) 0 else 1) { isText = it == 0 }
    if (isText) {
        OutlinedTextField(
            secret, { secret = it }, Modifier.fillMaxWidth().padding(top = 8.dp), minLines = 2,
            placeholder = { Text("The passphrase or note to split") },
        )
    } else {
        PickButton(file?.let { "✅ ${it.name.takeLast(28)}" } ?: "📎 Choose a file") { pick.launch(arrayOf("*/*")) }
    }

    Field("Threshold (needed to rebuild)")
    LabeledDropdown((2..8).map { "$it shares" }, threshold - 2) {
        threshold = it + 2; if (shares < threshold) shares = threshold
    }
    Field("Total shares to create")
    LabeledDropdown((threshold..8).map { "$it shares" }, shares - threshold) { shares = it + threshold }

    val ready = if (isText) secret.isNotEmpty() else file != null
    PrimaryButton(if (busy) "Splitting…" else "Split into shares", ready, busy) {
        busy = true; error = null; result = null
        run(scope, { busy = false }) {
            // Split the secret itself, not raw bytes, so a shared file recombines
            // under its own filename rather than as anonymous bytes.
            val payload = if (isText) Secret.Text(secret) else Secret.Files(listOf(file!!))
            try {
                result = withContext(Dispatchers.Default) {
                    sssSplitSecret(payload, threshold.toUByte(), shares.toUByte())
                }
            } catch (e: Exception) { error = e.message ?: "Could not split that secret" }
        }
    }
    error?.let { Banner(false, it) }
    result?.let { list ->
        Text(
            "Give each person one share. Any $threshold of $shares rebuild the secret.",
            style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline,
            modifier = Modifier.padding(top = 12.dp),
        )
        list.forEachIndexed { i, s -> CopyRow(s.encode(), "Share ${i + 1}") }
    }
}

@Composable
private fun ColumnScope.CombinePane(writeUri: (Uri, ByteArray) -> Unit) {
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<Pair<Boolean, String>?>(null) }
    var revealedText by remember { mutableStateOf<String?>(null) }

    val save = rememberFileSaver(
        writeUri,
        onComplete = { n -> out = true to "Rebuilt $n file(s)." },
        onError = { out = false to it },
    )

    Field("Paste shares (one per line)")
    OutlinedTextField(
        text, { text = it }, Modifier.fillMaxWidth(), minLines = 4,
        placeholder = { Text("3-1a2b3c…\n5-9f8e7d…") },
    )
    PrimaryButton(if (busy) "Rebuilding…" else "Reconstruct secret", text.isNotBlank(), busy) {
        busy = true; out = null; revealedText = null
        run(scope, { busy = false }) {
            val parsed = text.lines().mapNotNull { parseShare(it) }
            if (parsed.size < 2) { out = false to "Need at least 2 valid shares."; return@run }
            try {
                when (val rv = withContext(Dispatchers.Default) { sssCombineSecret(parsed) }) {
                    is Revealed.None -> out = false to "Could not reconstruct — wrong or too few shares."
                    is Revealed.Text -> { revealedText = rv.text; out = true to "Reconstructed the secret." }
                    is Revealed.File -> save(listOf(OutFile(rv.name, rv.bytes)))
                    is Revealed.Files -> save(rv.files.map { OutFile(it.name, it.bytes) })
                }
            } catch (e: Exception) {
                out = false to (e.message ?: "Could not reconstruct — wrong or too few shares.")
            }
        }
    }
    out?.let { Banner(it.first, it.second) }
    revealedText?.let {
        Surface(
            Modifier.fillMaxWidth().padding(top = 10.dp), shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.surfaceVariant,
        ) { Text(it, Modifier.padding(13.dp), fontWeight = FontWeight.SemiBold) }
    }
}
