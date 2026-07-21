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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.stegno_core.*

@Composable
internal fun RevealTab(readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var stegos by remember { mutableStateOf<List<ByteArray>>(emptyList()) }
    var names by remember { mutableStateOf<List<String>>(emptyList()) }
    var pass by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<Pair<Boolean, String>?>(null) }
    var revealedText by remember { mutableStateOf<String?>(null) }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        try {
            stegos = uris.map { readUri(it) }
            names = uris.map { displayNameOf(context, it) }
            out = null; revealedText = null
        } catch (e: Exception) {
            out = false to (e.message ?: "Could not read those files")
        }
    }
    val save = rememberFileSaver(
        writeUri,
        onComplete = { n -> out = true to "Recovered $n file(s)." },
        onError = { out = false to it },
    )

    SectionCard("Reveal a secret", "Pick the stego file(s) and a password. Carrier and method are detected.") {
        Field("Stego file(s)")
        PickButton(revealButtonLabel(names)) { pick.launch(arrayOf("*/*")) }
        Field("Password")
        OutlinedTextField(
            pass, { pass = it }, Modifier.fillMaxWidth(),
            visualTransformation = PasswordVisualTransformation(),
            placeholder = { Text("The password used to hide it") },
        )
        PrimaryButton(if (busy) "Revealing…" else "Reveal", stegos.isNotEmpty(), busy) {
            busy = true; out = null; revealedText = null
            run(scope, { busy = false }) {
                try {
                    val revealed = withContext(Dispatchers.Default) { revealFrom(stegos, pass) }
                    when (revealed) {
                        is Revealed.None -> out = false to "No hidden data found (or wrong password)."
                        is Revealed.Text -> { revealedText = revealed.text; out = true to "Revealed." }
                        is Revealed.File -> save(listOf(OutFile(revealed.name, revealed.bytes)))
                        is Revealed.Files -> save(revealed.files.map { OutFile(it.name, it.bytes) })
                    }
                } catch (e: Exception) {
                    out = false to (e.message ?: "Could not reveal anything")
                }
            }
        }
        out?.let { Banner(it.first, it.second) }
        revealedText?.let {
            Surface(
                Modifier.fillMaxWidth().padding(top = 10.dp), shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant,
            ) { Text(it, Modifier.padding(13.dp)) }
        }
    }
}

private fun revealButtonLabel(names: List<String>): String = when {
    names.isEmpty() -> "🗂️ Choose the file(s) — any type. If it was split, pick every part."
    names.size == 1 -> "✅ ${names[0].takeLast(28)}"
    else -> "✅ ${names.size} files"
}

/**
 * Composite covers every scheme the composer can produce. A file hidden by an
 * older single-method embed still opens, so fall back to the auto-detector.
 */
private fun revealFrom(stegos: List<ByteArray>, pass: String): Revealed {
    val composite = extractComposite(stegos.map { ByteChunk(it) }, pass)
    if (composite !is Revealed.None || stegos.size != 1) return composite
    return runCatching { extractAuto(stegos[0], pass).revealed }.getOrDefault(Revealed.None)
}
