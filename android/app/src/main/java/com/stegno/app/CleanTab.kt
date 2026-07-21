package com.stegno.app

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.stegno_core.*

@Composable
internal fun CleanTab(readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var data by remember { mutableStateOf<ByteArray?>(null) }
    var name by remember { mutableStateOf("file") }
    var busy by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<Pair<Boolean, String>?>(null) }
    var actions by remember { mutableStateOf<List<String>>(emptyList()) }
    var doneMsg by remember { mutableStateOf("") }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        try {
            data = readUri(uri); name = displayNameOf(context, uri); out = null; actions = emptyList()
        } catch (e: Exception) {
            out = false to (e.message ?: "Could not read that file")
        }
    }
    val save = rememberFileSaver(
        writeUri,
        onComplete = { out = true to doneMsg },
        onError = { out = false to it },
    )

    SectionCard("Remove hidden data", "Destroys any hidden payload. The file still looks the same.") {
        Field("File to clean")
        PickButton(if (data != null) "✅ ${name.takeLast(28)}" else "🧼 Choose a file") { pick.launch(arrayOf("*/*")) }
        PrimaryButton(if (busy) "Cleaning…" else "Sanitize & save", data != null, busy) {
            busy = true; out = null
            run(scope, { busy = false }) {
                try {
                    val r = withContext(Dispatchers.Default) { sanitize(data!!) }
                    actions = r.actions
                    doneMsg = if (r.changed) "Cleaned. Hidden payload destroyed." else "Nothing hidden was found."
                    save(listOf(OutFile(cleanNameFor(name, r.format), r.cleaned)))
                } catch (e: Exception) { out = false to (e.message ?: "Could not clean that file") }
            }
        }
        out?.let { Banner(it.first, it.second) }
        actions.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 4.dp)) }
    }
}

/** Photos are re-encoded to PNG; anything else keeps the extension it arrived with. */
private fun cleanNameFor(name: String, format: String): String {
    val ext = if (format == "image") ".png" else extOf(name).ifEmpty { ".txt" }
    return "${stemOf(name)}-clean$ext"
}
