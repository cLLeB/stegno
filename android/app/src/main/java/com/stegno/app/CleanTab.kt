package com.stegno.app

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.stegno_core.*

@Composable
internal fun CleanTab(readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    val scope = rememberCoroutineScope()
    var data by remember { mutableStateOf<ByteArray?>(null) }
    var name by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<Pair<Boolean, String>?>(null) }
    var actions by remember { mutableStateOf<List<String>>(emptyList()) }
    var pending by remember { mutableStateOf<ByteArray?>(null) }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        data = readUri(uri); name = uri.lastPathSegment; out = null
    }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val c = pending
        if (uri != null && c != null) writeUri(uri, c)
    }

    SectionCard("Remove hidden data", "Destroys any hidden payload. Photo looks the same.") {
        Field("File to clean")
        PickButton(name?.let { "✅ ${it.takeLast(28)}" } ?: "🧼 Choose a file") { pick.launch(arrayOf("*/*")) }
        PrimaryButton(if (busy) "Cleaning…" else "Sanitize & save", data != null, busy) {
            busy = true; out = null
            run(scope, { busy = false }) {
                try {
                    val r = withContext(Dispatchers.Default) { sanitize(data!!) }
                    actions = r.actions
                    pending = r.cleaned
                    val ext = if (r.format == "image") "png" else "txt"
                    saver.launch("cleaned.$ext")
                    out = true to if (r.changed) "Cleaned. Hidden payload destroyed." else "Nothing hidden was found."
                } catch (e: Exception) { out = false to (e.message ?: "Failed") }
            }
        }
        out?.let { Banner(it.first, it.second) }
        actions.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 4.dp)) }
    }
}
