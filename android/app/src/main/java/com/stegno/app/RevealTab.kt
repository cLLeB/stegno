package com.stegno.app

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.stegno_core.*

@Composable
internal fun RevealTab(readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    val scope = rememberCoroutineScope()
    var stego by remember { mutableStateOf<ByteArray?>(null) }
    var name by remember { mutableStateOf<String?>(null) }
    var pass by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<Triple<Boolean, String, String?>?>(null) } // ok, message, revealedText
    var pendingFile by remember { mutableStateOf<Pair<String, ByteArray>?>(null) }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        stego = readUri(uri); name = uri.lastPathSegment
    }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val f = pendingFile
        if (uri != null && f != null) writeUri(uri, f.second)
    }

    SectionCard("Reveal a secret", "Open a hidden message. Method detected automatically.") {
        Field("Stego file")
        PickButton(name?.let { "✅ ${it.takeLast(28)}" } ?: "🗂️ Choose the file") { pick.launch(arrayOf("*/*")) }
        Field("Password")
        OutlinedTextField(pass, { pass = it }, Modifier.fillMaxWidth(), visualTransformation = PasswordVisualTransformation(),
            placeholder = { Text("The password used to hide it") })
        PrimaryButton(if (busy) "Revealing…" else "Reveal", stego != null, busy) {
            busy = true; out = null
            run(scope, { busy = false }) {
                try {
                    val r = withContext(Dispatchers.Default) { extractAuto(stego!!, pass) }
                    when (val rv = r.revealed) {
                        is Revealed.None -> out = Triple(false, "No hidden data found (or wrong password).", null)
                        is Revealed.Text -> out = Triple(true, "Revealed via ${r.methodId}", rv.text)
                        is Revealed.File -> { pendingFile = rv.name to rv.bytes; saver.launch(rv.name); out = Triple(true, "Recovered file ${rv.name}", null) }
                        is Revealed.Files -> { out = Triple(true, "Recovered ${rv.files.size} files", null) }
                    }
                } catch (e: Exception) { out = Triple(false, e.message ?: "Failed", null) }
            }
        }
        out?.let { (ok, msg, revealed) ->
            Banner(ok, msg)
            revealed?.let {
                Surface(Modifier.fillMaxWidth().padding(top = 10.dp), shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant) {
                    Text(it, Modifier.padding(13.dp))
                }
            }
        }
    }
}
