package com.stegno.app

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.stegno_core.*

@Composable
internal fun SplitTab(methods: List<MethodInfo>, readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    var mode by remember { mutableStateOf(0) } // 0 = hide across, 1 = reveal from
    val imageMethods = methods.filter { it.media == "Image" }

    SectionCard("Split across several photos",
        "Spread one secret over multiple photos — every photo is needed to rebuild it. Losing any one keeps the secret safe.") {
        Row(Modifier.fillMaxWidth().padding(bottom = 4.dp)) {
            listOf("Hide across", "Reveal from").forEachIndexed { i, label ->
                FilterChip(selected = mode == i, onClick = { mode = i }, label = { Text(label) },
                    modifier = Modifier.padding(end = 8.dp))
            }
        }
        if (mode == 0) SplitHide(imageMethods, readUri, writeUri) else SplitReveal(imageMethods, readUri, writeUri)
    }
}

@Composable
private fun ColumnScope.SplitHide(methods: List<MethodInfo>, readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    val scope = rememberCoroutineScope()
    var covers by remember { mutableStateOf<List<ByteArray>>(emptyList()) }
    var text by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var method by remember { mutableStateOf("lsb_seeded") }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<Pair<Boolean, String>?>(null) }
    // Sequential multi-file save: remaining chunks and current index.
    var pending by remember { mutableStateOf<List<ByteArray>>(emptyList()) }
    var saveIndex by remember { mutableStateOf(0) }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNotEmpty()) covers = uris.map { readUri(it) }
    }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("image/png")) { uri ->
        val idx = saveIndex
        if (uri != null && idx < pending.size) {
            writeUri(uri, pending[idx])
            val next = idx + 1
            // Advancing saveIndex triggers the LaunchedEffect below to prompt for the next file.
            if (next < pending.size) saveIndex = next
            else result = true to "Saved ${pending.size} photos. All are needed to rebuild."
        }
    }
    // Launch the next save whenever the index advances and there is more to write.
    LaunchedEffect(saveIndex, pending) {
        if (pending.isNotEmpty() && saveIndex in 1 until pending.size) {
            saver.launch("part${saveIndex + 1}.png")
        }
    }

    Field("Cover photos (pick 2 or more)")
    PickButton(if (covers.isNotEmpty()) "✅ ${covers.size} photos" else "📷 Choose photos") { pick.launch(arrayOf("image/*")) }
    Field("Secret message")
    OutlinedTextField(text, { text = it }, Modifier.fillMaxWidth(), minLines = 3,
        placeholder = { Text("The message to spread across the photos") })
    Field("Password")
    OutlinedTextField(pass, { pass = it }, Modifier.fillMaxWidth(), visualTransformation = PasswordVisualTransformation(),
        placeholder = { Text("A strong passphrase") })
    Field("Method")
    MethodDropdown(methods, method) { method = it }

    PrimaryButton(if (busy) "Hiding…" else "Split & save each", covers.size >= 2 && text.isNotEmpty() && pass.isNotEmpty(), busy) {
        busy = true; result = null
        run(scope, { busy = false }) {
            try {
                val chunks = withContext(Dispatchers.Default) {
                    embedSplit(method, covers.map { ByteChunk(it) }, Secret.Text(text), pass)
                }.map { it.bytes }
                pending = chunks; saveIndex = 0
                if (chunks.isNotEmpty()) saver.launch("part1.png")
            } catch (e: Exception) { result = false to (e.message ?: "Failed") }
        }
    }
    result?.let { Banner(it.first, it.second) }
}

@Composable
private fun ColumnScope.SplitReveal(methods: List<MethodInfo>, readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    val scope = rememberCoroutineScope()
    var stegos by remember { mutableStateOf<List<ByteArray>>(emptyList()) }
    var pass by remember { mutableStateOf("") }
    var method by remember { mutableStateOf("lsb_seeded") }
    var busy by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<Triple<Boolean, String, String?>?>(null) }
    var pendingFile by remember { mutableStateOf<Pair<String, ByteArray>?>(null) }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNotEmpty()) stegos = uris.map { readUri(it) }
    }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val f = pendingFile
        if (uri != null && f != null) writeUri(uri, f.second)
    }

    Field("All the photos")
    PickButton(if (stegos.isNotEmpty()) "✅ ${stegos.size} photos" else "🗂️ Choose every photo") { pick.launch(arrayOf("image/*")) }
    Field("Password")
    OutlinedTextField(pass, { pass = it }, Modifier.fillMaxWidth(), visualTransformation = PasswordVisualTransformation(),
        placeholder = { Text("The password used to hide it") })
    Field("Method")
    MethodDropdown(methods, method) { method = it }

    PrimaryButton(if (busy) "Rebuilding…" else "Rebuild secret", stegos.size >= 2 && pass.isNotEmpty(), busy) {
        busy = true; out = null
        run(scope, { busy = false }) {
            try {
                val r = withContext(Dispatchers.Default) { extractSplit(method, stegos.map { ByteChunk(it) }, pass) }
                when (r) {
                    is Revealed.None -> out = Triple(false, "Nothing found (wrong password, method, or missing a photo).", null)
                    is Revealed.Text -> out = Triple(true, "Rebuilt the secret.", r.text)
                    is Revealed.File -> { pendingFile = r.name to r.bytes; saver.launch(r.name); out = Triple(true, "Recovered file ${r.name}", null) }
                    is Revealed.Files -> out = Triple(true, "Recovered ${r.files.size} files", null)
                }
            } catch (e: Exception) { out = Triple(false, e.message ?: "Failed", null) }
        }
    }
    out?.let { (ok, msg, revealed) ->
        Banner(ok, msg)
        revealed?.let {
            Surface(Modifier.fillMaxWidth().padding(top = 10.dp),
                shape = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant) { Text(it, Modifier.padding(13.dp)) }
        }
    }
}
