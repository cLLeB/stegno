package com.stegno.app

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.stegno_core.Revealed
import uniffi.stegno_core.Secret
import uniffi.stegno_core.capacity
import uniffi.stegno_core.embed
import uniffi.stegno_core.extract

private const val METHOD = "lsb_image"

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(Modifier.fillMaxSize()) { StegnoApp(::readUri, ::writeUri) }
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

@Composable
fun StegnoApp(readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    var tab by remember { mutableStateOf(0) }
    Column(
        Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
    ) {
        Text("Stegno", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Offline steganography · LSB image (PNG)",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline
        )
        Spacer(Modifier.height(12.dp))
        TabRow(selectedTabIndex = tab) {
            Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Hide") })
            Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("Extract") })
        }
        Spacer(Modifier.height(16.dp))
        if (tab == 0) HideTab(readUri, writeUri) else ExtractTab(readUri, writeUri)
        Spacer(Modifier.height(20.dp))
        Text(
            "Argon2id + AES-256-GCM · nothing leaves this device.",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.outline
        )
    }
}

@Composable
fun HideTab(readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    val scope = rememberCoroutineScope()
    var cover by remember { mutableStateOf<ByteArray?>(null) }
    var coverName by remember { mutableStateOf("") }
    var cap by remember { mutableStateOf<Long?>(null) }
    var useFile by remember { mutableStateOf(false) }
    var text by remember { mutableStateOf("") }
    var secretFile by remember { mutableStateOf<Pair<String, ByteArray>?>(null) }
    var pass by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }
    var pendingStego by remember { mutableStateOf<ByteArray?>(null) }

    val pickCover = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val bytes = readUri(uri)
        cover = bytes
        coverName = uri.lastPathSegment ?: "image"
        status = null
        scope.launch {
            cap = runCatching {
                withContext(Dispatchers.Default) { capacity(METHOD, bytes).toLong() }
            }.getOrNull()
        }
    }
    val pickSecret = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        secretFile = (uri.lastPathSegment ?: "file") to readUri(uri)
    }
    val saveStego = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("image/png")
    ) { uri ->
        val data = pendingStego
        if (uri != null && data != null) {
            writeUri(uri, data)
            status = "Saved ${data.size} bytes."
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedButton(onClick = { pickCover.launch(arrayOf("image/*")) }, Modifier.fillMaxWidth()) {
            Text(if (cover != null) "Cover: $coverName" else "Choose cover image…")
        }
        cap?.let { Text("Capacity: ~$it bytes", color = MaterialTheme.colorScheme.primary) }

        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            SegmentedButton(
                selected = !useFile,
                onClick = { useFile = false },
                shape = SegmentedButtonDefaults.itemShape(0, 2)
            ) { Text("Text") }
            SegmentedButton(
                selected = useFile,
                onClick = { useFile = true },
                shape = SegmentedButtonDefaults.itemShape(1, 2)
            ) { Text("File") }
        }

        if (!useFile) {
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                label = { Text("Secret message") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 3
            )
        } else {
            OutlinedButton(onClick = { pickSecret.launch(arrayOf("*/*")) }, Modifier.fillMaxWidth()) {
                Text(secretFile?.let { "File: ${it.first} (${it.second.size} B)" } ?: "Choose secret file…")
            }
        }

        OutlinedTextField(
            value = pass,
            onValueChange = { pass = it },
            label = { Text("Passphrase") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(),
            modifier = Modifier.fillMaxWidth()
        )

        val canEmbed = !busy && cover != null && pass.isNotEmpty() &&
            (if (useFile) secretFile != null else text.isNotEmpty())

        Button(
            onClick = {
                val c = cover ?: return@Button
                busy = true
                status = null
                scope.launch {
                    runCatching {
                        val secret = if (useFile) {
                            val (n, b) = secretFile!!
                            Secret.File(n, b)
                        } else Secret.Text(text)
                        withContext(Dispatchers.Default) { embed(METHOD, c, secret, pass) }
                    }.onSuccess {
                        pendingStego = it
                        saveStego.launch("stego.png")
                    }.onFailure { status = it.message ?: "Embedding failed" }
                    busy = false
                }
            },
            enabled = canEmbed,
            modifier = Modifier.fillMaxWidth()
        ) { Text(if (busy) "Embedding…" else "Hide & save PNG") }

        status?.let { Text(it) }
    }
}

@Composable
fun ExtractTab(readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    val scope = rememberCoroutineScope()
    var stego by remember { mutableStateOf<ByteArray?>(null) }
    var stegoName by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<Revealed?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var pendingFile by remember { mutableStateOf<Pair<String, ByteArray>?>(null) }

    val pickStego = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        stego = readUri(uri)
        stegoName = uri.lastPathSegment ?: "image"
        result = null
        error = null
    }
    val saveFile = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val pf = pendingFile
        if (uri != null && pf != null) writeUri(uri, pf.second)
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedButton(onClick = { pickStego.launch(arrayOf("image/png")) }, Modifier.fillMaxWidth()) {
            Text(if (stego != null) "Stego: $stegoName" else "Choose stego PNG…")
        }
        OutlinedTextField(
            value = pass,
            onValueChange = { pass = it },
            label = { Text("Passphrase") },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth()
        )
        Button(
            onClick = {
                val s = stego ?: return@Button
                busy = true; result = null; error = null
                scope.launch {
                    runCatching {
                        withContext(Dispatchers.Default) { extract(METHOD, s, pass) }
                    }.onSuccess { result = it }
                        .onFailure { error = it.message ?: "Extraction failed" }
                    busy = false
                }
            },
            enabled = !busy && stego != null && pass.isNotEmpty(),
            modifier = Modifier.fillMaxWidth()
        ) { Text(if (busy) "Extracting…" else "Reveal") }

        when (val r = result) {
            is Revealed.None -> Text("No hidden data found.")
            is Revealed.Text -> Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text("Hidden message", style = MaterialTheme.typography.labelSmall)
                    Text(r.text)
                }
            }
            is Revealed.File -> Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Hidden file: ${r.name}", style = MaterialTheme.typography.labelSmall)
                    Button(onClick = {
                        pendingFile = r.name to r.bytes
                        saveFile.launch(r.name)
                    }, Modifier.align(Alignment.Start)) { Text("Save file…") }
                }
            }
            null -> {}
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
}
