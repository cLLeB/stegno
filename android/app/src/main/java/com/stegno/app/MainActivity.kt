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
import androidx.compose.material3.MenuAnchorType
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.stegno_core.ByteChunk
import uniffi.stegno_core.DetectionReport
import uniffi.stegno_core.FileRecord
import uniffi.stegno_core.MethodInfo
import uniffi.stegno_core.QualityReport
import uniffi.stegno_core.Revealed
import uniffi.stegno_core.Secret
import uniffi.stegno_core.capacity
import uniffi.stegno_core.decoyCapacity
import uniffi.stegno_core.detectLsb
import uniffi.stegno_core.embed
import uniffi.stegno_core.embedSplit
import uniffi.stegno_core.embedWithDecoy
import uniffi.stegno_core.extract
import uniffi.stegno_core.extractSplit
import uniffi.stegno_core.listMethods
import uniffi.stegno_core.quality
import androidx.compose.ui.platform.LocalContext
import androidx.documentfile.provider.DocumentFile

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

/// Suggested output filename for a method. The method id takes precedence over
/// the carrier medium, since a few image methods emit a non-PNG container
/// (jpeg_jsteg produces a real JPEG).
private fun outputName(methodId: String, media: String): String = when (methodId) {
    "jpeg_jsteg", "jpeg_f5", "jpeg_outguess", "jpeg_mc" -> "stego.jpg"
    else -> when (media) {
        "Image" -> "stego.png"
        "Audio" -> "stego.wav"
        "Text" -> "stego.txt"
        else -> "stego.bin"
    }
}

@Composable
fun StegnoApp(readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    var tab by remember { mutableStateOf(0) }
    var methods by remember { mutableStateOf<List<MethodInfo>>(emptyList()) }
    var methodId by remember { mutableStateOf("lsb_image") }

    LaunchedEffect(Unit) {
        val ms = runCatching { withContext(Dispatchers.Default) { listMethods() } }.getOrDefault(emptyList())
        methods = ms
        if (ms.isNotEmpty() && ms.none { it.id == methodId }) methodId = ms.first().id
    }

    val media = methods.firstOrNull { it.id == methodId }?.media ?: "File"

    Column(
        Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
    ) {
        Text("Stegno", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Offline steganography · ${methods.size} methods",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline
        )
        Spacer(Modifier.height(12.dp))

        if (tab != 2) {
            MethodSelector(methods, methodId, onSelect = { methodId = it })
            Spacer(Modifier.height(12.dp))
        }

        TabRow(selectedTabIndex = tab) {
            Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Hide") })
            Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("Extract") })
            Tab(selected = tab == 2, onClick = { tab = 2 }, text = { Text("Analyze") })
        }
        Spacer(Modifier.height(16.dp))
        when (tab) {
            0 -> HideTab(methodId, media, readUri, writeUri)
            1 -> ExtractTab(methodId, readUri, writeUri)
            else -> AnalyzeTab(readUri)
        }
        Spacer(Modifier.height(20.dp))
        Text(
            "Argon2id + AES-256-GCM · nothing leaves this device.",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.outline
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MethodSelector(methods: List<MethodInfo>, selected: String, onSelect: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    val current = methods.firstOrNull { it.id == selected }
    val label = current?.let { "${it.displayName} · ${it.media}" } ?: selected

    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = !expanded }) {
        OutlinedTextField(
            value = label,
            onValueChange = {},
            readOnly = true,
            label = { Text("Method") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .menuAnchor(MenuAnchorType.PrimaryNotEditable, true)
                .fillMaxWidth()
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            methods.forEach { m ->
                DropdownMenuItem(
                    text = { Text("${m.displayName} · ${m.media}") },
                    onClick = {
                        onSelect(m.id)
                        expanded = false
                    }
                )
            }
        }
    }
}

@Composable
fun HideTab(
    methodId: String,
    media: String,
    readUri: (Uri) -> ByteArray,
    writeUri: (Uri, ByteArray) -> Unit
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var covers by remember { mutableStateOf<List<Pair<String, ByteArray>>>(emptyList()) }
    var cap by remember { mutableStateOf<Long?>(null) }
    var splitMode by remember { mutableStateOf(false) }
    
    var realUseFile by remember { mutableStateOf(false) }
    var realText by remember { mutableStateOf("") }
    var realFiles by remember { mutableStateOf<List<Pair<String, ByteArray>>>(emptyList()) }
    var pass by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }
    var pendingStegos by remember { mutableStateOf<List<ByteArray>>(emptyList()) }
    
    var decoy by remember { mutableStateOf(false) }
    var decoyUseFile by remember { mutableStateOf(false) }
    var decoyText by remember { mutableStateOf("") }
    var decoyFiles by remember { mutableStateOf<List<Pair<String, ByteArray>>>(emptyList()) }
    var decoyPass by remember { mutableStateOf("") }

    LaunchedEffect(covers, methodId, decoy, splitMode) {
        if (covers.isEmpty()) {
            cap = null
        } else if (splitMode) {
            runCatching {
                withContext(Dispatchers.Default) {
                    val caps = covers.map { capacity(methodId, it.second) }
                    (caps.minOrNull() ?: 0UL) * covers.size.toULong()
                }
            }.onSuccess { cap = it.toLong() }.onFailure { cap = null }
        } else {
            val c = covers.first().second
            runCatching {
                withContext(Dispatchers.Default) {
                    (if (decoy) decoyCapacity(c) else capacity(methodId, c)).toLong()
                }
            }.onSuccess { cap = it }.onFailure { cap = null }
        }
    }

    val pickCoverSingle = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        covers = listOf((uri.lastPathSegment ?: "cover") to readUri(uri))
        status = null
    }
    val pickCoverMultiple = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        covers = uris.map { uri -> (uri.lastPathSegment ?: "cover") to readUri(uri) }
        status = null
    }

    val pickReal = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        realFiles = uris.map { uri -> (uri.lastPathSegment ?: "file") to readUri(uri) }
    }
    val pickDecoy = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        decoyFiles = uris.map { uri -> (uri.lastPathSegment ?: "file") to readUri(uri) }
    }

    val saveStegoSingle = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val data = pendingStegos.firstOrNull()
        if (uri != null && data != null) {
            writeUri(uri, data)
            status = "Saved ${data.size} bytes."
        }
    }
    val saveStegoTree = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null && pendingStegos.isNotEmpty()) {
            val docFile = DocumentFile.fromTreeUri(context, uri)
            if (docFile != null) {
                var successCount = 0
                val ext = outputName(methodId, media).substringAfterLast('.', "bin")
                for ((i, data) in pendingStegos.withIndex()) {
                    val f = docFile.createFile("application/octet-stream", "stego_part${i + 1}.$ext")
                    if (f != null) {
                        context.contentResolver.openOutputStream(f.uri)?.use { it.write(data) }
                        successCount++
                    }
                }
                status = "Saved $successCount split files."
            }
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = splitMode, onCheckedChange = { 
                splitMode = it; if (it) decoy = false; covers = emptyList() 
            })
            Spacer(Modifier.width(8.dp))
            Text("Split across multiple covers")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = decoy, onCheckedChange = { 
                decoy = it; if (it) splitMode = false; covers = emptyList() 
            })
            Spacer(Modifier.width(8.dp))
            Text("Add a decoy message")
        }

        OutlinedButton(onClick = { 
            if (splitMode) pickCoverMultiple.launch(arrayOf("*/*")) else pickCoverSingle.launch(arrayOf("*/*")) 
        }, Modifier.fillMaxWidth()) {
            Text(if (covers.isNotEmpty()) "Covers: ${covers.size} selected" else if (splitMode) "Choose cover files…" else "Choose cover file…")
        }

        cap?.let {
            Text(
                if (splitMode) "Approximate Split Capacity: ~$it bytes" else if (decoy) "Capacity per message: ~$it bytes" else "Capacity: ~$it bytes",
                color = MaterialTheme.colorScheme.primary
            )
        }

        val realSize = if (realUseFile) realFiles.sumOf { it.second.size } else realText.toByteArray().size
        val decoySize = if (decoyUseFile) decoyFiles.sumOf { it.second.size } else decoyText.toByteArray().size
        if (cap != null) {
            val realOverflow = realSize - cap!!
            val decoyOverflow = decoySize - cap!!
            if (!decoy && realOverflow > 0) {
                Text("Secret is ${realOverflow} bytes over capacity.", color = MaterialTheme.colorScheme.error)
            }
            if (decoy && realOverflow > 0) {
                Text("Real secret is ${realOverflow} bytes over capacity.", color = MaterialTheme.colorScheme.error)
            }
            if (decoy && decoyOverflow > 0) {
                Text("Decoy secret is ${decoyOverflow} bytes over capacity.", color = MaterialTheme.colorScheme.error)
            }
        }

        if (!decoy) {
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                SegmentedButton(
                    selected = !realUseFile,
                    onClick = { realUseFile = false },
                    shape = SegmentedButtonDefaults.itemShape(0, 2)
                ) { Text("Text") }
                SegmentedButton(
                    selected = realUseFile,
                    onClick = { realUseFile = true },
                    shape = SegmentedButtonDefaults.itemShape(1, 2),
                    enabled = covers.isNotEmpty()
                ) { Text("File") }
            }

            if (!realUseFile) {
                OutlinedTextField(
                    value = realText,
                    onValueChange = { realText = it },
                    label = { Text("Secret message") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3
                )
            } else {
                OutlinedButton(onClick = { pickReal.launch(arrayOf("*/*")) }, Modifier.fillMaxWidth()) {
                    Text(if (realFiles.isNotEmpty()) "${realFiles.size} file(s) selected" else "Choose secret file(s)…")
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
        } else {
            Text("Real secret", style = MaterialTheme.typography.titleSmall)
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                SegmentedButton(
                    selected = !realUseFile,
                    onClick = { realUseFile = false },
                    shape = SegmentedButtonDefaults.itemShape(0, 2)
                ) { Text("Text") }
                SegmentedButton(
                    selected = realUseFile,
                    onClick = { realUseFile = true },
                    shape = SegmentedButtonDefaults.itemShape(1, 2),
                    enabled = covers.isNotEmpty()
                ) { Text("File") }
            }

            if (!realUseFile) {
                OutlinedTextField(
                    value = realText,
                    onValueChange = { realText = it },
                    label = { Text("Real message") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3
                )
            } else {
                OutlinedButton(onClick = { pickReal.launch(arrayOf("*/*")) }, Modifier.fillMaxWidth()) {
                    Text(if (realFiles.isNotEmpty()) "${realFiles.size} file(s) selected" else "Choose real secret file(s)…")
                }
            }

            OutlinedTextField(
                value = pass,
                onValueChange = { pass = it },
                label = { Text("Real password") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(),
                modifier = Modifier.fillMaxWidth()
            )

            Text("Decoy secret", style = MaterialTheme.typography.titleSmall)
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                SegmentedButton(
                    selected = !decoyUseFile,
                    onClick = { decoyUseFile = false },
                    shape = SegmentedButtonDefaults.itemShape(0, 2)
                ) { Text("Text") }
                SegmentedButton(
                    selected = decoyUseFile,
                    onClick = { decoyUseFile = true },
                    shape = SegmentedButtonDefaults.itemShape(1, 2),
                    enabled = covers.isNotEmpty()
                ) { Text("File") }
            }

            if (!decoyUseFile) {
                OutlinedTextField(
                    value = decoyText,
                    onValueChange = { decoyText = it },
                    label = { Text("Decoy message (the fake one)") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2
                )
            } else {
                OutlinedButton(onClick = { pickDecoy.launch(arrayOf("*/*")) }, Modifier.fillMaxWidth()) {
                    Text(if (decoyFiles.isNotEmpty()) "${decoyFiles.size} file(s) selected" else "Choose decoy file(s)…")
                }
            }

            OutlinedTextField(
                value = decoyPass,
                onValueChange = { decoyPass = it },
                label = { Text("Decoy password (must differ)") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
        }

        val withinCapacity = cap == null || (realSize <= cap!! && (!decoy || decoySize <= cap!!))
        val canEmbed = !busy && covers.isNotEmpty() && pass.isNotEmpty() && withinCapacity &&
            if (decoy) {
                (if (realUseFile) realFiles.isNotEmpty() else realText.isNotEmpty()) &&
                    (if (decoyUseFile) decoyFiles.isNotEmpty() else decoyText.isNotEmpty()) &&
                    decoyPass.isNotEmpty() &&
                    decoyPass != pass
            } else {
                if (realUseFile) realFiles.isNotEmpty() else realText.isNotEmpty()
            }

        Button(
            onClick = {
                busy = true
                status = null
                scope.launch {
                    runCatching {
                        withContext(Dispatchers.Default) {
                            val realSecret = if (realUseFile) {
                                if (realFiles.size == 1) Secret.File(realFiles[0].first, realFiles[0].second)
                                else Secret.Files(realFiles.map { FileRecord(it.first, it.second) })
                            } else Secret.Text(realText)

                            if (splitMode) {
                                embedSplit(methodId, covers.map { ByteChunk(it.second) }, realSecret, pass)
                                    .map { it.bytes }
                            } else if (decoy) {
                                val decoySecret = if (decoyUseFile) {
                                    if (decoyFiles.size == 1) Secret.File(decoyFiles[0].first, decoyFiles[0].second)
                                    else Secret.Files(decoyFiles.map { FileRecord(it.first, it.second) })
                                } else Secret.Text(decoyText)
                                listOf(embedWithDecoy(covers[0].second, realSecret, pass, decoySecret, decoyPass))
                            } else {
                                listOf(embed(methodId, covers[0].second, realSecret, pass))
                            }
                        }
                    }.onSuccess {
                        pendingStegos = it
                        if (splitMode) {
                            saveStegoTree.launch(null)
                        } else {
                            saveStegoSingle.launch(if (decoy) "stego.png" else outputName(methodId, media))
                        }
                    }.onFailure { status = it.message ?: "Embedding failed" }
                    busy = false
                }
            },
            enabled = canEmbed,
            modifier = Modifier.fillMaxWidth()
        ) { Text(if (busy) "Embedding…" else "Hide & save") }

        status?.let { Text(it) }
    }
}

@Composable
fun ExtractTab(
    methodId: String,
    readUri: (Uri) -> ByteArray,
    writeUri: (Uri, ByteArray) -> Unit
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var stegos by remember { mutableStateOf<List<Pair<String, ByteArray>>>(emptyList()) }
    var splitMode by remember { mutableStateOf(false) }
    var pass by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<Revealed?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var pendingFiles by remember { mutableStateOf<List<Pair<String, ByteArray>>>(emptyList()) }
    var status by remember { mutableStateOf<String?>(null) }

    val pickStegoSingle = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        stegos = listOf((uri.lastPathSegment ?: "stego") to readUri(uri))
        result = null; error = null; status = null
    }
    val pickStegoMultiple = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        stegos = uris.map { uri -> (uri.lastPathSegment ?: "stego") to readUri(uri) }
        result = null; error = null; status = null
    }

    val saveFileSingle = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val pf = pendingFiles.firstOrNull()
        if (uri != null && pf != null) {
            writeUri(uri, pf.second)
            status = "Saved file."
        }
    }
    val saveFilesTree = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null && pendingFiles.isNotEmpty()) {
            val docFile = DocumentFile.fromTreeUri(context, uri)
            if (docFile != null) {
                var successCount = 0
                for ((name, data) in pendingFiles) {
                    val f = docFile.createFile("application/octet-stream", name)
                    if (f != null) {
                        context.contentResolver.openOutputStream(f.uri)?.use { it.write(data) }
                        successCount++
                    }
                }
                status = "Saved $successCount files."
            }
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = splitMode, onCheckedChange = { splitMode = it; stegos = emptyList(); result = null })
            Spacer(Modifier.width(8.dp))
            Text("Extract from split covers")
        }

        OutlinedButton(onClick = { 
            if (splitMode) pickStegoMultiple.launch(arrayOf("*/*")) else pickStegoSingle.launch(arrayOf("*/*")) 
        }, Modifier.fillMaxWidth()) {
            Text(if (stegos.isNotEmpty()) "Stegos: ${stegos.size} selected" else if (splitMode) "Choose split stego files…" else "Choose stego file…")
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
                if (stegos.isEmpty() || pass.isEmpty()) return@Button
                busy = true; result = null; error = null; status = null
                scope.launch {
                    runCatching {
                        withContext(Dispatchers.Default) { 
                            if (splitMode) extractSplit(methodId, stegos.map { ByteChunk(it.second) }, pass)
                            else extract(methodId, stegos[0].second, pass)
                        }
                    }.onSuccess { result = it }
                        .onFailure { error = it.message ?: "Extraction failed" }
                    busy = false
                }
            },
            enabled = !busy && stegos.isNotEmpty() && pass.isNotEmpty(),
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
                        pendingFiles = listOf(r.name to r.bytes)
                        saveFileSingle.launch(r.name)
                    }, Modifier.align(Alignment.Start)) { Text("Save file…") }
                }
            }
            is Revealed.Files -> Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Hidden files (${r.files.size})", style = MaterialTheme.typography.labelSmall)
                    Button(onClick = {
                        pendingFiles = r.files.map { it.name to it.bytes }
                        saveFilesTree.launch(null)
                    }, Modifier.align(Alignment.Start)) { Text("Save all files…") }
                }
            }
            null -> {}
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        status?.let { Text(it, color = MaterialTheme.colorScheme.primary) }
    }
}

/// Plain-language verdict (text + level 0=ok,1=warn,2=bad) for the LSB detector.
private fun suspicionText(d: DetectionReport): Pair<String, Int> {
    val rate = d.samplePairRate
    return when {
        rate < 0.05 && d.chiSquareP < 0.5 -> "✓ Looks clean — no obvious hidden data." to 0
        rate < 0.2 && d.chiSquareP < 0.9 -> "⚠ Possibly hiding data — some suspicious signs." to 1
        else -> "⛔ Likely hiding data — strong signs of LSB embedding." to 2
    }
}

/// Plain-language verdict for a quality comparison. PSNR is ∞ when identical.
private fun qualityText(q: QualityReport): Pair<String, Int> {
    val psnr = if (q.psnrDb.isFinite()) q.psnrDb else Double.POSITIVE_INFINITY
    return when {
        psnr >= 45.0 || q.ssim >= 0.999 -> "✓ Looks identical to the eye." to 0
        psnr >= 35.0 -> "✓ Very similar — changes are hard to spot." to 0
        psnr >= 28.0 -> "⚠ Noticeably different on close inspection." to 1
        else -> "⛔ Clearly different." to 2
    }
}

@Composable
private fun verdictColor(level: Int) = when (level) {
    0 -> MaterialTheme.colorScheme.primary
    1 -> MaterialTheme.colorScheme.tertiary
    else -> MaterialTheme.colorScheme.error
}

@Composable
fun AnalyzeTab(readUri: (Uri) -> ByteArray) {
    val scope = rememberCoroutineScope()
    var scan by remember { mutableStateOf<ByteArray?>(null) }
    var detection by remember { mutableStateOf<DetectionReport?>(null) }
    var orig by remember { mutableStateOf<ByteArray?>(null) }
    var edited by remember { mutableStateOf<ByteArray?>(null) }
    var qual by remember { mutableStateOf<QualityReport?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val pickScan = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scan = readUri(uri); detection = null; error = null
    }
    val pickOrig = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        orig = readUri(uri); qual = null; error = null
    }
    val pickEdited = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        edited = readUri(uri); qual = null; error = null
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Scan a photo for hidden data", style = MaterialTheme.typography.titleMedium)
        Text(
            "Checks a photo for the most common hiding method (LSB). Best on PNG photos.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline
        )
        OutlinedButton(onClick = { pickScan.launch(arrayOf("image/*")) }, Modifier.fillMaxWidth()) {
            Text(if (scan != null) "Photo chosen ✓" else "Choose a photo…")
        }
        Button(
            onClick = {
                val s = scan ?: return@Button
                busy = true; error = null
                scope.launch {
                    runCatching { withContext(Dispatchers.Default) { detectLsb(s) } }
                        .onSuccess { detection = it }
                        .onFailure { error = it.message ?: "Scan failed" }
                    busy = false
                }
            },
            enabled = !busy && scan != null,
            modifier = Modifier.fillMaxWidth()
        ) { Text(if (busy) "Scanning…" else "Scan") }
        detection?.let { d ->
            val (txt, level) = suspicionText(d)
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text(txt, color = verdictColor(level))
                    Text(
                        "Embedding-rate estimate ${(d.samplePairRate * 100).toInt()}% · " +
                            "chi-square ${(d.chiSquareP * 100).toInt()}%",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.outline
                    )
                }
            }
        }

        Spacer(Modifier.height(4.dp))
        Text("Compare two photos", style = MaterialTheme.typography.titleMedium)
        Text(
            "Pick an original and an edited copy to see how much they differ.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline
        )
        OutlinedButton(onClick = { pickOrig.launch(arrayOf("image/*")) }, Modifier.fillMaxWidth()) {
            Text(if (orig != null) "Original chosen ✓" else "Choose the original…")
        }
        OutlinedButton(onClick = { pickEdited.launch(arrayOf("image/*")) }, Modifier.fillMaxWidth()) {
            Text(if (edited != null) "Edited copy chosen ✓" else "Choose the edited copy…")
        }
        Button(
            onClick = {
                val o = orig ?: return@Button
                val e = edited ?: return@Button
                busy = true; error = null
                scope.launch {
                    runCatching { withContext(Dispatchers.Default) { quality(o, e) } }
                        .onSuccess { qual = it }
                        .onFailure { error = it.message ?: "Compare failed" }
                    busy = false
                }
            },
            enabled = !busy && orig != null && edited != null,
            modifier = Modifier.fillMaxWidth()
        ) { Text(if (busy) "Comparing…" else "Compare") }
        qual?.let { q ->
            val (txt, level) = qualityText(q)
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text(txt, color = verdictColor(level))
                    val psnr = if (q.psnrDb.isFinite()) "%.1f".format(q.psnrDb) else "∞"
                    Text(
                        "PSNR $psnr dB · similarity ${"%.1f".format(q.ssim * 100)}%",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.outline
                    )
                }
            }
        }

        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
}
