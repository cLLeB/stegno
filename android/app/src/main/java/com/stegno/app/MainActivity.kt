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
import uniffi.stegno_core.DetectionReport
import uniffi.stegno_core.MethodInfo
import uniffi.stegno_core.QualityReport
import uniffi.stegno_core.Revealed
import uniffi.stegno_core.Secret
import uniffi.stegno_core.capacity
import uniffi.stegno_core.decoyCapacity
import uniffi.stegno_core.detectLsb
import uniffi.stegno_core.embed
import uniffi.stegno_core.embedWithDecoy
import uniffi.stegno_core.extract
import uniffi.stegno_core.listMethods
import uniffi.stegno_core.quality

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
                .menuAnchor()
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
    // Decoy mode: hide a second "fake" message under a different password.
    var decoy by remember { mutableStateOf(false) }
    var decoyText by remember { mutableStateOf("") }
    var decoyPass by remember { mutableStateOf("") }

    // Recompute capacity whenever the cover, method, or decoy toggle changes.
    LaunchedEffect(cover, methodId, decoy) {
        val c = cover
        cap = if (c == null) {
            null
        } else {
            runCatching {
                withContext(Dispatchers.Default) {
                    (if (decoy) decoyCapacity(c) else capacity(methodId, c)).toLong()
                }
            }.getOrNull()
        }
    }

    val pickCover = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        cover = readUri(uri)
        coverName = uri.lastPathSegment ?: "cover"
        status = null
    }
    val pickSecret = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        secretFile = (uri.lastPathSegment ?: "file") to readUri(uri)
    }
    val saveStego = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val data = pendingStego
        if (uri != null && data != null) {
            writeUri(uri, data)
            status = "Saved ${data.size} bytes."
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedButton(onClick = { pickCover.launch(arrayOf("*/*")) }, Modifier.fillMaxWidth()) {
            Text(if (cover != null) "Cover: $coverName" else "Choose cover file…")
        }
        cap?.let {
            Text(
                if (decoy) "Capacity per message: ~$it bytes" else "Capacity: ~$it bytes",
                color = MaterialTheme.colorScheme.primary
            )
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = decoy, onCheckedChange = { decoy = it })
            Spacer(Modifier.width(8.dp))
            Text("Add a decoy message")
        }
        if (decoy) {
            Text(
                "Hides two messages in one photo. The real password reveals the real " +
                    "message; the decoy password reveals a harmless fake — so you can safely " +
                    "hand over the decoy password if forced. Saved as a PNG photo.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline
            )
        }

        if (!decoy) {
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
        }

        if (decoy || !useFile) {
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                label = { Text(if (decoy) "Real message" else "Secret message") },
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
            label = { Text(if (decoy) "Real password" else "Passphrase") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(),
            modifier = Modifier.fillMaxWidth()
        )

        if (decoy) {
            OutlinedTextField(
                value = decoyText,
                onValueChange = { decoyText = it },
                label = { Text("Decoy message (the fake one)") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2
            )
            OutlinedTextField(
                value = decoyPass,
                onValueChange = { decoyPass = it },
                label = { Text("Decoy password (must differ)") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
        }

        val canEmbed = !busy && cover != null && pass.isNotEmpty() &&
            if (decoy) {
                text.isNotEmpty() && decoyText.isNotEmpty() && decoyPass.isNotEmpty() && decoyPass != pass
            } else {
                if (useFile) secretFile != null else text.isNotEmpty()
            }

        Button(
            onClick = {
                val c = cover ?: return@Button
                busy = true
                status = null
                scope.launch {
                    runCatching {
                        withContext(Dispatchers.Default) {
                            if (decoy) {
                                embedWithDecoy(c, Secret.Text(text), pass, Secret.Text(decoyText), decoyPass)
                            } else {
                                val secret = if (useFile) {
                                    val (n, b) = secretFile!!
                                    Secret.File(n, b)
                                } else Secret.Text(text)
                                embed(methodId, c, secret, pass)
                            }
                        }
                    }.onSuccess {
                        pendingStego = it
                        saveStego.launch(if (decoy) "stego.png" else outputName(methodId, media))
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
        stegoName = uri.lastPathSegment ?: "stego"
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
        OutlinedButton(onClick = { pickStego.launch(arrayOf("*/*")) }, Modifier.fillMaxWidth()) {
            Text(if (stego != null) "Stego: $stegoName" else "Choose stego file…")
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
                        withContext(Dispatchers.Default) { extract(methodId, s, pass) }
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
