package com.stegno.app

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.stegno_core.*

@Composable
internal fun HideTab(methods: List<MethodInfo>, readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    val scope = rememberCoroutineScope()
    var cover by remember { mutableStateOf<ByteArray?>(null) }
    var coverName by remember { mutableStateOf<String?>(null) }
    var text by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var method by remember { mutableStateOf("lsb_seeded") }
    var robust by remember { mutableStateOf(0) }
    var compress by remember { mutableStateOf(false) }
    var decoy by remember { mutableStateOf(false) }
    var decoyText by remember { mutableStateOf("") }
    var decoyPass by remember { mutableStateOf("") }
    var cap by remember { mutableStateOf<Long?>(null) }
    var strength by remember { mutableStateOf<PassphraseStrength?>(null) }
    var recs by remember { mutableStateOf<List<MethodRecommendation>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<Pair<Boolean, String>?>(null) }
    var pendingStego by remember { mutableStateOf<ByteArray?>(null) }
    val imageMethods = methods.filter { it.media == "Image" }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        cover = readUri(uri); coverName = uri.lastPathSegment
    }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("image/png")) { uri ->
        val s = pendingStego
        if (uri != null && s != null) { writeUri(uri, s); result = true to "Hidden in a ${s.size / 1024} KB image — saved." }
    }

    LaunchedEffect(method, cover, decoy) {
        val c = cover ?: return@LaunchedEffect
        cap = runCatching {
            withContext(Dispatchers.Default) { if (decoy) decoyCapacity(c).toLong() else capacity(method, c).toLong() }
        }.getOrNull()
    }

    SectionCard("Hide a secret", "Pick a cover, write your message, choose a password. Everything stays on your device.") {
        Field("Cover image")
        PickButton(coverName?.let { "✅ ${it.takeLast(28)}" } ?: "📷 Choose a photo") { pick.launch(arrayOf("image/*")) }

        Field("Secret message")
        OutlinedTextField(text, { text = it }, Modifier.fillMaxWidth(), minLines = 3,
            placeholder = { Text("Type the message you want to hide…") })

        Field("Password")
        OutlinedTextField(pass, {
            pass = it
            strength = if (it.isNotEmpty()) runCatching { estimatePassphraseStrength(it) }.getOrNull() else null
        }, Modifier.fillMaxWidth(), visualTransformation = PasswordVisualTransformation(),
            placeholder = { Text("A strong passphrase") })
        strength?.let { s ->
            val labels = listOf("Very weak", "Weak", "Fair", "Strong", "Excellent")
            val col = if (s.score >= 3u) Color(0xFF0CA678) else if (s.score >= 2u) Color(0xFFE8770C) else Color(0xFFE23B3B)
            LinearProgressIndicator(
                progress = { (s.score.toInt() + 1) / 5f },
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp), color = col,
            )
            Text("${labels[s.score.toInt()]} · ~${s.entropyBits.toInt()} bits · cracks in ${s.crackTimeDisplay}" +
                if (s.warning.isNotEmpty()) " · ${s.warning}" else "",
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline,
                modifier = Modifier.padding(top = 4.dp))
        }

        // Plausible-deniability decoy.
        Row(Modifier.fillMaxWidth().padding(top = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Checkbox(decoy, { decoy = it })
            Text("Add a decoy message (deniability)")
        }
        if (decoy) {
            Text("Under coercion, reveal the decoy password — the real message stays hidden.",
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
            Field("Decoy message")
            OutlinedTextField(decoyText, { decoyText = it }, Modifier.fillMaxWidth(), minLines = 2,
                placeholder = { Text("A believable, harmless message") })
            Field("Decoy password")
            OutlinedTextField(decoyPass, { decoyPass = it }, Modifier.fillMaxWidth(),
                visualTransformation = PasswordVisualTransformation(),
                placeholder = { Text("The password you'd hand over") })
        }

        if (!decoy) {
            Field("Method")
            MethodDropdown(imageMethods, method) { method = it }
            OutlinedButton(
                onClick = {
                    val c = cover ?: return@OutlinedButton
                    scope.launch {
                        recs = runCatching {
                            withContext(Dispatchers.Default) { planEmbedding(c, text.toByteArray().size.toULong()) }
                        }.getOrDefault(emptyList())
                    }
                },
                enabled = cover != null, modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                shape = RoundedCornerShape(12.dp),
            ) { Text("💡 Suggest the best method") }
            recs.take(4).forEach { r ->
                Surface(
                    onClick = { method = r.methodId; recs = emptyList() },
                    modifier = Modifier.fillMaxWidth().padding(top = 6.dp), shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                ) {
                    Column(Modifier.padding(10.dp)) {
                        Text("${if (r.fits) "✅" else "⚠️"} ${r.displayName} · stealth ${r.stealthTier}/3",
                            style = MaterialTheme.typography.bodySmall, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
                        Text(r.note, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
                    }
                }
            }
        }

        cap?.let {
            Text("Room for about ${"%,d".format(it)} bytes${if (decoy) " per slot" else ""}.",
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
        }

        if (!decoy) {
            Field("Toughness")
            val toughLabels = listOf("Standard", "Rugged — survives light edits", "Extra rugged", "Maximum — survives print/scan")
            LabeledDropdown(toughLabels, robust) { robust = it }
            Row(Modifier.fillMaxWidth().padding(top = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(compress, { compress = it })
                Text("Compress first (fit more in)")
            }
        }

        val ready = cover != null && text.isNotEmpty() && pass.isNotEmpty() &&
            (!decoy || (decoyText.isNotEmpty() && decoyPass.isNotEmpty()))
        PrimaryButton(if (busy) "Hiding…" else "Hide & save", ready, busy) {
            busy = true; result = null
            run(scope, { busy = false }) {
                try {
                    val stego = withContext(Dispatchers.Default) {
                        if (decoy) embedWithDecoy(cover!!, Secret.Text(text), pass, Secret.Text(decoyText), decoyPass)
                        else embedAdvanced(method, cover!!, Secret.Text(text), pass, robust.toUByte(), compress)
                    }
                    pendingStego = stego; saver.launch("stego.png")
                } catch (e: Exception) { result = false to (e.message ?: "Failed") }
            }
        }
        result?.let { Banner(it.first, it.second) }
    }
}
