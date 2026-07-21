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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.stegno_core.*

private val TOUGHNESS = listOf("Standard", "Rugged", "Extra rugged", "Maximum")

/**
 * The unified composer: any number of covers of any type, any number of secrets,
 * each with its own password. One secret in one cover is a plain hide; anything
 * else is placed by the engine's composite scheme.
 */
@Composable
internal fun HideTab(methods: List<MethodInfo>, readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var picked by remember { mutableStateOf<List<Pair<String, ByteArray>>>(emptyList()) }
    var covers by remember { mutableStateOf<List<CoverFile>>(emptyList()) }
    var entries by remember { mutableStateOf(listOf(SecretEntry())) }
    var method by remember { mutableStateOf("lsb_seeded") }
    var robust by remember { mutableStateOf(0) }
    var compress by remember { mutableStateOf(false) }
    var capacityBytes by remember { mutableStateOf<ULong?>(null) }
    var recs by remember { mutableStateOf<List<MethodRecommendation>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<Pair<Boolean, String>?>(null) }
    var doneMsg by remember { mutableStateOf("") }
    /** False once you pick a method yourself; a new cover hands control back. */
    var methodIsAuto by remember { mutableStateOf(true) }
    var autoNote by remember { mutableStateOf("") }

    val single = covers.size == 1 && entries.size == 1

    val pickCovers = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        try {
            picked = uris.map { displayNameOf(context, it) to readUri(it) }
            result = null
            // A new cover is a new situation, so resume choosing automatically.
            methodIsAuto = true
        } catch (e: Exception) {
            result = false to (e.message ?: "Could not read those files")
        }
    }
    val save = rememberFileSaver(
        writeUri,
        onComplete = { result = true to doneMsg },
        onError = { result = false to it },
    )

    // Ask the engine what each cover actually is, so capacity and the eventual
    // filename reflect the real carrier rather than assuming a photo.
    LaunchedEffect(picked) {
        covers = withContext(Dispatchers.Default) {
            picked.map { (name, bytes) -> CoverFile(name, bytes, runCatching { coverInfo(bytes) }.getOrNull()) }
        }
    }
    LaunchedEffect(covers, entries.size, method, single) {
        capacityBytes = if (covers.isEmpty()) null else runCatching {
            withContext(Dispatchers.Default) {
                if (single) capacity(method, covers[0].bytes)
                else compositeCapacity(covers.map { ByteChunk(it.bytes) }, entries.size.toUInt())
            }
        }.getOrNull()
    }
    // A planner suggestion only ever applies to a single-secret hide.
    LaunchedEffect(single) { if (!single) recs = emptyList() }

    // Pick the best method automatically, re-picking as the cover or secret
    // changes, until you override it. Delayed because planning asks every method
    // for its capacity and the image methods each decode the cover — about 1.8s
    // on a 6-megapixel photo, so running it per keystroke would make typing
    // unusable.
    val payloadLen = entries.firstOrNull()?.payloadLen ?: 0
    LaunchedEffect(covers, single, payloadLen, methodIsAuto) {
        if (!methodIsAuto || !single || covers.isEmpty()) {
            autoNote = if (methodIsAuto) "" else "Method chosen by you."
            return@LaunchedEffect
        }
        autoNote = "Choosing the best method…"
        delay(400)
        val best = runCatching {
            withContext(Dispatchers.Default) {
                planEmbedding(covers[0].bytes, payloadLen.toULong())
            }
        }.getOrNull()?.firstOrNull { it.fits }
        autoNote = if (best == null) {
            "No method fits this secret in this cover."
        } else {
            method = best.methodId
            "Chosen for you: ${best.displayName} — ${best.note}"
        }
    }

    SectionCard("Hide", "Add cover files and one or more secrets. Mix freely.") {
        Field("Cover file(s)")
        PickButton(coverButtonLabel(covers)) { pickCovers.launch(arrayOf("*/*")) }

        Field("Secrets")
        SecretEntryList(entries, readUri, onChange = { entries = it }, onError = { result = false to it })

        MethodSection(
            methods = methods, method = method, enabled = single, coverReady = covers.isNotEmpty(), recs = recs,
            autoNote = if (single) autoNote else "",
            onSelect = { methodIsAuto = false; method = it; recs = emptyList() },
            onPlan = {
                val cover = covers.firstOrNull() ?: return@MethodSection
                scope.launch {
                    recs = runCatching {
                        withContext(Dispatchers.Default) { planEmbedding(cover.bytes, entries[0].payloadLen.toULong()) }
                    }.getOrDefault(emptyList())
                }
            },
        )

        if (covers.isNotEmpty()) SchemeNote(describeScheme(covers.size, entries.size))
        SchemeNote(describeCapacity(covers, capacityBytes, single))

        // Toughness and squeeze apply to every scheme, so they stay fully active.
        Field("Toughness")
        LabeledDropdown(TOUGHNESS, robust) { robust = it }
        Row(Modifier.fillMaxWidth().padding(top = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Checkbox(compress, { compress = it })
            Text("Compress first (fit more in)")
        }

        val ready = covers.isNotEmpty() && entries.isNotEmpty() && entries.all { it.ready }
        PrimaryButton(if (busy) "Hiding…" else "Hide & save", ready, busy) {
            busy = true; result = null
            run(scope, { busy = false }) {
                try {
                    val outs = withContext(Dispatchers.Default) {
                        composeOutputs(covers, entries, method, robust, compress, single)
                    }
                    doneMsg = doneMessage(covers.size, entries.size, outs.size)
                    save(outs)
                } catch (e: Exception) {
                    result = false to (e.message ?: "Could not hide the secret")
                }
            }
        }
        result?.let { Banner(it.first, it.second) }

        Text(
            "One secret is a simple hide. Two or more each open with their own password (give one away " +
                "as a decoy). Two or more covers split the data across them, all needed to rebuild. Mix cover " +
                "types freely. Photos come back as PNG; everything else keeps its own format.",
            style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline,
            modifier = Modifier.padding(top = 14.dp),
        )
    }
}

/**
 * Method picker and planner. They govern a single-secret hide only — a mix is
 * placed by the layered region scheme — so they are dimmed rather than removed,
 * and nothing silently disappears from the form.
 */
@Composable
private fun ColumnScope.MethodSection(
    methods: List<MethodInfo>,
    method: String,
    enabled: Boolean,
    coverReady: Boolean,
    recs: List<MethodRecommendation>,
    autoNote: String,
    onSelect: (String) -> Unit,
    onPlan: () -> Unit,
) {
    Field("Method")
    Dimmed(enabled) {
        MethodDropdown(methods, method, enabled = enabled, showMedia = true, onSelect = onSelect)
        if (autoNote.isNotEmpty()) {
            Text(
                autoNote,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
        OutlinedButton(
            onClick = onPlan, enabled = enabled && coverReady,
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp), shape = RoundedCornerShape(12.dp),
        ) { Text("💡 Show other methods") }
        recs.take(4).forEach { r ->
            Surface(
                onClick = { onSelect(r.methodId) },
                modifier = Modifier.fillMaxWidth().padding(top = 6.dp), shape = RoundedCornerShape(10.dp),
                color = MaterialTheme.colorScheme.surfaceVariant,
            ) {
                Column(Modifier.padding(10.dp)) {
                    Text(
                        "${if (r.fits) "✅" else "⚠️"} ${r.displayName} · stealth ${r.stealthTier}/3",
                        style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold,
                    )
                    Text(r.note, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
                }
            }
        }
    }
}

private fun coverButtonLabel(covers: List<CoverFile>): String = when {
    covers.isEmpty() -> "📎 Choose covers — photo, audio, text, document, video, any file"
    covers.size == 1 -> "✅ ${covers[0].name.takeLast(28)}"
    else -> "✅ ${covers.size} covers"
}

/**
 * Runs the embed and names each result after the cover it came from. Called off
 * the main thread.
 */
private fun composeOutputs(
    covers: List<CoverFile>,
    entries: List<SecretEntry>,
    method: String,
    robust: Int,
    compress: Boolean,
    single: Boolean,
): List<OutFile> {
    if (single) {
        val cover = covers[0]
        val stego = embedAdvanced(
            method, cover.bytes, entries[0].toSecret(), entries[0].pass, robust.toUByte(), compress,
        )
        // A chosen method may re-encode (image methods emit PNG), so trust the
        // engine's view of the result rather than the cover's.
        val info = runCatching { coverInfo(stego) }.getOrNull() ?: cover.info
        return listOf(OutFile(stegoNameFor(cover.name, info, "stego"), stego))
    }
    val parts = embedComposite(
        covers.map { ByteChunk(it.bytes) }, entries.map { it.toRecipient() }, robust.toUByte(), compress,
    )
    return parts.mapIndexed { i, part ->
        val cover = covers.getOrNull(i)
        OutFile(stegoNameFor(cover?.name, cover?.info, "part${i + 1}"), part.bytes)
    }
}

private fun doneMessage(covers: Int, secrets: Int, saved: Int): String = when {
    covers == 1 && secrets == 1 -> "Hid your secret."
    saved > 1 -> "Hid $secrets secret(s) across $saved covers — all are needed to rebuild."
    else -> "Hid $secrets secret(s) in one cover."
}
