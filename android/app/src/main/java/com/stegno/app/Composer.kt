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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import uniffi.stegno_core.CoverInfo
import uniffi.stegno_core.FileRecord
import uniffi.stegno_core.PassphraseStrength
import uniffi.stegno_core.Recipient
import uniffi.stegno_core.Secret
import uniffi.stegno_core.estimatePassphraseStrength

/** Most secrets the composer will place in one go, matching the web PWA. */
internal const val MAX_ENTRIES = 8

/** A chosen cover plus what the engine says it is, so naming and capacity are honest. */
internal data class CoverFile(val name: String, val bytes: ByteArray, val info: CoverInfo? = null)

/** One secret in the composer: either typed text or a set of files, with its own password. */
internal data class SecretEntry(
    val isText: Boolean = true,
    val text: String = "",
    val files: List<FileRecord> = emptyList(),
    val pass: String = "",
    val strength: PassphraseStrength? = null,
) {
    val ready: Boolean get() = pass.isNotEmpty() && if (isText) text.isNotEmpty() else files.isNotEmpty()
    val payloadLen: Int get() = if (isText) text.toByteArray().size else files.sumOf { it.bytes.size }

    fun toSecret(): Secret = if (isText) Secret.Text(text) else Secret.Files(files)
    fun toRecipient(): Recipient = Recipient(toSecret(), pass)
}

/**
 * The dynamic list of secrets. One file picker is shared by every row because
 * launchers must not be created inside a list whose length changes.
 */
@Composable
internal fun ColumnScope.SecretEntryList(
    entries: List<SecretEntry>,
    readUri: (Uri) -> ByteArray,
    onChange: (List<SecretEntry>) -> Unit,
    onError: (String) -> Unit,
) {
    val context = LocalContext.current
    var target by remember { mutableStateOf(-1) }

    val pickFiles = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        val i = target
        if (uris.isEmpty() || i !in entries.indices) return@rememberLauncherForActivityResult
        try {
            val records = uris.map { FileRecord(displayNameOf(context, it), readUri(it)) }
            onChange(entries.mapIndexed { j, e -> if (j == i) e.copy(files = records) else e })
        } catch (e: Exception) {
            onError(e.message ?: "Could not read those files")
        }
    }

    entries.forEachIndexed { i, entry ->
        SecretEntryCard(
            entry = entry,
            removable = entries.size > 1,
            onUpdate = { updated -> onChange(entries.mapIndexed { j, e -> if (j == i) updated else e }) },
            onRemove = { onChange(entries.filterIndexed { j, _ -> j != i }) },
            onPickFiles = { target = i; pickFiles.launch(arrayOf("*/*")) },
        )
    }

    OutlinedButton(
        onClick = { if (entries.size < MAX_ENTRIES) onChange(entries + SecretEntry()) },
        enabled = entries.size < MAX_ENTRIES,
        modifier = Modifier.padding(top = 12.dp), shape = RoundedCornerShape(12.dp),
    ) { Text("+ Add another secret") }
}

@Composable
private fun SecretEntryCard(
    entry: SecretEntry,
    removable: Boolean,
    onUpdate: (SecretEntry) -> Unit,
    onRemove: () -> Unit,
    onPickFiles: () -> Unit,
) {
    Surface(
        Modifier.fillMaxWidth().padding(top = 10.dp), shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.weight(1f)) {
                    SegToggle(listOf("Text", "File(s)"), if (entry.isText) 0 else 1) {
                        onUpdate(entry.copy(isText = it == 0))
                    }
                }
                if (removable) TextButton(onClick = onRemove) { Text("✕") }
            }

            if (entry.isText) {
                OutlinedTextField(
                    entry.text, { onUpdate(entry.copy(text = it)) },
                    Modifier.fillMaxWidth().padding(top = 8.dp), minLines = 2,
                    placeholder = { Text("Secret message") },
                )
            } else {
                PickButton(
                    if (entry.files.isEmpty()) "📎 Choose file(s)"
                    else "✅ ${entry.files.size} file(s) · ${entry.files.first().name.takeLast(22)}",
                    onPickFiles,
                )
            }

            OutlinedTextField(
                entry.pass,
                { value ->
                    val s = if (value.isNotEmpty()) runCatching { estimatePassphraseStrength(value) }.getOrNull() else null
                    onUpdate(entry.copy(pass = value, strength = s))
                },
                Modifier.fillMaxWidth().padding(top = 8.dp),
                visualTransformation = PasswordVisualTransformation(),
                placeholder = { Text("Password for this secret") }, singleLine = true,
            )
            StrengthMeter(entry.strength)
        }
    }
}

/** Plain-language summary of what the current cover/secret counts will do. */
internal fun describeScheme(covers: Int, secrets: Int): String {
    val single = covers == 1 && secrets == 1
    val who =
        if (secrets == 1) "one secret"
        else "$secrets secrets, each with its own password (hand one over as a decoy)"
    val where =
        if (covers == 1) "in one cover"
        else "split across $covers covers — all of them are needed to rebuild"
    val scheme = if (single) "Chosen method." else "Layered region scheme (method is chosen for you)."
    return "$scheme $who, $where."
}

/** "Carrier: photo, video (frame-level). Room for about N bytes per secret." */
internal fun describeCapacity(covers: List<CoverFile>, capacity: ULong?, single: Boolean): String {
    if (covers.isEmpty() || capacity == null) return ""
    val kinds = covers.map { kindLabel(it.info?.kind) }.distinct().joinToString(", ")
    val perSecret = if (single) "" else " per secret"
    return "Carrier: $kinds. Room for about ${"%,d".format(capacity.toLong())} bytes$perSecret."
}

@Composable
internal fun SchemeNote(text: String) {
    if (text.isEmpty()) return
    Text(
        text, style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.outline, fontWeight = FontWeight.Medium,
        modifier = Modifier.padding(top = 10.dp),
    )
}
