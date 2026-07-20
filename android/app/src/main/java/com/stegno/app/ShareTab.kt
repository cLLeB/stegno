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
internal fun ShareTab(readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    val scope = rememberCoroutineScope()
    var cover by remember { mutableStateOf<ByteArray?>(null) }
    var name by remember { mutableStateOf<String?>(null) }
    var rows by remember { mutableStateOf(listOf("" to "", "" to "")) }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<Pair<Boolean, String>?>(null) }
    var pending by remember { mutableStateOf<ByteArray?>(null) }
    val valid = rows.filter { it.first.isNotEmpty() && it.second.isNotEmpty() }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        cover = readUri(uri); name = uri.lastPathSegment
    }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("image/png")) { uri ->
        val s = pending
        if (uri != null && s != null) { writeUri(uri, s); result = true to "Hid ${valid.size} messages in one photo." }
    }

    SectionCard("One photo, many people", "Hide a different message for each person. Each opens only their own with their own password.") {
        Field("Cover image")
        PickButton(name?.let { "✅ ${it.takeLast(28)}" } ?: "📷 Choose a photo") { pick.launch(arrayOf("image/*")) }
        rows.forEachIndexed { i, row ->
            Surface(Modifier.fillMaxWidth().padding(top = 10.dp), shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant) {
                Column(Modifier.padding(10.dp)) {
                    OutlinedTextField(row.first, { v -> rows = rows.mapIndexed { j, r -> if (j == i) v to r.second else r } },
                        Modifier.fillMaxWidth(), placeholder = { Text("Message for this person") }, singleLine = true)
                    OutlinedTextField(row.second, { v -> rows = rows.mapIndexed { j, r -> if (j == i) r.first to v else r } },
                        Modifier.fillMaxWidth().padding(top = 6.dp), visualTransformation = PasswordVisualTransformation(),
                        placeholder = { Text("Their password") }, singleLine = true,
                        trailingIcon = { TextButton(onClick = { rows = rows.filterIndexed { j, _ -> j != i } }) { Text("✕") } })
                }
            }
        }
        OutlinedButton(onClick = { if (rows.size < 8) rows = rows + ("" to "") },
            modifier = Modifier.padding(top = 12.dp), enabled = rows.size < 8, shape = RoundedCornerShape(12.dp)) { Text("+ Add person") }
        PrimaryButton(if (busy) "Hiding…" else "Hide all & save", cover != null && valid.size >= 2, busy) {
            busy = true; result = null
            run(scope, { busy = false }) {
                try {
                    val recips = valid.map { Recipient(Secret.Text(it.first), it.second) }
                    pending = withContext(Dispatchers.Default) { embedMulti(cover!!, recips) }
                    saver.launch("shared.png")
                } catch (e: Exception) { result = false to (e.message ?: "Failed") }
            }
        }
        result?.let { Banner(it.first, it.second) }
    }
}
