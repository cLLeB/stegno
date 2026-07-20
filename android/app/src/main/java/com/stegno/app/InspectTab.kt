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
internal fun InspectTab(readUri: (Uri) -> ByteArray) {
    val scope = rememberCoroutineScope()
    var data by remember { mutableStateOf<ByteArray?>(null) }
    var name by remember { mutableStateOf<String?>(null) }
    var report by remember { mutableStateOf<StructuralReport?>(null) }
    var guesses by remember { mutableStateOf<List<MethodGuess>>(emptyList()) }
    var detection by remember { mutableStateOf<DetectionReport?>(null) }
    var busy by remember { mutableStateOf(false) }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        data = readUri(uri); name = uri.lastPathSegment; report = null; guesses = emptyList(); detection = null
    }

    SectionCard("Inspect a file", "Structure, statistics, and a method guess.") {
        Field("File to inspect")
        PickButton(name?.let { "✅ ${it.takeLast(28)}" } ?: "🔍 Choose a file") { pick.launch(arrayOf("*/*")) }
        PrimaryButton(if (busy) "Inspecting…" else "Inspect", data != null, busy) {
            busy = true
            run(scope, { busy = false }) {
                report = withContext(Dispatchers.Default) { scanStructure(data!!) }
                guesses = withContext(Dispatchers.Default) { fingerprint(data!!) }
                detection = runCatching { withContext(Dispatchers.Default) { detectLsb(data!!) } }.getOrNull()
            }
        }
        report?.let { r ->
            Banner(!r.suspicious, if (r.suspicious) "Signs of hidden data found" else "Nothing obvious found")
            Text("Format: ${r.format}", style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.outline, modifier = Modifier.padding(top = 8.dp))
            r.findings.forEach { f ->
                Text("• ${f.kind}: ${f.detail}", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 4.dp))
            }
            if (guesses.isNotEmpty()) {
                Field("Likely method")
                guesses.take(4).forEach { g ->
                    Text("${(g.confidence * 100).toInt()}%  ${g.label}", style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(top = 2.dp))
                }
            }
            detection?.let { d ->
                Field("Statistical LSB analysis")
                Text("Overall likelihood of hidden data: ${(d.mlConfidence * 100).toInt()}%",
                    style = MaterialTheme.typography.bodySmall, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
                StatRow("Chi-square p", "%.3f".format(d.chiSquareP))
                StatRow("RS regularity gap", "%.3f".format(d.rsRegularityGap))
                StatRow("Sample-pair rate", "%.3f".format(d.samplePairRate))
                StatRow("HoG uniformity", "%.3f".format(d.hogUniformity))
                StatRow("Noise residual energy", "%.3f".format(d.noiseResidualEnergy))
            }
        }
    }
}
