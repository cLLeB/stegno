package com.stegno.app

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.stegno_core.*

@Composable
internal fun LabTab(methods: List<MethodInfo>, readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    BitPlaneCard(readUri, writeUri)
    CompareCard(readUri)
    DetectabilityCard(methods.filter { it.media == "Image" }, readUri)
    DoctorCard()
    BenchmarkCard()
}

/* ---- Bit-plane viewer ---- */
@Composable
private fun BitPlaneCard(readUri: (Uri) -> ByteArray, writeUri: (Uri, ByteArray) -> Unit) {
    val scope = rememberCoroutineScope()
    var img by remember { mutableStateOf<ByteArray?>(null) }
    var channel by remember { mutableStateOf(0) }
    var plane by remember { mutableStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<ByteArray?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { img = readUri(it); result = null }
    }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("image/png")) { uri ->
        val r = result
        if (uri != null && r != null) writeUri(uri, r)
    }

    SectionCard("Bit-plane viewer", "Hidden LSB data shows up as noise.") {
        PickButton(if (img != null) "✅ Photo loaded" else "📷 Choose a photo") { pick.launch(arrayOf("image/*")) }
        Field("Channel")
        LabeledDropdown(listOf("Red", "Green", "Blue"), channel) { channel = it }
        Field("Bit plane (0 = lowest)")
        LabeledDropdown((0..7).map { "Plane $it" }, plane) { plane = it }
        PrimaryButton(if (busy) "Rendering…" else "Show bit plane", img != null, busy) {
            busy = true; error = null
            run(scope, { busy = false }) {
                try {
                    result = withContext(Dispatchers.Default) { bitPlane(img!!, channel.toUByte(), plane.toUByte()) }
                } catch (e: Exception) { error = e.message ?: "Failed" }
            }
        }
        error?.let { Banner(false, it) }
        result?.let {
            ImagePreview(it)
            OutlinedButton(onClick = { saver.launch("bitplane.png") },
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                shape = androidx.compose.foundation.shape.RoundedCornerShape(12.dp)) { Text("Save image") }
        }
    }
}

/* ---- Cover vs stego compare ---- */
@Composable
private fun CompareCard(readUri: (Uri) -> ByteArray) {
    val scope = rememberCoroutineScope()
    var cover by remember { mutableStateOf<ByteArray?>(null) }
    var stego by remember { mutableStateOf<ByteArray?>(null) }
    var busy by remember { mutableStateOf(false) }
    var rate by remember { mutableStateOf<Double?>(null) }
    var q by remember { mutableStateOf<QualityReport?>(null) }
    var map by remember { mutableStateOf<ByteArray?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    val pickCover = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { cover = readUri(it); rate = null; q = null; map = null }
    }
    val pickStego = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { stego = readUri(it); rate = null; q = null; map = null }
    }

    SectionCard("Compare original vs stego", "Quality scores and a change map.") {
        Field("Original photo")
        PickButton(if (cover != null) "✅ Original loaded" else "📷 Choose original") { pickCover.launch(arrayOf("image/*")) }
        Field("Stego photo")
        PickButton(if (stego != null) "✅ Stego loaded" else "🖼️ Choose stego") { pickStego.launch(arrayOf("image/*")) }
        PrimaryButton(if (busy) "Comparing…" else "Compare", cover != null && stego != null, busy) {
            busy = true; error = null
            run(scope, { busy = false }) {
                try {
                    rate = withContext(Dispatchers.Default) { changeRate(cover!!, stego!!) }
                    q = withContext(Dispatchers.Default) { quality(cover!!, stego!!) }
                    map = runCatching { withContext(Dispatchers.Default) { changeMap(cover!!, stego!!) } }.getOrNull()
                } catch (e: Exception) { error = e.message ?: "Failed" }
            }
        }
        error?.let { Banner(false, it) }
        rate?.let { StatRow("Pixels changed", "%.2f%%".format(it * 100)) }
        q?.let {
            StatRow("PSNR", "%.1f dB".format(it.psnrDb))
            StatRow("SSIM", "%.4f".format(it.ssim))
            StatRow("MSE", "%.3f".format(it.mse))
        }
        map?.let { Field("Change map"); ImagePreview(it) }
    }
}

/* ---- Detectability estimate ---- */
@Composable
private fun DetectabilityCard(methods: List<MethodInfo>, readUri: (Uri) -> ByteArray) {
    val scope = rememberCoroutineScope()
    var cover by remember { mutableStateOf<ByteArray?>(null) }
    var method by remember { mutableStateOf("lsb_seeded") }
    var payload by remember { mutableStateOf("1024") }
    var busy by remember { mutableStateOf(false) }
    var report by remember { mutableStateOf<DetectabilityReport?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { cover = readUri(it); report = null }
    }

    SectionCard("Will it be detectable?", "How much a payload raises suspicion.") {
        PickButton(if (cover != null) "✅ Cover loaded" else "📷 Choose a cover") { pick.launch(arrayOf("image/*")) }
        Field("Method")
        MethodDropdown(methods, method) { method = it }
        Field("Payload size (bytes)")
        OutlinedTextField(payload, { payload = it.filter { c -> c.isDigit() } }, Modifier.fillMaxWidth(),
            placeholder = { Text("1024") }, singleLine = true)
        PrimaryButton(if (busy) "Estimating…" else "Estimate", cover != null && payload.isNotEmpty(), busy) {
            busy = true; error = null
            run(scope, { busy = false }) {
                try {
                    report = withContext(Dispatchers.Default) {
                        detectability(method, cover!!, payload.toULongOrNull() ?: 0uL)
                    }
                } catch (e: Exception) { error = e.message ?: "Failed" }
            }
        }
        error?.let { Banner(false, it) }
        report?.let { d ->
            Banner(d.delta < 0.15, d.verdict)
            StatRow("Suspicion (clean)", "%.0f%%".format(d.cleanConfidence * 100))
            StatRow("Suspicion (with payload)", "%.0f%%".format(d.stegoConfidence * 100))
            StatRow("Increase", "%.0f%%".format(d.delta * 100))
            StatRow("PSNR", "%.1f dB".format(d.psnrDb))
        }
    }
}

/* ---- Engine self-test ---- */
@Composable
private fun DoctorCard() {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var results by remember { mutableStateOf<List<SelfTestResult>>(emptyList()) }

    SectionCard("Engine self-test", "Round-trip every method to check it works.") {
        PrimaryButton(if (busy) "Testing…" else "Run self-test", true, busy) {
            busy = true
            run(scope, { busy = false }) {
                results = runCatching { withContext(Dispatchers.Default) { runSelfTest() } }.getOrDefault(emptyList())
            }
        }
        if (results.isNotEmpty()) {
            val passed = results.count { it.ok }
            Banner(passed == results.size, "$passed of ${results.size} methods passed")
            results.forEach { r ->
                Text("${if (r.ok) "✅" else "❌"} ${r.methodId} - ${r.detail}",
                    style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 4.dp))
            }
        }
    }
}

/* ---- KDF benchmark ---- */
@Composable
private fun BenchmarkCard() {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<KdfBenchmark?>(null) }

    SectionCard("Password hashing benchmark", "Time password hashing. Slower is stronger.") {
        PrimaryButton(if (busy) "Benchmarking…" else "Run benchmark", true, busy) {
            busy = true
            run(scope, { busy = false }) {
                result = runCatching { withContext(Dispatchers.Default) { benchmarkKdf() } }.getOrNull()
            }
        }
        result?.let { b ->
            Text(b.verdict, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(top = 8.dp))
            StatRow("Time", "%.0f ms".format(b.millis))
            StatRow("Memory", "${b.memoryKib.toInt() / 1024} MiB")
            StatRow("Iterations", "${b.iterations}")
        }
    }
}
