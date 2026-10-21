// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

import android.Manifest
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.sipral.android.telecom.SipralTelecom
import org.sipral.telecom.AudioRoute
import org.sipral.telecom.TelecomCall
import org.sipral.telecom.TelecomDirection
import org.sipral.telecom.TelecomPhase

class MainActivity : ComponentActivity() {
    private val phone: Phone get() = (application as SampleApplication).phone

    override fun onCreate(savedInstanceState: Bundle?) {
        // Edge to edge on every release, with dark bar icons over this always-light
        // screen. The no-argument form picks icon colour from the system dark-mode
        // setting (`SystemBarStyle.auto`), which in dark mode gives white icons on
        // a light window, so `light` is set explicitly for both bars.
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.light(
                scrim = Color.argb(0xe6, 0xff, 0xff, 0xff),
                darkScrim = Color.argb(0x80, 0x1b, 0x1b, 0x1b),
            ),
        )
        super.onCreate(savedInstanceState)
        // registered when the last process ended (killed by the system, or
        // swiped away): registered again, carrying the binding on
        if (phone.store.keepRegistered && !phone.running) {
            phone.start("opened by the user after the process had gone")
        }
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    FirstLaunchPermissions()
                    Screens(phone)
                }
            }
        }
    }
}

@Composable
private fun FirstLaunchPermissions() {
    val wanted = buildList {
        add(Manifest.permission.RECORD_AUDIO)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            add(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
    // what was refused is shown on the Readiness screen, which asks again
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { _ -> }
    LaunchedEffect(Unit) { ask.launch(wanted.toTypedArray()) }
}

private enum class Screen(val title: String) { PHONE("Phone"), READINESS("Readiness"), DIAGNOSTICS("Diagnostics") }

@Composable
private fun Screens(phone: Phone) {
    var screen by rememberSaveable { mutableStateOf(Screen.PHONE) }
    // Android 15 draws apps targeting it edge to edge under the status bar,
    // navigation bar and keyboard; the screen keeps content clear of all three.
    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            for (each in Screen.entries) {
                FilterChip(selected = screen == each, onClick = { screen = each }, label = { Text(each.title) })
            }
        }
        when (screen) {
            Screen.PHONE -> PhoneScreen(phone)
            Screen.READINESS -> ReadinessScreen()
            Screen.DIAGNOSTICS -> DiagnosticsScreen(phone)
        }
    }
}

@Composable
private fun PhoneScreen(phone: Phone) {
    val s = phone.settings
    Text("Account", style = MaterialTheme.typography.titleMedium)
    Field("Address of record", s.aor) { v -> phone.edit { it.copy(aor = v) } }
    Field("Registrar address (host:port)", s.registrarAddress) { v -> phone.edit { it.copy(registrarAddress = v) } }
    Field("Registrar URI (empty: no registration)", s.registrar) { v -> phone.edit { it.copy(registrar = v) } }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        Text("Transport")
        for (transport in listOf("udp", "tcp", "tls")) {
            FilterChip(
                selected = s.transport == transport,
                onClick = { phone.edit { it.copy(transport = transport) } },
                label = { Text(transport.uppercase()) },
            )
        }
    }
    Field("Auth user", s.authUser) { v -> phone.edit { it.copy(authUser = v) } }
    Secret("Auth password", s.authPassword) { v -> phone.edit { it.copy(authPassword = v) } }
    Field("STUN server (host:port, empty: none)", s.stunServer) { v -> phone.edit { it.copy(stunServer = v) } }
    Field("TURN server (host:port, needs STUN)", s.turnServer) { v -> phone.edit { it.copy(turnServer = v) } }
    Field("TURN user", s.turnUser) { v -> phone.edit { it.copy(turnUser = v) } }
    Secret("TURN password", s.turnPassword) { v -> phone.edit { it.copy(turnPassword = v) } }
    Text(
        "Passwords are kept encrypted with a key held by the Android Keystore.",
        style = MaterialTheme.typography.bodySmall,
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = { phone.start("Register tapped") }) { Text("Register") }
        OutlinedButton(onClick = { phone.stop() }) { Text("Unregister") }
    }
    Text(phone.status)

    Text("Call", style = MaterialTheme.typography.titleMedium)
    Field("Target", phone.target) { phone.target = it }
    Button(onClick = { phone.call() }) { Text("Call") }
    Field("Caller a push would name", phone.pushCaller) { phone.pushCaller = it }
    OutlinedButton(onClick = {
        if (phone.pushCaller.isNotBlank()) phone.pushArrived(phone.pushCaller.trim())
    }) { Text("Simulate a push") }

    for (call in phone.calls) {
        CallCard(phone, call)
    }

    Text("Events", style = MaterialTheme.typography.titleMedium)
    for (line in phone.screenLog) {
        Text(line, style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * What the phone allows this application, read again whenever the screen
 * comes back (the user may have changed it in the system settings), each
 * with the one thing that can be done about it. Battery optimisation is
 * shown, never asked to be lifted: Google Play allows that request only to
 * applications whose core function Doze breaks, and a calling application
 * that can be woken by a high-priority push is not one of them.
 */
@Composable
private fun ReadinessScreen() {
    val context = LocalContext.current
    var facts by remember { mutableStateOf(Diagnostics.facts(context)) }
    LifecycleResumeEffect(Unit) {
        facts = Diagnostics.facts(context)
        onPauseOrDispose { }
    }
    val refresh: (Boolean) -> Unit = { facts = Diagnostics.facts(context) }
    val microphone = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission(), refresh)
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission(), refresh)
    Text("Readiness", style = MaterialTheme.typography.titleMedium)
    Text(
        "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) on ${Build.MANUFACTURER} ${Build.MODEL}",
        style = MaterialTheme.typography.bodySmall,
    )
    for (item in readinessOf(facts)) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text((if (item.ready) "Ready: " else "Needs attention: ") + item.title, style = MaterialTheme.typography.titleSmall)
                Text(item.explanation, style = MaterialTheme.typography.bodyMedium)
                when (item.action) {
                    ReadinessAction.ASK_MICROPHONE -> OutlinedButton(onClick = {
                        microphone.launch(Manifest.permission.RECORD_AUDIO)
                    }) { Text("Allow the microphone") }
                    ReadinessAction.ASK_NOTIFICATIONS -> OutlinedButton(onClick = {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
                        }
                    }) { Text("Allow notifications") }
                    ReadinessAction.FULL_SCREEN_SETTINGS -> OutlinedButton(onClick = {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                            open(context, Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT, packageUri(context)))
                        }
                    }) { Text("Open the setting") }
                    ReadinessAction.BATTERY_SETTINGS -> OutlinedButton(onClick = {
                        open(context, Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                    }) { Text("Battery settings") }
                    ReadinessAction.APP_SETTINGS -> OutlinedButton(onClick = {
                        open(context, Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, packageUri(context)))
                    }) { Text("Application settings") }
                    null -> Unit
                }
            }
        }
    }
    Text(
        "A permission refused twice is no longer asked for by Android; the application settings are where it " +
            "is given back.",
        style = MaterialTheme.typography.bodySmall,
    )
    OutlinedButton(onClick = {
        open(context, Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, packageUri(context)))
    }) { Text("Application settings") }
}

private fun packageUri(context: Context): Uri = Uri.fromParts("package", context.packageName, null)

private fun open(context: Context, intent: Intent) {
    try {
        context.startActivity(intent)
    } catch (_: android.content.ActivityNotFoundException) {
        context.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, packageUri(context)))
    }
}

/** Evidence for a report: what the log keeps, and one zip of all of it
 * through the share sheet. */
@Composable
private fun DiagnosticsScreen(phone: Phone) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var written by remember { mutableStateOf("") }
    Text("Diagnostics", style = MaterialTheme.typography.titleMedium)
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Switch(checked = phone.sipMessages, onCheckedChange = { phone.logSipMessages(it) })
        Text("SIP messages in the log (users and addresses pseudonymised)")
    }
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Switch(checked = phone.diagnosticTrace, onCheckedChange = { phone.traceDiagnostics(it) })
        Text("Diagnostic trace: real addresses and numbers, for comparing with the PBX's own log")
    }
    Text(
        "Kept: ${phone.events.size} event lines, ${phone.stackLog.size} stack log lines. Credentials are " +
            "never logged, and the bundle removes the account's passwords and every Authorization header " +
            "again before it is written.",
        style = MaterialTheme.typography.bodySmall,
    )
    Button(onClick = {
        scope.launch {
            val file = withContext(Dispatchers.IO) { Diagnostics.bundle(context, phone) }
            written = "${file.name}, ${file.length()} bytes"
            Diagnostics.share(context, file)
        }
    }) { Text("Share log") }
    if (written.isNotEmpty()) {
        Text(written, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun Field(label: String, value: String, onChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun Secret(label: String, value: String, onChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun CallCard(phone: Phone, call: TelecomCall) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(call.displayName ?: call.caller, style = MaterialTheme.typography.titleSmall)
            Text(
                buildString {
                    append(call.phase.name.lowercase())
                    if (call.announced && call.call == 0L) append(", announced by a push, INVITE not here yet")
                    if (call.remoteHold) append(", held by the far end")
                    phone.audioStates[call.id]?.let { append(", audio ${it.name.lowercase()}") }
                },
            )
            phone.mediaCounts[call.id]?.let { Text("RTP $it", style = MaterialTheme.typography.bodySmall) }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (call.direction == TelecomDirection.INCOMING && call.phase == TelecomPhase.RINGING) {
                    Button(onClick = { phone.answer(call.id) }) { Text("Answer") }
                    OutlinedButton(onClick = { phone.decline(call.id) }) { Text("Decline") }
                } else {
                    OutlinedButton(onClick = { phone.hangup(call.id) }) { Text("Hang up") }
                    if (call.phase == TelecomPhase.ACTIVE || call.phase == TelecomPhase.HELD) {
                        OutlinedButton(onClick = { phone.toggleHold(call) }) {
                            Text(if (call.phase == TelecomPhase.HELD) "Resume" else "Hold")
                        }
                    }
                }
            }
            if (call.phase == TelecomPhase.ACTIVE) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    for (digit in "123456789*0#") {
                        OutlinedButton(onClick = { phone.dtmf(call.id, digit) }) { Text(digit.toString()) }
                    }
                }
            }
            Routes(phone, call.id)
        }
    }
}

/** The audio routes the platform offers for this call, and the one it is
 * using; choosing one asks the platform for it. */
@Composable
private fun Routes(phone: Phone, id: String) {
    val connections by SipralTelecom.connections.collectAsStateWithLifecycle()
    val connection = connections[id] ?: return
    val routes by connection.routes.collectAsStateWithLifecycle()
    val current by connection.route.collectAsStateWithLifecycle()
    if (routes.isEmpty()) {
        return
    }
    FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        for (route: AudioRoute in routes) {
            FilterChip(
                selected = route.id == current?.id,
                onClick = { phone.selectRoute(id, route) },
                label = { Text(route.name) },
            )
        }
    }
}
