// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.sample

import android.Manifest
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.sipral.android.telecom.AudioRoute
import org.sipral.android.telecom.SipralTelecom
import org.sipral.telecom.TelecomCall
import org.sipral.telecom.TelecomDirection
import org.sipral.telecom.TelecomPhase

class MainActivity : ComponentActivity() {
    private val model: SampleModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        // Edge to edge on every release, not only from Android 15 on, and
        // with the status and navigation bars' icons dark over this light
        // screen rather than the platform's white ones. The no-argument
        // form picks icon colour from the system's dark-mode setting
        // (`SystemBarStyle.auto`), not from this app's content, which is
        // unconditionally light (`MaterialTheme` here takes no colour
        // scheme, so it is always `lightColorScheme()`): in system dark
        // mode that leaves white icons over a light window. `light` style
        // is used explicitly instead, for both bars.
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.light(
                scrim = Color.argb(0xe6, 0xff, 0xff, 0xff),
                darkScrim = Color.argb(0x80, 0x1b, 0x1b, 0x1b),
            ),
        )
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    Permissions()
                    Sample(model)
                }
            }
        }
    }
}

@Composable
private fun Permissions() {
    val wanted = buildList {
        add(Manifest.permission.RECORD_AUDIO)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            add(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
    // The answer is not kept here: AudioPump asks again when a call starts,
    // and a notification the user refused is simply not shown.
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { _ -> }
    LaunchedEffect(Unit) { ask.launch(wanted.toTypedArray()) }
}

@Composable
private fun Sample(model: SampleModel) {
    // Android 15 draws every application targeting it edge to edge, under
    // the status bar, the navigation bar and the keyboard: the screen keeps
    // its content out of all three itself.
    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text("Account", style = MaterialTheme.typography.titleMedium)
        Field("Address of record", model.aor) { model.aor = it }
        Field("Registrar address (host:port)", model.registrarAddress) { model.registrarAddress = it }
        Field("Registrar URI (empty: no registration)", model.registrar) { model.registrar = it }
        Field("Auth user", model.authUser) { model.authUser = it }
        OutlinedTextField(
            value = model.authPassword,
            onValueChange = { model.authPassword = it },
            label = { Text("Auth password") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        Field("STUN server (host:port, empty: none)", model.stunServer) { model.stunServer = it }
        Field("TURN server (host:port, needs STUN)", model.turnServer) { model.turnServer = it }
        Field("TURN user", model.turnUser) { model.turnUser = it }
        OutlinedTextField(
            value = model.turnPassword,
            onValueChange = { model.turnPassword = it },
            label = { Text("TURN password") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        Button(onClick = { model.register() }) { Text("Register") }
        Text(model.status)

        Text("Call", style = MaterialTheme.typography.titleMedium)
        Field("Target", model.target) { model.target = it }
        Button(onClick = { model.call() }) { Text("Call") }
        Field("Caller a push would name", model.pushCaller) { model.pushCaller = it }
        OutlinedButton(onClick = { model.simulatePush() }) { Text("Simulate a push") }

        for (call in model.calls) {
            CallCard(model, call)
        }

        Text("Events", style = MaterialTheme.typography.titleMedium)
        for (line in model.log) {
            Text(line, style = MaterialTheme.typography.bodySmall)
        }
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
private fun CallCard(model: SampleModel, call: TelecomCall) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(call.displayName ?: call.caller, style = MaterialTheme.typography.titleSmall)
            Text(
                buildString {
                    append(call.phase.name.lowercase())
                    if (call.announced && call.call == 0L) append(", announced by a push, INVITE not here yet")
                    if (call.remoteHold) append(", held by the far end")
                },
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (call.direction == TelecomDirection.INCOMING && call.phase == TelecomPhase.RINGING) {
                    Button(onClick = { model.answer(call.id) }) { Text("Answer") }
                    OutlinedButton(onClick = { model.decline(call.id) }) { Text("Decline") }
                } else {
                    OutlinedButton(onClick = { model.hangup(call.id) }) { Text("Hang up") }
                    if (call.phase == TelecomPhase.ACTIVE || call.phase == TelecomPhase.HELD) {
                        OutlinedButton(onClick = { model.toggleHold(call) }) {
                            Text(if (call.phase == TelecomPhase.HELD) "Resume" else "Hold")
                        }
                    }
                }
            }
            if (call.phase == TelecomPhase.ACTIVE) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    for (digit in "123456789*0#") {
                        OutlinedButton(onClick = { model.dtmf(call.id, digit) }) { Text(digit.toString()) }
                    }
                }
            }
            Routes(model, call.id)
        }
    }
}

/** The audio routes the platform offers for this call, and the one it is
 * using; choosing one asks the platform for it. */
@Composable
private fun Routes(model: SampleModel, id: String) {
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
                onClick = { model.selectRoute(id, route) },
                label = { Text(route.name) },
            )
        }
    }
}
