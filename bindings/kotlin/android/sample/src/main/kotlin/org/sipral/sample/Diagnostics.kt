// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

import android.Manifest
import android.app.ActivityManager
import android.app.NotificationManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.PowerManager
import androidx.core.content.FileProvider
import androidx.core.content.pm.PackageInfoCompat
import java.io.File

/** What the phone allows, the bundle the Diagnostics screen shares, and the
 * share itself: the Android half of [Evidence.kt]'s classes. */
object Diagnostics {
    fun facts(context: Context): ReadinessFacts {
        val sdk = Build.VERSION.SDK_INT
        fun granted(permission: String) =
            context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
        return ReadinessFacts(
            sdk = sdk,
            microphone = granted(Manifest.permission.RECORD_AUDIO),
            notifications = if (sdk >= Build.VERSION_CODES.TIRAMISU) granted(Manifest.permission.POST_NOTIFICATIONS) else null,
            fullScreenIntent = if (sdk >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                context.getSystemService(NotificationManager::class.java).canUseFullScreenIntent()
            } else {
                null
            },
            batteryUnrestricted = context.getSystemService(PowerManager::class.java)
                .isIgnoringBatteryOptimizations(context.packageName),
            backgroundRestricted = if (sdk >= Build.VERSION_CODES.P) {
                context.getSystemService(ActivityManager::class.java).isBackgroundRestricted
            } else {
                null
            },
            standbyBucket = if (sdk >= Build.VERSION_CODES.P) {
                context.getSystemService(UsageStatsManager::class.java).appStandbyBucket
            } else {
                null
            },
        )
    }

    /** Everything a bug report needs, in one zip under the cache: written
     * through [EvidenceBundle], so no password the account holds is in it. */
    fun bundle(context: Context, phone: Phone): File {
        val now = System.currentTimeMillis()
        val facts = facts(context)
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.getPackageInfo(context.packageName, PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(context.packageName, 0)
        }
        val evidence = EvidenceBundle(phone.settings.secrets)
        val readme = buildString {
            append("Sipral sample diagnostics\n")
            append("written ${stamp(now)}\n")
            append("application ${info.versionName} (${PackageInfoCompat.getLongVersionCode(info)}), ${context.packageName}\n")
            append("device ${Build.MANUFACTURER} ${Build.MODEL}, Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}), ")
            append("ABIs ${Build.SUPPORTED_ABIS.joinToString()}\n")
            append("process started ${stamp(phone.processStartedAt)}\n")
            append("status ${phone.status}\n")
            append("account ${phone.settings.aor} at ${phone.settings.registrarAddress} over ${phone.settings.transport}\n\n")
            append("readiness\n")
            for (item in readinessOf(facts)) {
                append("  ${if (item.ready) "ok  " else "NOT "} ${item.title}: ${item.explanation}\n")
            }
            append("\nfiles\n")
            append("  events.txt        the sample's own log: registration, calls, network, audio, media gaps\n")
            append("  stack-log.txt     the stack's log (docs/17-observability.md), redacted by the stack\n")
            append("  diagnostics.json  the decision record of every call the stack holds (docs/14-diagnostics.md)\n")
            append("  state.txt         the stack's state snapshot, redacted by the stack\n")
            append("  logcat.txt        this application's logcat\n")
            append("  no pcapng: the C ABI offers no packet capture; take one on the network or the PBX\n")
            append("\nEvery line is stamped with the phone's wall clock, offset included. Passwords the account\n")
            append("holds (${EvidenceBundle.MIN_SECRET} characters or longer) and every Authorization header are removed.\n")
        }
        evidence.add("README.txt", readme)
        evidence.add("events.txt", phone.events.text())
        evidence.add("stack-log.txt", phone.stackLog.text())
        evidence.add("diagnostics.json", phone.diagnostics() ?: "{}")
        evidence.add("state.txt", phone.state() ?: "no stack is open\n")
        evidence.add("logcat.txt", logcat())
        val directory = File(context.cacheDir, "diagnostics").apply { mkdirs() }
        directory.listFiles()?.forEach { it.delete() }
        val name = "sipral-diagnostics-${stamp(now).replace(':', '-')}.zip"
        val file = File(directory, name)
        file.outputStream().use { evidence.write(it) }
        phone.note("diagnostics bundle written: $name, ${file.length()} bytes")
        return file
    }

    fun share(context: Context, file: File) {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.diagnostics", file)
        val send = Intent(Intent.ACTION_SEND)
            .setType("application/zip")
            .putExtra(Intent.EXTRA_STREAM, uri)
            .putExtra(Intent.EXTRA_SUBJECT, file.name)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        context.startActivity(Intent.createChooser(send, "Share diagnostics").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    /** This application's logcat: Android shows an application only its
     * own lines, from this process and the ones before it. */
    private fun logcat(): String = try {
        val process = ProcessBuilder("logcat", "-d", "-v", "threadtime", "-v", "year", "-v", "zone", "-t", "20000")
            .redirectErrorStream(true)
            .start()
        process.inputStream.bufferedReader().use { it.readText() }.also { process.waitFor() }
    } catch (failed: Exception) {
        "logcat could not be read: $failed\n"
    }
}
