// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.idiomatic

import java.nio.ByteBuffer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralRegistrationState
import org.sipral.SipralStatus
import org.sipral.SipralSuspending

/**
 * Where [SipralLifecycle] writes registrations down: one record per key,
 * opaque bytes. On Android, `org.sipral.android.telecom.SipralKeystoreStore`
 * keeps them encrypted under a key the Android Keystore holds; a record
 * names an address of record, so it is the application's to protect.
 */
interface SipralSnapshotStore {
    fun write(key: String, record: ByteArray)
    fun read(key: String): ByteArray?
    fun remove(key: String)
}

/**
 * A client tied to the application's own lifecycle on a phone, the
 * Kotlin counterpart of the .NET `SipralAppLifecycle` (`docs/16-lifecycle.md`,
 * `docs/15-mobile.md` "C3"):
 *
 * - every registration a registrar accepts for a [keep]-ed account is
 *   written down ([SipralAccount.freeze]) with the wall-clock time, so the
 *   record is never older than the binding's last refresh, whose sequence
 *   number the next process has to continue past;
 * - [enteredBackground] writes each down once more and then tells the stack
 *   it is [SipralClient.suspending], in that order: once told, the stack no
 *   longer counts a registration as bound, and there would be nothing to
 *   write;
 * - [enteredForeground] is [SipralClient.resumed];
 * - [restore], in a process the system started again (a push, the user),
 *   reads the record back onto the account just added
 *   ([SipralAccount.thaw]) with how long it sat, measured on the wall clock,
 *   since a monotonic one does not survive the process.
 *
 * The cold start after a push, in the order a push needs it, is
 * `org.sipral.telecom.wakeForPush`, over this.
 */
class SipralLifecycle(
    private val store: SipralSnapshotStore,
    private val wallClockMs: () -> Long = System::currentTimeMillis,
) {
    private val lock = Any()
    private val kept = LinkedHashMap<String, SipralAccount>()
    private var client: SipralClient? = null
    private var watching: Job? = null

    /** Told when a record could not be written or read back; the stack
     * carries on either way. */
    @Volatile
    var failed: (Exception) -> Unit = {}

    /** The client the lifecycle applies to, and the scope its
     * registrations are followed in; null to let it go. */
    fun attach(client: SipralClient?, scope: CoroutineScope?) {
        val previous = synchronized(lock) {
            val job = watching
            this.client = client
            watching = null
            job
        }
        previous?.cancel()
        if (client == null || scope == null) {
            return
        }
        val job = scope.launch {
            client.events.collect { event ->
                if (event.kind != SipralEventKind.REGISTRATION_CHANGED.value.toLong()) return@collect
                val state = SipralRegistrationState.of(event.payload.registration.state.toInt())
                val entry = synchronized(lock) { kept.entries.firstOrNull { it.value.handle == event.account } }
                    ?: return@collect
                when (state) {
                    SipralRegistrationState.REGISTERED -> write(entry.key, entry.value)
                    SipralRegistrationState.UNREGISTERED, SipralRegistrationState.FAILED -> store.remove(PREFIX + entry.key)
                    else -> Unit
                }
            }
        }
        synchronized(lock) { watching = job }
    }

    /** Write [account]'s registration down under [key] from now on. The
     * key names the account across processes, so it must not change between
     * runs; its address of record is the obvious one. */
    fun keep(account: SipralAccount, key: String) {
        require(key.isNotEmpty()) { "a key names the account across processes" }
        synchronized(lock) { kept[key] = account }
    }

    /** Stop keeping [key], and remove what was written: for an account the
     * user removed or unregistered. */
    fun forget(key: String) {
        synchronized(lock) { kept.remove(key) }
        store.remove(PREFIX + key)
    }

    /**
     * Read what was written under [key] back onto [account], just added and
     * not registered, and keep it from then on. True when it was carried on:
     * the account reads `RESTORED` until a registrar answers its next
     * REGISTER, which [SipralAccount.refreshBinding] (or the announce a push
     * makes) sends at once. False when there was nothing usable: the
     * application registers from the beginning.
     */
    fun restore(account: SipralAccount, key: String): Boolean {
        keep(account, key)
        val record = try {
            store.read(PREFIX + key)
        } catch (unreadable: Exception) {
            failed(unreadable)
            null
        } ?: return false
        val (writtenAt, snapshot) = parse(record) ?: run {
            store.remove(PREFIX + key)
            return false
        }
        val asleep = (wallClockMs() - writtenAt).coerceAtLeast(0)
        return try {
            account.thaw(snapshot, asleep)
            true
        } catch (refused: SipralException) {
            failed(refused)
            store.remove(PREFIX + key)
            false
        }
    }

    /** Every kept account written down, then [SipralClient.suspending];
     * null when no client is attached. */
    fun enteredBackground(): SipralSuspending? {
        val current = synchronized(lock) { client } ?: return null
        writeDown()
        return current.suspending()
    }

    /** Every kept account written down now, the stack told nothing. */
    fun writeDown() {
        val accounts = synchronized(lock) { kept.entries.map { it.key to it.value } }
        for ((key, account) in accounts) {
            write(key, account)
        }
    }

    /** [SipralClient.resumed], when a client is attached. */
    fun enteredForeground() {
        synchronized(lock) { client }?.resumed()
    }

    private fun write(key: String, account: SipralAccount) {
        val snapshot = try {
            account.freeze()
        } catch (refused: SipralException) {
            if (refused.status == SipralStatus.WRONG_STATE) {
                store.remove(PREFIX + key)
            } else {
                failed(refused)
            }
            return
        }
        try {
            store.write(PREFIX + key, ByteBuffer.allocate(8 + snapshot.size).putLong(wallClockMs()).put(snapshot).array())
        } catch (unwritable: Exception) {
            failed(unwritable)
        }
    }

    internal companion object {
        const val PREFIX = "sipral.registration."

        /** Eight bytes of wall-clock milliseconds, big-endian, then the
         * snapshot; null for anything shorter. */
        fun parse(record: ByteArray): Pair<Long, ByteArray>? {
            if (record.size <= 8) {
                return null
            }
            val buffer = ByteBuffer.wrap(record)
            return buffer.getLong() to record.copyOfRange(8, record.size)
        }
    }
}
