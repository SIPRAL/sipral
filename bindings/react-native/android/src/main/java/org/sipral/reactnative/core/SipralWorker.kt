// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The one thread the module runs every call into the core on, and how a call
// that arrives after the module was invalidated is answered.

package org.sipral.reactnative.core

import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * One thread, so that the calls JavaScript makes reach the stack in the order
 * it made them; and not the JavaScript one, since placing a call can wait for
 * a STUN server.
 *
 * [settle] runs an action there and hands its outcome to [resolve] or
 * [reject] -- a refusal by its own code, anything else as `platform`. Once
 * [shutdown] has run, the module is gone and the thread with it: an action
 * that arrives then is not run and is rejected as `closed`, rather than
 * throwing on the JavaScript thread that called it.
 */
class SipralWorker(name: String = "sipral-react-native") {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, name).apply { isDaemon = true }
    }

    fun settle(
        resolve: (Any?) -> Unit,
        reject: (code: String, message: String, cause: Throwable) -> Unit,
        action: () -> Any,
    ) {
        try {
            executor.execute {
                try {
                    // a handle or an address as a string, a record as a map,
                    // and nothing for an action that returns none
                    resolve(action().takeUnless { it is Unit })
                } catch (refused: SipralRefusal) {
                    reject(refused.code, refused.message ?: "", refused)
                } catch (failed: Exception) {
                    reject("platform", failed.message ?: failed.toString(), failed)
                }
            }
        } catch (gone: RejectedExecutionException) {
            reject("closed", "the module was invalidated", gone)
        }
    }

    /** Run [last] -- the core's close -- after everything queued, and take no
     * more. */
    fun shutdown(last: () -> Unit) {
        try {
            executor.execute(last)
        } catch (_: RejectedExecutionException) {
            // shut down already: the close ran then
        }
        executor.shutdown()
    }
}
