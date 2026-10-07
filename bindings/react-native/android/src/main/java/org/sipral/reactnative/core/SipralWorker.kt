// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The single thread the module runs every core call on, and how calls
// after invalidation are answered.

package org.sipral.reactnative.core

import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * One thread, so JavaScript's calls reach the stack in order, and not the
 * JavaScript thread, since placing a call can wait for STUN.
 *
 * [settle] runs an action there and passes its outcome to [resolve] or
 * [reject] (a refusal by its code, anything else as `platform`). After
 * [shutdown] the module and thread are gone: a late action is not run and
 * is rejected as `closed` rather than throwing on the JavaScript thread.
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
                    // a handle or address as a string, a record as a map, nothing for Unit
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

    /** Run [last] (the core's close) after everything queued, and accept
     * nothing more. */
    fun shutdown(last: () -> Unit) {
        try {
            executor.execute(last)
        } catch (_: RejectedExecutionException) {
            // already shut down: the close ran then
        }
        executor.shutdown()
    }
}
