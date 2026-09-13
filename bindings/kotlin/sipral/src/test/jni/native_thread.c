/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Tiberiu Balasea
 *
 * The one thing BindingCheck.kt cannot do from Kotlin: poll a stack on a
 * thread no JVM made. The event callback then lands on a thread the JNI shim
 * has to attach before it can call the listener, and has to detach again
 * before the thread ends -- which is the half of the shim a poll made from
 * Kotlin never reaches, because a thread that calls a native method is
 * attached already.
 */

#include <jni.h>
#include <pthread.h>

#include "sipral.h"

struct polled {
    sipral_handle_t stack;
    uint64_t now_ms;
    sipral_status_t status;
};

static void *poll_here(void *argument)
{
    struct polled *polled = (struct polled *)argument;

    polled->status = sipral_stack_poll(polled->stack, polled->now_ms, NULL);
    return NULL;
}

JNIEXPORT jint JNICALL
Java_org_sipral_NativeThread_poll(JNIEnv *env, jobject self, jlong stack, jlong nowMs)
{
    pthread_t thread;
    /* a status the poll cannot answer without panicking, so a thread that
     * never ran fails the check rather than passing it */
    struct polled polled = { (sipral_handle_t)stack, (uint64_t)nowMs, SIPRAL_STATUS_PANIC };

    (void)env;
    (void)self;
    if (pthread_create(&thread, NULL, poll_here, &polled) != 0) {
        return -1;
    }
    if (pthread_join(thread, NULL) != 0) {
        return -1;
    }
    return (jint)polled.status;
}
