/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Sytek
 *
 * Two things BindingCheck.kt cannot do from Kotlin. First, poll a stack on
 * a thread no JVM made, so the shim must attach it before calling the
 * listener and detach it after; a thread calling a native method is
 * already attached, so a Kotlin poll never reaches that path.
 *
 * Second, read what a stack wants sent: sipral_stack_poll_transmit takes a
 * caller-filled struct the binding passes as an address, and header fields
 * set from a list can only be read back out of the message.
 */

/* Before any header: pthread.h is POSIX, not ISO C, and glibc under a
 * strict -std hides what is not asked for (see `scripts/check.sh`). */
#define _POSIX_C_SOURCE 200809L

#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

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
    /* a status the poll cannot return without panicking, so a thread that
     * never ran fails the check */
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

JNIEXPORT jbyteArray JNICALL
Java_org_sipral_NativeThread_transmitted(JNIEnv *env, jobject self, jlong stack)
{
    char destination[SIPRAL_ADDRESS_BYTES];
    char source[SIPRAL_ADDRESS_BYTES];
    sipral_transmit_t transmit;
    jbyteArray datagram = NULL;
    uint8_t *data = malloc(SIPRAL_MESSAGE_BYTES);
    jclass thrown;

    (void)self;
    if (data == NULL) {
        thrown = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (thrown != NULL) {
            (*env)->ThrowNew(env, thrown, "no room for a datagram");
            (*env)->DeleteLocalRef(env, thrown);
        }
        return NULL;
    }
    memset(&transmit, 0, sizeof transmit);
    transmit.size = sizeof transmit;
    transmit.data = data;
    transmit.capacity = SIPRAL_MESSAGE_BYTES;
    transmit.destination = destination;
    transmit.destination_capacity = sizeof destination;
    transmit.source = source;
    transmit.source_capacity = sizeof source;
    if (sipral_stack_poll_transmit((sipral_handle_t)stack, &transmit) != SIPRAL_STATUS_OK) {
        /* a failed poll is not a stack with nothing to send, and the caller must
         * hear the difference */
        thrown = (*env)->FindClass(env, "java/lang/IllegalStateException");
        if (thrown != NULL) {
            (*env)->ThrowNew(env, thrown, "sipral_stack_poll_transmit did not answer ok");
            (*env)->DeleteLocalRef(env, thrown);
        }
    } else if (transmit.len > 0) {
        datagram = (*env)->NewByteArray(env, (jsize)transmit.len);
        if (datagram != NULL) {
            (*env)->SetByteArrayRegion(env, datagram, 0, (jsize)transmit.len, (const jbyte *)data);
        }
    }
    free(data);
    return datagram;
}
