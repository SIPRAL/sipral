/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Tiberiu Balasea
 *
 * Hand-written, not printed by tools/abi-gen: the idiomatic layer's own
 * small shim, sitting beside the generated sipral_jni.c rather than inside
 * it. bindings/kotlin/README.md names the gap this closes -- "docs/08-ffi.md
 * says what else the binding does not carry: the event payload union, and
 * the two structs a caller part-fills with buffers, which still cross as
 * addresses" -- sipral_media_packet_t is one of those two structs, and the
 * generated Kotlin binding has no way to build one: sipral_media_capture,
 * sipral_media_poll_rtcp, sipral_media_poll_transmit and
 * sipral_stack_poll_farewell all take a `sipral_media_packet_t *`, printed
 * into SipralAbi.kt as a bare `packet: Long` -- a native address a caller is
 * left to construct however it can (docs/08-ffi.md, "The conventions are
 * load-bearing now"). This file is that construction, exposed as plain
 * byte arrays so org.sipral.idiomatic can stay pure Kotlin above it.
 *
 * Four entry points, each building one sipral_media_packet_t on the C stack,
 * filling it from Java arrays the caller owns, and copying what came back
 * into two more the caller also owns -- nothing here keeps a pointer past
 * its own call, the same rule sipral_jni.c follows throughout.
 */

#include <jni.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sipral.h"

/* Fill one sipral_media_packet_t pointed at data/destination buffers the
 * caller pinned, run `fetch`, and copy `len`/`destination_len` back into
 * `outLen` (two longs: len, destination_len). Returns the status. */
static jint
run_packet_call(JNIEnv *env, jbyteArray outData, jbyteArray outDestination, jlongArray outLen,
    sipral_status_t (*fetch)(sipral_media_packet_t *, void *), void *arg)
{
    sipral_media_packet_t packet;
    jbyte *data_buf;
    jsize data_cap;
    jbyte *dest_buf = NULL;
    jsize dest_cap = 0;
    sipral_status_t status;
    jlong lens[2];

    memset(&packet, 0, sizeof packet);
    packet.size = sizeof packet;

    data_cap = (*env)->GetArrayLength(env, outData);
    data_buf = (*env)->GetByteArrayElements(env, outData, NULL);
    if (data_buf == NULL) {
        return (jint)-1;
    }
    packet.data = (uint8_t *)data_buf;
    packet.capacity = (size_t)data_cap;

    if (outDestination != NULL) {
        dest_cap = (*env)->GetArrayLength(env, outDestination);
        dest_buf = (*env)->GetByteArrayElements(env, outDestination, NULL);
        if (dest_buf == NULL) {
            (*env)->ReleaseByteArrayElements(env, outData, data_buf, JNI_ABORT);
            return (jint)-1;
        }
        packet.destination = (char *)dest_buf;
        packet.destination_capacity = (size_t)dest_cap;
    }

    status = fetch(&packet, arg);

    (*env)->ReleaseByteArrayElements(env, outData, data_buf, 0);
    if (dest_buf != NULL) {
        (*env)->ReleaseByteArrayElements(env, outDestination, dest_buf, 0);
    }

    lens[0] = (jlong)packet.len;
    lens[1] = (jlong)packet.destination_len;
    (*env)->SetLongArrayRegion(env, outLen, 0, 2, lens);
    return (jint)status;
}

struct capture_args {
    sipral_handle_t media;
    uint64_t now_ms;
    const int16_t *samples;
    size_t sample_count;
};

static sipral_status_t
capture_fetch(sipral_media_packet_t *packet, void *raw)
{
    struct capture_args *args = (struct capture_args *)raw;
    return sipral_media_capture(args->media, args->now_ms, args->samples, args->sample_count, packet);
}

JNIEXPORT jint JNICALL
Java_org_sipral_idiomatic_SipralMediaNative_mediaCapture(JNIEnv *env, jclass cls,
    jlong media, jlong nowMs, jshortArray samples, jbyteArray outData, jbyteArray outDestination, jlongArray outLen)
{
    struct capture_args args;
    jshort *samples_data;
    jsize sample_count;
    jint status;

    (void)cls;
    sample_count = (*env)->GetArrayLength(env, samples);
    samples_data = (*env)->GetShortArrayElements(env, samples, NULL);
    if (samples_data == NULL) {
        return (jint)-1;
    }
    args.media = (sipral_handle_t)media;
    args.now_ms = (uint64_t)nowMs;
    args.samples = (const int16_t *)samples_data;
    args.sample_count = (size_t)sample_count;
    status = run_packet_call(env, outData, outDestination, outLen, capture_fetch, &args);
    (*env)->ReleaseShortArrayElements(env, samples, samples_data, JNI_ABORT);
    return status;
}

struct media_now_args {
    sipral_handle_t media;
    uint64_t now_ms;
};

static sipral_status_t
poll_rtcp_fetch(sipral_media_packet_t *packet, void *raw)
{
    struct media_now_args *args = (struct media_now_args *)raw;
    return sipral_media_poll_rtcp(args->media, args->now_ms, packet);
}

JNIEXPORT jint JNICALL
Java_org_sipral_idiomatic_SipralMediaNative_mediaPollRtcp(JNIEnv *env, jclass cls,
    jlong media, jlong nowMs, jbyteArray outData, jbyteArray outDestination, jlongArray outLen)
{
    struct media_now_args args;

    (void)cls;
    args.media = (sipral_handle_t)media;
    args.now_ms = (uint64_t)nowMs;
    return run_packet_call(env, outData, outDestination, outLen, poll_rtcp_fetch, &args);
}

static sipral_status_t
poll_transmit_fetch(sipral_media_packet_t *packet, void *raw)
{
    struct media_now_args *args = (struct media_now_args *)raw;
    return sipral_media_poll_transmit(args->media, args->now_ms, packet);
}

JNIEXPORT jint JNICALL
Java_org_sipral_idiomatic_SipralMediaNative_mediaPollTransmit(JNIEnv *env, jclass cls,
    jlong media, jlong nowMs, jbyteArray outData, jbyteArray outDestination, jlongArray outLen)
{
    struct media_now_args args;

    (void)cls;
    args.media = (sipral_handle_t)media;
    args.now_ms = (uint64_t)nowMs;
    return run_packet_call(env, outData, outDestination, outLen, poll_transmit_fetch, &args);
}

struct farewell_args {
    sipral_handle_t stack;
    sipral_handle_t out_call;
};

static sipral_status_t
farewell_fetch(sipral_media_packet_t *packet, void *raw)
{
    struct farewell_args *args = (struct farewell_args *)raw;
    return sipral_stack_poll_farewell(args->stack, &args->out_call, packet);
}

JNIEXPORT jint JNICALL
Java_org_sipral_idiomatic_SipralMediaNative_stackPollFarewell(JNIEnv *env, jclass cls,
    jlong stack, jbyteArray outData, jbyteArray outDestination, jlongArray outLen, jlongArray outCall)
{
    struct farewell_args args;
    jint status;
    jlong call_slot;

    (void)cls;
    args.stack = (sipral_handle_t)stack;
    args.out_call = 0;
    status = run_packet_call(env, outData, outDestination, outLen, farewell_fetch, &args);
    call_slot = (jlong)args.out_call;
    (*env)->SetLongArrayRegion(env, outCall, 0, 1, &call_slot);
    return status;
}

/* sipral_stack_poll_transmit's sipral_transmit_t is the other struct a
 * caller "part-fills with buffers", for signalling rather than media, and
 * SipralAbi.kt has the same gap for it as for sipral_media_packet_t above:
 * the generated sipral_stack_poll_transmit(stack: Long, transmit: Long)
 * takes a native address with nothing here to build one from. */
JNIEXPORT jint JNICALL
Java_org_sipral_idiomatic_SipralSignalNative_stackPollTransmit(JNIEnv *env, jclass cls,
    jlong stack, jbyteArray outData, jbyteArray outDestination, jlongArray outLen)
{
    sipral_transmit_t transmit;
    jbyte *data_buf;
    jsize data_cap;
    jbyte *dest_buf;
    jsize dest_cap;
    sipral_status_t status;
    jlong lens[3];

    (void)cls;
    memset(&transmit, 0, sizeof transmit);
    transmit.size = sizeof transmit;

    data_cap = (*env)->GetArrayLength(env, outData);
    data_buf = (*env)->GetByteArrayElements(env, outData, NULL);
    if (data_buf == NULL) {
        return (jint)-1;
    }
    transmit.data = (uint8_t *)data_buf;
    transmit.capacity = (size_t)data_cap;

    dest_cap = (*env)->GetArrayLength(env, outDestination);
    dest_buf = (*env)->GetByteArrayElements(env, outDestination, NULL);
    if (dest_buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, outData, data_buf, JNI_ABORT);
        return (jint)-1;
    }
    transmit.destination = (char *)dest_buf;
    transmit.destination_capacity = (size_t)dest_cap;
    /* transmit.source left null/zero: this shim is used only where the
     * caller's own socket is unconnected and does not need to answer from
     * a source address of its own -- loopback tests and the lab agent. */

    status = sipral_stack_poll_transmit((sipral_handle_t)stack, &transmit);

    (*env)->ReleaseByteArrayElements(env, outData, data_buf, 0);
    (*env)->ReleaseByteArrayElements(env, outDestination, dest_buf, 0);

    lens[0] = (jlong)transmit.len;
    lens[1] = (jlong)transmit.destination_len;
    lens[2] = (jlong)transmit.protocol;
    (*env)->SetLongArrayRegion(env, outLen, 0, 3, lens);
    return (jint)status;
}
