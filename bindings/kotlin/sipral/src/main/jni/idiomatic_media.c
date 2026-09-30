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
 * Six entry points -- the four above, and sipral_media_poll_text and
 * sipral_media_poll_recording beside them -- each building one
 * sipral_media_packet_t on the C stack (and sipral_media_mix, two),
 * filling it from Java arrays the caller owns, and copying what came back
 * into two more the caller also owns -- nothing here keeps a pointer past
 * its own call, the same rule sipral_jni.c follows throughout. Below them,
 * the same done for sipral_path_candidate_t and sipral_transmit_t, the
 * other structs a caller part-fills with buffers.
 */

#include <jni.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sipral.h"

/* Fill one sipral_media_packet_t pointed at data/destination buffers the
 * caller pinned, run `fetch`, and copy `len`, `destination_len` and
 * `protocol` back into `outLen` -- as many of the three as it has room for,
 * so a caller that brings two longs still gets the first two. Returns the
 * status. */
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
    jlong lens[3];
    jsize room;

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
    lens[2] = (jlong)packet.protocol;
    room = (*env)->GetArrayLength(env, outLen);
    (*env)->SetLongArrayRegion(env, outLen, 0, room < 3 ? room : 3, lens);
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

/* One sipral_media_packet_t over arrays the caller owns, for the one entry
 * point that fills two at once and so cannot go through run_packet_call. */
struct pinned_packet {
    sipral_media_packet_t packet;
    jbyteArray data;
    jbyte *data_buf;
    jbyteArray destination;
    jbyte *dest_buf;
};

/* Pin `outData` (and `outDestination`, when not null) under `pinned`'s
 * packet. Returns 0, or -1 with nothing left pinned. */
static int
pin_packet(JNIEnv *env, struct pinned_packet *pinned, jbyteArray outData,
    jbyteArray outDestination)
{
    memset(pinned, 0, sizeof *pinned);
    pinned->packet.size = sizeof pinned->packet;
    pinned->data = outData;
    pinned->data_buf = (*env)->GetByteArrayElements(env, outData, NULL);
    if (pinned->data_buf == NULL) {
        return -1;
    }
    pinned->packet.data = (uint8_t *)pinned->data_buf;
    pinned->packet.capacity = (size_t)(*env)->GetArrayLength(env, outData);
    if (outDestination != NULL) {
        pinned->destination = outDestination;
        pinned->dest_buf = (*env)->GetByteArrayElements(env, outDestination, NULL);
        if (pinned->dest_buf == NULL) {
            (*env)->ReleaseByteArrayElements(env, outData, pinned->data_buf, JNI_ABORT);
            return -1;
        }
        pinned->packet.destination = (char *)pinned->dest_buf;
        pinned->packet.destination_capacity =
            (size_t)(*env)->GetArrayLength(env, outDestination);
    }
    return 0;
}

/* Copy what the library wrote back into the arrays, and `len`,
 * `destination_len` and `protocol` into `outLen` as run_packet_call does. */
static void
unpin_packet(JNIEnv *env, struct pinned_packet *pinned, jlongArray outLen)
{
    jlong lens[3];
    jsize room;

    (*env)->ReleaseByteArrayElements(env, pinned->data, pinned->data_buf, 0);
    if (pinned->dest_buf != NULL) {
        (*env)->ReleaseByteArrayElements(env, pinned->destination, pinned->dest_buf, 0);
    }
    lens[0] = (jlong)pinned->packet.len;
    lens[1] = (jlong)pinned->packet.destination_len;
    lens[2] = (jlong)pinned->packet.protocol;
    room = (*env)->GetArrayLength(env, outLen);
    (*env)->SetLongArrayRegion(env, outLen, 0, room < 3 ? room : 3, lens);
}

/* sipral_media_mix: a frame of the microphone into each of two joined calls,
 * and what their far ends sent into `local`. SipralAbi.kt prints its two
 * sipral_media_packet_t as bare addresses, which is no way to call it. */
JNIEXPORT jint JNICALL
Java_org_sipral_idiomatic_SipralMediaNative_mediaMix(JNIEnv *env, jclass cls,
    jlong mediaA, jlong mediaB, jlong nowMs, jshortArray mic, jshortArray local,
    jbyteArray outDataA, jbyteArray outDestinationA, jlongArray outLenA,
    jbyteArray outDataB, jbyteArray outDestinationB, jlongArray outLenB)
{
    struct pinned_packet a;
    struct pinned_packet b;
    jshort *mic_buf;
    jshort *local_buf;
    sipral_status_t status;

    (void)cls;
    mic_buf = (*env)->GetShortArrayElements(env, mic, NULL);
    if (mic_buf == NULL) {
        return (jint)-1;
    }
    local_buf = (*env)->GetShortArrayElements(env, local, NULL);
    if (local_buf == NULL) {
        (*env)->ReleaseShortArrayElements(env, mic, mic_buf, JNI_ABORT);
        return (jint)-1;
    }
    if (pin_packet(env, &a, outDataA, outDestinationA) != 0) {
        (*env)->ReleaseShortArrayElements(env, local, local_buf, JNI_ABORT);
        (*env)->ReleaseShortArrayElements(env, mic, mic_buf, JNI_ABORT);
        return (jint)-1;
    }
    if (pin_packet(env, &b, outDataB, outDestinationB) != 0) {
        unpin_packet(env, &a, outLenA);
        (*env)->ReleaseShortArrayElements(env, local, local_buf, JNI_ABORT);
        (*env)->ReleaseShortArrayElements(env, mic, mic_buf, JNI_ABORT);
        return (jint)-1;
    }
    status = sipral_media_mix((sipral_handle_t)mediaA, (sipral_handle_t)mediaB,
        (uint64_t)nowMs, (const int16_t *)mic_buf, (size_t)(*env)->GetArrayLength(env, mic),
        (int16_t *)local_buf, (size_t)(*env)->GetArrayLength(env, local), &a.packet, &b.packet);
    unpin_packet(env, &b, outLenB);
    unpin_packet(env, &a, outLenA);
    (*env)->ReleaseShortArrayElements(env, local, local_buf, 0);
    (*env)->ReleaseShortArrayElements(env, mic, mic_buf, JNI_ABORT);
    return (jint)status;
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

struct conference_args {
    sipral_handle_t conference;
    sipral_handle_t out_call;
};

static sipral_status_t
conference_fetch(sipral_media_packet_t *packet, void *raw)
{
    struct conference_args *args = (struct conference_args *)raw;
    return sipral_local_conference_poll_transmit(args->conference, &args->out_call, packet);
}

/* sipral_local_conference_poll_transmit: the oldest packet a member of a
 * local conference owes its far end, filled the same way, with the call it
 * belongs to in outCall. */
JNIEXPORT jint JNICALL
Java_org_sipral_idiomatic_SipralMediaNative_localConferencePollTransmit(JNIEnv *env, jclass cls,
    jlong conference, jbyteArray outData, jbyteArray outDestination, jlongArray outLen, jlongArray outCall)
{
    struct conference_args args;
    jint status;
    jlong call_slot;

    (void)cls;
    args.conference = (sipral_handle_t)conference;
    args.out_call = 0;
    status = run_packet_call(env, outData, outDestination, outLen, conference_fetch, &args);
    call_slot = (jlong)args.out_call;
    (*env)->SetLongArrayRegion(env, outCall, 0, 1, &call_slot);
    return status;
}

static sipral_status_t
poll_text_fetch(sipral_media_packet_t *packet, void *raw)
{
    struct media_now_args *args = (struct media_now_args *)raw;
    return sipral_media_poll_text(args->media, args->now_ms, packet);
}

/* sipral_media_poll_text: the next datagram due on the call's real-time text
 * socket, filled the same way. */
JNIEXPORT jint JNICALL
Java_org_sipral_idiomatic_SipralMediaNative_mediaPollText(JNIEnv *env, jclass cls,
    jlong media, jlong nowMs, jbyteArray outData, jbyteArray outDestination, jlongArray outLen)
{
    struct media_now_args args;

    (void)cls;
    args.media = (sipral_handle_t)media;
    args.now_ms = (uint64_t)nowMs;
    return run_packet_call(env, outData, outDestination, outLen, poll_text_fetch, &args);
}

struct recording_args {
    sipral_handle_t media;
    uint32_t far_end;
};

static sipral_status_t
poll_recording_fetch(sipral_media_packet_t *packet, void *raw)
{
    struct recording_args *args = (struct recording_args *)raw;
    return sipral_media_poll_recording(args->media, packet, &args->far_end);
}

/* sipral_media_poll_recording: the next copy for the recording server,
 * filled the same way, with which socket it leaves from -- 0 this end's, 1
 * the far end's -- in `outFarEnd`. */
JNIEXPORT jint JNICALL
Java_org_sipral_idiomatic_SipralMediaNative_mediaPollRecording(JNIEnv *env, jclass cls,
    jlong media, jbyteArray outData, jbyteArray outDestination, jlongArray outLen, jlongArray outFarEnd)
{
    struct recording_args args;
    jint status;
    jlong far_end;

    (void)cls;
    args.media = (sipral_handle_t)media;
    args.far_end = 0;
    status = run_packet_call(env, outData, outDestination, outLen, poll_recording_fetch, &args);
    far_end = (jlong)args.far_end;
    (*env)->SetLongArrayRegion(env, outFarEnd, 0, 1, &far_end);
    return status;
}

/* sipral_media_path_candidate_at's sipral_path_candidate_t is a third struct
 * a caller part-fills with buffers: two addresses, the path's own and the far
 * one. Both buffers are the caller's, and `outNumbers` comes back as
 * [priority, kind, outcome, code, local_kind, remote_kind, local_len,
 * remote_len]. */
JNIEXPORT jint JNICALL
Java_org_sipral_idiomatic_SipralMediaNative_mediaPathCandidateAt(JNIEnv *env, jclass cls,
    jlong media, jlong index, jbyteArray outLocal, jbyteArray outRemote, jlongArray outNumbers)
{
    sipral_path_candidate_t path;
    jbyte *local_buf;
    jbyte *remote_buf;
    sipral_status_t status;
    jlong numbers[8];

    (void)cls;
    memset(&path, 0, sizeof path);
    path.size = sizeof path;

    local_buf = (*env)->GetByteArrayElements(env, outLocal, NULL);
    if (local_buf == NULL) {
        return (jint)-1;
    }
    remote_buf = (*env)->GetByteArrayElements(env, outRemote, NULL);
    if (remote_buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, outLocal, local_buf, JNI_ABORT);
        return (jint)-1;
    }
    path.local = (char *)local_buf;
    path.local_capacity = (size_t)(*env)->GetArrayLength(env, outLocal);
    path.remote = (char *)remote_buf;
    path.remote_capacity = (size_t)(*env)->GetArrayLength(env, outRemote);

    status = sipral_media_path_candidate_at((sipral_handle_t)media, (size_t)index, &path);

    (*env)->ReleaseByteArrayElements(env, outRemote, remote_buf, 0);
    (*env)->ReleaseByteArrayElements(env, outLocal, local_buf, 0);

    numbers[0] = (jlong)path.priority;
    numbers[1] = (jlong)path.kind;
    numbers[2] = (jlong)path.outcome;
    numbers[3] = (jlong)path.code;
    numbers[4] = (jlong)path.local_kind;
    numbers[5] = (jlong)path.remote_kind;
    numbers[6] = (jlong)path.local_len;
    numbers[7] = (jlong)path.remote_len;
    (*env)->SetLongArrayRegion(env, outNumbers, 0, 8, numbers);
    return (jint)status;
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
    jlong lens[4];
    jsize room;

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

    /* the transport it goes out on fourth, for a caller that brings room:
     * a recording session's own connection is not the main one */
    lens[0] = (jlong)transmit.len;
    lens[1] = (jlong)transmit.destination_len;
    lens[2] = (jlong)transmit.protocol;
    lens[3] = (jlong)transmit.transport;
    room = (*env)->GetArrayLength(env, outLen);
    (*env)->SetLongArrayRegion(env, outLen, 0, room < 4 ? room : 4, lens);
    return (jint)status;
}

/* sipral_stack_poll_stun fills the same sipral_transmit_t, and here the
 * source is the point: it names the media socket the request has to leave
 * from, since the address the server sees it come from is the answer. So all
 * three buffers are the caller's, and `outLen` comes back as
 * [len, destination_len, source_len, protocol] -- as many as it has room
 * for -- the last saying whether it is a datagram or bytes for the socket's
 * connection to a TURN server reached over TCP or TLS. */
JNIEXPORT jint JNICALL
Java_org_sipral_idiomatic_SipralSignalNative_stackPollStun(JNIEnv *env, jclass cls,
    jlong stack, jbyteArray outData, jbyteArray outDestination, jbyteArray outSource,
    jlongArray outLen)
{
    sipral_transmit_t transmit;
    jbyte *data_buf;
    jbyte *dest_buf;
    jbyte *source_buf;
    sipral_status_t status;
    jlong lens[4];
    jsize room;

    (void)cls;
    memset(&transmit, 0, sizeof transmit);
    transmit.size = sizeof transmit;

    data_buf = (*env)->GetByteArrayElements(env, outData, NULL);
    if (data_buf == NULL) {
        return (jint)-1;
    }
    dest_buf = (*env)->GetByteArrayElements(env, outDestination, NULL);
    if (dest_buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, outData, data_buf, JNI_ABORT);
        return (jint)-1;
    }
    source_buf = (*env)->GetByteArrayElements(env, outSource, NULL);
    if (source_buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, outDestination, dest_buf, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, outData, data_buf, JNI_ABORT);
        return (jint)-1;
    }
    transmit.data = (uint8_t *)data_buf;
    transmit.capacity = (size_t)(*env)->GetArrayLength(env, outData);
    transmit.destination = (char *)dest_buf;
    transmit.destination_capacity = (size_t)(*env)->GetArrayLength(env, outDestination);
    transmit.source = (char *)source_buf;
    transmit.source_capacity = (size_t)(*env)->GetArrayLength(env, outSource);

    status = sipral_stack_poll_stun((sipral_handle_t)stack, &transmit);

    (*env)->ReleaseByteArrayElements(env, outSource, source_buf, 0);
    (*env)->ReleaseByteArrayElements(env, outDestination, dest_buf, 0);
    (*env)->ReleaseByteArrayElements(env, outData, data_buf, 0);

    lens[0] = (jlong)transmit.len;
    lens[1] = (jlong)transmit.destination_len;
    lens[2] = (jlong)transmit.source_len;
    lens[3] = (jlong)transmit.protocol;
    room = (*env)->GetArrayLength(env, outLen);
    (*env)->SetLongArrayRegion(env, outLen, 0, room < 4 ? room : 4, lens);
    return (jint)status;
}

/* sipral_stack_transport_bind for the main transport, bound again at
 * `local` after the network changed, speaking what it already speaks. The
 * remote is the null pointer a datagram transport says "none" with: the
 * generated shim turns an empty Kotlin array into a pointer the stack reads
 * as an address, and refuses. */
JNIEXPORT jint JNICALL
Java_org_sipral_idiomatic_SipralSignalNative_stackTransportRebind(JNIEnv *env, jclass cls,
    jlong stack, jbyteArray local, jlong nowMs)
{
    jbyte *local_buf;
    jsize local_len;
    sipral_status_t status;

    (void)cls;
    local_len = (*env)->GetArrayLength(env, local);
    local_buf = (*env)->GetByteArrayElements(env, local, NULL);
    if (local_buf == NULL) {
        return (jint)-1;
    }
    status = sipral_stack_transport_bind((sipral_handle_t)stack, SIPRAL_TRANSPORT_MAIN, 0,
        (const char *)local_buf, (size_t)local_len, NULL, 0, (uint64_t)nowMs, NULL);
    (*env)->ReleaseByteArrayElements(env, local, local_buf, JNI_ABORT);
    return (jint)status;
}
