/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Tiberiu Balasea
 *
 * Printed from the declarations in crates/sipral-ffi by tools/abi-gen.
 * Do not edit: `cargo run -p sipral-abi-gen` writes it again, and
 * `scripts/check.sh` fails when what is committed is not what came out.
 *
 * One function per entry point, and nothing else: the casts are the
 * whole of what it does, so that the two halves of the Kotlin binding
 * cannot drift apart without the generator saying so.
 */

#include <jni.h>
#include <string.h>

#include "sipral.h"

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1last_1error_1message(JNIEnv *env, jobject self, jbyteArray buffer, jlongArray len)
{
    (void)env;
    (void)self;
    jbyte *buffer_data = buffer ? (*env)->GetByteArrayElements(env, buffer, NULL) : NULL;
    jsize buffer_size = buffer ? (*env)->GetArrayLength(env, buffer) : 0;
    size_t len_value = 0;
    sipral_status_t status = sipral_last_error_message((char *)buffer_data, (size_t)buffer_size, &len_value);
    if (buffer) {
        (*env)->ReleaseByteArrayElements(env, buffer, buffer_data, 0);
    }
    {
        jlong slot = (jlong)len_value;
        (*env)->SetLongArrayRegion(env, len, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jstring JNICALL
Java_org_sipral_SipralNative_sipral_1status_1name(JNIEnv *env, jobject self, jlong status)
{
    (void)env;
    (void)self;
    const char *text = sipral_status_name((int32_t)status);
    return text ? (*env)->NewStringUTF(env, text) : NULL;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1abi_1version(JNIEnv *env, jobject self, jlongArray version)
{
    (void)env;
    (void)self;
    sipral_abi_version_t version_value;
    memset(&version_value, 0, sizeof version_value);
    version_value.size = sizeof version_value;
    sipral_status_t status = sipral_abi_version(&version_value);
    {
        jlong slots[4];
        slots[0] = (jlong)version_value.size;
        slots[1] = (jlong)version_value.major;
        slots[2] = (jlong)version_value.minor;
        slots[3] = (jlong)version_value.patch;
        (*env)->SetLongArrayRegion(env, version, 0, 4, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1abi_1check(JNIEnv *env, jobject self, jlong major, jlong minor)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_abi_check((uint32_t)major, (uint32_t)minor);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1capabilities(JNIEnv *env, jobject self, jlongArray capabilities)
{
    (void)env;
    (void)self;
    sipral_capabilities_t capabilities_value;
    memset(&capabilities_value, 0, sizeof capabilities_value);
    capabilities_value.size = sizeof capabilities_value;
    sipral_status_t status = sipral_capabilities(&capabilities_value);
    {
        jlong slots[4];
        slots[0] = (jlong)capabilities_value.size;
        slots[1] = (jlong)capabilities_value.codec_count;
        slots[2] = (jlong)capabilities_value.transports;
        slots[3] = (jlong)capabilities_value.features;
        (*env)->SetLongArrayRegion(env, capabilities, 0, 4, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1create(JNIEnv *env, jobject self, jlong config, jlongArray stack)
{
    (void)env;
    (void)self;
    sipral_handle_t stack_value = 0;
    sipral_status_t status = sipral_stack_create((const sipral_stack_config_t *)(intptr_t)config, &stack_value);
    {
        jlong slot = (jlong)stack_value;
        (*env)->SetLongArrayRegion(env, stack, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1settings(JNIEnv *env, jobject self, jlong stack, jlongArray settings)
{
    (void)env;
    (void)self;
    sipral_stack_settings_t settings_value;
    memset(&settings_value, 0, sizeof settings_value);
    settings_value.size = sizeof settings_value;
    sipral_status_t status = sipral_stack_settings((sipral_handle_t)stack, &settings_value);
    {
        jlong slots[12];
        slots[0] = (jlong)settings_value.size;
        slots[1] = (jlong)settings_value.transport;
        slots[2] = (jlong)settings_value.retransmits;
        slots[3] = (jlong)settings_value.timer_t1_ms;
        slots[4] = (jlong)settings_value.timer_t2_ms;
        slots[5] = (jlong)settings_value.timer_t4_ms;
        slots[6] = (jlong)settings_value.codec_count;
        slots[7] = (jlong)settings_value.frame_ms;
        slots[8] = (jlong)settings_value.offer_dtmf;
        slots[9] = (jlong)settings_value.offer_rtcp_mux;
        slots[10] = (jlong)settings_value.silence_suppression;
        slots[11] = (jlong)settings_value.media_stall_ms;
        (*env)->SetLongArrayRegion(env, settings, 0, 12, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1destroy(JNIEnv *env, jobject self, jlong stack)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_destroy((sipral_handle_t)stack);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1poll(JNIEnv *env, jobject self, jlong stack, jlong nowMs, jlongArray result)
{
    (void)env;
    (void)self;
    sipral_poll_result_t result_value;
    memset(&result_value, 0, sizeof result_value);
    result_value.size = sizeof result_value;
    sipral_status_t status = sipral_stack_poll((sipral_handle_t)stack, (uint64_t)nowMs, &result_value);
    {
        jlong slots[6];
        slots[0] = (jlong)result_value.size;
        slots[1] = (jlong)result_value.events_delivered;
        slots[2] = (jlong)result_value.events_unclaimed;
        slots[3] = (jlong)result_value.transmits_discarded;
        slots[4] = (jlong)result_value.has_deadline;
        slots[5] = (jlong)result_value.next_poll_in_ms;
        (*env)->SetLongArrayRegion(env, result, 0, 6, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1counters(JNIEnv *env, jobject self, jlong stack, jlongArray counters)
{
    (void)env;
    (void)self;
    sipral_counters_t counters_value;
    memset(&counters_value, 0, sizeof counters_value);
    counters_value.size = sizeof counters_value;
    sipral_status_t status = sipral_stack_counters((sipral_handle_t)stack, &counters_value);
    {
        jlong slots[19];
        slots[0] = (jlong)counters_value.size;
        slots[1] = (jlong)counters_value.registrations_attempted;
        slots[2] = (jlong)counters_value.registrations_succeeded;
        slots[3] = (jlong)counters_value.registrations_failed_rejected;
        slots[4] = (jlong)counters_value.registrations_failed_bad_credentials;
        slots[5] = (jlong)counters_value.registrations_failed_unreachable;
        slots[6] = (jlong)counters_value.registrations_failed_redirected;
        slots[7] = (jlong)counters_value.calls_ended_local_hangup;
        slots[8] = (jlong)counters_value.calls_ended_remote_hangup;
        slots[9] = (jlong)counters_value.calls_ended_refused;
        slots[10] = (jlong)counters_value.calls_ended_cancelled;
        slots[11] = (jlong)counters_value.calls_ended_unreachable;
        slots[12] = (jlong)counters_value.calls_ended_fork_lost;
        slots[13] = (jlong)counters_value.calls_ended_abandoned;
        slots[14] = (jlong)counters_value.calls_ended_expired;
        slots[15] = (jlong)counters_value.media_gaps;
        slots[16] = (jlong)counters_value.jitter_buffer_events;
        slots[17] = (jlong)counters_value.stream_transport_wanted;
        slots[18] = (jlong)counters_value.active_calls;
        (*env)->SetLongArrayRegion(env, counters, 0, 19, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1add(JNIEnv *env, jobject self, jlong stack, jlong config, jlongArray account)
{
    (void)env;
    (void)self;
    sipral_handle_t account_value = 0;
    sipral_status_t status = sipral_account_add((sipral_handle_t)stack, (const sipral_account_config_t *)(intptr_t)config, &account_value);
    {
        jlong slot = (jlong)account_value;
        (*env)->SetLongArrayRegion(env, account, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1remove(JNIEnv *env, jobject self, jlong stack, jlong account)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_account_remove((sipral_handle_t)stack, (sipral_handle_t)account);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1register(JNIEnv *env, jobject self, jlong stack, jlong account, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_account_register((sipral_handle_t)stack, (sipral_handle_t)account, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1unregister(JNIEnv *env, jobject self, jlong stack, jlong account, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_account_unregister((sipral_handle_t)stack, (sipral_handle_t)account, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1registration_1state(JNIEnv *env, jobject self, jlong stack, jlong account, jlongArray state)
{
    (void)env;
    (void)self;
    uint32_t state_value = 0;
    sipral_status_t status = sipral_account_registration_state((sipral_handle_t)stack, (sipral_handle_t)account, &state_value);
    {
        jlong slot = (jlong)state_value;
        (*env)->SetLongArrayRegion(env, state, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1place(JNIEnv *env, jobject self, jlong stack, jlong account, jlong config, jlongArray call, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_handle_t call_value = 0;
    sipral_status_t status = sipral_call_place((sipral_handle_t)stack, (sipral_handle_t)account, (const sipral_call_config_t *)(intptr_t)config, &call_value, (uint64_t)nowMs);
    {
        jlong slot = (jlong)call_value;
        (*env)->SetLongArrayRegion(env, call, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1ring(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray sdp, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *sdp_data = sdp ? (*env)->GetByteArrayElements(env, sdp, NULL) : NULL;
    jsize sdp_size = sdp ? (*env)->GetArrayLength(env, sdp) : 0;
    sipral_status_t status = sipral_call_ring((sipral_handle_t)stack, (sipral_handle_t)call, (const uint8_t *)sdp_data, (size_t)sdp_size, (uint64_t)nowMs);
    if (sdp) {
        (*env)->ReleaseByteArrayElements(env, sdp, sdp_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1answer(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray sdp, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *sdp_data = sdp ? (*env)->GetByteArrayElements(env, sdp, NULL) : NULL;
    jsize sdp_size = sdp ? (*env)->GetArrayLength(env, sdp) : 0;
    sipral_status_t status = sipral_call_answer((sipral_handle_t)stack, (sipral_handle_t)call, (const uint8_t *)sdp_data, (size_t)sdp_size, (uint64_t)nowMs);
    if (sdp) {
        (*env)->ReleaseByteArrayElements(env, sdp, sdp_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1answer_1media(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray mediaAddress, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *mediaAddress_data = mediaAddress ? (*env)->GetByteArrayElements(env, mediaAddress, NULL) : NULL;
    jsize mediaAddress_size = mediaAddress ? (*env)->GetArrayLength(env, mediaAddress) : 0;
    sipral_status_t status = sipral_call_answer_media((sipral_handle_t)stack, (sipral_handle_t)call, (const char *)mediaAddress_data, (size_t)mediaAddress_size, (uint64_t)nowMs);
    if (mediaAddress) {
        (*env)->ReleaseByteArrayElements(env, mediaAddress, mediaAddress_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1reject(JNIEnv *env, jobject self, jlong stack, jlong call, jlong status, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_reject((sipral_handle_t)stack, (sipral_handle_t)call, (uint32_t)status, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1hangup(JNIEnv *env, jobject self, jlong stack, jlong call, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_hangup((sipral_handle_t)stack, (sipral_handle_t)call, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1hold(JNIEnv *env, jobject self, jlong stack, jlong call, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_hold((sipral_handle_t)stack, (sipral_handle_t)call, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1resume(JNIEnv *env, jobject self, jlong stack, jlong call, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_resume((sipral_handle_t)stack, (sipral_handle_t)call, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1accept_1session(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray sdp, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *sdp_data = sdp ? (*env)->GetByteArrayElements(env, sdp, NULL) : NULL;
    jsize sdp_size = sdp ? (*env)->GetArrayLength(env, sdp) : 0;
    sipral_status_t status = sipral_call_accept_session((sipral_handle_t)stack, (sipral_handle_t)call, (const uint8_t *)sdp_data, (size_t)sdp_size, (uint64_t)nowMs);
    if (sdp) {
        (*env)->ReleaseByteArrayElements(env, sdp, sdp_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1reject_1session(JNIEnv *env, jobject self, jlong stack, jlong call, jlong status, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_reject_session((sipral_handle_t)stack, (sipral_handle_t)call, (uint32_t)status, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1send_1dtmf(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray digits, jlong via, jlong durationMs, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *digits_data = digits ? (*env)->GetByteArrayElements(env, digits, NULL) : NULL;
    jsize digits_size = digits ? (*env)->GetArrayLength(env, digits) : 0;
    sipral_status_t status = sipral_call_send_dtmf((sipral_handle_t)stack, (sipral_handle_t)call, (const char *)digits_data, (size_t)digits_size, (uint32_t)via, (uint32_t)durationMs, (uint64_t)nowMs);
    if (digits) {
        (*env)->ReleaseByteArrayElements(env, digits, digits_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1transfer(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray target, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *target_data = target ? (*env)->GetByteArrayElements(env, target, NULL) : NULL;
    jsize target_size = target ? (*env)->GetArrayLength(env, target) : 0;
    sipral_status_t status = sipral_call_transfer((sipral_handle_t)stack, (sipral_handle_t)call, (const char *)target_data, (size_t)target_size, (uint64_t)nowMs);
    if (target) {
        (*env)->ReleaseByteArrayElements(env, target, target_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1consult(JNIEnv *env, jobject self, jlong stack, jlong call, jlong config, jlongArray call, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_handle_t call_value = 0;
    sipral_status_t status = sipral_call_consult((sipral_handle_t)stack, (sipral_handle_t)call, (const sipral_call_config_t *)(intptr_t)config, &call_value, (uint64_t)nowMs);
    {
        jlong slot = (jlong)call_value;
        (*env)->SetLongArrayRegion(env, call, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1transfer_1to(JNIEnv *env, jobject self, jlong stack, jlong call, jlong other, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_transfer_to((sipral_handle_t)stack, (sipral_handle_t)call, (sipral_handle_t)other, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1accept_1transfer(JNIEnv *env, jobject self, jlong stack, jlong call, jlongArray call, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_handle_t call_value = 0;
    sipral_status_t status = sipral_call_accept_transfer((sipral_handle_t)stack, (sipral_handle_t)call, &call_value, (uint64_t)nowMs);
    {
        jlong slot = (jlong)call_value;
        (*env)->SetLongArrayRegion(env, call, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1reject_1transfer(JNIEnv *env, jobject self, jlong stack, jlong call, jlong status, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_reject_transfer((sipral_handle_t)stack, (sipral_handle_t)call, (uint32_t)status, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1state(JNIEnv *env, jobject self, jlong stack, jlong call, jlongArray state)
{
    (void)env;
    (void)self;
    uint32_t state_value = 0;
    sipral_status_t status = sipral_call_state((sipral_handle_t)stack, (sipral_handle_t)call, &state_value);
    {
        jlong slot = (jlong)state_value;
        (*env)->SetLongArrayRegion(env, state, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1hold_1state(JNIEnv *env, jobject self, jlong stack, jlong call, jlongArray here, jlongArray there)
{
    (void)env;
    (void)self;
    uint32_t here_value = 0;
    uint32_t there_value = 0;
    sipral_status_t status = sipral_call_hold_state((sipral_handle_t)stack, (sipral_handle_t)call, &here_value, &there_value);
    {
        jlong slot = (jlong)here_value;
        (*env)->SetLongArrayRegion(env, here, 0, 1, &slot);
    }
    {
        jlong slot = (jlong)there_value;
        (*env)->SetLongArrayRegion(env, there, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jstring JNICALL
Java_org_sipral_SipralNative_sipral_1codec_1name(JNIEnv *env, jobject self, jlong codec)
{
    (void)env;
    (void)self;
    const char *text = sipral_codec_name((uint32_t)codec);
    return text ? (*env)->NewStringUTF(env, text) : NULL;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1codec_1count(JNIEnv *env, jobject self, jlongArray count)
{
    (void)env;
    (void)self;
    size_t count_value = 0;
    sipral_status_t status = sipral_codec_count(&count_value);
    {
        jlong slot = (jlong)count_value;
        (*env)->SetLongArrayRegion(env, count, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1codec_1at(JNIEnv *env, jobject self, jlong index, jlongArray info)
{
    (void)env;
    (void)self;
    sipral_codec_info_t info_value;
    memset(&info_value, 0, sizeof info_value);
    info_value.size = sizeof info_value;
    sipral_status_t status = sipral_codec_at((size_t)index, &info_value);
    {
        jlong slots[6];
        slots[0] = (jlong)info_value.size;
        slots[1] = (jlong)info_value.codec;
        slots[2] = (jlong)info_value.clock_rate;
        slots[3] = (jlong)info_value.sample_rate;
        slots[4] = (jlong)info_value.static_payload_type;
        slots[5] = (jlong)info_value.has_static_payload_type;
        (*env)->SetLongArrayRegion(env, info, 0, 6, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1codec_1order(JNIEnv *env, jobject self, jlong stack, jintArray outCodecs, jlongArray count)
{
    (void)env;
    (void)self;
    jint *outCodecs_data = outCodecs ? (*env)->GetIntArrayElements(env, outCodecs, NULL) : NULL;
    jsize outCodecs_size = outCodecs ? (*env)->GetArrayLength(env, outCodecs) : 0;
    size_t count_value = 0;
    sipral_status_t status = sipral_stack_codec_order((sipral_handle_t)stack, (uint32_t *)outCodecs_data, (size_t)outCodecs_size, &count_value);
    if (outCodecs) {
        (*env)->ReleaseIntArrayElements(env, outCodecs, outCodecs_data, 0);
    }
    {
        jlong slot = (jlong)count_value;
        (*env)->SetLongArrayRegion(env, count, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1media_1info(JNIEnv *env, jobject self, jlong stack, jlong call, jlongArray info)
{
    (void)env;
    (void)self;
    sipral_media_info_t info_value;
    memset(&info_value, 0, sizeof info_value);
    info_value.size = sizeof info_value;
    sipral_status_t status = sipral_call_media_info((sipral_handle_t)stack, (sipral_handle_t)call, &info_value);
    {
        jlong slots[17];
        slots[0] = (jlong)info_value.size;
        slots[1] = (jlong)info_value.codec;
        slots[2] = (jlong)info_value.payload_type;
        slots[3] = (jlong)info_value.clock_rate;
        slots[4] = (jlong)info_value.sample_rate;
        slots[5] = (jlong)info_value.frame_ms;
        slots[6] = (jlong)info_value.frame_samples;
        slots[7] = (jlong)info_value.direction;
        slots[8] = (jlong)info_value.sending;
        slots[9] = (jlong)info_value.receiving;
        slots[10] = (jlong)info_value.has_dtmf;
        slots[11] = (jlong)info_value.dtmf_payload_type;
        slots[12] = (jlong)info_value.rtcp;
        slots[13] = (jlong)info_value.secured;
        slots[14] = (jlong)info_value.recording;
        slots[15] = (jlong)info_value.recorded_ms;
        slots[16] = (jlong)info_value.stalled;
        (*env)->SetLongArrayRegion(env, info, 0, 17, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1statistics(JNIEnv *env, jobject self, jlong stack, jlong call, jlong nowMs, jlongArray stats)
{
    (void)env;
    (void)self;
    sipral_stream_stats_t stats_value;
    memset(&stats_value, 0, sizeof stats_value);
    stats_value.size = sizeof stats_value;
    sipral_status_t status = sipral_call_statistics((sipral_handle_t)stack, (sipral_handle_t)call, (uint64_t)nowMs, &stats_value);
    {
        jlong slots[21];
        slots[0] = (jlong)stats_value.size;
        slots[1] = (jlong)stats_value.codec;
        slots[2] = (jlong)stats_value.has_round_trip;
        slots[3] = (jlong)stats_value.round_trip_us;
        slots[4] = (jlong)stats_value.packets_sent;
        slots[5] = (jlong)stats_value.octets_sent;
        slots[6] = (jlong)stats_value.packets_received;
        slots[7] = (jlong)stats_value.packets_lost;
        slots[8] = (jlong)stats_value.packets_late;
        slots[9] = (jlong)stats_value.packets_overflowed;
        slots[10] = (jlong)stats_value.packets_duplicated;
        slots[11] = (jlong)stats_value.packets_reordered;
        slots[12] = (jlong)stats_value.frames_shrunk;
        slots[13] = (jlong)stats_value.frames_stretched;
        slots[14] = (jlong)stats_value.delay_us;
        slots[15] = (jlong)stats_value.target_delay_us;
        slots[16] = (jlong)stats_value.jitter_us;
        {
            uint32_t bits;
            memcpy(&bits, &stats_value.loss_rate, sizeof bits);
            slots[17] = (jlong)bits;
        }
        {
            uint32_t bits;
            memcpy(&bits, &stats_value.score, sizeof bits);
            slots[18] = (jlong)bits;
        }
        slots[19] = (jlong)stats_value.suffering;
        slots[20] = (jlong)stats_value.silent_for_ms;
        (*env)->SetLongArrayRegion(env, stats, 0, 21, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1media_1receive(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray data, jbyteArray from, jlong nowMs, jlongArray arrival)
{
    (void)env;
    (void)self;
    jbyte *data_data = data ? (*env)->GetByteArrayElements(env, data, NULL) : NULL;
    jsize data_size = data ? (*env)->GetArrayLength(env, data) : 0;
    jbyte *from_data = from ? (*env)->GetByteArrayElements(env, from, NULL) : NULL;
    jsize from_size = from ? (*env)->GetArrayLength(env, from) : 0;
    uint32_t arrival_value = 0;
    sipral_status_t status = sipral_call_media_receive((sipral_handle_t)stack, (sipral_handle_t)call, (uint8_t *)data_data, (size_t)data_size, (const char *)from_data, (size_t)from_size, (uint64_t)nowMs, &arrival_value);
    if (data) {
        (*env)->ReleaseByteArrayElements(env, data, data_data, 0);
    }
    if (from) {
        (*env)->ReleaseByteArrayElements(env, from, from_data, JNI_ABORT);
    }
    {
        jlong slot = (jlong)arrival_value;
        (*env)->SetLongArrayRegion(env, arrival, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1playback(JNIEnv *env, jobject self, jlong stack, jlong call, jshortArray samples, jlongArray written, jlongArray source)
{
    (void)env;
    (void)self;
    jshort *samples_data = samples ? (*env)->GetShortArrayElements(env, samples, NULL) : NULL;
    jsize samples_size = samples ? (*env)->GetArrayLength(env, samples) : 0;
    size_t written_value = 0;
    uint32_t source_value = 0;
    sipral_status_t status = sipral_call_playback((sipral_handle_t)stack, (sipral_handle_t)call, (int16_t *)samples_data, (size_t)samples_size, &written_value, &source_value);
    if (samples) {
        (*env)->ReleaseShortArrayElements(env, samples, samples_data, 0);
    }
    {
        jlong slot = (jlong)written_value;
        (*env)->SetLongArrayRegion(env, written, 0, 1, &slot);
    }
    {
        jlong slot = (jlong)source_value;
        (*env)->SetLongArrayRegion(env, source, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1capture(JNIEnv *env, jobject self, jlong stack, jlong call, jshortArray samples, jlong packet)
{
    (void)env;
    (void)self;
    jshort *samples_data = samples ? (*env)->GetShortArrayElements(env, samples, NULL) : NULL;
    jsize samples_size = samples ? (*env)->GetArrayLength(env, samples) : 0;
    sipral_status_t status = sipral_call_capture((sipral_handle_t)stack, (sipral_handle_t)call, (const int16_t *)samples_data, (size_t)samples_size, (sipral_media_packet_t *)(intptr_t)packet);
    if (samples) {
        (*env)->ReleaseShortArrayElements(env, samples, samples_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1poll_1rtcp(JNIEnv *env, jobject self, jlong stack, jlong nowMs, jlongArray call, jlong packet)
{
    (void)env;
    (void)self;
    sipral_handle_t call_value = 0;
    sipral_status_t status = sipral_stack_poll_rtcp((sipral_handle_t)stack, (uint64_t)nowMs, &call_value, (sipral_media_packet_t *)(intptr_t)packet);
    {
        jlong slot = (jlong)call_value;
        (*env)->SetLongArrayRegion(env, call, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1dialling(JNIEnv *env, jobject self, jlong stack, jlong call, jlongArray dialling, jlongArray waiting)
{
    (void)env;
    (void)self;
    uint32_t dialling_value = 0;
    size_t waiting_value = 0;
    sipral_status_t status = sipral_call_dialling((sipral_handle_t)stack, (sipral_handle_t)call, &dialling_value, &waiting_value);
    {
        jlong slot = (jlong)dialling_value;
        (*env)->SetLongArrayRegion(env, dialling, 0, 1, &slot);
    }
    {
        jlong slot = (jlong)waiting_value;
        (*env)->SetLongArrayRegion(env, waiting, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1stop_1dialling(JNIEnv *env, jobject self, jlong stack, jlong call)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_stop_dialling((sipral_handle_t)stack, (sipral_handle_t)call);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1record_1start(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray path)
{
    (void)env;
    (void)self;
    jbyte *path_data = path ? (*env)->GetByteArrayElements(env, path, NULL) : NULL;
    jsize path_size = path ? (*env)->GetArrayLength(env, path) : 0;
    sipral_status_t status = sipral_call_record_start((sipral_handle_t)stack, (sipral_handle_t)call, (const char *)path_data, (size_t)path_size);
    if (path) {
        (*env)->ReleaseByteArrayElements(env, path, path_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1record_1stop(JNIEnv *env, jobject self, jlong stack, jlong call)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_record_stop((sipral_handle_t)stack, (sipral_handle_t)call);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1record_1state(JNIEnv *env, jobject self, jlong stack, jlong call, jlongArray recording, jlongArray recordedMs)
{
    (void)env;
    (void)self;
    uint32_t recording_value = 0;
    uint64_t recordedMs_value = 0;
    sipral_status_t status = sipral_call_record_state((sipral_handle_t)stack, (sipral_handle_t)call, &recording_value, &recordedMs_value);
    {
        jlong slot = (jlong)recording_value;
        (*env)->SetLongArrayRegion(env, recording, 0, 1, &slot);
    }
    {
        jlong slot = (jlong)recordedMs_value;
        (*env)->SetLongArrayRegion(env, recordedMs, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1poll_1transmit(JNIEnv *env, jobject self, jlong stack, jlong transmit)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_poll_transmit((sipral_handle_t)stack, (sipral_transmit_t *)(intptr_t)transmit);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1receive_1datagram(JNIEnv *env, jobject self, jlong stack, jlong transport, jbyteArray data, jbyteArray from, jbyteArray to, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *data_data = data ? (*env)->GetByteArrayElements(env, data, NULL) : NULL;
    jsize data_size = data ? (*env)->GetArrayLength(env, data) : 0;
    jbyte *from_data = from ? (*env)->GetByteArrayElements(env, from, NULL) : NULL;
    jsize from_size = from ? (*env)->GetArrayLength(env, from) : 0;
    jbyte *to_data = to ? (*env)->GetByteArrayElements(env, to, NULL) : NULL;
    jsize to_size = to ? (*env)->GetArrayLength(env, to) : 0;
    sipral_status_t status = sipral_stack_receive_datagram((sipral_handle_t)stack, (uint32_t)transport, (const uint8_t *)data_data, (size_t)data_size, (const char *)from_data, (size_t)from_size, (const char *)to_data, (size_t)to_size, (uint64_t)nowMs);
    if (data) {
        (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);
    }
    if (from) {
        (*env)->ReleaseByteArrayElements(env, from, from_data, JNI_ABORT);
    }
    if (to) {
        (*env)->ReleaseByteArrayElements(env, to, to_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1receive_1stream(JNIEnv *env, jobject self, jlong stack, jlong transport, jbyteArray data, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *data_data = data ? (*env)->GetByteArrayElements(env, data, NULL) : NULL;
    jsize data_size = data ? (*env)->GetArrayLength(env, data) : 0;
    sipral_status_t status = sipral_stack_receive_stream((sipral_handle_t)stack, (uint32_t)transport, (const uint8_t *)data_data, (size_t)data_size, (uint64_t)nowMs);
    if (data) {
        (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1transport_1bind(JNIEnv *env, jobject self, jlong stack, jlong transport, jbyteArray local, jbyteArray remote, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *local_data = local ? (*env)->GetByteArrayElements(env, local, NULL) : NULL;
    jsize local_size = local ? (*env)->GetArrayLength(env, local) : 0;
    jbyte *remote_data = remote ? (*env)->GetByteArrayElements(env, remote, NULL) : NULL;
    jsize remote_size = remote ? (*env)->GetArrayLength(env, remote) : 0;
    sipral_status_t status = sipral_stack_transport_bind((sipral_handle_t)stack, (uint32_t)transport, (const char *)local_data, (size_t)local_size, (const char *)remote_data, (size_t)remote_size, (uint64_t)nowMs);
    if (local) {
        (*env)->ReleaseByteArrayElements(env, local, local_data, JNI_ABORT);
    }
    if (remote) {
        (*env)->ReleaseByteArrayElements(env, remote, remote_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1transport_1failed(JNIEnv *env, jobject self, jlong stack, jlong transport, jlong error, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_transport_failed((sipral_handle_t)stack, (uint32_t)transport, (uint32_t)error, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1stream_1closed(JNIEnv *env, jobject self, jlong stack, jlong transport, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_stream_closed((sipral_handle_t)stack, (uint32_t)transport, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jstring JNICALL
Java_org_sipral_SipralNative_sipral_1event_1kind_1name(JNIEnv *env, jobject self, jlong kind)
{
    (void)env;
    (void)self;
    const char *text = sipral_event_kind_name((uint32_t)kind);
    return text ? (*env)->NewStringUTF(env, text) : NULL;
}

