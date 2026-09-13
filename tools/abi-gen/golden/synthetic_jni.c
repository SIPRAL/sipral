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
Java_org_sipral_SipralNative_sipral_1abi_1check(JNIEnv *env, jobject self, jlong major, jlong minor)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_abi_check((uint32_t)major, (uint32_t)minor);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1last_1error_1message(JNIEnv *env, jobject self, jbyteArray buffer, jlongArray needed)
{
    (void)env;
    (void)self;
    jbyte *buffer_data = buffer ? (*env)->GetByteArrayElements(env, buffer, NULL) : NULL;
    jsize buffer_size = buffer ? (*env)->GetArrayLength(env, buffer) : 0;
    size_t needed_value = 0;
    sipral_status_t status = sipral_last_error_message((char *)buffer_data, (size_t)buffer_size, &needed_value);
    if (buffer) {
        (*env)->ReleaseByteArrayElements(env, buffer, buffer_data, 0);
    }
    {
        jlong slot = (jlong)needed_value;
        (*env)->SetLongArrayRegion(env, needed, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jstring JNICALL
Java_org_sipral_SipralNative_sipral_1status_1name(JNIEnv *env, jobject self, jlong code)
{
    (void)env;
    (void)self;
    const char *text = sipral_status_name((int32_t)code);
    return text ? (*env)->NewStringUTF(env, text) : NULL;
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
Java_org_sipral_SipralNative_sipral_1stack_1counters(JNIEnv *env, jobject self, jlong stack, jlongArray counters)
{
    (void)env;
    (void)self;
    sipral_counters_t counters_value;
    memset(&counters_value, 0, sizeof counters_value);
    counters_value.size = sizeof counters_value;
    sipral_status_t status = sipral_stack_counters((sipral_handle_t)stack, &counters_value);
    {
        jlong slots[3];
        slots[0] = (jlong)counters_value.size;
        slots[1] = (jlong)counters_value.requests_sent;
        {
            uint32_t bits;
            memcpy(&bits, &counters_value.loss, sizeof bits);
            slots[2] = (jlong)bits;
        }
        (*env)->SetLongArrayRegion(env, counters, 0, 3, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1send(JNIEnv *env, jobject self, jlong stack, jbyteArray message)
{
    (void)env;
    (void)self;
    jbyte *message_data = message ? (*env)->GetByteArrayElements(env, message, NULL) : NULL;
    jsize message_size = message ? (*env)->GetArrayLength(env, message) : 0;
    sipral_status_t status = sipral_stack_send((sipral_handle_t)stack, (const uint8_t *)message_data, (size_t)message_size);
    if (message) {
        (*env)->ReleaseByteArrayElements(env, message, message_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1describe(JNIEnv *env, jobject self, jlong stack, jbyteArray note)
{
    (void)env;
    (void)self;
    jbyte *note_data = note ? (*env)->GetByteArrayElements(env, note, NULL) : NULL;
    jsize note_size = note ? (*env)->GetArrayLength(env, note) : 0;
    sipral_status_t status = sipral_stack_describe((sipral_handle_t)stack, (const char *)note_data, (size_t)note_size);
    if (note) {
        (*env)->ReleaseByteArrayElements(env, note, note_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1name(JNIEnv *env, jobject self, jlong stack, jbyteArray name, jlongArray len)
{
    (void)env;
    (void)self;
    jbyte *name_data = name ? (*env)->GetByteArrayElements(env, name, NULL) : NULL;
    jsize name_size = name ? (*env)->GetArrayLength(env, name) : 0;
    size_t len_value = 0;
    sipral_status_t status = sipral_stack_name((sipral_handle_t)stack, (char *)name_data, (size_t)name_size, &len_value);
    if (name) {
        (*env)->ReleaseByteArrayElements(env, name, name_data, 0);
    }
    {
        jlong slot = (jlong)len_value;
        (*env)->SetLongArrayRegion(env, len, 0, 1, &slot);
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
Java_org_sipral_SipralNative_sipral_1call_1playback(JNIEnv *env, jobject self, jlong stack, jshortArray samples, jlongArray written)
{
    (void)env;
    (void)self;
    jshort *samples_data = samples ? (*env)->GetShortArrayElements(env, samples, NULL) : NULL;
    jsize samples_size = samples ? (*env)->GetArrayLength(env, samples) : 0;
    size_t written_value = 0;
    sipral_status_t status = sipral_call_playback((sipral_handle_t)stack, (int16_t *)samples_data, (size_t)samples_size, &written_value);
    if (samples) {
        (*env)->ReleaseShortArrayElements(env, samples, samples_data, 0);
    }
    {
        jlong slot = (jlong)written_value;
        (*env)->SetLongArrayRegion(env, written, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1capture(JNIEnv *env, jobject self, jlong stack, jshortArray samples, jlong packet)
{
    (void)env;
    (void)self;
    jshort *samples_data = samples ? (*env)->GetShortArrayElements(env, samples, NULL) : NULL;
    jsize samples_size = samples ? (*env)->GetArrayLength(env, samples) : 0;
    sipral_status_t status = sipral_call_capture((sipral_handle_t)stack, (const int16_t *)samples_data, (size_t)samples_size, (sipral_media_packet_t *)(intptr_t)packet);
    if (samples) {
        (*env)->ReleaseShortArrayElements(env, samples, samples_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1media_1receive(JNIEnv *env, jobject self, jlong stack, jbyteArray data, jlongArray arrival)
{
    (void)env;
    (void)self;
    jbyte *data_data = data ? (*env)->GetByteArrayElements(env, data, NULL) : NULL;
    jsize data_size = data ? (*env)->GetArrayLength(env, data) : 0;
    uint32_t arrival_value = 0;
    sipral_status_t status = sipral_call_media_receive((sipral_handle_t)stack, (uint8_t *)data_data, (size_t)data_size, &arrival_value);
    if (data) {
        (*env)->ReleaseByteArrayElements(env, data, data_data, 0);
    }
    {
        jlong slot = (jlong)arrival_value;
        (*env)->SetLongArrayRegion(env, arrival, 0, 1, &slot);
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

