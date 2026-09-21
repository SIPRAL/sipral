/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Tiberiu Balasea
 *
 * Printed from the declarations in crates/sipral-ffi by tools/abi-gen.
 * Do not edit: `cargo run -p sipral-abi-gen` writes it again, and
 * `scripts/check.sh` fails when what is committed is not what came out.
 *
 * One function per entry point, one function per callback for it to land
 * in, and the load hook that finds what those hand events to. All of it
 * is printed from the same walk as the Kotlin beside it, so that the two
 * halves of the binding cannot drift apart without the generator saying so.
 */

#include <jni.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "sipral.h"

/* The JVM this library was loaded into, and for each callback the class and
 * method its events are handed to. They are looked up as the library loads,
 * on the thread that loaded it, because a thread attached later looks a
 * class up through the system class loader, which on Android cannot see
 * the application's. */
static JavaVM *jni_vm;
static jclass jni_event_callback_class;
static jmethodID jni_event_callback_deliver;
static jclass jni_screen_callback_class;
static jmethodID jni_screen_callback_deliver;

/* Whether the struct a callback was handed reaches as far as one of its
 * members: the library fills in no more of it than its size member says. */
#define JNI_REACHES(pointer, type, member) \
    ((pointer)->size >= offsetof(type, member) + sizeof (pointer)->member)

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;

    (void)reserved;
    if ((*vm)->GetEnv(vm, (void *)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    {
        jclass found = (*env)->FindClass(env, "org/sipral/SipralEventListeners");
        if (found == NULL) {
            return JNI_ERR;
        }
        jni_event_callback_class = (jclass)(*env)->NewGlobalRef(env, found);
        (*env)->DeleteLocalRef(env, found);
        if (jni_event_callback_class == NULL) {
            return JNI_ERR;
        }
        jni_event_callback_deliver = (*env)->GetStaticMethodID(env, jni_event_callback_class, "deliver", "(JJJJJJ[B)V");
        if (jni_event_callback_deliver == NULL) {
            return JNI_ERR;
        }
    }
    {
        jclass found = (*env)->FindClass(env, "org/sipral/SipralScreenListeners");
        if (found == NULL) {
            return JNI_ERR;
        }
        jni_screen_callback_class = (jclass)(*env)->NewGlobalRef(env, found);
        (*env)->DeleteLocalRef(env, found);
        if (jni_screen_callback_class == NULL) {
            return JNI_ERR;
        }
        jni_screen_callback_deliver = (*env)->GetStaticMethodID(env, jni_screen_callback_class, "deliver", "(JJJ[B[B)J");
        if (jni_screen_callback_deliver == NULL) {
            return JNI_ERR;
        }
    }
    jni_vm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL
JNI_OnUnload(JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;

    (void)reserved;
    jni_vm = NULL;
    if ((*vm)->GetEnv(vm, (void *)&env, JNI_VERSION_1_6) != JNI_OK) {
        return;
    }
    if (jni_event_callback_class != NULL) {
        (*env)->DeleteGlobalRef(env, jni_event_callback_class);
        jni_event_callback_class = NULL;
    }
    if (jni_screen_callback_class != NULL) {
        (*env)->DeleteGlobalRef(env, jni_screen_callback_class);
        jni_screen_callback_class = NULL;
    }
}

/* Where a sipral_event_callback_t lands. The event is handed to
 * SipralEventListeners.deliver under the key its user pointer carries, on a
 * thread attached to the JVM for the length of the call when it was not
 * attached already, and every local reference made here is deleted
 * before it returns: a poll delivers all its events inside one native
 * call, and nothing made here would be released until that call ended. */
static void
jni_event_callback(const sipral_event_t *event, void *user_data)
{
    JNIEnv *env = NULL;
    int attached = 0;
    int built = 1;
    jint found;
    jbyteArray message = NULL;

    if (jni_vm == NULL || event == NULL) {
        return;
    }
    found = (*jni_vm)->GetEnv(jni_vm, (void *)&env, JNI_VERSION_1_6);
    if (found == JNI_EDETACHED) {
        if ((*jni_vm)->AttachCurrentThread(jni_vm, (void *)&env, NULL) != JNI_OK) {
            return;
        }
        attached = 1;
    } else if (found != JNI_OK) {
        return;
    }
    if (built && JNI_REACHES(event, sipral_event_t, message_len) && event->message != NULL) {
        message = (*env)->NewByteArray(env, (jsize)event->message_len);
        if (message == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, message, 0, (jsize)event->message_len, (const jbyte *)event->message);
        }
    }
    if (built) {
        (*env)->CallStaticVoidMethod(env, jni_event_callback_class, jni_event_callback_deliver, (jlong)(intptr_t)user_data, (jlong)event->size, JNI_REACHES(event, sipral_event_t, stack) ? (jlong)event->stack : 0, JNI_REACHES(event, sipral_event_t, kind) ? (jlong)event->kind : 0, JNI_REACHES(event, sipral_event_t, account) ? (jlong)event->account : 0, JNI_REACHES(event, sipral_event_t, call) ? (jlong)event->call : 0, message);
    }
    /* deliver hands what a listener throws to the thread's own handler, so
     * what is pending here is the JVM's -- an array it could not make --
     * and a callback has no Java frame beneath it to throw into */
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
    if (message != NULL) {
        (*env)->DeleteLocalRef(env, message);
    }
    if (attached) {
        (*jni_vm)->DetachCurrentThread(jni_vm);
    }
}

/* Where a sipral_screen_callback_t lands. The event is handed to
 * SipralScreenListeners.deliver under the key its user pointer carries, on a
 * thread attached to the JVM for the length of the call when it was not
 * attached already, and every local reference made here is deleted
 * before it returns: a poll delivers all its events inside one native
 * call, and nothing made here would be released until that call ended. Answers with what the listener answered, or with the value that
 * fails closed when there was none. */
static uint32_t
jni_screen_callback(const sipral_screen_request_t *request, void *user_data)
{
    JNIEnv *env = NULL;
    int attached = 0;
    int built = 1;
    jint found;
    uint32_t answer = 0;
    jbyteArray source = NULL;
    jbyteArray message = NULL;

    if (jni_vm == NULL || request == NULL) {
        return (uint32_t)answer;
    }
    found = (*jni_vm)->GetEnv(jni_vm, (void *)&env, JNI_VERSION_1_6);
    if (found == JNI_EDETACHED) {
        if ((*jni_vm)->AttachCurrentThread(jni_vm, (void *)&env, NULL) != JNI_OK) {
            return (uint32_t)answer;
        }
        attached = 1;
    } else if (found != JNI_OK) {
        return (uint32_t)answer;
    }
    if (built && JNI_REACHES(request, sipral_screen_request_t, source_len) && request->source != NULL) {
        source = (*env)->NewByteArray(env, (jsize)request->source_len);
        if (source == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, source, 0, (jsize)request->source_len, (const jbyte *)request->source);
        }
    }
    if (built && JNI_REACHES(request, sipral_screen_request_t, message_len) && request->message != NULL) {
        message = (*env)->NewByteArray(env, (jsize)request->message_len);
        if (message == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, message, 0, (jsize)request->message_len, (const jbyte *)request->message);
        }
    }
    if (built) {
        answer = (uint32_t)(*env)->CallStaticLongMethod(env, jni_screen_callback_class, jni_screen_callback_deliver, (jlong)(intptr_t)user_data, (jlong)request->size, JNI_REACHES(request, sipral_screen_request_t, stack) ? (jlong)request->stack : 0, source, message);
    }
    /* Pending here either because an array could not be made, or because
     * deliver let a listener's own exception through rather than catch it:
     * a policy question with no answer fails closed rather than carry on
     * with whatever the call above happened to return. */
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        answer = 0;
    }
    if (source != NULL) {
        (*env)->DeleteLocalRef(env, source);
    }
    if (message != NULL) {
        (*env)->DeleteLocalRef(env, message);
    }
    if (attached) {
        (*jni_vm)->DetachCurrentThread(jni_vm);
    }
    return (uint32_t)answer;
}

/* Throw a new exception of the class named. What is wrong with a list the
 * shim was handed is the JVM's to report: a status would be read as the
 * library's answer, and the library was never called. */
static void
jni_refuse(JNIEnv *env, const char *thrown, const char *why)
{
    jclass found = (*env)->FindClass(env, thrown);
    if (found != NULL) {
        (*env)->ThrowNew(env, found, why);
        (*env)->DeleteLocalRef(env, found);
    }
}

/* A list of sipral_header_t as SipralHeader.packed hands it over, made into the
 * array the library reads. `bytes` is every piece of text in every element,
 * one after another, and `lengths` how many bytes each took, 2 to an
 * element in the order the struct declares them. The bytes are pinned, and
 * every length is read once and checked against what is left of them before
 * a pointer is made from it, so no element reaches past the array it came
 * in; an empty piece of text is a null pointer with a length of zero. Answers
 * 1 with what jni_header_release lets go of in the three out parameters, or 0
 * with an exception pending and nothing held. */
static int
jni_header_array(JNIEnv *env, jbyteArray bytes, jlongArray lengths, jbyte **out_pinned, sipral_header_t **out_array, size_t *out_count)
{
    jsize parts;
    jsize room;
    size_t count;
    size_t index;
    size_t at = 0;
    jlong length;
    jlong *given;
    jbyte *pinned = NULL;
    sipral_header_t *array;

    *out_pinned = NULL;
    *out_array = NULL;
    *out_count = 0;
    parts = lengths != NULL ? (*env)->GetArrayLength(env, lengths) : 0;
    room = bytes != NULL ? (*env)->GetArrayLength(env, bytes) : 0;
    if (parts % 2 != 0) {
        jni_refuse(env, "java/lang/IllegalArgumentException", "the lengths of a list of sipral_header_t are not 2 to an element");
        return 0;
    }
    count = (size_t)parts / 2;
    if (count == 0) {
        if (room != 0) {
            jni_refuse(env, "java/lang/IllegalArgumentException", "the lengths of a list of sipral_header_t do not account for its bytes");
            return 0;
        }
        return 1;
    }
    if (count > SIZE_MAX / sizeof *array) {
        jni_refuse(env, "java/lang/OutOfMemoryError", "a list of sipral_header_t longer than memory can hold");
        return 0;
    }
    array = malloc(count * sizeof *array);
    if (array == NULL) {
        jni_refuse(env, "java/lang/OutOfMemoryError", "no memory for a list of sipral_header_t");
        return 0;
    }
    given = (*env)->GetLongArrayElements(env, lengths, NULL);
    if (given == NULL) {
        free(array);
        return 0;
    }
    if (room > 0) {
        pinned = (*env)->GetByteArrayElements(env, bytes, NULL);
        if (pinned == NULL) {
            (*env)->ReleaseLongArrayElements(env, lengths, given, JNI_ABORT);
            free(array);
            return 0;
        }
    }
    for (index = 0; index < count; index++) {
        length = given[index * 2 + 0];
        if (length < 0 || (uint64_t)length > (uint64_t)((size_t)room - at)) {
            break;
        }
        array[index].name = length == 0 ? NULL : (const char *)pinned + at;
        array[index].name_len = (size_t)length;
        at += (size_t)length;
        length = given[index * 2 + 1];
        if (length < 0 || (uint64_t)length > (uint64_t)((size_t)room - at)) {
            break;
        }
        array[index].value = length == 0 ? NULL : (const char *)pinned + at;
        array[index].value_len = (size_t)length;
        at += (size_t)length;
    }
    (*env)->ReleaseLongArrayElements(env, lengths, given, JNI_ABORT);
    if (index != count || at != (size_t)room) {
        if (pinned != NULL) {
            (*env)->ReleaseByteArrayElements(env, bytes, pinned, JNI_ABORT);
        }
        free(array);
        jni_refuse(env, "java/lang/IllegalArgumentException", "the lengths of a list of sipral_header_t do not account for its bytes");
        return 0;
    }
    *out_pinned = pinned;
    *out_array = array;
    *out_count = count;
    return 1;
}

/* Let go of what jni_header_array made, which is nothing when it answered 0. */
static void
jni_header_release(JNIEnv *env, jbyteArray bytes, jbyte *pinned, sipral_header_t *array)
{
    if (pinned != NULL) {
        (*env)->ReleaseByteArrayElements(env, bytes, pinned, JNI_ABORT);
    }
    free(array);
}

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
Java_org_sipral_SipralNative_sipral_1abi_1struct_1size(JNIEnv *env, jobject self, jbyteArray name, jlongArray size)
{
    (void)env;
    (void)self;
    jbyte *name_data = name ? (*env)->GetByteArrayElements(env, name, NULL) : NULL;
    jsize name_size = name ? (*env)->GetArrayLength(env, name) : 0;
    size_t size_value = 0;
    sipral_status_t status = sipral_abi_struct_size((const char *)name_data, (size_t)name_size, &size_value);
    if (name) {
        (*env)->ReleaseByteArrayElements(env, name, name_data, JNI_ABORT);
    }
    {
        jlong slot = (jlong)size_value;
        (*env)->SetLongArrayRegion(env, size, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1abi_1versioned_1count(JNIEnv *env, jobject self, jlongArray count)
{
    (void)env;
    (void)self;
    size_t count_value = 0;
    sipral_status_t status = sipral_abi_versioned_count(&count_value);
    {
        jlong slot = (jlong)count_value;
        (*env)->SetLongArrayRegion(env, count, 0, 1, &slot);
    }
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
Java_org_sipral_SipralNative_sipral_1stack_1create(JNIEnv *env, jobject self, jlong configEventCallback, jlong configTransport, jbyteArray configBindAddress, jbyteArray configUserAgent, jbyteArray configEntropy, jlong configTimerT1Ms, jlong configTimerT2Ms, jlong configTimerT4Ms, jbyteArray configCodecs, jlong configFrameMs, jlong configOfferDtmf, jlong configOfferRtcpMux, jlong configSilenceSuppression, jlong configMediaStallWatchdog, jlong configMediaStallMs, jlong configMediaClockUnixSeconds, jbyteArray configMediaSeed, jlong configSrtp, jlong configIce, jlongArray stack)
{
    (void)env;
    (void)self;
    sipral_stack_config_t config_value;
    memset(&config_value, 0, sizeof config_value);
    config_value.size = sizeof config_value;
    config_value.event_callback = configEventCallback != 0 ? jni_event_callback : NULL;
    config_value.event_user_data = (void *)(intptr_t)configEventCallback;
    config_value.transport = (uint32_t)configTransport;
    jbyte *configBindAddress_data = configBindAddress ? (*env)->GetByteArrayElements(env, configBindAddress, NULL) : NULL;
    jsize configBindAddress_size = configBindAddress ? (*env)->GetArrayLength(env, configBindAddress) : 0;
    config_value.bind_address = (const char *)configBindAddress_data;
    config_value.bind_address_len = (size_t)configBindAddress_size;
    jbyte *configUserAgent_data = configUserAgent ? (*env)->GetByteArrayElements(env, configUserAgent, NULL) : NULL;
    jsize configUserAgent_size = configUserAgent ? (*env)->GetArrayLength(env, configUserAgent) : 0;
    config_value.user_agent = (const char *)configUserAgent_data;
    config_value.user_agent_len = (size_t)configUserAgent_size;
    jbyte *configEntropy_data = configEntropy ? (*env)->GetByteArrayElements(env, configEntropy, NULL) : NULL;
    jsize configEntropy_size = configEntropy ? (*env)->GetArrayLength(env, configEntropy) : 0;
    config_value.entropy = (const uint8_t *)configEntropy_data;
    config_value.entropy_len = (size_t)configEntropy_size;
    config_value.timer_t1_ms = (uint64_t)configTimerT1Ms;
    config_value.timer_t2_ms = (uint64_t)configTimerT2Ms;
    config_value.timer_t4_ms = (uint64_t)configTimerT4Ms;
    jbyte *configCodecs_data = configCodecs ? (*env)->GetByteArrayElements(env, configCodecs, NULL) : NULL;
    jsize configCodecs_size = configCodecs ? (*env)->GetArrayLength(env, configCodecs) : 0;
    config_value.codecs = (const char *)configCodecs_data;
    config_value.codecs_len = (size_t)configCodecs_size;
    config_value.frame_ms = (uint32_t)configFrameMs;
    config_value.offer_dtmf = (uint32_t)configOfferDtmf;
    config_value.offer_rtcp_mux = (uint32_t)configOfferRtcpMux;
    config_value.silence_suppression = (uint32_t)configSilenceSuppression;
    config_value.media_stall_watchdog = (uint32_t)configMediaStallWatchdog;
    config_value.media_stall_ms = (uint64_t)configMediaStallMs;
    config_value.media_clock_unix_seconds = (uint64_t)configMediaClockUnixSeconds;
    jbyte *configMediaSeed_data = configMediaSeed ? (*env)->GetByteArrayElements(env, configMediaSeed, NULL) : NULL;
    jsize configMediaSeed_size = configMediaSeed ? (*env)->GetArrayLength(env, configMediaSeed) : 0;
    config_value.media_seed = (const uint8_t *)configMediaSeed_data;
    config_value.media_seed_len = (size_t)configMediaSeed_size;
    config_value.srtp = (uint32_t)configSrtp;
    config_value.ice = (uint32_t)configIce;
    sipral_handle_t stack_value = 0;
    sipral_status_t status = sipral_stack_create(&config_value, &stack_value);
    if (configBindAddress) {
        (*env)->ReleaseByteArrayElements(env, configBindAddress, configBindAddress_data, JNI_ABORT);
    }
    if (configUserAgent) {
        (*env)->ReleaseByteArrayElements(env, configUserAgent, configUserAgent_data, JNI_ABORT);
    }
    if (configEntropy) {
        (*env)->ReleaseByteArrayElements(env, configEntropy, configEntropy_data, JNI_ABORT);
    }
    if (configCodecs) {
        (*env)->ReleaseByteArrayElements(env, configCodecs, configCodecs_data, JNI_ABORT);
    }
    if (configMediaSeed) {
        (*env)->ReleaseByteArrayElements(env, configMediaSeed, configMediaSeed_data, JNI_ABORT);
    }
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
        jlong slots[25];
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
        slots[19] = (jlong)counters_value.events_dropped;
        slots[20] = (jlong)counters_value.farewells_dropped;
        slots[21] = (jlong)counters_value.screened_refused_by_policy;
        slots[22] = (jlong)counters_value.screened_refused_by_rate;
        slots[23] = (jlong)counters_value.screened_refused_by_crowding;
        slots[24] = (jlong)counters_value.screened_refused_by_replaces;
        (*env)->SetLongArrayRegion(env, counters, 0, 25, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1screen(JNIEnv *env, jobject self, jlong stack, jlong callback)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_screen((sipral_handle_t)stack, callback != 0 ? jni_screen_callback : NULL, (void *)(intptr_t)callback);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1invite_1limit(JNIEnv *env, jobject self, jlong stack, jlong everyMs, jlong burst)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_invite_limit((sipral_handle_t)stack, (uint64_t)everyMs, (uint32_t)burst);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1subscribe(JNIEnv *env, jobject self, jlong stack, jlong account, jbyteArray configTarget, jbyteArray configPackage, jbyteArray configAccept, jlong configExpiresSeconds, jbyteArray configDestination, jlong configTransport, jlongArray subscription, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_subscribe_config_t config_value;
    memset(&config_value, 0, sizeof config_value);
    config_value.size = sizeof config_value;
    jbyte *configTarget_data = configTarget ? (*env)->GetByteArrayElements(env, configTarget, NULL) : NULL;
    jsize configTarget_size = configTarget ? (*env)->GetArrayLength(env, configTarget) : 0;
    config_value.target = (const char *)configTarget_data;
    config_value.target_len = (size_t)configTarget_size;
    jbyte *configPackage_data = configPackage ? (*env)->GetByteArrayElements(env, configPackage, NULL) : NULL;
    jsize configPackage_size = configPackage ? (*env)->GetArrayLength(env, configPackage) : 0;
    config_value.package = (const char *)configPackage_data;
    config_value.package_len = (size_t)configPackage_size;
    jbyte *configAccept_data = configAccept ? (*env)->GetByteArrayElements(env, configAccept, NULL) : NULL;
    jsize configAccept_size = configAccept ? (*env)->GetArrayLength(env, configAccept) : 0;
    config_value.accept = (const char *)configAccept_data;
    config_value.accept_len = (size_t)configAccept_size;
    config_value.expires_seconds = (uint32_t)configExpiresSeconds;
    jbyte *configDestination_data = configDestination ? (*env)->GetByteArrayElements(env, configDestination, NULL) : NULL;
    jsize configDestination_size = configDestination ? (*env)->GetArrayLength(env, configDestination) : 0;
    config_value.destination = (const char *)configDestination_data;
    config_value.destination_len = (size_t)configDestination_size;
    config_value.transport = (uint32_t)configTransport;
    sipral_handle_t subscription_value = 0;
    sipral_status_t status = sipral_account_subscribe((sipral_handle_t)stack, (sipral_handle_t)account, &config_value, &subscription_value, (uint64_t)nowMs);
    if (configTarget) {
        (*env)->ReleaseByteArrayElements(env, configTarget, configTarget_data, JNI_ABORT);
    }
    if (configPackage) {
        (*env)->ReleaseByteArrayElements(env, configPackage, configPackage_data, JNI_ABORT);
    }
    if (configAccept) {
        (*env)->ReleaseByteArrayElements(env, configAccept, configAccept_data, JNI_ABORT);
    }
    if (configDestination) {
        (*env)->ReleaseByteArrayElements(env, configDestination, configDestination_data, JNI_ABORT);
    }
    {
        jlong slot = (jlong)subscription_value;
        (*env)->SetLongArrayRegion(env, subscription, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1subscription_1end(JNIEnv *env, jobject self, jlong stack, jlong subscription, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_subscription_end((sipral_handle_t)stack, (sipral_handle_t)subscription, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1subscription_1state(JNIEnv *env, jobject self, jlong stack, jlong subscription, jlongArray state)
{
    (void)env;
    (void)self;
    uint32_t state_value = 0;
    sipral_status_t status = sipral_subscription_state((sipral_handle_t)stack, (sipral_handle_t)subscription, &state_value);
    {
        jlong slot = (jlong)state_value;
        (*env)->SetLongArrayRegion(env, state, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1subscription_1lamp(JNIEnv *env, jobject self, jlong stack, jlong subscription, jlongArray phase)
{
    (void)env;
    (void)self;
    uint32_t phase_value = 0;
    sipral_status_t status = sipral_subscription_lamp((sipral_handle_t)stack, (sipral_handle_t)subscription, &phase_value);
    {
        jlong slot = (jlong)phase_value;
        (*env)->SetLongArrayRegion(env, phase, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1subscription_1dialog_1count(JNIEnv *env, jobject self, jlong stack, jlong subscription, jlongArray count)
{
    (void)env;
    (void)self;
    size_t count_value = 0;
    sipral_status_t status = sipral_subscription_dialog_count((sipral_handle_t)stack, (sipral_handle_t)subscription, &count_value);
    {
        jlong slot = (jlong)count_value;
        (*env)->SetLongArrayRegion(env, count, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1subscription_1dialog_1at(JNIEnv *env, jobject self, jlong stack, jlong subscription, jlong index, jlongArray dialog)
{
    (void)env;
    (void)self;
    sipral_watched_dialog_t dialog_value;
    memset(&dialog_value, 0, sizeof dialog_value);
    dialog_value.size = sizeof dialog_value;
    sipral_status_t status = sipral_subscription_dialog_at((sipral_handle_t)stack, (sipral_handle_t)subscription, (size_t)index, &dialog_value);
    {
        jlong slots[6];
        slots[0] = (jlong)dialog_value.size;
        slots[1] = (jlong)dialog_value.phase;
        slots[2] = (jlong)dialog_value.direction;
        slots[3] = (jlong)dialog_value.ended;
        slots[4] = (jlong)dialog_value.status_code;
        slots[5] = (jlong)dialog_value.duration_ms;
        (*env)->SetLongArrayRegion(env, dialog, 0, 6, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1subscription_1dialog_1text(JNIEnv *env, jobject self, jlong stack, jlong subscription, jlong index, jlong which, jbyteArray buffer, jlongArray needed)
{
    (void)env;
    (void)self;
    jbyte *buffer_data = buffer ? (*env)->GetByteArrayElements(env, buffer, NULL) : NULL;
    jsize buffer_size = buffer ? (*env)->GetArrayLength(env, buffer) : 0;
    size_t needed_value = 0;
    sipral_status_t status = sipral_subscription_dialog_text((sipral_handle_t)stack, (sipral_handle_t)subscription, (size_t)index, (uint32_t)which, (char *)buffer_data, (size_t)buffer_size, &needed_value);
    if (buffer) {
        (*env)->ReleaseByteArrayElements(env, buffer, buffer_data, 0);
    }
    {
        jlong slot = (jlong)needed_value;
        (*env)->SetLongArrayRegion(env, needed, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1message(JNIEnv *env, jobject self, jlong stack, jlong account, jbyteArray target, jbyteArray contentType, jbyteArray body, jlongArray message, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *target_data = target ? (*env)->GetByteArrayElements(env, target, NULL) : NULL;
    jsize target_size = target ? (*env)->GetArrayLength(env, target) : 0;
    jbyte *contentType_data = contentType ? (*env)->GetByteArrayElements(env, contentType, NULL) : NULL;
    jsize contentType_size = contentType ? (*env)->GetArrayLength(env, contentType) : 0;
    jbyte *body_data = body ? (*env)->GetByteArrayElements(env, body, NULL) : NULL;
    jsize body_size = body ? (*env)->GetArrayLength(env, body) : 0;
    sipral_handle_t message_value = 0;
    sipral_status_t status = sipral_account_message((sipral_handle_t)stack, (sipral_handle_t)account, (const char *)target_data, (size_t)target_size, (const char *)contentType_data, (size_t)contentType_size, (const uint8_t *)body_data, (size_t)body_size, &message_value, (uint64_t)nowMs);
    if (target) {
        (*env)->ReleaseByteArrayElements(env, target, target_data, JNI_ABORT);
    }
    if (contentType) {
        (*env)->ReleaseByteArrayElements(env, contentType, contentType_data, JNI_ABORT);
    }
    if (body) {
        (*env)->ReleaseByteArrayElements(env, body, body_data, JNI_ABORT);
    }
    {
        jlong slot = (jlong)message_value;
        (*env)->SetLongArrayRegion(env, message, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1announce(JNIEnv *env, jobject self, jlong stack, jlong account, jbyteArray caller, jlongArray announcement, jlongArray call, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *caller_data = caller ? (*env)->GetByteArrayElements(env, caller, NULL) : NULL;
    jsize caller_size = caller ? (*env)->GetArrayLength(env, caller) : 0;
    sipral_handle_t announcement_value = 0;
    sipral_handle_t call_value = 0;
    sipral_status_t status = sipral_account_announce((sipral_handle_t)stack, (sipral_handle_t)account, (const char *)caller_data, (size_t)caller_size, &announcement_value, &call_value, (uint64_t)nowMs);
    if (caller) {
        (*env)->ReleaseByteArrayElements(env, caller, caller_data, JNI_ABORT);
    }
    {
        jlong slot = (jlong)announcement_value;
        (*env)->SetLongArrayRegion(env, announcement, 0, 1, &slot);
    }
    {
        jlong slot = (jlong)call_value;
        (*env)->SetLongArrayRegion(env, call, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1refresh_1binding(JNIEnv *env, jobject self, jlong stack, jlong account, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_account_refresh_binding((sipral_handle_t)stack, (sipral_handle_t)account, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1announcement_1forget(JNIEnv *env, jobject self, jlong stack, jlong announcement)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_announcement_forget((sipral_handle_t)stack, (sipral_handle_t)announcement);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1push_1echo(JNIEnv *env, jobject self, jlong stack, jlong account, jlongArray echo)
{
    (void)env;
    (void)self;
    sipral_push_echo_t echo_value;
    memset(&echo_value, 0, sizeof echo_value);
    echo_value.size = sizeof echo_value;
    sipral_status_t status = sipral_account_push_echo((sipral_handle_t)stack, (sipral_handle_t)account, &echo_value);
    {
        jlong slots[4];
        slots[0] = (jlong)echo_value.size;
        slots[1] = (jlong)echo_value.accepted;
        slots[2] = (jlong)echo_value.has_refresh_lead;
        slots[3] = (jlong)echo_value.refresh_lead_ms;
        (*env)->SetLongArrayRegion(env, echo, 0, 4, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1add(JNIEnv *env, jobject self, jlong stack, jbyteArray configAor, jbyteArray configRegistrar, jbyteArray configContact, jbyteArray configRegistrarAddress, jbyteArray configDisplayName, jbyteArray configAuthUser, jbyteArray configAuthPassword, jbyteArray configInstanceId, jlong configExpiresSeconds, jbyteArray configHeadersBytes, jlongArray configHeadersLengths, jlong configTransport, jbyteArray configPushProvider, jbyteArray configPushPrid, jbyteArray configPushParam, jlong configPushWakesItself, jbyteArray configQualityReportUri, jlongArray account)
{
    (void)env;
    (void)self;
    sipral_account_config_t config_value;
    memset(&config_value, 0, sizeof config_value);
    config_value.size = sizeof config_value;
    jbyte *configAor_data = configAor ? (*env)->GetByteArrayElements(env, configAor, NULL) : NULL;
    jsize configAor_size = configAor ? (*env)->GetArrayLength(env, configAor) : 0;
    config_value.aor = (const char *)configAor_data;
    config_value.aor_len = (size_t)configAor_size;
    jbyte *configRegistrar_data = configRegistrar ? (*env)->GetByteArrayElements(env, configRegistrar, NULL) : NULL;
    jsize configRegistrar_size = configRegistrar ? (*env)->GetArrayLength(env, configRegistrar) : 0;
    config_value.registrar = (const char *)configRegistrar_data;
    config_value.registrar_len = (size_t)configRegistrar_size;
    jbyte *configContact_data = configContact ? (*env)->GetByteArrayElements(env, configContact, NULL) : NULL;
    jsize configContact_size = configContact ? (*env)->GetArrayLength(env, configContact) : 0;
    config_value.contact = (const char *)configContact_data;
    config_value.contact_len = (size_t)configContact_size;
    jbyte *configRegistrarAddress_data = configRegistrarAddress ? (*env)->GetByteArrayElements(env, configRegistrarAddress, NULL) : NULL;
    jsize configRegistrarAddress_size = configRegistrarAddress ? (*env)->GetArrayLength(env, configRegistrarAddress) : 0;
    config_value.registrar_address = (const char *)configRegistrarAddress_data;
    config_value.registrar_address_len = (size_t)configRegistrarAddress_size;
    jbyte *configDisplayName_data = configDisplayName ? (*env)->GetByteArrayElements(env, configDisplayName, NULL) : NULL;
    jsize configDisplayName_size = configDisplayName ? (*env)->GetArrayLength(env, configDisplayName) : 0;
    config_value.display_name = (const char *)configDisplayName_data;
    config_value.display_name_len = (size_t)configDisplayName_size;
    jbyte *configAuthUser_data = configAuthUser ? (*env)->GetByteArrayElements(env, configAuthUser, NULL) : NULL;
    jsize configAuthUser_size = configAuthUser ? (*env)->GetArrayLength(env, configAuthUser) : 0;
    config_value.auth_user = (const char *)configAuthUser_data;
    config_value.auth_user_len = (size_t)configAuthUser_size;
    jbyte *configAuthPassword_data = configAuthPassword ? (*env)->GetByteArrayElements(env, configAuthPassword, NULL) : NULL;
    jsize configAuthPassword_size = configAuthPassword ? (*env)->GetArrayLength(env, configAuthPassword) : 0;
    config_value.auth_password = (const char *)configAuthPassword_data;
    config_value.auth_password_len = (size_t)configAuthPassword_size;
    jbyte *configInstanceId_data = configInstanceId ? (*env)->GetByteArrayElements(env, configInstanceId, NULL) : NULL;
    jsize configInstanceId_size = configInstanceId ? (*env)->GetArrayLength(env, configInstanceId) : 0;
    config_value.instance_id = (const char *)configInstanceId_data;
    config_value.instance_id_len = (size_t)configInstanceId_size;
    config_value.expires_seconds = (uint64_t)configExpiresSeconds;
    config_value.transport = (uint32_t)configTransport;
    jbyte *configPushProvider_data = configPushProvider ? (*env)->GetByteArrayElements(env, configPushProvider, NULL) : NULL;
    jsize configPushProvider_size = configPushProvider ? (*env)->GetArrayLength(env, configPushProvider) : 0;
    config_value.push_provider = (const char *)configPushProvider_data;
    config_value.push_provider_len = (size_t)configPushProvider_size;
    jbyte *configPushPrid_data = configPushPrid ? (*env)->GetByteArrayElements(env, configPushPrid, NULL) : NULL;
    jsize configPushPrid_size = configPushPrid ? (*env)->GetArrayLength(env, configPushPrid) : 0;
    config_value.push_prid = (const char *)configPushPrid_data;
    config_value.push_prid_len = (size_t)configPushPrid_size;
    jbyte *configPushParam_data = configPushParam ? (*env)->GetByteArrayElements(env, configPushParam, NULL) : NULL;
    jsize configPushParam_size = configPushParam ? (*env)->GetArrayLength(env, configPushParam) : 0;
    config_value.push_param = (const char *)configPushParam_data;
    config_value.push_param_len = (size_t)configPushParam_size;
    config_value.push_wakes_itself = (uint32_t)configPushWakesItself;
    jbyte *configQualityReportUri_data = configQualityReportUri ? (*env)->GetByteArrayElements(env, configQualityReportUri, NULL) : NULL;
    jsize configQualityReportUri_size = configQualityReportUri ? (*env)->GetArrayLength(env, configQualityReportUri) : 0;
    config_value.quality_report_uri = (const char *)configQualityReportUri_data;
    config_value.quality_report_uri_len = (size_t)configQualityReportUri_size;
    sipral_handle_t account_value = 0;
    int ready = 1;
    jbyte *configHeaders_pinned = NULL;
    sipral_header_t *configHeaders_array = NULL;
    size_t configHeaders_count = 0;
    ready = ready && jni_header_array(env, configHeadersBytes, configHeadersLengths, &configHeaders_pinned, &configHeaders_array, &configHeaders_count);
    config_value.headers = configHeaders_array;
    config_value.headers_len = configHeaders_count;
    /* -1 is no status the library answers with, and it is never read: a list
     * that did not make an array left an exception pending, and the JVM
     * throws that instead */
    sipral_status_t status = -1;
    if (ready) {
        status = sipral_account_add((sipral_handle_t)stack, &config_value, &account_value);
    }
    if (configAor) {
        (*env)->ReleaseByteArrayElements(env, configAor, configAor_data, JNI_ABORT);
    }
    if (configRegistrar) {
        (*env)->ReleaseByteArrayElements(env, configRegistrar, configRegistrar_data, JNI_ABORT);
    }
    if (configContact) {
        (*env)->ReleaseByteArrayElements(env, configContact, configContact_data, JNI_ABORT);
    }
    if (configRegistrarAddress) {
        (*env)->ReleaseByteArrayElements(env, configRegistrarAddress, configRegistrarAddress_data, JNI_ABORT);
    }
    if (configDisplayName) {
        (*env)->ReleaseByteArrayElements(env, configDisplayName, configDisplayName_data, JNI_ABORT);
    }
    if (configAuthUser) {
        (*env)->ReleaseByteArrayElements(env, configAuthUser, configAuthUser_data, JNI_ABORT);
    }
    if (configAuthPassword) {
        (*env)->ReleaseByteArrayElements(env, configAuthPassword, configAuthPassword_data, JNI_ABORT);
    }
    if (configInstanceId) {
        (*env)->ReleaseByteArrayElements(env, configInstanceId, configInstanceId_data, JNI_ABORT);
    }
    jni_header_release(env, configHeadersBytes, configHeaders_pinned, configHeaders_array);
    if (configPushProvider) {
        (*env)->ReleaseByteArrayElements(env, configPushProvider, configPushProvider_data, JNI_ABORT);
    }
    if (configPushPrid) {
        (*env)->ReleaseByteArrayElements(env, configPushPrid, configPushPrid_data, JNI_ABORT);
    }
    if (configPushParam) {
        (*env)->ReleaseByteArrayElements(env, configPushParam, configPushParam_data, JNI_ABORT);
    }
    if (configQualityReportUri) {
        (*env)->ReleaseByteArrayElements(env, configQualityReportUri, configQualityReportUri_data, JNI_ABORT);
    }
    if (ready) {
        {
            jlong slot = (jlong)account_value;
            (*env)->SetLongArrayRegion(env, account, 0, 1, &slot);
        }
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
Java_org_sipral_SipralNative_sipral_1call_1place(JNIEnv *env, jobject self, jlong stack, jlong account, jbyteArray configTarget, jbyteArray configSdp, jbyteArray configDestination, jlong configKeepAllForks, jbyteArray configMediaAddress, jbyteArray configHeadersBytes, jlongArray configHeadersLengths, jlong configSrtp, jlong configTransport, jbyteArray configCodecs, jlong configIce, jlongArray call, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_call_config_t config_value;
    memset(&config_value, 0, sizeof config_value);
    config_value.size = sizeof config_value;
    jbyte *configTarget_data = configTarget ? (*env)->GetByteArrayElements(env, configTarget, NULL) : NULL;
    jsize configTarget_size = configTarget ? (*env)->GetArrayLength(env, configTarget) : 0;
    config_value.target = (const char *)configTarget_data;
    config_value.target_len = (size_t)configTarget_size;
    jbyte *configSdp_data = configSdp ? (*env)->GetByteArrayElements(env, configSdp, NULL) : NULL;
    jsize configSdp_size = configSdp ? (*env)->GetArrayLength(env, configSdp) : 0;
    config_value.sdp = (const uint8_t *)configSdp_data;
    config_value.sdp_len = (size_t)configSdp_size;
    jbyte *configDestination_data = configDestination ? (*env)->GetByteArrayElements(env, configDestination, NULL) : NULL;
    jsize configDestination_size = configDestination ? (*env)->GetArrayLength(env, configDestination) : 0;
    config_value.destination = (const char *)configDestination_data;
    config_value.destination_len = (size_t)configDestination_size;
    config_value.keep_all_forks = (uint32_t)configKeepAllForks;
    jbyte *configMediaAddress_data = configMediaAddress ? (*env)->GetByteArrayElements(env, configMediaAddress, NULL) : NULL;
    jsize configMediaAddress_size = configMediaAddress ? (*env)->GetArrayLength(env, configMediaAddress) : 0;
    config_value.media_address = (const char *)configMediaAddress_data;
    config_value.media_address_len = (size_t)configMediaAddress_size;
    config_value.srtp = (uint32_t)configSrtp;
    config_value.transport = (uint32_t)configTransport;
    jbyte *configCodecs_data = configCodecs ? (*env)->GetByteArrayElements(env, configCodecs, NULL) : NULL;
    jsize configCodecs_size = configCodecs ? (*env)->GetArrayLength(env, configCodecs) : 0;
    config_value.codecs = (const char *)configCodecs_data;
    config_value.codecs_len = (size_t)configCodecs_size;
    config_value.ice = (uint32_t)configIce;
    sipral_handle_t call_value = 0;
    int ready = 1;
    jbyte *configHeaders_pinned = NULL;
    sipral_header_t *configHeaders_array = NULL;
    size_t configHeaders_count = 0;
    ready = ready && jni_header_array(env, configHeadersBytes, configHeadersLengths, &configHeaders_pinned, &configHeaders_array, &configHeaders_count);
    config_value.headers = configHeaders_array;
    config_value.headers_len = configHeaders_count;
    /* -1 is no status the library answers with, and it is never read: a list
     * that did not make an array left an exception pending, and the JVM
     * throws that instead */
    sipral_status_t status = -1;
    if (ready) {
        status = sipral_call_place((sipral_handle_t)stack, (sipral_handle_t)account, &config_value, &call_value, (uint64_t)nowMs);
    }
    if (configTarget) {
        (*env)->ReleaseByteArrayElements(env, configTarget, configTarget_data, JNI_ABORT);
    }
    if (configSdp) {
        (*env)->ReleaseByteArrayElements(env, configSdp, configSdp_data, JNI_ABORT);
    }
    if (configDestination) {
        (*env)->ReleaseByteArrayElements(env, configDestination, configDestination_data, JNI_ABORT);
    }
    if (configMediaAddress) {
        (*env)->ReleaseByteArrayElements(env, configMediaAddress, configMediaAddress_data, JNI_ABORT);
    }
    jni_header_release(env, configHeadersBytes, configHeaders_pinned, configHeaders_array);
    if (configCodecs) {
        (*env)->ReleaseByteArrayElements(env, configCodecs, configCodecs_data, JNI_ABORT);
    }
    if (ready) {
        {
            jlong slot = (jlong)call_value;
            (*env)->SetLongArrayRegion(env, call, 0, 1, &slot);
        }
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
Java_org_sipral_SipralNative_sipral_1call_1ring_1media(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray configTarget, jbyteArray configSdp, jbyteArray configDestination, jlong configKeepAllForks, jbyteArray configMediaAddress, jbyteArray configHeadersBytes, jlongArray configHeadersLengths, jlong configSrtp, jlong configTransport, jbyteArray configCodecs, jlong configIce, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_call_config_t config_value;
    memset(&config_value, 0, sizeof config_value);
    config_value.size = sizeof config_value;
    jbyte *configTarget_data = configTarget ? (*env)->GetByteArrayElements(env, configTarget, NULL) : NULL;
    jsize configTarget_size = configTarget ? (*env)->GetArrayLength(env, configTarget) : 0;
    config_value.target = (const char *)configTarget_data;
    config_value.target_len = (size_t)configTarget_size;
    jbyte *configSdp_data = configSdp ? (*env)->GetByteArrayElements(env, configSdp, NULL) : NULL;
    jsize configSdp_size = configSdp ? (*env)->GetArrayLength(env, configSdp) : 0;
    config_value.sdp = (const uint8_t *)configSdp_data;
    config_value.sdp_len = (size_t)configSdp_size;
    jbyte *configDestination_data = configDestination ? (*env)->GetByteArrayElements(env, configDestination, NULL) : NULL;
    jsize configDestination_size = configDestination ? (*env)->GetArrayLength(env, configDestination) : 0;
    config_value.destination = (const char *)configDestination_data;
    config_value.destination_len = (size_t)configDestination_size;
    config_value.keep_all_forks = (uint32_t)configKeepAllForks;
    jbyte *configMediaAddress_data = configMediaAddress ? (*env)->GetByteArrayElements(env, configMediaAddress, NULL) : NULL;
    jsize configMediaAddress_size = configMediaAddress ? (*env)->GetArrayLength(env, configMediaAddress) : 0;
    config_value.media_address = (const char *)configMediaAddress_data;
    config_value.media_address_len = (size_t)configMediaAddress_size;
    config_value.srtp = (uint32_t)configSrtp;
    config_value.transport = (uint32_t)configTransport;
    jbyte *configCodecs_data = configCodecs ? (*env)->GetByteArrayElements(env, configCodecs, NULL) : NULL;
    jsize configCodecs_size = configCodecs ? (*env)->GetArrayLength(env, configCodecs) : 0;
    config_value.codecs = (const char *)configCodecs_data;
    config_value.codecs_len = (size_t)configCodecs_size;
    config_value.ice = (uint32_t)configIce;
    int ready = 1;
    jbyte *configHeaders_pinned = NULL;
    sipral_header_t *configHeaders_array = NULL;
    size_t configHeaders_count = 0;
    ready = ready && jni_header_array(env, configHeadersBytes, configHeadersLengths, &configHeaders_pinned, &configHeaders_array, &configHeaders_count);
    config_value.headers = configHeaders_array;
    config_value.headers_len = configHeaders_count;
    /* -1 is no status the library answers with, and it is never read: a list
     * that did not make an array left an exception pending, and the JVM
     * throws that instead */
    sipral_status_t status = -1;
    if (ready) {
        status = sipral_call_ring_media((sipral_handle_t)stack, (sipral_handle_t)call, &config_value, (uint64_t)nowMs);
    }
    if (configTarget) {
        (*env)->ReleaseByteArrayElements(env, configTarget, configTarget_data, JNI_ABORT);
    }
    if (configSdp) {
        (*env)->ReleaseByteArrayElements(env, configSdp, configSdp_data, JNI_ABORT);
    }
    if (configDestination) {
        (*env)->ReleaseByteArrayElements(env, configDestination, configDestination_data, JNI_ABORT);
    }
    if (configMediaAddress) {
        (*env)->ReleaseByteArrayElements(env, configMediaAddress, configMediaAddress_data, JNI_ABORT);
    }
    jni_header_release(env, configHeadersBytes, configHeaders_pinned, configHeaders_array);
    if (configCodecs) {
        (*env)->ReleaseByteArrayElements(env, configCodecs, configCodecs_data, JNI_ABORT);
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
Java_org_sipral_SipralNative_sipral_1call_1reject(JNIEnv *env, jobject self, jlong stack, jlong call, jlong code, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_reject((sipral_handle_t)stack, (sipral_handle_t)call, (uint32_t)code, (uint64_t)nowMs);
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
Java_org_sipral_SipralNative_sipral_1call_1set_1headers(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray headersBytes, jlongArray headersLengths)
{
    (void)env;
    (void)self;
    int ready = 1;
    jbyte *headers_pinned = NULL;
    sipral_header_t *headers_array = NULL;
    size_t headers_count = 0;
    ready = ready && jni_header_array(env, headersBytes, headersLengths, &headers_pinned, &headers_array, &headers_count);
    /* -1 is no status the library answers with, and it is never read: a list
     * that did not make an array left an exception pending, and the JVM
     * throws that instead */
    sipral_status_t status = -1;
    if (ready) {
        status = sipral_call_set_headers((sipral_handle_t)stack, (sipral_handle_t)call, headers_array, headers_count);
    }
    jni_header_release(env, headersBytes, headers_pinned, headers_array);
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
Java_org_sipral_SipralNative_sipral_1call_1change_1codecs(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray codecs, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *codecs_data = codecs ? (*env)->GetByteArrayElements(env, codecs, NULL) : NULL;
    jsize codecs_size = codecs ? (*env)->GetArrayLength(env, codecs) : 0;
    sipral_status_t status = sipral_call_change_codecs((sipral_handle_t)stack, (sipral_handle_t)call, (const char *)codecs_data, (size_t)codecs_size, (uint64_t)nowMs);
    if (codecs) {
        (*env)->ReleaseByteArrayElements(env, codecs, codecs_data, JNI_ABORT);
    }
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
Java_org_sipral_SipralNative_sipral_1call_1reject_1session(JNIEnv *env, jobject self, jlong stack, jlong call, jlong code, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_reject_session((sipral_handle_t)stack, (sipral_handle_t)call, (uint32_t)code, (uint64_t)nowMs);
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
Java_org_sipral_SipralNative_sipral_1call_1consult(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray configTarget, jbyteArray configSdp, jbyteArray configDestination, jlong configKeepAllForks, jbyteArray configMediaAddress, jbyteArray configHeadersBytes, jlongArray configHeadersLengths, jlong configSrtp, jlong configTransport, jbyteArray configCodecs, jlong configIce, jlongArray consultation, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_call_config_t config_value;
    memset(&config_value, 0, sizeof config_value);
    config_value.size = sizeof config_value;
    jbyte *configTarget_data = configTarget ? (*env)->GetByteArrayElements(env, configTarget, NULL) : NULL;
    jsize configTarget_size = configTarget ? (*env)->GetArrayLength(env, configTarget) : 0;
    config_value.target = (const char *)configTarget_data;
    config_value.target_len = (size_t)configTarget_size;
    jbyte *configSdp_data = configSdp ? (*env)->GetByteArrayElements(env, configSdp, NULL) : NULL;
    jsize configSdp_size = configSdp ? (*env)->GetArrayLength(env, configSdp) : 0;
    config_value.sdp = (const uint8_t *)configSdp_data;
    config_value.sdp_len = (size_t)configSdp_size;
    jbyte *configDestination_data = configDestination ? (*env)->GetByteArrayElements(env, configDestination, NULL) : NULL;
    jsize configDestination_size = configDestination ? (*env)->GetArrayLength(env, configDestination) : 0;
    config_value.destination = (const char *)configDestination_data;
    config_value.destination_len = (size_t)configDestination_size;
    config_value.keep_all_forks = (uint32_t)configKeepAllForks;
    jbyte *configMediaAddress_data = configMediaAddress ? (*env)->GetByteArrayElements(env, configMediaAddress, NULL) : NULL;
    jsize configMediaAddress_size = configMediaAddress ? (*env)->GetArrayLength(env, configMediaAddress) : 0;
    config_value.media_address = (const char *)configMediaAddress_data;
    config_value.media_address_len = (size_t)configMediaAddress_size;
    config_value.srtp = (uint32_t)configSrtp;
    config_value.transport = (uint32_t)configTransport;
    jbyte *configCodecs_data = configCodecs ? (*env)->GetByteArrayElements(env, configCodecs, NULL) : NULL;
    jsize configCodecs_size = configCodecs ? (*env)->GetArrayLength(env, configCodecs) : 0;
    config_value.codecs = (const char *)configCodecs_data;
    config_value.codecs_len = (size_t)configCodecs_size;
    config_value.ice = (uint32_t)configIce;
    sipral_handle_t consultation_value = 0;
    int ready = 1;
    jbyte *configHeaders_pinned = NULL;
    sipral_header_t *configHeaders_array = NULL;
    size_t configHeaders_count = 0;
    ready = ready && jni_header_array(env, configHeadersBytes, configHeadersLengths, &configHeaders_pinned, &configHeaders_array, &configHeaders_count);
    config_value.headers = configHeaders_array;
    config_value.headers_len = configHeaders_count;
    /* -1 is no status the library answers with, and it is never read: a list
     * that did not make an array left an exception pending, and the JVM
     * throws that instead */
    sipral_status_t status = -1;
    if (ready) {
        status = sipral_call_consult((sipral_handle_t)stack, (sipral_handle_t)call, &config_value, &consultation_value, (uint64_t)nowMs);
    }
    if (configTarget) {
        (*env)->ReleaseByteArrayElements(env, configTarget, configTarget_data, JNI_ABORT);
    }
    if (configSdp) {
        (*env)->ReleaseByteArrayElements(env, configSdp, configSdp_data, JNI_ABORT);
    }
    if (configDestination) {
        (*env)->ReleaseByteArrayElements(env, configDestination, configDestination_data, JNI_ABORT);
    }
    if (configMediaAddress) {
        (*env)->ReleaseByteArrayElements(env, configMediaAddress, configMediaAddress_data, JNI_ABORT);
    }
    jni_header_release(env, configHeadersBytes, configHeaders_pinned, configHeaders_array);
    if (configCodecs) {
        (*env)->ReleaseByteArrayElements(env, configCodecs, configCodecs_data, JNI_ABORT);
    }
    if (ready) {
        {
            jlong slot = (jlong)consultation_value;
            (*env)->SetLongArrayRegion(env, consultation, 0, 1, &slot);
        }
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
Java_org_sipral_SipralNative_sipral_1call_1accept_1transfer(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray configTarget, jbyteArray configSdp, jbyteArray configDestination, jlong configKeepAllForks, jbyteArray configMediaAddress, jbyteArray configHeadersBytes, jlongArray configHeadersLengths, jlong configSrtp, jlong configTransport, jbyteArray configCodecs, jlong configIce, jlongArray placed, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_call_config_t config_value;
    memset(&config_value, 0, sizeof config_value);
    config_value.size = sizeof config_value;
    jbyte *configTarget_data = configTarget ? (*env)->GetByteArrayElements(env, configTarget, NULL) : NULL;
    jsize configTarget_size = configTarget ? (*env)->GetArrayLength(env, configTarget) : 0;
    config_value.target = (const char *)configTarget_data;
    config_value.target_len = (size_t)configTarget_size;
    jbyte *configSdp_data = configSdp ? (*env)->GetByteArrayElements(env, configSdp, NULL) : NULL;
    jsize configSdp_size = configSdp ? (*env)->GetArrayLength(env, configSdp) : 0;
    config_value.sdp = (const uint8_t *)configSdp_data;
    config_value.sdp_len = (size_t)configSdp_size;
    jbyte *configDestination_data = configDestination ? (*env)->GetByteArrayElements(env, configDestination, NULL) : NULL;
    jsize configDestination_size = configDestination ? (*env)->GetArrayLength(env, configDestination) : 0;
    config_value.destination = (const char *)configDestination_data;
    config_value.destination_len = (size_t)configDestination_size;
    config_value.keep_all_forks = (uint32_t)configKeepAllForks;
    jbyte *configMediaAddress_data = configMediaAddress ? (*env)->GetByteArrayElements(env, configMediaAddress, NULL) : NULL;
    jsize configMediaAddress_size = configMediaAddress ? (*env)->GetArrayLength(env, configMediaAddress) : 0;
    config_value.media_address = (const char *)configMediaAddress_data;
    config_value.media_address_len = (size_t)configMediaAddress_size;
    config_value.srtp = (uint32_t)configSrtp;
    config_value.transport = (uint32_t)configTransport;
    jbyte *configCodecs_data = configCodecs ? (*env)->GetByteArrayElements(env, configCodecs, NULL) : NULL;
    jsize configCodecs_size = configCodecs ? (*env)->GetArrayLength(env, configCodecs) : 0;
    config_value.codecs = (const char *)configCodecs_data;
    config_value.codecs_len = (size_t)configCodecs_size;
    config_value.ice = (uint32_t)configIce;
    sipral_handle_t placed_value = 0;
    int ready = 1;
    jbyte *configHeaders_pinned = NULL;
    sipral_header_t *configHeaders_array = NULL;
    size_t configHeaders_count = 0;
    ready = ready && jni_header_array(env, configHeadersBytes, configHeadersLengths, &configHeaders_pinned, &configHeaders_array, &configHeaders_count);
    config_value.headers = configHeaders_array;
    config_value.headers_len = configHeaders_count;
    /* -1 is no status the library answers with, and it is never read: a list
     * that did not make an array left an exception pending, and the JVM
     * throws that instead */
    sipral_status_t status = -1;
    if (ready) {
        status = sipral_call_accept_transfer((sipral_handle_t)stack, (sipral_handle_t)call, &config_value, &placed_value, (uint64_t)nowMs);
    }
    if (configTarget) {
        (*env)->ReleaseByteArrayElements(env, configTarget, configTarget_data, JNI_ABORT);
    }
    if (configSdp) {
        (*env)->ReleaseByteArrayElements(env, configSdp, configSdp_data, JNI_ABORT);
    }
    if (configDestination) {
        (*env)->ReleaseByteArrayElements(env, configDestination, configDestination_data, JNI_ABORT);
    }
    if (configMediaAddress) {
        (*env)->ReleaseByteArrayElements(env, configMediaAddress, configMediaAddress_data, JNI_ABORT);
    }
    jni_header_release(env, configHeadersBytes, configHeaders_pinned, configHeaders_array);
    if (configCodecs) {
        (*env)->ReleaseByteArrayElements(env, configCodecs, configCodecs_data, JNI_ABORT);
    }
    if (ready) {
        {
            jlong slot = (jlong)placed_value;
            (*env)->SetLongArrayRegion(env, placed, 0, 1, &slot);
        }
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1reject_1transfer(JNIEnv *env, jobject self, jlong stack, jlong call, jlong code, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_reject_transfer((sipral_handle_t)stack, (sipral_handle_t)call, (uint32_t)code, (uint64_t)nowMs);
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
Java_org_sipral_SipralNative_sipral_1call_1media(JNIEnv *env, jobject self, jlong stack, jlong call, jlongArray media)
{
    (void)env;
    (void)self;
    sipral_handle_t media_value = 0;
    sipral_status_t status = sipral_call_media((sipral_handle_t)stack, (sipral_handle_t)call, &media_value);
    {
        jlong slot = (jlong)media_value;
        (*env)->SetLongArrayRegion(env, media, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1release(JNIEnv *env, jobject self, jlong media)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_media_release((sipral_handle_t)media);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1info(JNIEnv *env, jobject self, jlong media, jlongArray info)
{
    (void)env;
    (void)self;
    sipral_media_info_t info_value;
    memset(&info_value, 0, sizeof info_value);
    info_value.size = sizeof info_value;
    sipral_status_t status = sipral_media_info((sipral_handle_t)media, &info_value);
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
Java_org_sipral_SipralNative_sipral_1media_1codec_1candidate_1count(JNIEnv *env, jobject self, jlong media, jlongArray count)
{
    (void)env;
    (void)self;
    size_t count_value = 0;
    sipral_status_t status = sipral_media_codec_candidate_count((sipral_handle_t)media, &count_value);
    {
        jlong slot = (jlong)count_value;
        (*env)->SetLongArrayRegion(env, count, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1codec_1candidate_1at(JNIEnv *env, jobject self, jlong media, jlong index, jlongArray candidate)
{
    (void)env;
    (void)self;
    sipral_codec_candidate_t candidate_value;
    memset(&candidate_value, 0, sizeof candidate_value);
    candidate_value.size = sizeof candidate_value;
    sipral_status_t status = sipral_media_codec_candidate_at((sipral_handle_t)media, (size_t)index, &candidate_value);
    {
        jlong slots[4];
        slots[0] = (jlong)candidate_value.size;
        slots[1] = (jlong)candidate_value.codec;
        slots[2] = (jlong)candidate_value.outcome;
        slots[3] = (jlong)candidate_value.outranked_by;
        (*env)->SetLongArrayRegion(env, candidate, 0, 4, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1statistics(JNIEnv *env, jobject self, jlong media, jlong nowMs, jlongArray stats)
{
    (void)env;
    (void)self;
    sipral_stream_stats_t stats_value;
    memset(&stats_value, 0, sizeof stats_value);
    stats_value.size = sizeof stats_value;
    sipral_status_t status = sipral_media_statistics((sipral_handle_t)media, (uint64_t)nowMs, &stats_value);
    {
        jlong slots[39];
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
        slots[21] = (jlong)stats_value.has_voip_metrics;
        slots[22] = (jlong)stats_value.voip_loss_rate_256;
        slots[23] = (jlong)stats_value.voip_discard_rate_256;
        slots[24] = (jlong)stats_value.voip_burst_density_256;
        slots[25] = (jlong)stats_value.voip_burst_duration_us;
        slots[26] = (jlong)stats_value.voip_gap_density_256;
        slots[27] = (jlong)stats_value.voip_gap_duration_us;
        slots[28] = (jlong)stats_value.voip_gmin;
        slots[29] = (jlong)stats_value.voip_end_system_delay_us;
        slots[30] = (jlong)stats_value.voip_jitter_buffer_nominal_us;
        slots[31] = (jlong)stats_value.voip_jitter_buffer_maximum_us;
        slots[32] = (jlong)stats_value.voip_jitter_buffer_abs_max_us;
        slots[33] = (jlong)stats_value.has_voip_r_factor;
        slots[34] = (jlong)stats_value.voip_r_factor;
        slots[35] = (jlong)stats_value.has_voip_mos_lq;
        slots[36] = (jlong)stats_value.voip_mos_lq_x10;
        slots[37] = (jlong)stats_value.has_voip_mos_cq;
        slots[38] = (jlong)stats_value.voip_mos_cq_x10;
        (*env)->SetLongArrayRegion(env, stats, 0, 39, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1receive(JNIEnv *env, jobject self, jlong media, jbyteArray data, jbyteArray from, jlong nowMs, jlongArray arrival)
{
    (void)env;
    (void)self;
    jbyte *data_data = data ? (*env)->GetByteArrayElements(env, data, NULL) : NULL;
    jsize data_size = data ? (*env)->GetArrayLength(env, data) : 0;
    jbyte *from_data = from ? (*env)->GetByteArrayElements(env, from, NULL) : NULL;
    jsize from_size = from ? (*env)->GetArrayLength(env, from) : 0;
    uint32_t arrival_value = 0;
    sipral_status_t status = sipral_media_receive((sipral_handle_t)media, (uint8_t *)data_data, (size_t)data_size, (const char *)from_data, (size_t)from_size, (uint64_t)nowMs, &arrival_value);
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
Java_org_sipral_SipralNative_sipral_1media_1playback(JNIEnv *env, jobject self, jlong media, jshortArray samples, jlongArray written, jlongArray source)
{
    (void)env;
    (void)self;
    jshort *samples_data = samples ? (*env)->GetShortArrayElements(env, samples, NULL) : NULL;
    jsize samples_size = samples ? (*env)->GetArrayLength(env, samples) : 0;
    size_t written_value = 0;
    uint32_t source_value = 0;
    sipral_status_t status = sipral_media_playback((sipral_handle_t)media, (int16_t *)samples_data, (size_t)samples_size, &written_value, &source_value);
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
Java_org_sipral_SipralNative_sipral_1media_1capture(JNIEnv *env, jobject self, jlong media, jlong nowMs, jshortArray samples, jlong packet)
{
    (void)env;
    (void)self;
    jshort *samples_data = samples ? (*env)->GetShortArrayElements(env, samples, NULL) : NULL;
    jsize samples_size = samples ? (*env)->GetArrayLength(env, samples) : 0;
    sipral_status_t status = sipral_media_capture((sipral_handle_t)media, (uint64_t)nowMs, (const int16_t *)samples_data, (size_t)samples_size, (sipral_media_packet_t *)(intptr_t)packet);
    if (samples) {
        (*env)->ReleaseShortArrayElements(env, samples, samples_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1poll_1rtcp(JNIEnv *env, jobject self, jlong media, jlong nowMs, jlong packet)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_media_poll_rtcp((sipral_handle_t)media, (uint64_t)nowMs, (sipral_media_packet_t *)(intptr_t)packet);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1poll_1transmit(JNIEnv *env, jobject self, jlong media, jlong nowMs, jlong packet)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_media_poll_transmit((sipral_handle_t)media, (uint64_t)nowMs, (sipral_media_packet_t *)(intptr_t)packet);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1poll_1farewell(JNIEnv *env, jobject self, jlong stack, jlongArray call, jlong outPacket)
{
    (void)env;
    (void)self;
    sipral_handle_t call_value = 0;
    sipral_status_t status = sipral_stack_poll_farewell((sipral_handle_t)stack, &call_value, (sipral_media_packet_t *)(intptr_t)outPacket);
    {
        jlong slot = (jlong)call_value;
        (*env)->SetLongArrayRegion(env, call, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1dialling(JNIEnv *env, jobject self, jlong media, jlongArray dialling, jlongArray waiting)
{
    (void)env;
    (void)self;
    uint32_t dialling_value = 0;
    size_t waiting_value = 0;
    sipral_status_t status = sipral_media_dialling((sipral_handle_t)media, &dialling_value, &waiting_value);
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
Java_org_sipral_SipralNative_sipral_1media_1stop_1dialling(JNIEnv *env, jobject self, jlong media)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_media_stop_dialling((sipral_handle_t)media);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1record_1start(JNIEnv *env, jobject self, jlong media, jbyteArray path)
{
    (void)env;
    (void)self;
    jbyte *path_data = path ? (*env)->GetByteArrayElements(env, path, NULL) : NULL;
    jsize path_size = path ? (*env)->GetArrayLength(env, path) : 0;
    sipral_status_t status = sipral_media_record_start((sipral_handle_t)media, (const char *)path_data, (size_t)path_size);
    if (path) {
        (*env)->ReleaseByteArrayElements(env, path, path_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1record_1stop(JNIEnv *env, jobject self, jlong media)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_media_record_stop((sipral_handle_t)media);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1record_1state(JNIEnv *env, jobject self, jlong media, jlongArray recording, jlongArray recordedMs)
{
    (void)env;
    (void)self;
    uint32_t recording_value = 0;
    uint64_t recordedMs_value = 0;
    sipral_status_t status = sipral_media_record_state((sipral_handle_t)media, &recording_value, &recordedMs_value);
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
Java_org_sipral_SipralNative_sipral_1stack_1transport_1bind(JNIEnv *env, jobject self, jlong stack, jlong transport, jlong protocol, jbyteArray local, jbyteArray remote, jlong nowMs, jlongArray transportId)
{
    (void)env;
    (void)self;
    jbyte *local_data = local ? (*env)->GetByteArrayElements(env, local, NULL) : NULL;
    jsize local_size = local ? (*env)->GetArrayLength(env, local) : 0;
    jbyte *remote_data = remote ? (*env)->GetByteArrayElements(env, remote, NULL) : NULL;
    jsize remote_size = remote ? (*env)->GetArrayLength(env, remote) : 0;
    uint32_t transportId_value = 0;
    sipral_status_t status = sipral_stack_transport_bind((sipral_handle_t)stack, (uint32_t)transport, (uint32_t)protocol, (const char *)local_data, (size_t)local_size, (const char *)remote_data, (size_t)remote_size, (uint64_t)nowMs, &transportId_value);
    if (local) {
        (*env)->ReleaseByteArrayElements(env, local, local_data, JNI_ABORT);
    }
    if (remote) {
        (*env)->ReleaseByteArrayElements(env, remote, remote_data, JNI_ABORT);
    }
    {
        jlong slot = (jlong)transportId_value;
        (*env)->SetLongArrayRegion(env, transportId, 0, 1, &slot);
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

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1message_1header_1count(JNIEnv *env, jobject self, jbyteArray message, jbyteArray name, jlongArray count)
{
    (void)env;
    (void)self;
    jbyte *message_data = message ? (*env)->GetByteArrayElements(env, message, NULL) : NULL;
    jsize message_size = message ? (*env)->GetArrayLength(env, message) : 0;
    jbyte *name_data = name ? (*env)->GetByteArrayElements(env, name, NULL) : NULL;
    jsize name_size = name ? (*env)->GetArrayLength(env, name) : 0;
    size_t count_value = 0;
    sipral_status_t status = sipral_message_header_count((const uint8_t *)message_data, (size_t)message_size, (const char *)name_data, (size_t)name_size, &count_value);
    if (message) {
        (*env)->ReleaseByteArrayElements(env, message, message_data, JNI_ABORT);
    }
    if (name) {
        (*env)->ReleaseByteArrayElements(env, name, name_data, JNI_ABORT);
    }
    {
        jlong slot = (jlong)count_value;
        (*env)->SetLongArrayRegion(env, count, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1message_1header(JNIEnv *env, jobject self, jbyteArray message, jbyteArray name, jlong index, jlongArray offset, jlongArray len)
{
    (void)env;
    (void)self;
    jbyte *message_data = message ? (*env)->GetByteArrayElements(env, message, NULL) : NULL;
    jsize message_size = message ? (*env)->GetArrayLength(env, message) : 0;
    jbyte *name_data = name ? (*env)->GetByteArrayElements(env, name, NULL) : NULL;
    jsize name_size = name ? (*env)->GetArrayLength(env, name) : 0;
    size_t offset_value = 0;
    size_t len_value = 0;
    sipral_status_t status = sipral_message_header((const uint8_t *)message_data, (size_t)message_size, (const char *)name_data, (size_t)name_size, (size_t)index, &offset_value, &len_value);
    if (message) {
        (*env)->ReleaseByteArrayElements(env, message, message_data, JNI_ABORT);
    }
    if (name) {
        (*env)->ReleaseByteArrayElements(env, name, name_data, JNI_ABORT);
    }
    {
        jlong slot = (jlong)offset_value;
        (*env)->SetLongArrayRegion(env, offset, 0, 1, &slot);
    }
    {
        jlong slot = (jlong)len_value;
        (*env)->SetLongArrayRegion(env, len, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1message_1header_1element_1count(JNIEnv *env, jobject self, jbyteArray message, jbyteArray name, jlongArray count)
{
    (void)env;
    (void)self;
    jbyte *message_data = message ? (*env)->GetByteArrayElements(env, message, NULL) : NULL;
    jsize message_size = message ? (*env)->GetArrayLength(env, message) : 0;
    jbyte *name_data = name ? (*env)->GetByteArrayElements(env, name, NULL) : NULL;
    jsize name_size = name ? (*env)->GetArrayLength(env, name) : 0;
    size_t count_value = 0;
    sipral_status_t status = sipral_message_header_element_count((const uint8_t *)message_data, (size_t)message_size, (const char *)name_data, (size_t)name_size, &count_value);
    if (message) {
        (*env)->ReleaseByteArrayElements(env, message, message_data, JNI_ABORT);
    }
    if (name) {
        (*env)->ReleaseByteArrayElements(env, name, name_data, JNI_ABORT);
    }
    {
        jlong slot = (jlong)count_value;
        (*env)->SetLongArrayRegion(env, count, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1message_1header_1element(JNIEnv *env, jobject self, jbyteArray message, jbyteArray name, jlong index, jlongArray offset, jlongArray len)
{
    (void)env;
    (void)self;
    jbyte *message_data = message ? (*env)->GetByteArrayElements(env, message, NULL) : NULL;
    jsize message_size = message ? (*env)->GetArrayLength(env, message) : 0;
    jbyte *name_data = name ? (*env)->GetByteArrayElements(env, name, NULL) : NULL;
    jsize name_size = name ? (*env)->GetArrayLength(env, name) : 0;
    size_t offset_value = 0;
    size_t len_value = 0;
    sipral_status_t status = sipral_message_header_element((const uint8_t *)message_data, (size_t)message_size, (const char *)name_data, (size_t)name_size, (size_t)index, &offset_value, &len_value);
    if (message) {
        (*env)->ReleaseByteArrayElements(env, message, message_data, JNI_ABORT);
    }
    if (name) {
        (*env)->ReleaseByteArrayElements(env, name, name_data, JNI_ABORT);
    }
    {
        jlong slot = (jlong)offset_value;
        (*env)->SetLongArrayRegion(env, offset, 0, 1, &slot);
    }
    {
        jlong slot = (jlong)len_value;
        (*env)->SetLongArrayRegion(env, len, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1suspending(JNIEnv *env, jobject self, jlong stack, jlong nowMs, jlongArray report)
{
    (void)env;
    (void)self;
    sipral_suspending_t report_value;
    memset(&report_value, 0, sizeof report_value);
    report_value.size = sizeof report_value;
    sipral_status_t status = sipral_stack_suspending((sipral_handle_t)stack, (uint64_t)nowMs, &report_value);
    {
        jlong slots[4];
        slots[0] = (jlong)report_value.size;
        slots[1] = (jlong)report_value.unverified;
        slots[2] = (jlong)report_value.subscriptions;
        slots[3] = (jlong)report_value.calls;
        (*env)->SetLongArrayRegion(env, report, 0, 4, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1resumed(JNIEnv *env, jobject self, jlong stack, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_resumed((sipral_handle_t)stack, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1network_1changed(JNIEnv *env, jobject self, jlong stack, jlong fromLink, jbyteArray fromAddress, jbyteArray fromInterface, jlong fromResolves, jlong toLink, jbyteArray toAddress, jbyteArray toInterface, jlong toResolves, jlong nowMs, jlongArray recovery)
{
    (void)env;
    (void)self;
    jbyte *fromAddress_data = fromAddress ? (*env)->GetByteArrayElements(env, fromAddress, NULL) : NULL;
    jsize fromAddress_size = fromAddress ? (*env)->GetArrayLength(env, fromAddress) : 0;
    jbyte *fromInterface_data = fromInterface ? (*env)->GetByteArrayElements(env, fromInterface, NULL) : NULL;
    jsize fromInterface_size = fromInterface ? (*env)->GetArrayLength(env, fromInterface) : 0;
    jbyte *toAddress_data = toAddress ? (*env)->GetByteArrayElements(env, toAddress, NULL) : NULL;
    jsize toAddress_size = toAddress ? (*env)->GetArrayLength(env, toAddress) : 0;
    jbyte *toInterface_data = toInterface ? (*env)->GetByteArrayElements(env, toInterface, NULL) : NULL;
    jsize toInterface_size = toInterface ? (*env)->GetArrayLength(env, toInterface) : 0;
    uint32_t recovery_value = 0;
    sipral_status_t status = sipral_stack_network_changed((sipral_handle_t)stack, (uint32_t)fromLink, (const char *)fromAddress_data, (size_t)fromAddress_size, (const char *)fromInterface_data, (size_t)fromInterface_size, (uint32_t)fromResolves, (uint32_t)toLink, (const char *)toAddress_data, (size_t)toAddress_size, (const char *)toInterface_data, (size_t)toInterface_size, (uint32_t)toResolves, (uint64_t)nowMs, &recovery_value);
    if (fromAddress) {
        (*env)->ReleaseByteArrayElements(env, fromAddress, fromAddress_data, JNI_ABORT);
    }
    if (fromInterface) {
        (*env)->ReleaseByteArrayElements(env, fromInterface, fromInterface_data, JNI_ABORT);
    }
    if (toAddress) {
        (*env)->ReleaseByteArrayElements(env, toAddress, toAddress_data, JNI_ABORT);
    }
    if (toInterface) {
        (*env)->ReleaseByteArrayElements(env, toInterface, toInterface_data, JNI_ABORT);
    }
    {
        jlong slot = (jlong)recovery_value;
        (*env)->SetLongArrayRegion(env, recovery, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1interface_1lost(JNIEnv *env, jobject self, jlong stack, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_interface_lost((sipral_handle_t)stack, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1name_1resolution_1lost(JNIEnv *env, jobject self, jlong stack, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_name_resolution_lost((sipral_handle_t)stack, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1rebind(JNIEnv *env, jobject self, jlong stack, jlong account, jlong transport, jbyteArray remote, jbyteArray contact, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *remote_data = remote ? (*env)->GetByteArrayElements(env, remote, NULL) : NULL;
    jsize remote_size = remote ? (*env)->GetArrayLength(env, remote) : 0;
    jbyte *contact_data = contact ? (*env)->GetByteArrayElements(env, contact, NULL) : NULL;
    jsize contact_size = contact ? (*env)->GetArrayLength(env, contact) : 0;
    sipral_status_t status = sipral_account_rebind((sipral_handle_t)stack, (sipral_handle_t)account, (uint32_t)transport, (const char *)remote_data, (size_t)remote_size, (const char *)contact_data, (size_t)contact_size, (uint64_t)nowMs);
    if (remote) {
        (*env)->ReleaseByteArrayElements(env, remote, remote_data, JNI_ABORT);
    }
    if (contact) {
        (*env)->ReleaseByteArrayElements(env, contact, contact_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1cold_1start(JNIEnv *env, jobject self, jlong stack, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_cold_start((sipral_handle_t)stack, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1freeze(JNIEnv *env, jobject self, jlong stack, jlong account, jbyteArray buffer, jlongArray len, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *buffer_data = buffer ? (*env)->GetByteArrayElements(env, buffer, NULL) : NULL;
    jsize buffer_size = buffer ? (*env)->GetArrayLength(env, buffer) : 0;
    size_t len_value = 0;
    sipral_status_t status = sipral_account_freeze((sipral_handle_t)stack, (sipral_handle_t)account, (uint8_t *)buffer_data, (size_t)buffer_size, &len_value, (uint64_t)nowMs);
    if (buffer) {
        (*env)->ReleaseByteArrayElements(env, buffer, buffer_data, 0);
    }
    {
        jlong slot = (jlong)len_value;
        (*env)->SetLongArrayRegion(env, len, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1thaw(JNIEnv *env, jobject self, jlong stack, jlong account, jbyteArray snapshot, jlong asleepMs, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *snapshot_data = snapshot ? (*env)->GetByteArrayElements(env, snapshot, NULL) : NULL;
    jsize snapshot_size = snapshot ? (*env)->GetArrayLength(env, snapshot) : 0;
    sipral_status_t status = sipral_account_thaw((sipral_handle_t)stack, (sipral_handle_t)account, (const uint8_t *)snapshot_data, (size_t)snapshot_size, (uint64_t)asleepMs, (uint64_t)nowMs);
    if (snapshot) {
        (*env)->ReleaseByteArrayElements(env, snapshot, snapshot_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1time_1to_1ready(JNIEnv *env, jobject self, jlong stack, jlong account, jlongArray hasValue, jlongArray ms)
{
    (void)env;
    (void)self;
    uint32_t hasValue_value = 0;
    uint64_t ms_value = 0;
    sipral_status_t status = sipral_account_time_to_ready((sipral_handle_t)stack, (sipral_handle_t)account, &hasValue_value, &ms_value);
    {
        jlong slot = (jlong)hasValue_value;
        (*env)->SetLongArrayRegion(env, hasValue, 0, 1, &slot);
    }
    {
        jlong slot = (jlong)ms_value;
        (*env)->SetLongArrayRegion(env, ms, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1resolved(JNIEnv *env, jobject self, jlong stack, jlong dialog, jbyteArray addresses, jlong protocol)
{
    (void)env;
    (void)self;
    jbyte *addresses_data = addresses ? (*env)->GetByteArrayElements(env, addresses, NULL) : NULL;
    jsize addresses_size = addresses ? (*env)->GetArrayLength(env, addresses) : 0;
    sipral_status_t status = sipral_stack_resolved((sipral_handle_t)stack, (sipral_handle_t)dialog, (const char *)addresses_data, (size_t)addresses_size, (uint32_t)protocol);
    if (addresses) {
        (*env)->ReleaseByteArrayElements(env, addresses, addresses_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1retarget(JNIEnv *env, jobject self, jlong stack, jlong account, jbyteArray registrarAddress, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *registrarAddress_data = registrarAddress ? (*env)->GetByteArrayElements(env, registrarAddress, NULL) : NULL;
    jsize registrarAddress_size = registrarAddress ? (*env)->GetArrayLength(env, registrarAddress) : 0;
    sipral_status_t status = sipral_account_retarget((sipral_handle_t)stack, (sipral_handle_t)account, (const char *)registrarAddress_data, (size_t)registrarAddress_size, (uint64_t)nowMs);
    if (registrarAddress) {
        (*env)->ReleaseByteArrayElements(env, registrarAddress, registrarAddress_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1record_1json(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray buffer, jlongArray len)
{
    (void)env;
    (void)self;
    jbyte *buffer_data = buffer ? (*env)->GetByteArrayElements(env, buffer, NULL) : NULL;
    jsize buffer_size = buffer ? (*env)->GetArrayLength(env, buffer) : 0;
    size_t len_value = 0;
    sipral_status_t status = sipral_call_record_json((sipral_handle_t)stack, (sipral_handle_t)call, (char *)buffer_data, (size_t)buffer_size, &len_value);
    if (buffer) {
        (*env)->ReleaseByteArrayElements(env, buffer, buffer_data, 0);
    }
    {
        jlong slot = (jlong)len_value;
        (*env)->SetLongArrayRegion(env, len, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1diagnostics_1json(JNIEnv *env, jobject self, jlong stack, jbyteArray buffer, jlongArray len)
{
    (void)env;
    (void)self;
    jbyte *buffer_data = buffer ? (*env)->GetByteArrayElements(env, buffer, NULL) : NULL;
    jsize buffer_size = buffer ? (*env)->GetArrayLength(env, buffer) : 0;
    size_t len_value = 0;
    sipral_status_t status = sipral_stack_diagnostics_json((sipral_handle_t)stack, (char *)buffer_data, (size_t)buffer_size, &len_value);
    if (buffer) {
        (*env)->ReleaseByteArrayElements(env, buffer, buffer_data, 0);
    }
    {
        jlong slot = (jlong)len_value;
        (*env)->SetLongArrayRegion(env, len, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1recording_1start(JNIEnv *env, jobject self, jlong stack, jbyteArray note)
{
    (void)env;
    (void)self;
    jbyte *note_data = note ? (*env)->GetByteArrayElements(env, note, NULL) : NULL;
    jsize note_size = note ? (*env)->GetArrayLength(env, note) : 0;
    sipral_status_t status = sipral_stack_recording_start((sipral_handle_t)stack, (const char *)note_data, (size_t)note_size);
    if (note) {
        (*env)->ReleaseByteArrayElements(env, note, note_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1recording_1stop(JNIEnv *env, jobject self, jlong stack, jbyteArray buffer, jlongArray len)
{
    (void)env;
    (void)self;
    jbyte *buffer_data = buffer ? (*env)->GetByteArrayElements(env, buffer, NULL) : NULL;
    jsize buffer_size = buffer ? (*env)->GetArrayLength(env, buffer) : 0;
    size_t len_value = 0;
    sipral_status_t status = sipral_stack_recording_stop((sipral_handle_t)stack, (char *)buffer_data, (size_t)buffer_size, &len_value);
    if (buffer) {
        (*env)->ReleaseByteArrayElements(env, buffer, buffer_data, 0);
    }
    {
        jlong slot = (jlong)len_value;
        (*env)->SetLongArrayRegion(env, len, 0, 1, &slot);
    }
    return (jint)status;
}

