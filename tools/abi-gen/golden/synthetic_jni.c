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
        jni_event_callback_deliver = (*env)->GetStaticMethodID(env, jni_event_callback_class, "deliver", "(JJJJ[B)V");
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
        jni_screen_callback_deliver = (*env)->GetStaticMethodID(env, jni_screen_callback_class, "deliver", "(JJ[B)J");
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
        (*env)->CallStaticVoidMethod(env, jni_event_callback_class, jni_event_callback_deliver, (jlong)(intptr_t)user_data, (jlong)event->size, JNI_REACHES(event, sipral_event_t, stack) ? (jlong)event->stack : 0, JNI_REACHES(event, sipral_event_t, kind) ? (jlong)event->kind : 0, message);
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
jni_screen_callback(const sipral_screen_event_t *event, void *user_data)
{
    JNIEnv *env = NULL;
    int attached = 0;
    int built = 1;
    jint found;
    uint32_t answer = 0;
    jbyteArray from = NULL;

    if (jni_vm == NULL || event == NULL) {
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
    if (built && JNI_REACHES(event, sipral_screen_event_t, from_len) && event->from != NULL) {
        from = (*env)->NewByteArray(env, (jsize)event->from_len);
        if (from == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, from, 0, (jsize)event->from_len, (const jbyte *)event->from);
        }
    }
    if (built) {
        answer = (uint32_t)(*env)->CallStaticLongMethod(env, jni_screen_callback_class, jni_screen_callback_deliver, (jlong)(intptr_t)user_data, (jlong)event->size, from);
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
    if (from != NULL) {
        (*env)->DeleteLocalRef(env, from);
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
Java_org_sipral_SipralNative_sipral_1stack_1create(JNIEnv *env, jobject self, jlong configEventCallback, jbyteArray configBindAddress, jlong configEcho, jbyteArray configHeadersBytes, jlongArray configHeadersLengths, jlongArray stack)
{
    (void)env;
    (void)self;
    sipral_stack_config_t config_value;
    memset(&config_value, 0, sizeof config_value);
    config_value.size = sizeof config_value;
    config_value.event_callback = configEventCallback != 0 ? jni_event_callback : NULL;
    config_value.event_user_data = (void *)(intptr_t)configEventCallback;
    jbyte *configBindAddress_data = configBindAddress ? (*env)->GetByteArrayElements(env, configBindAddress, NULL) : NULL;
    jsize configBindAddress_size = configBindAddress ? (*env)->GetArrayLength(env, configBindAddress) : 0;
    config_value.bind_address = (const char *)configBindAddress_data;
    config_value.bind_address_len = (size_t)configBindAddress_size;
    config_value.echo = (sipral_toggle_t)configEcho;
    sipral_handle_t stack_value = 0;
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
        status = sipral_stack_create(&config_value, &stack_value);
    }
    if (configBindAddress) {
        (*env)->ReleaseByteArrayElements(env, configBindAddress, configBindAddress_data, JNI_ABORT);
    }
    jni_header_release(env, configHeadersBytes, configHeaders_pinned, configHeaders_array);
    if (ready) {
        {
            jlong slot = (jlong)stack_value;
            (*env)->SetLongArrayRegion(env, stack, 0, 1, &slot);
        }
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
Java_org_sipral_SipralNative_sipral_1stack_1label(JNIEnv *env, jobject self, jlong stack, jbyteArray headersBytes, jlongArray headersLengths)
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
        status = sipral_stack_label((sipral_handle_t)stack, headers_array, headers_count);
    }
    jni_header_release(env, headersBytes, headers_pinned, headers_array);
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
Java_org_sipral_SipralNative_sipral_1stack_1freeze(JNIEnv *env, jobject self, jlong stack, jbyteArray buffer, jlongArray len)
{
    (void)env;
    (void)self;
    jbyte *buffer_data = buffer ? (*env)->GetByteArrayElements(env, buffer, NULL) : NULL;
    jsize buffer_size = buffer ? (*env)->GetArrayLength(env, buffer) : 0;
    size_t len_value = 0;
    sipral_status_t status = sipral_stack_freeze((sipral_handle_t)stack, (uint8_t *)buffer_data, (size_t)buffer_size, &len_value);
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
Java_org_sipral_SipralNative_sipral_1call_1mix(JNIEnv *env, jobject self, jlong stack, jshortArray mic, jshortArray local)
{
    (void)env;
    (void)self;
    jshort *mic_data = mic ? (*env)->GetShortArrayElements(env, mic, NULL) : NULL;
    jsize mic_size = mic ? (*env)->GetArrayLength(env, mic) : 0;
    jshort *local_data = local ? (*env)->GetShortArrayElements(env, local, NULL) : NULL;
    jsize local_size = local ? (*env)->GetArrayLength(env, local) : 0;
    sipral_status_t status = sipral_call_mix((sipral_handle_t)stack, (const int16_t *)mic_data, (size_t)mic_size, (int16_t *)local_data, (size_t)local_size);
    if (mic) {
        (*env)->ReleaseShortArrayElements(env, mic, mic_data, JNI_ABORT);
    }
    if (local) {
        (*env)->ReleaseShortArrayElements(env, local, local_data, 0);
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
Java_org_sipral_SipralNative_sipral_1stack_1screen(JNIEnv *env, jobject self, jlong stack, jlong callback)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_screen((sipral_handle_t)stack, callback != 0 ? jni_screen_callback : NULL, (void *)(intptr_t)callback);
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

