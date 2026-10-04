/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Sytek
 *
 * Hand-written, not printed by tools/abi-gen: a phone's audio devices and
 * the route of its calls, for the library's own audio engine on Android.
 *
 * The engine opens its streams through AAudio, which lists no devices and
 * routes nothing: both are AudioManager's, a Java API that needs the
 * application's Context to reach and a JavaVM to call. This library is the
 * one a JVM loads, so it holds both: SipralAndroidAudio.attach(context)
 * hands the context over, and sipral_jni_audio_bridge() hands the Rust
 * library (crates/sipral-io-aaudio/src/bridge.rs, which finds it with
 * dlsym in the library already loaded) a table of plain C functions over
 * it. The table is this file's and that one's, and not part of sipral.h.
 *
 * Every function in the table may be called from a thread no JVM made; it
 * attaches the thread for the length of the call and detaches it again,
 * clears any exception a Java call threw, and answers a negative number
 * for "could not ask" -- no context attached, a method this API level does
 * not have, or a call that threw. They are serialised by one mutex, which
 * is held for a binder call to the audio service at most.
 *
 * On a JVM that is not Android, attach finds no android.content.Context
 * and says so, and the table answers "could not ask" to everything.
 */

#define _POSIX_C_SOURCE 200809L

#include <jni.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

typedef struct sipral_jni_audio_device {
    int32_t id;
    int32_t type;
    int32_t source;
    int32_t sink;
    int32_t channels;
    char address[64];
    char product[128];
} sipral_jni_audio_device_t;

typedef struct sipral_jni_audio_bridge {
    uint32_t size;
    int32_t (*devices)(sipral_jni_audio_device_t *out, int32_t capacity);
    int32_t (*communication_device)(void);
    int32_t (*set_communication_device)(int32_t id);
    int32_t (*clear_communication_device)(void);
    int32_t (*speakerphone)(int32_t set);
    int32_t (*bluetooth_sco)(int32_t set);
} sipral_jni_audio_bridge_t;

/* AudioManager.GET_DEVICES_ALL */
#define ROUTES_GET_DEVICES_ALL 3

static pthread_mutex_t routes_lock = PTHREAD_MUTEX_INITIALIZER;
static JavaVM *routes_vm;
static jobject routes_manager;
static jclass routes_device_class;
static jclass routes_list_class;
static jmethodID routes_get_devices;
static jmethodID routes_get_communication_device;
static jmethodID routes_set_communication_device;
static jmethodID routes_clear_communication_device;
static jmethodID routes_available_communication_devices;
static jmethodID routes_is_speakerphone_on;
static jmethodID routes_set_speakerphone_on;
static jmethodID routes_is_bluetooth_sco_on;
static jmethodID routes_set_bluetooth_sco_on;
static jmethodID routes_start_bluetooth_sco;
static jmethodID routes_stop_bluetooth_sco;
static jmethodID routes_device_id;
static jmethodID routes_device_type;
static jmethodID routes_device_is_source;
static jmethodID routes_device_is_sink;
static jmethodID routes_device_channel_counts;
static jmethodID routes_device_product;
static jmethodID routes_device_address;
static jmethodID routes_list_size;
static jmethodID routes_list_get;
static jmethodID routes_object_to_string;

/* Whether the last Java call threw; the exception is cleared either way. */
static int
routes_threw(JNIEnv *env)
{
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return 1;
    }
    return 0;
}

/* A method this API level may not have: NULL, and no exception left behind. */
static jmethodID
routes_optional(JNIEnv *env, jclass cls, const char *name, const char *signature)
{
    jmethodID found = (*env)->GetMethodID(env, cls, name, signature);
    if (found == NULL) {
        routes_threw(env);
    }
    return found;
}

/* The calling thread's JNIEnv, attached for the call when it was not. */
static JNIEnv *
routes_enter(int *attached)
{
    JNIEnv *env = NULL;
    jint found;

    *attached = 0;
    if (routes_vm == NULL) {
        return NULL;
    }
    found = (*routes_vm)->GetEnv(routes_vm, (void *)&env, JNI_VERSION_1_6);
    if (found == JNI_EDETACHED) {
        if ((*routes_vm)->AttachCurrentThread(routes_vm, (void *)&env, NULL) != JNI_OK) {
            return NULL;
        }
        *attached = 1;
    } else if (found != JNI_OK) {
        return NULL;
    }
    return env;
}

static void
routes_leave(int attached)
{
    if (attached) {
        (*routes_vm)->DetachCurrentThread(routes_vm);
    }
}

/* Copy a Java string's UTF-8 into a fixed buffer, cut at a byte boundary
 * that does not split a character. */
static void
routes_copy(JNIEnv *env, jstring text, char *out, size_t capacity)
{
    const char *chars;
    size_t len;

    out[0] = '\0';
    if (text == NULL) {
        return;
    }
    chars = (*env)->GetStringUTFChars(env, text, NULL);
    if (chars == NULL) {
        routes_threw(env);
        return;
    }
    len = strlen(chars);
    if (len >= capacity) {
        len = capacity - 1;
        while (len > 0 && (((unsigned char)chars[len]) & 0xC0) == 0x80) {
            len--;
        }
    }
    memcpy(out, chars, len);
    out[len] = '\0';
    (*env)->ReleaseStringUTFChars(env, text, chars);
}

/* One AudioDeviceInfo into one entry. Zero, or -1 when a call threw. */
static int
routes_read_device(JNIEnv *env, jobject device, sipral_jni_audio_device_t *out)
{
    jintArray counts;
    jobject product;
    jstring text;
    jsize n;
    jsize i;

    memset(out, 0, sizeof *out);
    out->id = (*env)->CallIntMethod(env, device, routes_device_id);
    if (routes_threw(env)) {
        return -1;
    }
    out->type = (*env)->CallIntMethod(env, device, routes_device_type);
    if (routes_threw(env)) {
        return -1;
    }
    out->source = (*env)->CallBooleanMethod(env, device, routes_device_is_source) ? 1 : 0;
    if (routes_threw(env)) {
        return -1;
    }
    out->sink = (*env)->CallBooleanMethod(env, device, routes_device_is_sink) ? 1 : 0;
    if (routes_threw(env)) {
        return -1;
    }
    counts = (jintArray)(*env)->CallObjectMethod(env, device, routes_device_channel_counts);
    if (routes_threw(env)) {
        return -1;
    }
    if (counts != NULL) {
        n = (*env)->GetArrayLength(env, counts);
        for (i = 0; i < n; i++) {
            jint one = 0;
            (*env)->GetIntArrayRegion(env, counts, i, 1, &one);
            if (one > out->channels) {
                out->channels = one;
            }
        }
        (*env)->DeleteLocalRef(env, counts);
    }
    product = (*env)->CallObjectMethod(env, device, routes_device_product);
    if (!routes_threw(env) && product != NULL) {
        text = (jstring)(*env)->CallObjectMethod(env, product, routes_object_to_string);
        if (!routes_threw(env)) {
            routes_copy(env, text, out->product, sizeof out->product);
        }
        if (text != NULL) {
            (*env)->DeleteLocalRef(env, text);
        }
        (*env)->DeleteLocalRef(env, product);
    }
    if (routes_device_address != NULL) {
        text = (jstring)(*env)->CallObjectMethod(env, device, routes_device_address);
        if (!routes_threw(env)) {
            routes_copy(env, text, out->address, sizeof out->address);
        }
        if (text != NULL) {
            (*env)->DeleteLocalRef(env, text);
        }
    }
    return 0;
}

static int32_t
routes_devices(sipral_jni_audio_device_t *out, int32_t capacity)
{
    JNIEnv *env;
    int attached;
    jobjectArray devices;
    jsize n;
    jsize i;
    int32_t written = 0;

    pthread_mutex_lock(&routes_lock);
    env = routes_manager != NULL ? routes_enter(&attached) : NULL;
    if (env == NULL) {
        pthread_mutex_unlock(&routes_lock);
        return -1;
    }
    devices = (jobjectArray)(*env)->CallObjectMethod(env, routes_manager, routes_get_devices,
        (jint)ROUTES_GET_DEVICES_ALL);
    if (routes_threw(env) || devices == NULL) {
        routes_leave(attached);
        pthread_mutex_unlock(&routes_lock);
        return -1;
    }
    n = (*env)->GetArrayLength(env, devices);
    for (i = 0; i < n && written < capacity; i++) {
        jobject device = (*env)->GetObjectArrayElement(env, devices, i);
        if (device == NULL) {
            routes_threw(env);
            continue;
        }
        if (routes_read_device(env, device, &out[written]) == 0) {
            written++;
        }
        (*env)->DeleteLocalRef(env, device);
    }
    (*env)->DeleteLocalRef(env, devices);
    routes_leave(attached);
    pthread_mutex_unlock(&routes_lock);
    return written;
}

static int32_t
routes_communication_device(void)
{
    JNIEnv *env;
    int attached;
    jobject device;
    int32_t id = -1;

    pthread_mutex_lock(&routes_lock);
    env = routes_manager != NULL && routes_get_communication_device != NULL
        ? routes_enter(&attached) : NULL;
    if (env == NULL) {
        pthread_mutex_unlock(&routes_lock);
        return -1;
    }
    device = (*env)->CallObjectMethod(env, routes_manager, routes_get_communication_device);
    if (!routes_threw(env)) {
        id = 0;
        if (device != NULL) {
            id = (*env)->CallIntMethod(env, device, routes_device_id);
            if (routes_threw(env)) {
                id = -1;
            }
        }
    }
    if (device != NULL) {
        (*env)->DeleteLocalRef(env, device);
    }
    routes_leave(attached);
    pthread_mutex_unlock(&routes_lock);
    return id;
}

/* setCommunicationDevice takes an AudioDeviceInfo, and only one of
 * getAvailableCommunicationDevices: found there by id. */
static int32_t
routes_set_communication(int32_t id)
{
    JNIEnv *env;
    int attached;
    jobject list;
    jint n;
    jint i;
    int32_t answer = -1;

    pthread_mutex_lock(&routes_lock);
    env = routes_manager != NULL && routes_set_communication_device != NULL
            && routes_available_communication_devices != NULL
        ? routes_enter(&attached) : NULL;
    if (env == NULL) {
        pthread_mutex_unlock(&routes_lock);
        return -1;
    }
    list = (*env)->CallObjectMethod(env, routes_manager, routes_available_communication_devices);
    if (routes_threw(env) || list == NULL) {
        routes_leave(attached);
        pthread_mutex_unlock(&routes_lock);
        return -1;
    }
    answer = 0;
    n = (*env)->CallIntMethod(env, list, routes_list_size);
    if (routes_threw(env)) {
        n = 0;
        answer = -1;
    }
    for (i = 0; i < n; i++) {
        jobject device = (*env)->CallObjectMethod(env, list, routes_list_get, i);
        jint found;
        if (routes_threw(env) || device == NULL) {
            continue;
        }
        found = (*env)->CallIntMethod(env, device, routes_device_id);
        if (!routes_threw(env) && found == id) {
            jboolean taken = (*env)->CallBooleanMethod(env, routes_manager,
                routes_set_communication_device, device);
            answer = routes_threw(env) ? -1 : (taken ? 1 : 0);
            (*env)->DeleteLocalRef(env, device);
            break;
        }
        (*env)->DeleteLocalRef(env, device);
    }
    (*env)->DeleteLocalRef(env, list);
    routes_leave(attached);
    pthread_mutex_unlock(&routes_lock);
    return answer;
}

static int32_t
routes_clear_communication(void)
{
    JNIEnv *env;
    int attached;
    int32_t answer;

    pthread_mutex_lock(&routes_lock);
    env = routes_manager != NULL && routes_clear_communication_device != NULL
        ? routes_enter(&attached) : NULL;
    if (env == NULL) {
        pthread_mutex_unlock(&routes_lock);
        return -1;
    }
    (*env)->CallVoidMethod(env, routes_manager, routes_clear_communication_device);
    answer = routes_threw(env) ? -1 : 0;
    routes_leave(attached);
    pthread_mutex_unlock(&routes_lock);
    return answer;
}

/* One of the two switches: `set` below zero only asks. Answers what the
 * switch is at afterwards, or -1. */
static int32_t
routes_switch(int32_t set, jmethodID is_on, jmethodID set_on, jmethodID start, jmethodID stop)
{
    JNIEnv *env;
    int attached;
    jboolean on;
    int32_t answer = -1;

    pthread_mutex_lock(&routes_lock);
    env = routes_manager != NULL ? routes_enter(&attached) : NULL;
    if (env == NULL) {
        pthread_mutex_unlock(&routes_lock);
        return -1;
    }
    if (set >= 0) {
        if (set && start != NULL) {
            (*env)->CallVoidMethod(env, routes_manager, start);
            routes_threw(env);
        }
        (*env)->CallVoidMethod(env, routes_manager, set_on, set ? JNI_TRUE : JNI_FALSE);
        routes_threw(env);
        if (!set && stop != NULL) {
            (*env)->CallVoidMethod(env, routes_manager, stop);
            routes_threw(env);
        }
    }
    on = (*env)->CallBooleanMethod(env, routes_manager, is_on);
    if (!routes_threw(env)) {
        answer = on ? 1 : 0;
    }
    routes_leave(attached);
    pthread_mutex_unlock(&routes_lock);
    return answer;
}

static int32_t
routes_speakerphone(int32_t set)
{
    return routes_switch(set, routes_is_speakerphone_on, routes_set_speakerphone_on, NULL, NULL);
}

static int32_t
routes_bluetooth_sco(int32_t set)
{
    return routes_switch(set, routes_is_bluetooth_sco_on, routes_set_bluetooth_sco_on,
        routes_start_bluetooth_sco, routes_stop_bluetooth_sco);
}

static const sipral_jni_audio_bridge_t routes_bridge = {
    sizeof(sipral_jni_audio_bridge_t),
    routes_devices,
    routes_communication_device,
    routes_set_communication,
    routes_clear_communication,
    routes_speakerphone,
    routes_bluetooth_sco,
};

/* What crates/sipral-io-aaudio looks up by name. */
JNIEXPORT const sipral_jni_audio_bridge_t *
sipral_jni_audio_bridge(void)
{
    return &routes_bridge;
}

/* A class as a global reference, or NULL with nothing pending. */
static jclass
routes_class(JNIEnv *env, const char *name)
{
    jclass local = (*env)->FindClass(env, name);
    jclass global;
    if (local == NULL) {
        routes_threw(env);
        return NULL;
    }
    global = (jclass)(*env)->NewGlobalRef(env, local);
    (*env)->DeleteLocalRef(env, local);
    return global;
}

/* SipralAudioRoutesNative.attach(context): 0 once the context's
 * AudioManager is held, -1 for an object that is no android.content.Context
 * (or a JVM that has none), -2 when the context would not give one. A
 * second call replaces the first. */
JNIEXPORT jint JNICALL
Java_org_sipral_idiomatic_SipralAudioRoutesNative_attach(JNIEnv *env, jobject self, jobject context)
{
    jclass context_class;
    jclass manager_class;
    jclass char_sequence;
    jmethodID get_application_context;
    jmethodID get_system_service;
    jobject application;
    jstring name;
    jobject manager;
    jint answer = 0;

    (void)self;
    context_class = routes_class(env, "android/content/Context");
    if (context_class == NULL || context == NULL
        || !(*env)->IsInstanceOf(env, context, context_class)) {
        if (context_class != NULL) {
            (*env)->DeleteGlobalRef(env, context_class);
        }
        return -1;
    }
    get_application_context = routes_optional(env, context_class, "getApplicationContext",
        "()Landroid/content/Context;");
    get_system_service = routes_optional(env, context_class, "getSystemService",
        "(Ljava/lang/String;)Ljava/lang/Object;");
    if (get_application_context == NULL || get_system_service == NULL) {
        (*env)->DeleteGlobalRef(env, context_class);
        return -1;
    }
    application = (*env)->CallObjectMethod(env, context, get_application_context);
    if (routes_threw(env) || application == NULL) {
        application = (*env)->NewLocalRef(env, context);
    }
    name = (*env)->NewStringUTF(env, "audio");
    manager = name != NULL
        ? (*env)->CallObjectMethod(env, application, get_system_service, name) : NULL;
    if (routes_threw(env) || manager == NULL) {
        answer = -2;
    }
    if (name != NULL) {
        (*env)->DeleteLocalRef(env, name);
    }
    (*env)->DeleteLocalRef(env, application);
    (*env)->DeleteGlobalRef(env, context_class);
    if (answer != 0) {
        return answer;
    }

    pthread_mutex_lock(&routes_lock);
    if (routes_manager != NULL) {
        (*env)->DeleteGlobalRef(env, routes_manager);
        routes_manager = NULL;
    }
    if (routes_device_class == NULL) {
        routes_device_class = routes_class(env, "android/media/AudioDeviceInfo");
    }
    if (routes_list_class == NULL) {
        routes_list_class = routes_class(env, "java/util/List");
    }
    manager_class = (*env)->GetObjectClass(env, manager);
    char_sequence = routes_class(env, "java/lang/CharSequence");
    if (routes_device_class == NULL || routes_list_class == NULL || manager_class == NULL
        || char_sequence == NULL) {
        answer = -2;
    } else {
        routes_get_devices = routes_optional(env, manager_class, "getDevices",
            "(I)[Landroid/media/AudioDeviceInfo;");
        routes_get_communication_device = routes_optional(env, manager_class,
            "getCommunicationDevice", "()Landroid/media/AudioDeviceInfo;");
        routes_set_communication_device = routes_optional(env, manager_class,
            "setCommunicationDevice", "(Landroid/media/AudioDeviceInfo;)Z");
        routes_clear_communication_device = routes_optional(env, manager_class,
            "clearCommunicationDevice", "()V");
        routes_available_communication_devices = routes_optional(env, manager_class,
            "getAvailableCommunicationDevices", "()Ljava/util/List;");
        routes_is_speakerphone_on = routes_optional(env, manager_class, "isSpeakerphoneOn", "()Z");
        routes_set_speakerphone_on = routes_optional(env, manager_class, "setSpeakerphoneOn", "(Z)V");
        routes_is_bluetooth_sco_on = routes_optional(env, manager_class, "isBluetoothScoOn", "()Z");
        routes_set_bluetooth_sco_on = routes_optional(env, manager_class, "setBluetoothScoOn", "(Z)V");
        routes_start_bluetooth_sco = routes_optional(env, manager_class, "startBluetoothSco", "()V");
        routes_stop_bluetooth_sco = routes_optional(env, manager_class, "stopBluetoothSco", "()V");
        routes_device_id = routes_optional(env, routes_device_class, "getId", "()I");
        routes_device_type = routes_optional(env, routes_device_class, "getType", "()I");
        routes_device_is_source = routes_optional(env, routes_device_class, "isSource", "()Z");
        routes_device_is_sink = routes_optional(env, routes_device_class, "isSink", "()Z");
        routes_device_channel_counts = routes_optional(env, routes_device_class,
            "getChannelCounts", "()[I");
        routes_device_product = routes_optional(env, routes_device_class, "getProductName",
            "()Ljava/lang/CharSequence;");
        routes_device_address = routes_optional(env, routes_device_class, "getAddress",
            "()Ljava/lang/String;");
        routes_list_size = routes_optional(env, routes_list_class, "size", "()I");
        routes_list_get = routes_optional(env, routes_list_class, "get", "(I)Ljava/lang/Object;");
        routes_object_to_string = routes_optional(env, char_sequence, "toString",
            "()Ljava/lang/String;");
        if (routes_get_devices == NULL || routes_is_speakerphone_on == NULL
            || routes_set_speakerphone_on == NULL || routes_is_bluetooth_sco_on == NULL
            || routes_set_bluetooth_sco_on == NULL || routes_device_id == NULL
            || routes_device_type == NULL || routes_device_is_source == NULL
            || routes_device_is_sink == NULL || routes_device_channel_counts == NULL
            || routes_device_product == NULL || routes_list_size == NULL
            || routes_list_get == NULL || routes_object_to_string == NULL) {
            answer = -2;
        }
    }
    if (answer == 0) {
        if ((*env)->GetJavaVM(env, &routes_vm) != JNI_OK) {
            answer = -2;
        } else {
            routes_manager = (*env)->NewGlobalRef(env, manager);
            if (routes_manager == NULL) {
                answer = -2;
            }
        }
    }
    if (char_sequence != NULL) {
        (*env)->DeleteGlobalRef(env, char_sequence);
    }
    if (manager_class != NULL) {
        (*env)->DeleteLocalRef(env, manager_class);
    }
    pthread_mutex_unlock(&routes_lock);
    (*env)->DeleteLocalRef(env, manager);
    return answer;
}
