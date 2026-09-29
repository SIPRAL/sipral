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
static jclass jni_processor_callback_class;
static jmethodID jni_processor_callback_deliver;
static jclass jni_audio_transmit_callback_class;
static jmethodID jni_audio_transmit_callback_deliver;
static jclass jni_log_callback_class;
static jmethodID jni_log_callback_deliver;

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
        jni_event_callback_deliver = (*env)->GetStaticMethodID(env, jni_event_callback_class, "deliver", "(JJJJJJ[BJJJJJJJJJJJJ[B[BJ[B[B[B[BJJJ[BJ[B[BJJ[B[BJJJJJJJJJ[BJJJJJ[BJJJJJ[B[JJJJJJJJJJJJJJJ[BJJJJJJJJJJJJJJ[BJJJJJ[B[BJJJJJ[BJJJJ[B[B[BJJ[B[B[B[BJJ[B[BJJ[B[BJJJJJJ[B[BJJJJJJJ[B[B[B[BJJJJJJJJJJJJJJJJJJJJ[BJJJJJ[B[BJJJJJJJJJ[B)V");
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
    {
        jclass found = (*env)->FindClass(env, "org/sipral/SipralProcessorListeners");
        if (found == NULL) {
            return JNI_ERR;
        }
        jni_processor_callback_class = (jclass)(*env)->NewGlobalRef(env, found);
        (*env)->DeleteLocalRef(env, found);
        if (jni_processor_callback_class == NULL) {
            return JNI_ERR;
        }
        jni_processor_callback_deliver = (*env)->GetStaticMethodID(env, jni_processor_callback_class, "deliver", "(JJJ[S[S[S)V");
        if (jni_processor_callback_deliver == NULL) {
            return JNI_ERR;
        }
    }
    {
        jclass found = (*env)->FindClass(env, "org/sipral/SipralAudioTransmitListeners");
        if (found == NULL) {
            return JNI_ERR;
        }
        jni_audio_transmit_callback_class = (jclass)(*env)->NewGlobalRef(env, found);
        (*env)->DeleteLocalRef(env, found);
        if (jni_audio_transmit_callback_class == NULL) {
            return JNI_ERR;
        }
        jni_audio_transmit_callback_deliver = (*env)->GetStaticMethodID(env, jni_audio_transmit_callback_class, "deliver", "(JJJJ[B[B)V");
        if (jni_audio_transmit_callback_deliver == NULL) {
            return JNI_ERR;
        }
    }
    {
        jclass found = (*env)->FindClass(env, "org/sipral/SipralLogListeners");
        if (found == NULL) {
            return JNI_ERR;
        }
        jni_log_callback_class = (jclass)(*env)->NewGlobalRef(env, found);
        (*env)->DeleteLocalRef(env, found);
        if (jni_log_callback_class == NULL) {
            return JNI_ERR;
        }
        jni_log_callback_deliver = (*env)->GetStaticMethodID(env, jni_log_callback_class, "deliver", "(JJJJ[B[BJ)V");
        if (jni_log_callback_deliver == NULL) {
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
    if (jni_processor_callback_class != NULL) {
        (*env)->DeleteGlobalRef(env, jni_processor_callback_class);
        jni_processor_callback_class = NULL;
    }
    if (jni_audio_transmit_callback_class != NULL) {
        (*env)->DeleteGlobalRef(env, jni_audio_transmit_callback_class);
        jni_audio_transmit_callback_class = NULL;
    }
    if (jni_log_callback_class != NULL) {
        (*env)->DeleteGlobalRef(env, jni_log_callback_class);
        jni_log_callback_class = NULL;
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
    jbyteArray payloadCallLocalSdp = NULL;
    jbyteArray payloadCallRemoteSdp = NULL;
    jbyteArray payloadCallFromUri = NULL;
    jbyteArray payloadCallFromDisplay = NULL;
    jbyteArray payloadCallToUri = NULL;
    jbyteArray payloadCallCallId = NULL;
    jbyteArray payloadCallCauseText = NULL;
    jbyteArray payloadCallAssertedUri = NULL;
    jbyteArray payloadCallAssertedDisplay = NULL;
    jbyteArray payloadCallDivertedFrom = NULL;
    jbyteArray payloadCallDiversionReason = NULL;
    jbyteArray payloadCallAlertInfo = NULL;
    jbyteArray payloadTransferTarget = NULL;
    jbyteArray payloadMediaReason = NULL;
    jlongArray payloadMediaStatistics = NULL;
    jbyteArray payloadTransportWantedDestination = NULL;
    jbyteArray payloadResolveHost = NULL;
    jbyteArray payloadMessageContentType = NULL;
    jbyteArray payloadMessageBody = NULL;
    jbyteArray payloadMessageMessageAccount = NULL;
    jbyteArray payloadNatLocal = NULL;
    jbyteArray payloadNatMapped = NULL;
    jbyteArray payloadNatPrevious = NULL;
    jbyteArray payloadRelayLocal = NULL;
    jbyteArray payloadRelayRelayed = NULL;
    jbyteArray payloadRelayMapped = NULL;
    jbyteArray payloadRelayReason = NULL;
    jbyteArray payloadReferralTarget = NULL;
    jbyteArray payloadReferralReferredBy = NULL;
    jbyteArray payloadTurnStreamLocal = NULL;
    jbyteArray payloadTurnStreamServer = NULL;
    jbyteArray payloadStunServerServer = NULL;
    jbyteArray payloadStunServerPrevious = NULL;
    jbyteArray payloadVerificationCertificateUrl = NULL;
    jbyteArray payloadVerificationOrig = NULL;
    jbyteArray payloadVerificationOrigid = NULL;
    jbyteArray payloadVerificationDetail = NULL;
    jbyteArray payloadTextText = NULL;
    jbyteArray payloadPresenceEntity = NULL;
    jbyteArray payloadPresenceNote = NULL;
    jbyteArray payloadTransportFailedDetail = NULL;

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
    if (built && (event->kind == SIPRAL_EVENT_KIND_STARTED || event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL || event->kind == SIPRAL_EVENT_KIND_CALL_PROGRESS || event->kind == SIPRAL_EVENT_KIND_CALL_FORKED || event->kind == SIPRAL_EVENT_KIND_CALL_CONFIRMED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGED || event->kind == SIPRAL_EVENT_KIND_SESSION_OFFERED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED || event->kind == SIPRAL_EVENT_KIND_CALL_REPLACED || event->kind == SIPRAL_EVENT_KIND_CALL_ENDED || event->kind == SIPRAL_EVENT_KIND_DTMF_SENT || event->kind == SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED) && JNI_REACHES(event, sipral_event_t, payload.call.local_sdp_len) && event->payload.call.local_sdp != NULL) {
        payloadCallLocalSdp = (*env)->NewByteArray(env, (jsize)event->payload.call.local_sdp_len);
        if (payloadCallLocalSdp == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadCallLocalSdp, 0, (jsize)event->payload.call.local_sdp_len, (const jbyte *)event->payload.call.local_sdp);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_STARTED || event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL || event->kind == SIPRAL_EVENT_KIND_CALL_PROGRESS || event->kind == SIPRAL_EVENT_KIND_CALL_FORKED || event->kind == SIPRAL_EVENT_KIND_CALL_CONFIRMED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGED || event->kind == SIPRAL_EVENT_KIND_SESSION_OFFERED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED || event->kind == SIPRAL_EVENT_KIND_CALL_REPLACED || event->kind == SIPRAL_EVENT_KIND_CALL_ENDED || event->kind == SIPRAL_EVENT_KIND_DTMF_SENT || event->kind == SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED) && JNI_REACHES(event, sipral_event_t, payload.call.remote_sdp_len) && event->payload.call.remote_sdp != NULL) {
        payloadCallRemoteSdp = (*env)->NewByteArray(env, (jsize)event->payload.call.remote_sdp_len);
        if (payloadCallRemoteSdp == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadCallRemoteSdp, 0, (jsize)event->payload.call.remote_sdp_len, (const jbyte *)event->payload.call.remote_sdp);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_STARTED || event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL || event->kind == SIPRAL_EVENT_KIND_CALL_PROGRESS || event->kind == SIPRAL_EVENT_KIND_CALL_FORKED || event->kind == SIPRAL_EVENT_KIND_CALL_CONFIRMED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGED || event->kind == SIPRAL_EVENT_KIND_SESSION_OFFERED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED || event->kind == SIPRAL_EVENT_KIND_CALL_REPLACED || event->kind == SIPRAL_EVENT_KIND_CALL_ENDED || event->kind == SIPRAL_EVENT_KIND_DTMF_SENT || event->kind == SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED) && JNI_REACHES(event, sipral_event_t, payload.call.from_uri_len) && event->payload.call.from_uri != NULL) {
        payloadCallFromUri = (*env)->NewByteArray(env, (jsize)event->payload.call.from_uri_len);
        if (payloadCallFromUri == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadCallFromUri, 0, (jsize)event->payload.call.from_uri_len, (const jbyte *)event->payload.call.from_uri);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_STARTED || event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL || event->kind == SIPRAL_EVENT_KIND_CALL_PROGRESS || event->kind == SIPRAL_EVENT_KIND_CALL_FORKED || event->kind == SIPRAL_EVENT_KIND_CALL_CONFIRMED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGED || event->kind == SIPRAL_EVENT_KIND_SESSION_OFFERED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED || event->kind == SIPRAL_EVENT_KIND_CALL_REPLACED || event->kind == SIPRAL_EVENT_KIND_CALL_ENDED || event->kind == SIPRAL_EVENT_KIND_DTMF_SENT || event->kind == SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED) && JNI_REACHES(event, sipral_event_t, payload.call.from_display_len) && event->payload.call.from_display != NULL) {
        payloadCallFromDisplay = (*env)->NewByteArray(env, (jsize)event->payload.call.from_display_len);
        if (payloadCallFromDisplay == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadCallFromDisplay, 0, (jsize)event->payload.call.from_display_len, (const jbyte *)event->payload.call.from_display);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_STARTED || event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL || event->kind == SIPRAL_EVENT_KIND_CALL_PROGRESS || event->kind == SIPRAL_EVENT_KIND_CALL_FORKED || event->kind == SIPRAL_EVENT_KIND_CALL_CONFIRMED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGED || event->kind == SIPRAL_EVENT_KIND_SESSION_OFFERED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED || event->kind == SIPRAL_EVENT_KIND_CALL_REPLACED || event->kind == SIPRAL_EVENT_KIND_CALL_ENDED || event->kind == SIPRAL_EVENT_KIND_DTMF_SENT || event->kind == SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED) && JNI_REACHES(event, sipral_event_t, payload.call.to_uri_len) && event->payload.call.to_uri != NULL) {
        payloadCallToUri = (*env)->NewByteArray(env, (jsize)event->payload.call.to_uri_len);
        if (payloadCallToUri == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadCallToUri, 0, (jsize)event->payload.call.to_uri_len, (const jbyte *)event->payload.call.to_uri);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_STARTED || event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL || event->kind == SIPRAL_EVENT_KIND_CALL_PROGRESS || event->kind == SIPRAL_EVENT_KIND_CALL_FORKED || event->kind == SIPRAL_EVENT_KIND_CALL_CONFIRMED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGED || event->kind == SIPRAL_EVENT_KIND_SESSION_OFFERED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED || event->kind == SIPRAL_EVENT_KIND_CALL_REPLACED || event->kind == SIPRAL_EVENT_KIND_CALL_ENDED || event->kind == SIPRAL_EVENT_KIND_DTMF_SENT || event->kind == SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED) && JNI_REACHES(event, sipral_event_t, payload.call.call_id_len) && event->payload.call.call_id != NULL) {
        payloadCallCallId = (*env)->NewByteArray(env, (jsize)event->payload.call.call_id_len);
        if (payloadCallCallId == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadCallCallId, 0, (jsize)event->payload.call.call_id_len, (const jbyte *)event->payload.call.call_id);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_STARTED || event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL || event->kind == SIPRAL_EVENT_KIND_CALL_PROGRESS || event->kind == SIPRAL_EVENT_KIND_CALL_FORKED || event->kind == SIPRAL_EVENT_KIND_CALL_CONFIRMED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGED || event->kind == SIPRAL_EVENT_KIND_SESSION_OFFERED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED || event->kind == SIPRAL_EVENT_KIND_CALL_REPLACED || event->kind == SIPRAL_EVENT_KIND_CALL_ENDED || event->kind == SIPRAL_EVENT_KIND_DTMF_SENT || event->kind == SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED) && JNI_REACHES(event, sipral_event_t, payload.call.cause_text_len) && event->payload.call.cause_text != NULL) {
        payloadCallCauseText = (*env)->NewByteArray(env, (jsize)event->payload.call.cause_text_len);
        if (payloadCallCauseText == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadCallCauseText, 0, (jsize)event->payload.call.cause_text_len, (const jbyte *)event->payload.call.cause_text);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_STARTED || event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL || event->kind == SIPRAL_EVENT_KIND_CALL_PROGRESS || event->kind == SIPRAL_EVENT_KIND_CALL_FORKED || event->kind == SIPRAL_EVENT_KIND_CALL_CONFIRMED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGED || event->kind == SIPRAL_EVENT_KIND_SESSION_OFFERED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED || event->kind == SIPRAL_EVENT_KIND_CALL_REPLACED || event->kind == SIPRAL_EVENT_KIND_CALL_ENDED || event->kind == SIPRAL_EVENT_KIND_DTMF_SENT || event->kind == SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED) && JNI_REACHES(event, sipral_event_t, payload.call.asserted_uri_len) && event->payload.call.asserted_uri != NULL) {
        payloadCallAssertedUri = (*env)->NewByteArray(env, (jsize)event->payload.call.asserted_uri_len);
        if (payloadCallAssertedUri == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadCallAssertedUri, 0, (jsize)event->payload.call.asserted_uri_len, (const jbyte *)event->payload.call.asserted_uri);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_STARTED || event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL || event->kind == SIPRAL_EVENT_KIND_CALL_PROGRESS || event->kind == SIPRAL_EVENT_KIND_CALL_FORKED || event->kind == SIPRAL_EVENT_KIND_CALL_CONFIRMED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGED || event->kind == SIPRAL_EVENT_KIND_SESSION_OFFERED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED || event->kind == SIPRAL_EVENT_KIND_CALL_REPLACED || event->kind == SIPRAL_EVENT_KIND_CALL_ENDED || event->kind == SIPRAL_EVENT_KIND_DTMF_SENT || event->kind == SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED) && JNI_REACHES(event, sipral_event_t, payload.call.asserted_display_len) && event->payload.call.asserted_display != NULL) {
        payloadCallAssertedDisplay = (*env)->NewByteArray(env, (jsize)event->payload.call.asserted_display_len);
        if (payloadCallAssertedDisplay == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadCallAssertedDisplay, 0, (jsize)event->payload.call.asserted_display_len, (const jbyte *)event->payload.call.asserted_display);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_STARTED || event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL || event->kind == SIPRAL_EVENT_KIND_CALL_PROGRESS || event->kind == SIPRAL_EVENT_KIND_CALL_FORKED || event->kind == SIPRAL_EVENT_KIND_CALL_CONFIRMED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGED || event->kind == SIPRAL_EVENT_KIND_SESSION_OFFERED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED || event->kind == SIPRAL_EVENT_KIND_CALL_REPLACED || event->kind == SIPRAL_EVENT_KIND_CALL_ENDED || event->kind == SIPRAL_EVENT_KIND_DTMF_SENT || event->kind == SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED) && JNI_REACHES(event, sipral_event_t, payload.call.diverted_from_len) && event->payload.call.diverted_from != NULL) {
        payloadCallDivertedFrom = (*env)->NewByteArray(env, (jsize)event->payload.call.diverted_from_len);
        if (payloadCallDivertedFrom == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadCallDivertedFrom, 0, (jsize)event->payload.call.diverted_from_len, (const jbyte *)event->payload.call.diverted_from);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_STARTED || event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL || event->kind == SIPRAL_EVENT_KIND_CALL_PROGRESS || event->kind == SIPRAL_EVENT_KIND_CALL_FORKED || event->kind == SIPRAL_EVENT_KIND_CALL_CONFIRMED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGED || event->kind == SIPRAL_EVENT_KIND_SESSION_OFFERED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED || event->kind == SIPRAL_EVENT_KIND_CALL_REPLACED || event->kind == SIPRAL_EVENT_KIND_CALL_ENDED || event->kind == SIPRAL_EVENT_KIND_DTMF_SENT || event->kind == SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED) && JNI_REACHES(event, sipral_event_t, payload.call.diversion_reason_len) && event->payload.call.diversion_reason != NULL) {
        payloadCallDiversionReason = (*env)->NewByteArray(env, (jsize)event->payload.call.diversion_reason_len);
        if (payloadCallDiversionReason == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadCallDiversionReason, 0, (jsize)event->payload.call.diversion_reason_len, (const jbyte *)event->payload.call.diversion_reason);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_STARTED || event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL || event->kind == SIPRAL_EVENT_KIND_CALL_PROGRESS || event->kind == SIPRAL_EVENT_KIND_CALL_FORKED || event->kind == SIPRAL_EVENT_KIND_CALL_CONFIRMED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGED || event->kind == SIPRAL_EVENT_KIND_SESSION_OFFERED || event->kind == SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED || event->kind == SIPRAL_EVENT_KIND_CALL_REPLACED || event->kind == SIPRAL_EVENT_KIND_CALL_ENDED || event->kind == SIPRAL_EVENT_KIND_DTMF_SENT || event->kind == SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED) && JNI_REACHES(event, sipral_event_t, payload.call.alert_info_len) && event->payload.call.alert_info != NULL) {
        payloadCallAlertInfo = (*env)->NewByteArray(env, (jsize)event->payload.call.alert_info_len);
        if (payloadCallAlertInfo == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadCallAlertInfo, 0, (jsize)event->payload.call.alert_info_len, (const jbyte *)event->payload.call.alert_info);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_TRANSFER_REQUESTED || event->kind == SIPRAL_EVENT_KIND_TRANSFER_PROGRESS || event->kind == SIPRAL_EVENT_KIND_TRANSFER_DONE) && JNI_REACHES(event, sipral_event_t, payload.transfer.target_len) && event->payload.transfer.target != NULL) {
        payloadTransferTarget = (*env)->NewByteArray(env, (jsize)event->payload.transfer.target_len);
        if (payloadTransferTarget == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadTransferTarget, 0, (jsize)event->payload.transfer.target_len, (const jbyte *)event->payload.transfer.target);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_MEDIA_STATISTICS || event->kind == SIPRAL_EVENT_KIND_MEDIA_STALLED || event->kind == SIPRAL_EVENT_KIND_MEDIA_STARTED || event->kind == SIPRAL_EVENT_KIND_MEDIA_CHANGED || event->kind == SIPRAL_EVENT_KIND_MEDIA_RESUMED || event->kind == SIPRAL_EVENT_KIND_MEDIA_FAILED || event->kind == SIPRAL_EVENT_KIND_RECORDING_STOPPED || event->kind == SIPRAL_EVENT_KIND_DIGIT_RECEIVED || event->kind == SIPRAL_EVENT_KIND_MEDIA_SECURED || event->kind == SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN || event->kind == SIPRAL_EVENT_KIND_QUALITY_REPORT_SENT || event->kind == SIPRAL_EVENT_KIND_MEDIA_UNJOINED || event->kind == SIPRAL_EVENT_KIND_IN_BAND_DIGIT) && JNI_REACHES(event, sipral_event_t, payload.media.reason_len) && event->payload.media.reason != NULL) {
        payloadMediaReason = (*env)->NewByteArray(env, (jsize)event->payload.media.reason_len);
        if (payloadMediaReason == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadMediaReason, 0, (jsize)event->payload.media.reason_len, (const jbyte *)event->payload.media.reason);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_MEDIA_STATISTICS || event->kind == SIPRAL_EVENT_KIND_MEDIA_STALLED || event->kind == SIPRAL_EVENT_KIND_MEDIA_STARTED || event->kind == SIPRAL_EVENT_KIND_MEDIA_CHANGED || event->kind == SIPRAL_EVENT_KIND_MEDIA_RESUMED || event->kind == SIPRAL_EVENT_KIND_MEDIA_FAILED || event->kind == SIPRAL_EVENT_KIND_RECORDING_STOPPED || event->kind == SIPRAL_EVENT_KIND_DIGIT_RECEIVED || event->kind == SIPRAL_EVENT_KIND_MEDIA_SECURED || event->kind == SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN || event->kind == SIPRAL_EVENT_KIND_QUALITY_REPORT_SENT || event->kind == SIPRAL_EVENT_KIND_MEDIA_UNJOINED || event->kind == SIPRAL_EVENT_KIND_IN_BAND_DIGIT) && JNI_REACHES(event, sipral_event_t, payload.media.statistics) && event->payload.media.statistics != NULL) {
        payloadMediaStatistics = (*env)->NewLongArray(env, 49);
        if (payloadMediaStatistics == NULL) {
            built = 0;
        } else {
            jlong slots[49];
            slots[0] = (jlong)event->payload.media.statistics->size;
            slots[1] = (jlong)event->payload.media.statistics->codec;
            slots[2] = (jlong)event->payload.media.statistics->has_round_trip;
            slots[3] = (jlong)event->payload.media.statistics->round_trip_us;
            slots[4] = (jlong)event->payload.media.statistics->packets_sent;
            slots[5] = (jlong)event->payload.media.statistics->octets_sent;
            slots[6] = (jlong)event->payload.media.statistics->packets_received;
            slots[7] = (jlong)event->payload.media.statistics->packets_lost;
            slots[8] = (jlong)event->payload.media.statistics->packets_late;
            slots[9] = (jlong)event->payload.media.statistics->packets_overflowed;
            slots[10] = (jlong)event->payload.media.statistics->packets_duplicated;
            slots[11] = (jlong)event->payload.media.statistics->packets_reordered;
            slots[12] = (jlong)event->payload.media.statistics->frames_shrunk;
            slots[13] = (jlong)event->payload.media.statistics->frames_stretched;
            slots[14] = (jlong)event->payload.media.statistics->delay_us;
            slots[15] = (jlong)event->payload.media.statistics->target_delay_us;
            slots[16] = (jlong)event->payload.media.statistics->jitter_us;
            {
                uint32_t bits;
                memcpy(&bits, &event->payload.media.statistics->loss_rate, sizeof bits);
                slots[17] = (jlong)bits;
            }
            {
                uint32_t bits;
                memcpy(&bits, &event->payload.media.statistics->score, sizeof bits);
                slots[18] = (jlong)bits;
            }
            slots[19] = (jlong)event->payload.media.statistics->suffering;
            slots[20] = (jlong)event->payload.media.statistics->silent_for_ms;
            slots[21] = (jlong)event->payload.media.statistics->has_voip_metrics;
            slots[22] = (jlong)event->payload.media.statistics->voip_loss_rate_256;
            slots[23] = (jlong)event->payload.media.statistics->voip_discard_rate_256;
            slots[24] = (jlong)event->payload.media.statistics->voip_burst_density_256;
            slots[25] = (jlong)event->payload.media.statistics->voip_burst_duration_us;
            slots[26] = (jlong)event->payload.media.statistics->voip_gap_density_256;
            slots[27] = (jlong)event->payload.media.statistics->voip_gap_duration_us;
            slots[28] = (jlong)event->payload.media.statistics->voip_gmin;
            slots[29] = (jlong)event->payload.media.statistics->voip_end_system_delay_us;
            slots[30] = (jlong)event->payload.media.statistics->voip_jitter_buffer_nominal_us;
            slots[31] = (jlong)event->payload.media.statistics->voip_jitter_buffer_maximum_us;
            slots[32] = (jlong)event->payload.media.statistics->voip_jitter_buffer_abs_max_us;
            slots[33] = (jlong)event->payload.media.statistics->has_voip_r_factor;
            slots[34] = (jlong)event->payload.media.statistics->voip_r_factor;
            slots[35] = (jlong)event->payload.media.statistics->has_voip_mos_lq;
            slots[36] = (jlong)event->payload.media.statistics->voip_mos_lq_x10;
            slots[37] = (jlong)event->payload.media.statistics->has_voip_mos_cq;
            slots[38] = (jlong)event->payload.media.statistics->voip_mos_cq_x10;
            slots[39] = (jlong)event->payload.media.statistics->frames_underrun;
            slots[40] = (jlong)event->payload.media.statistics->feedback;
            slots[41] = (jlong)event->payload.media.statistics->trr_interval_ms;
            slots[42] = (jlong)event->payload.media.statistics->nacks_sent;
            slots[43] = (jlong)event->payload.media.statistics->packets_nacked;
            slots[44] = (jlong)event->payload.media.statistics->nacks_received;
            slots[45] = (jlong)event->payload.media.statistics->packets_asked_for;
            slots[46] = (jlong)event->payload.media.statistics->early_packets;
            slots[47] = (jlong)event->payload.media.statistics->reduced_size_packets;
            slots[48] = (jlong)event->payload.media.statistics->feedback_suppressed;
            (*env)->SetLongArrayRegion(env, payloadMediaStatistics, 0, 49, slots);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_TRANSPORT_WANTED) && JNI_REACHES(event, sipral_event_t, payload.transport_wanted.destination_len) && event->payload.transport_wanted.destination != NULL) {
        payloadTransportWantedDestination = (*env)->NewByteArray(env, (jsize)event->payload.transport_wanted.destination_len);
        if (payloadTransportWantedDestination == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadTransportWantedDestination, 0, (jsize)event->payload.transport_wanted.destination_len, (const jbyte *)event->payload.transport_wanted.destination);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_RESOLVE_NEEDED) && JNI_REACHES(event, sipral_event_t, payload.resolve.host_len) && event->payload.resolve.host != NULL) {
        payloadResolveHost = (*env)->NewByteArray(env, (jsize)event->payload.resolve.host_len);
        if (payloadResolveHost == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadResolveHost, 0, (jsize)event->payload.resolve.host_len, (const jbyte *)event->payload.resolve.host);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_MESSAGE_RECEIVED || event->kind == SIPRAL_EVENT_KIND_MESSAGE_SENT || event->kind == SIPRAL_EVENT_KIND_MESSAGES_WAITING) && JNI_REACHES(event, sipral_event_t, payload.message.content_type_len) && event->payload.message.content_type != NULL) {
        payloadMessageContentType = (*env)->NewByteArray(env, (jsize)event->payload.message.content_type_len);
        if (payloadMessageContentType == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadMessageContentType, 0, (jsize)event->payload.message.content_type_len, (const jbyte *)event->payload.message.content_type);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_MESSAGE_RECEIVED || event->kind == SIPRAL_EVENT_KIND_MESSAGE_SENT || event->kind == SIPRAL_EVENT_KIND_MESSAGES_WAITING) && JNI_REACHES(event, sipral_event_t, payload.message.body_len) && event->payload.message.body != NULL) {
        payloadMessageBody = (*env)->NewByteArray(env, (jsize)event->payload.message.body_len);
        if (payloadMessageBody == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadMessageBody, 0, (jsize)event->payload.message.body_len, (const jbyte *)event->payload.message.body);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_MESSAGE_RECEIVED || event->kind == SIPRAL_EVENT_KIND_MESSAGE_SENT || event->kind == SIPRAL_EVENT_KIND_MESSAGES_WAITING) && JNI_REACHES(event, sipral_event_t, payload.message.message_account_len) && event->payload.message.message_account != NULL) {
        payloadMessageMessageAccount = (*env)->NewByteArray(env, (jsize)event->payload.message.message_account_len);
        if (payloadMessageMessageAccount == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadMessageMessageAccount, 0, (jsize)event->payload.message.message_account_len, (const jbyte *)event->payload.message.message_account);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_NAT_MAPPING) && JNI_REACHES(event, sipral_event_t, payload.nat.local_len) && event->payload.nat.local != NULL) {
        payloadNatLocal = (*env)->NewByteArray(env, (jsize)event->payload.nat.local_len);
        if (payloadNatLocal == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadNatLocal, 0, (jsize)event->payload.nat.local_len, (const jbyte *)event->payload.nat.local);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_NAT_MAPPING) && JNI_REACHES(event, sipral_event_t, payload.nat.mapped_len) && event->payload.nat.mapped != NULL) {
        payloadNatMapped = (*env)->NewByteArray(env, (jsize)event->payload.nat.mapped_len);
        if (payloadNatMapped == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadNatMapped, 0, (jsize)event->payload.nat.mapped_len, (const jbyte *)event->payload.nat.mapped);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_NAT_MAPPING) && JNI_REACHES(event, sipral_event_t, payload.nat.previous_len) && event->payload.nat.previous != NULL) {
        payloadNatPrevious = (*env)->NewByteArray(env, (jsize)event->payload.nat.previous_len);
        if (payloadNatPrevious == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadNatPrevious, 0, (jsize)event->payload.nat.previous_len, (const jbyte *)event->payload.nat.previous);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_NAT_RELAY) && JNI_REACHES(event, sipral_event_t, payload.relay.local_len) && event->payload.relay.local != NULL) {
        payloadRelayLocal = (*env)->NewByteArray(env, (jsize)event->payload.relay.local_len);
        if (payloadRelayLocal == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadRelayLocal, 0, (jsize)event->payload.relay.local_len, (const jbyte *)event->payload.relay.local);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_NAT_RELAY) && JNI_REACHES(event, sipral_event_t, payload.relay.relayed_len) && event->payload.relay.relayed != NULL) {
        payloadRelayRelayed = (*env)->NewByteArray(env, (jsize)event->payload.relay.relayed_len);
        if (payloadRelayRelayed == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadRelayRelayed, 0, (jsize)event->payload.relay.relayed_len, (const jbyte *)event->payload.relay.relayed);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_NAT_RELAY) && JNI_REACHES(event, sipral_event_t, payload.relay.mapped_len) && event->payload.relay.mapped != NULL) {
        payloadRelayMapped = (*env)->NewByteArray(env, (jsize)event->payload.relay.mapped_len);
        if (payloadRelayMapped == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadRelayMapped, 0, (jsize)event->payload.relay.mapped_len, (const jbyte *)event->payload.relay.mapped);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_NAT_RELAY) && JNI_REACHES(event, sipral_event_t, payload.relay.reason_len) && event->payload.relay.reason != NULL) {
        payloadRelayReason = (*env)->NewByteArray(env, (jsize)event->payload.relay.reason_len);
        if (payloadRelayReason == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadRelayReason, 0, (jsize)event->payload.relay.reason_len, (const jbyte *)event->payload.relay.reason);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_REFERRAL) && JNI_REACHES(event, sipral_event_t, payload.referral.target_len) && event->payload.referral.target != NULL) {
        payloadReferralTarget = (*env)->NewByteArray(env, (jsize)event->payload.referral.target_len);
        if (payloadReferralTarget == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadReferralTarget, 0, (jsize)event->payload.referral.target_len, (const jbyte *)event->payload.referral.target);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_REFERRAL) && JNI_REACHES(event, sipral_event_t, payload.referral.referred_by_len) && event->payload.referral.referred_by != NULL) {
        payloadReferralReferredBy = (*env)->NewByteArray(env, (jsize)event->payload.referral.referred_by_len);
        if (payloadReferralReferredBy == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadReferralReferredBy, 0, (jsize)event->payload.referral.referred_by_len, (const jbyte *)event->payload.referral.referred_by);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_TURN_STREAM) && JNI_REACHES(event, sipral_event_t, payload.turn_stream.local_len) && event->payload.turn_stream.local != NULL) {
        payloadTurnStreamLocal = (*env)->NewByteArray(env, (jsize)event->payload.turn_stream.local_len);
        if (payloadTurnStreamLocal == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadTurnStreamLocal, 0, (jsize)event->payload.turn_stream.local_len, (const jbyte *)event->payload.turn_stream.local);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_TURN_STREAM) && JNI_REACHES(event, sipral_event_t, payload.turn_stream.server_len) && event->payload.turn_stream.server != NULL) {
        payloadTurnStreamServer = (*env)->NewByteArray(env, (jsize)event->payload.turn_stream.server_len);
        if (payloadTurnStreamServer == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadTurnStreamServer, 0, (jsize)event->payload.turn_stream.server_len, (const jbyte *)event->payload.turn_stream.server);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_STUN_SERVER) && JNI_REACHES(event, sipral_event_t, payload.stun_server.server_len) && event->payload.stun_server.server != NULL) {
        payloadStunServerServer = (*env)->NewByteArray(env, (jsize)event->payload.stun_server.server_len);
        if (payloadStunServerServer == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadStunServerServer, 0, (jsize)event->payload.stun_server.server_len, (const jbyte *)event->payload.stun_server.server);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_STUN_SERVER) && JNI_REACHES(event, sipral_event_t, payload.stun_server.previous_len) && event->payload.stun_server.previous != NULL) {
        payloadStunServerPrevious = (*env)->NewByteArray(env, (jsize)event->payload.stun_server.previous_len);
        if (payloadStunServerPrevious == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadStunServerPrevious, 0, (jsize)event->payload.stun_server.previous_len, (const jbyte *)event->payload.stun_server.previous);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_CALLER_VERIFICATION) && JNI_REACHES(event, sipral_event_t, payload.verification.certificate_url_len) && event->payload.verification.certificate_url != NULL) {
        payloadVerificationCertificateUrl = (*env)->NewByteArray(env, (jsize)event->payload.verification.certificate_url_len);
        if (payloadVerificationCertificateUrl == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadVerificationCertificateUrl, 0, (jsize)event->payload.verification.certificate_url_len, (const jbyte *)event->payload.verification.certificate_url);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_CALLER_VERIFICATION) && JNI_REACHES(event, sipral_event_t, payload.verification.orig_len) && event->payload.verification.orig != NULL) {
        payloadVerificationOrig = (*env)->NewByteArray(env, (jsize)event->payload.verification.orig_len);
        if (payloadVerificationOrig == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadVerificationOrig, 0, (jsize)event->payload.verification.orig_len, (const jbyte *)event->payload.verification.orig);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_CALLER_VERIFICATION) && JNI_REACHES(event, sipral_event_t, payload.verification.origid_len) && event->payload.verification.origid != NULL) {
        payloadVerificationOrigid = (*env)->NewByteArray(env, (jsize)event->payload.verification.origid_len);
        if (payloadVerificationOrigid == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadVerificationOrigid, 0, (jsize)event->payload.verification.origid_len, (const jbyte *)event->payload.verification.origid);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_CALLER_VERIFICATION) && JNI_REACHES(event, sipral_event_t, payload.verification.detail_len) && event->payload.verification.detail != NULL) {
        payloadVerificationDetail = (*env)->NewByteArray(env, (jsize)event->payload.verification.detail_len);
        if (payloadVerificationDetail == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadVerificationDetail, 0, (jsize)event->payload.verification.detail_len, (const jbyte *)event->payload.verification.detail);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_TEXT_RECEIVED) && JNI_REACHES(event, sipral_event_t, payload.text.text_len) && event->payload.text.text != NULL) {
        payloadTextText = (*env)->NewByteArray(env, (jsize)event->payload.text.text_len);
        if (payloadTextText == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadTextText, 0, (jsize)event->payload.text.text_len, (const jbyte *)event->payload.text.text);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_PRESENCE_CHANGED) && JNI_REACHES(event, sipral_event_t, payload.presence.entity_len) && event->payload.presence.entity != NULL) {
        payloadPresenceEntity = (*env)->NewByteArray(env, (jsize)event->payload.presence.entity_len);
        if (payloadPresenceEntity == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadPresenceEntity, 0, (jsize)event->payload.presence.entity_len, (const jbyte *)event->payload.presence.entity);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_PRESENCE_CHANGED) && JNI_REACHES(event, sipral_event_t, payload.presence.note_len) && event->payload.presence.note != NULL) {
        payloadPresenceNote = (*env)->NewByteArray(env, (jsize)event->payload.presence.note_len);
        if (payloadPresenceNote == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadPresenceNote, 0, (jsize)event->payload.presence.note_len, (const jbyte *)event->payload.presence.note);
        }
    }
    if (built && (event->kind == SIPRAL_EVENT_KIND_TRANSPORT_FAILED) && JNI_REACHES(event, sipral_event_t, payload.transport_failed.detail_len) && event->payload.transport_failed.detail != NULL) {
        payloadTransportFailedDetail = (*env)->NewByteArray(env, (jsize)event->payload.transport_failed.detail_len);
        if (payloadTransportFailedDetail == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payloadTransportFailedDetail, 0, (jsize)event->payload.transport_failed.detail_len, (const jbyte *)event->payload.transport_failed.detail);
        }
    }
    if (built) {
        (*env)->CallStaticVoidMethod(env, jni_event_callback_class, jni_event_callback_deliver, (jlong)(intptr_t)user_data, (jlong)event->size, JNI_REACHES(event, sipral_event_t, stack) ? (jlong)event->stack : 0, JNI_REACHES(event, sipral_event_t, kind) ? (jlong)event->kind : 0, JNI_REACHES(event, sipral_event_t, account) ? (jlong)event->account : 0, JNI_REACHES(event, sipral_event_t, call) ? (jlong)event->call : 0, message, JNI_REACHES(event, sipral_event_t, payload.registration.state) ? (jlong)event->payload.registration.state : 0, JNI_REACHES(event, sipral_event_t, payload.registration.failure) ? (jlong)event->payload.registration.failure : 0, JNI_REACHES(event, sipral_event_t, payload.registration.status_code) ? (jlong)event->payload.registration.status_code : 0, JNI_REACHES(event, sipral_event_t, payload.registration.expires_ms) ? (jlong)event->payload.registration.expires_ms : 0, JNI_REACHES(event, sipral_event_t, payload.registration.refresh_in_ms) ? (jlong)event->payload.registration.refresh_in_ms : 0, JNI_REACHES(event, sipral_event_t, payload.registration.retry_in_ms) ? (jlong)event->payload.registration.retry_in_ms : 0, JNI_REACHES(event, sipral_event_t, payload.call.state) ? (jlong)event->payload.call.state : 0, JNI_REACHES(event, sipral_event_t, payload.call.end_reason) ? (jlong)event->payload.call.end_reason : 0, JNI_REACHES(event, sipral_event_t, payload.call.status_code) ? (jlong)event->payload.call.status_code : 0, JNI_REACHES(event, sipral_event_t, payload.call.other) ? (jlong)event->payload.call.other : 0, JNI_REACHES(event, sipral_event_t, payload.call.held_here) ? (jlong)event->payload.call.held_here : 0, JNI_REACHES(event, sipral_event_t, payload.call.held_there) ? (jlong)event->payload.call.held_there : 0, payloadCallLocalSdp, payloadCallRemoteSdp, JNI_REACHES(event, sipral_event_t, payload.call.retry_in_ms) ? (jlong)event->payload.call.retry_in_ms : 0, payloadCallFromUri, payloadCallFromDisplay, payloadCallToUri, payloadCallCallId, JNI_REACHES(event, sipral_event_t, payload.call.digit) ? (jlong)event->payload.call.digit : 0, JNI_REACHES(event, sipral_event_t, payload.call.cause_sip) ? (jlong)event->payload.call.cause_sip : 0, JNI_REACHES(event, sipral_event_t, payload.call.cause_q850) ? (jlong)event->payload.call.cause_q850 : 0, payloadCallCauseText, JNI_REACHES(event, sipral_event_t, payload.call.identity_trusted) ? (jlong)event->payload.call.identity_trusted : 0, payloadCallAssertedUri, payloadCallAssertedDisplay, JNI_REACHES(event, sipral_event_t, payload.call.verstat) ? (jlong)event->payload.call.verstat : 0, JNI_REACHES(event, sipral_event_t, payload.call.privacy) ? (jlong)event->payload.call.privacy : 0, payloadCallDivertedFrom, payloadCallDiversionReason, JNI_REACHES(event, sipral_event_t, payload.call.diversion_count) ? (jlong)event->payload.call.diversion_count : 0, JNI_REACHES(event, sipral_event_t, payload.call.history_count) ? (jlong)event->payload.call.history_count : 0, JNI_REACHES(event, sipral_event_t, payload.call.answer_mode) ? (jlong)event->payload.call.answer_mode : 0, JNI_REACHES(event, sipral_event_t, payload.call.answer_mode_required) ? (jlong)event->payload.call.answer_mode_required : 0, JNI_REACHES(event, sipral_event_t, payload.call.priv_answer_mode) ? (jlong)event->payload.call.priv_answer_mode : 0, JNI_REACHES(event, sipral_event_t, payload.call.priv_answer_mode_required) ? (jlong)event->payload.call.priv_answer_mode_required : 0, JNI_REACHES(event, sipral_event_t, payload.call.has_answer_after) ? (jlong)event->payload.call.has_answer_after : 0, JNI_REACHES(event, sipral_event_t, payload.call.answer_after_ms) ? (jlong)event->payload.call.answer_after_ms : 0, JNI_REACHES(event, sipral_event_t, payload.call.ring_source) ? (jlong)event->payload.call.ring_source : 0, payloadCallAlertInfo, JNI_REACHES(event, sipral_event_t, payload.call.verification) ? (jlong)event->payload.call.verification : 0, JNI_REACHES(event, sipral_event_t, payload.call.attestation) ? (jlong)event->payload.call.attestation : 0, JNI_REACHES(event, sipral_event_t, payload.call.verification_failure) ? (jlong)event->payload.call.verification_failure : 0, JNI_REACHES(event, sipral_event_t, payload.transfer.status_code) ? (jlong)event->payload.transfer.status_code : 0, JNI_REACHES(event, sipral_event_t, payload.transfer.attended) ? (jlong)event->payload.transfer.attended : 0, payloadTransferTarget, JNI_REACHES(event, sipral_event_t, payload.media.codec) ? (jlong)event->payload.media.codec : 0, JNI_REACHES(event, sipral_event_t, payload.media.direction) ? (jlong)event->payload.media.direction : 0, JNI_REACHES(event, sipral_event_t, payload.media.silent_for_ms) ? (jlong)event->payload.media.silent_for_ms : 0, JNI_REACHES(event, sipral_event_t, payload.media.recorded_ms) ? (jlong)event->payload.media.recorded_ms : 0, JNI_REACHES(event, sipral_event_t, payload.media.fault) ? (jlong)event->payload.media.fault : 0, payloadMediaReason, payloadMediaStatistics, JNI_REACHES(event, sipral_event_t, payload.media.digit) ? (jlong)event->payload.media.digit : 0, JNI_REACHES(event, sipral_event_t, payload.media.event_code) ? (jlong)event->payload.media.event_code : 0, JNI_REACHES(event, sipral_event_t, payload.media.held_ms) ? (jlong)event->payload.media.held_ms : 0, JNI_REACHES(event, sipral_event_t, payload.media.suite) ? (jlong)event->payload.media.suite : 0, JNI_REACHES(event, sipral_event_t, payload.media.source) ? (jlong)event->payload.media.source : 0, JNI_REACHES(event, sipral_event_t, payload.media.quality_report_sent) ? (jlong)event->payload.media.quality_report_sent : 0, JNI_REACHES(event, sipral_event_t, payload.media.key_exchange) ? (jlong)event->payload.media.key_exchange : 0, JNI_REACHES(event, sipral_event_t, payload.media.encrypted) ? (jlong)event->payload.media.encrypted : 0, JNI_REACHES(event, sipral_event_t, payload.media.authenticated) ? (jlong)event->payload.media.authenticated : 0, JNI_REACHES(event, sipral_event_t, payload.recovery.state) ? (jlong)event->payload.recovery.state : 0, JNI_REACHES(event, sipral_event_t, payload.recovery.rung) ? (jlong)event->payload.recovery.rung : 0, JNI_REACHES(event, sipral_event_t, payload.recovery.reason) ? (jlong)event->payload.recovery.reason : 0, JNI_REACHES(event, sipral_event_t, payload.recovery.unverified) ? (jlong)event->payload.recovery.unverified : 0, JNI_REACHES(event, sipral_event_t, payload.transport_wanted.protocol) ? (jlong)event->payload.transport_wanted.protocol : 0, payloadTransportWantedDestination, JNI_REACHES(event, sipral_event_t, payload.transport_wanted.request_bytes) ? (jlong)event->payload.transport_wanted.request_bytes : 0, JNI_REACHES(event, sipral_event_t, payload.transport_wanted.limit_bytes) ? (jlong)event->payload.transport_wanted.limit_bytes : 0, JNI_REACHES(event, sipral_event_t, payload.subscription.subscription) ? (jlong)event->payload.subscription.subscription : 0, JNI_REACHES(event, sipral_event_t, payload.subscription.state) ? (jlong)event->payload.subscription.state : 0, JNI_REACHES(event, sipral_event_t, payload.subscription.reason) ? (jlong)event->payload.subscription.reason : 0, JNI_REACHES(event, sipral_event_t, payload.subscription.status_code) ? (jlong)event->payload.subscription.status_code : 0, JNI_REACHES(event, sipral_event_t, payload.subscription.has_dialog_info) ? (jlong)event->payload.subscription.has_dialog_info : 0, JNI_REACHES(event, sipral_event_t, payload.subscription.expires_ms) ? (jlong)event->payload.subscription.expires_ms : 0, JNI_REACHES(event, sipral_event_t, payload.subscription.refresh_in_ms) ? (jlong)event->payload.subscription.refresh_in_ms : 0, JNI_REACHES(event, sipral_event_t, payload.subscription.retry_in_ms) ? (jlong)event->payload.subscription.retry_in_ms : 0, JNI_REACHES(event, sipral_event_t, payload.subscription.forked_from) ? (jlong)event->payload.subscription.forked_from : 0, JNI_REACHES(event, sipral_event_t, payload.announce.announcement) ? (jlong)event->payload.announce.announcement : 0, JNI_REACHES(event, sipral_event_t, payload.announce.waited_ms) ? (jlong)event->payload.announce.waited_ms : 0, JNI_REACHES(event, sipral_event_t, payload.resolve.dialog) ? (jlong)event->payload.resolve.dialog : 0, payloadResolveHost, JNI_REACHES(event, sipral_event_t, payload.resolve.port) ? (jlong)event->payload.resolve.port : 0, JNI_REACHES(event, sipral_event_t, payload.resolve.protocol) ? (jlong)event->payload.resolve.protocol : 0, JNI_REACHES(event, sipral_event_t, payload.message.message) ? (jlong)event->payload.message.message : 0, JNI_REACHES(event, sipral_event_t, payload.message.subscription) ? (jlong)event->payload.message.subscription : 0, JNI_REACHES(event, sipral_event_t, payload.message.status_code) ? (jlong)event->payload.message.status_code : 0, payloadMessageContentType, payloadMessageBody, JNI_REACHES(event, sipral_event_t, payload.message.waiting) ? (jlong)event->payload.message.waiting : 0, JNI_REACHES(event, sipral_event_t, payload.message.new_messages) ? (jlong)event->payload.message.new_messages : 0, JNI_REACHES(event, sipral_event_t, payload.message.old_messages) ? (jlong)event->payload.message.old_messages : 0, JNI_REACHES(event, sipral_event_t, payload.message.urgent_new_messages) ? (jlong)event->payload.message.urgent_new_messages : 0, JNI_REACHES(event, sipral_event_t, payload.message.urgent_old_messages) ? (jlong)event->payload.message.urgent_old_messages : 0, payloadMessageMessageAccount, JNI_REACHES(event, sipral_event_t, payload.nat.mapping) ? (jlong)event->payload.nat.mapping : 0, JNI_REACHES(event, sipral_event_t, payload.nat.signalling) ? (jlong)event->payload.nat.signalling : 0, JNI_REACHES(event, sipral_event_t, payload.nat.transport) ? (jlong)event->payload.nat.transport : 0, JNI_REACHES(event, sipral_event_t, payload.nat.accounts) ? (jlong)event->payload.nat.accounts : 0, payloadNatLocal, payloadNatMapped, payloadNatPrevious, JNI_REACHES(event, sipral_event_t, payload.relay.outcome) ? (jlong)event->payload.relay.outcome : 0, JNI_REACHES(event, sipral_event_t, payload.relay.code) ? (jlong)event->payload.relay.code : 0, payloadRelayLocal, payloadRelayRelayed, payloadRelayMapped, payloadRelayReason, JNI_REACHES(event, sipral_event_t, payload.referral.status_code) ? (jlong)event->payload.referral.status_code : 0, JNI_REACHES(event, sipral_event_t, payload.referral.attended) ? (jlong)event->payload.referral.attended : 0, payloadReferralTarget, payloadReferralReferredBy, JNI_REACHES(event, sipral_event_t, payload.turn_stream.state) ? (jlong)event->payload.turn_stream.state : 0, JNI_REACHES(event, sipral_event_t, payload.turn_stream.protocol) ? (jlong)event->payload.turn_stream.protocol : 0, payloadTurnStreamLocal, payloadTurnStreamServer, JNI_REACHES(event, sipral_event_t, payload.audio.change) ? (jlong)event->payload.audio.change : 0, JNI_REACHES(event, sipral_event_t, payload.audio.origin) ? (jlong)event->payload.audio.origin : 0, JNI_REACHES(event, sipral_event_t, payload.audio.role) ? (jlong)event->payload.audio.role : 0, JNI_REACHES(event, sipral_event_t, payload.audio.direction) ? (jlong)event->payload.audio.direction : 0, JNI_REACHES(event, sipral_event_t, payload.audio.device) ? (jlong)event->payload.audio.device : 0, JNI_REACHES(event, sipral_event_t, payload.stun_server.state) ? (jlong)event->payload.stun_server.state : 0, payloadStunServerServer, payloadStunServerPrevious, JNI_REACHES(event, sipral_event_t, payload.verification.stage) ? (jlong)event->payload.verification.stage : 0, JNI_REACHES(event, sipral_event_t, payload.verification.outcome) ? (jlong)event->payload.verification.outcome : 0, JNI_REACHES(event, sipral_event_t, payload.verification.failure) ? (jlong)event->payload.verification.failure : 0, JNI_REACHES(event, sipral_event_t, payload.verification.attestation) ? (jlong)event->payload.verification.attestation : 0, JNI_REACHES(event, sipral_event_t, payload.verification.verstat) ? (jlong)event->payload.verification.verstat : 0, JNI_REACHES(event, sipral_event_t, payload.verification.response_code) ? (jlong)event->payload.verification.response_code : 0, JNI_REACHES(event, sipral_event_t, payload.verification.refused) ? (jlong)event->payload.verification.refused : 0, payloadVerificationCertificateUrl, payloadVerificationOrig, payloadVerificationOrigid, payloadVerificationDetail, JNI_REACHES(event, sipral_event_t, payload.progress.what) ? (jlong)event->payload.progress.what : 0, JNI_REACHES(event, sipral_event_t, payload.progress.tone) ? (jlong)event->payload.progress.tone : 0, JNI_REACHES(event, sipral_event_t, payload.progress.verdict) ? (jlong)event->payload.progress.verdict : 0, JNI_REACHES(event, sipral_event_t, payload.progress.reason) ? (jlong)event->payload.progress.reason : 0, JNI_REACHES(event, sipral_event_t, payload.progress.at_ms) ? (jlong)event->payload.progress.at_ms : 0, JNI_REACHES(event, sipral_event_t, payload.progress.initial_silence_ms) ? (jlong)event->payload.progress.initial_silence_ms : 0, JNI_REACHES(event, sipral_event_t, payload.progress.greeting_ms) ? (jlong)event->payload.progress.greeting_ms : 0, JNI_REACHES(event, sipral_event_t, payload.progress.words) ? (jlong)event->payload.progress.words : 0, JNI_REACHES(event, sipral_event_t, payload.progress.frequency_hz) ? (jlong)event->payload.progress.frequency_hz : 0, JNI_REACHES(event, sipral_event_t, payload.progress.length_ms) ? (jlong)event->payload.progress.length_ms : 0, JNI_REACHES(event, sipral_event_t, payload.progress.sit_hz_1) ? (jlong)event->payload.progress.sit_hz_1 : 0, JNI_REACHES(event, sipral_event_t, payload.progress.sit_hz_2) ? (jlong)event->payload.progress.sit_hz_2 : 0, JNI_REACHES(event, sipral_event_t, payload.progress.sit_hz_3) ? (jlong)event->payload.progress.sit_hz_3 : 0, JNI_REACHES(event, sipral_event_t, payload.progress.sit_ms_1) ? (jlong)event->payload.progress.sit_ms_1 : 0, JNI_REACHES(event, sipral_event_t, payload.progress.sit_ms_2) ? (jlong)event->payload.progress.sit_ms_2 : 0, JNI_REACHES(event, sipral_event_t, payload.progress.sit_ms_3) ? (jlong)event->payload.progress.sit_ms_3 : 0, JNI_REACHES(event, sipral_event_t, payload.conference.subscription) ? (jlong)event->payload.conference.subscription : 0, JNI_REACHES(event, sipral_event_t, payload.conference.update) ? (jlong)event->payload.conference.update : 0, JNI_REACHES(event, sipral_event_t, payload.conference.version) ? (jlong)event->payload.conference.version : 0, JNI_REACHES(event, sipral_event_t, payload.conference.users) ? (jlong)event->payload.conference.users : 0, payloadTextText, JNI_REACHES(event, sipral_event_t, payload.text.missing) ? (jlong)event->payload.text.missing : 0, JNI_REACHES(event, sipral_event_t, payload.presence.kind) ? (jlong)event->payload.presence.kind : 0, JNI_REACHES(event, sipral_event_t, payload.presence.subscription) ? (jlong)event->payload.presence.subscription : 0, JNI_REACHES(event, sipral_event_t, payload.presence.basic) ? (jlong)event->payload.presence.basic : 0, JNI_REACHES(event, sipral_event_t, payload.presence.activity) ? (jlong)event->payload.presence.activity : 0, payloadPresenceEntity, payloadPresenceNote, JNI_REACHES(event, sipral_event_t, payload.presence.publication_state) ? (jlong)event->payload.presence.publication_state : 0, JNI_REACHES(event, sipral_event_t, payload.presence.failure) ? (jlong)event->payload.presence.failure : 0, JNI_REACHES(event, sipral_event_t, payload.presence.status_code) ? (jlong)event->payload.presence.status_code : 0, JNI_REACHES(event, sipral_event_t, payload.presence.expires_ms) ? (jlong)event->payload.presence.expires_ms : 0, JNI_REACHES(event, sipral_event_t, payload.presence.refresh_in_ms) ? (jlong)event->payload.presence.refresh_in_ms : 0, JNI_REACHES(event, sipral_event_t, payload.transport_failed.transport) ? (jlong)event->payload.transport_failed.transport : 0, JNI_REACHES(event, sipral_event_t, payload.transport_failed.protocol) ? (jlong)event->payload.transport_failed.protocol : 0, JNI_REACHES(event, sipral_event_t, payload.transport_failed.error) ? (jlong)event->payload.transport_failed.error : 0, JNI_REACHES(event, sipral_event_t, payload.transport_failed.tls) ? (jlong)event->payload.transport_failed.tls : 0, payloadTransportFailedDetail);
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
    if (payloadCallLocalSdp != NULL) {
        (*env)->DeleteLocalRef(env, payloadCallLocalSdp);
    }
    if (payloadCallRemoteSdp != NULL) {
        (*env)->DeleteLocalRef(env, payloadCallRemoteSdp);
    }
    if (payloadCallFromUri != NULL) {
        (*env)->DeleteLocalRef(env, payloadCallFromUri);
    }
    if (payloadCallFromDisplay != NULL) {
        (*env)->DeleteLocalRef(env, payloadCallFromDisplay);
    }
    if (payloadCallToUri != NULL) {
        (*env)->DeleteLocalRef(env, payloadCallToUri);
    }
    if (payloadCallCallId != NULL) {
        (*env)->DeleteLocalRef(env, payloadCallCallId);
    }
    if (payloadCallCauseText != NULL) {
        (*env)->DeleteLocalRef(env, payloadCallCauseText);
    }
    if (payloadCallAssertedUri != NULL) {
        (*env)->DeleteLocalRef(env, payloadCallAssertedUri);
    }
    if (payloadCallAssertedDisplay != NULL) {
        (*env)->DeleteLocalRef(env, payloadCallAssertedDisplay);
    }
    if (payloadCallDivertedFrom != NULL) {
        (*env)->DeleteLocalRef(env, payloadCallDivertedFrom);
    }
    if (payloadCallDiversionReason != NULL) {
        (*env)->DeleteLocalRef(env, payloadCallDiversionReason);
    }
    if (payloadCallAlertInfo != NULL) {
        (*env)->DeleteLocalRef(env, payloadCallAlertInfo);
    }
    if (payloadTransferTarget != NULL) {
        (*env)->DeleteLocalRef(env, payloadTransferTarget);
    }
    if (payloadMediaReason != NULL) {
        (*env)->DeleteLocalRef(env, payloadMediaReason);
    }
    if (payloadMediaStatistics != NULL) {
        (*env)->DeleteLocalRef(env, payloadMediaStatistics);
    }
    if (payloadTransportWantedDestination != NULL) {
        (*env)->DeleteLocalRef(env, payloadTransportWantedDestination);
    }
    if (payloadResolveHost != NULL) {
        (*env)->DeleteLocalRef(env, payloadResolveHost);
    }
    if (payloadMessageContentType != NULL) {
        (*env)->DeleteLocalRef(env, payloadMessageContentType);
    }
    if (payloadMessageBody != NULL) {
        (*env)->DeleteLocalRef(env, payloadMessageBody);
    }
    if (payloadMessageMessageAccount != NULL) {
        (*env)->DeleteLocalRef(env, payloadMessageMessageAccount);
    }
    if (payloadNatLocal != NULL) {
        (*env)->DeleteLocalRef(env, payloadNatLocal);
    }
    if (payloadNatMapped != NULL) {
        (*env)->DeleteLocalRef(env, payloadNatMapped);
    }
    if (payloadNatPrevious != NULL) {
        (*env)->DeleteLocalRef(env, payloadNatPrevious);
    }
    if (payloadRelayLocal != NULL) {
        (*env)->DeleteLocalRef(env, payloadRelayLocal);
    }
    if (payloadRelayRelayed != NULL) {
        (*env)->DeleteLocalRef(env, payloadRelayRelayed);
    }
    if (payloadRelayMapped != NULL) {
        (*env)->DeleteLocalRef(env, payloadRelayMapped);
    }
    if (payloadRelayReason != NULL) {
        (*env)->DeleteLocalRef(env, payloadRelayReason);
    }
    if (payloadReferralTarget != NULL) {
        (*env)->DeleteLocalRef(env, payloadReferralTarget);
    }
    if (payloadReferralReferredBy != NULL) {
        (*env)->DeleteLocalRef(env, payloadReferralReferredBy);
    }
    if (payloadTurnStreamLocal != NULL) {
        (*env)->DeleteLocalRef(env, payloadTurnStreamLocal);
    }
    if (payloadTurnStreamServer != NULL) {
        (*env)->DeleteLocalRef(env, payloadTurnStreamServer);
    }
    if (payloadStunServerServer != NULL) {
        (*env)->DeleteLocalRef(env, payloadStunServerServer);
    }
    if (payloadStunServerPrevious != NULL) {
        (*env)->DeleteLocalRef(env, payloadStunServerPrevious);
    }
    if (payloadVerificationCertificateUrl != NULL) {
        (*env)->DeleteLocalRef(env, payloadVerificationCertificateUrl);
    }
    if (payloadVerificationOrig != NULL) {
        (*env)->DeleteLocalRef(env, payloadVerificationOrig);
    }
    if (payloadVerificationOrigid != NULL) {
        (*env)->DeleteLocalRef(env, payloadVerificationOrigid);
    }
    if (payloadVerificationDetail != NULL) {
        (*env)->DeleteLocalRef(env, payloadVerificationDetail);
    }
    if (payloadTextText != NULL) {
        (*env)->DeleteLocalRef(env, payloadTextText);
    }
    if (payloadPresenceEntity != NULL) {
        (*env)->DeleteLocalRef(env, payloadPresenceEntity);
    }
    if (payloadPresenceNote != NULL) {
        (*env)->DeleteLocalRef(env, payloadPresenceNote);
    }
    if (payloadTransportFailedDetail != NULL) {
        (*env)->DeleteLocalRef(env, payloadTransportFailedDetail);
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

/* Where a sipral_processor_callback_t lands. The event is handed to
 * SipralProcessorListeners.deliver under the key its user pointer carries, on a
 * thread attached to the JVM for the length of the call when it was not
 * attached already, and every local reference made here is deleted
 * before it returns: a poll delivers all its events inside one native
 * call, and nothing made here would be released until that call ended. */
static void
jni_processor_callback(const sipral_processor_frame_t *frame, void *user_data)
{
    JNIEnv *env = NULL;
    int attached = 0;
    int built = 1;
    jint found;
    jshortArray near_end = NULL;
    jshortArray far_end = NULL;
    jshortArray out = NULL;

    if (jni_vm == NULL || frame == NULL) {
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
    if (built && JNI_REACHES(frame, sipral_processor_frame_t, near_end_len) && frame->near_end != NULL) {
        near_end = (*env)->NewShortArray(env, (jsize)frame->near_end_len);
        if (near_end == NULL) {
            built = 0;
        } else {
            (*env)->SetShortArrayRegion(env, near_end, 0, (jsize)frame->near_end_len, (const jshort *)frame->near_end);
        }
    }
    if (built && JNI_REACHES(frame, sipral_processor_frame_t, far_end_len) && frame->far_end != NULL) {
        far_end = (*env)->NewShortArray(env, (jsize)frame->far_end_len);
        if (far_end == NULL) {
            built = 0;
        } else {
            (*env)->SetShortArrayRegion(env, far_end, 0, (jsize)frame->far_end_len, (const jshort *)frame->far_end);
        }
    }
    if (built && JNI_REACHES(frame, sipral_processor_frame_t, out_len) && frame->out != NULL) {
        out = (*env)->NewShortArray(env, (jsize)frame->out_len);
        if (out == NULL) {
            built = 0;
        }
    }
    if (built) {
        (*env)->CallStaticVoidMethod(env, jni_processor_callback_class, jni_processor_callback_deliver, (jlong)(intptr_t)user_data, (jlong)frame->size, JNI_REACHES(frame, sipral_processor_frame_t, reset) ? (jlong)frame->reset : 0, near_end, far_end, out);
    }
    /* deliver hands what a listener throws to the thread's own handler, so
     * what is pending here is the JVM's -- an array it could not make --
     * and a callback has no Java frame beneath it to throw into */
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
    if (out != NULL) {
        (*env)->GetShortArrayRegion(env, out, 0, (jsize)frame->out_len, (jshort *)frame->out);
    }
    if (near_end != NULL) {
        (*env)->DeleteLocalRef(env, near_end);
    }
    if (far_end != NULL) {
        (*env)->DeleteLocalRef(env, far_end);
    }
    if (out != NULL) {
        (*env)->DeleteLocalRef(env, out);
    }
    if (attached) {
        (*jni_vm)->DetachCurrentThread(jni_vm);
    }
}

/* Where a sipral_audio_transmit_callback_t lands. The event is handed to
 * SipralAudioTransmitListeners.deliver under the key its user pointer carries, on a
 * thread attached to the JVM for the length of the call when it was not
 * attached already, and every local reference made here is deleted
 * before it returns: a poll delivers all its events inside one native
 * call, and nothing made here would be released until that call ended. */
static void
jni_audio_transmit_callback(const sipral_audio_transmit_t *transmit, void *user_data)
{
    JNIEnv *env = NULL;
    int attached = 0;
    int built = 1;
    jint found;
    jbyteArray destination = NULL;
    jbyteArray payload = NULL;

    if (jni_vm == NULL || transmit == NULL) {
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
    if (built && JNI_REACHES(transmit, sipral_audio_transmit_t, destination_len) && transmit->destination != NULL) {
        destination = (*env)->NewByteArray(env, (jsize)transmit->destination_len);
        if (destination == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, destination, 0, (jsize)transmit->destination_len, (const jbyte *)transmit->destination);
        }
    }
    if (built && JNI_REACHES(transmit, sipral_audio_transmit_t, payload_len) && transmit->payload != NULL) {
        payload = (*env)->NewByteArray(env, (jsize)transmit->payload_len);
        if (payload == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, payload, 0, (jsize)transmit->payload_len, (const jbyte *)transmit->payload);
        }
    }
    if (built) {
        (*env)->CallStaticVoidMethod(env, jni_audio_transmit_callback_class, jni_audio_transmit_callback_deliver, (jlong)(intptr_t)user_data, (jlong)transmit->size, JNI_REACHES(transmit, sipral_audio_transmit_t, call) ? (jlong)transmit->call : 0, JNI_REACHES(transmit, sipral_audio_transmit_t, protocol) ? (jlong)transmit->protocol : 0, destination, payload);
    }
    /* deliver hands what a listener throws to the thread's own handler, so
     * what is pending here is the JVM's -- an array it could not make --
     * and a callback has no Java frame beneath it to throw into */
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
    if (destination != NULL) {
        (*env)->DeleteLocalRef(env, destination);
    }
    if (payload != NULL) {
        (*env)->DeleteLocalRef(env, payload);
    }
    if (attached) {
        (*jni_vm)->DetachCurrentThread(jni_vm);
    }
}

/* Where a sipral_log_callback_t lands. The event is handed to
 * SipralLogListeners.deliver under the key its user pointer carries, on a
 * thread attached to the JVM for the length of the call when it was not
 * attached already, and every local reference made here is deleted
 * before it returns: a poll delivers all its events inside one native
 * call, and nothing made here would be released until that call ended. */
static void
jni_log_callback(const sipral_log_record_t *record, void *user_data)
{
    JNIEnv *env = NULL;
    int attached = 0;
    int built = 1;
    jint found;
    jbyteArray target = NULL;
    jbyteArray message = NULL;

    if (jni_vm == NULL || record == NULL) {
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
    if (built && JNI_REACHES(record, sipral_log_record_t, target_len) && record->target != NULL) {
        target = (*env)->NewByteArray(env, (jsize)record->target_len);
        if (target == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, target, 0, (jsize)record->target_len, (const jbyte *)record->target);
        }
    }
    if (built && JNI_REACHES(record, sipral_log_record_t, message_len) && record->message != NULL) {
        message = (*env)->NewByteArray(env, (jsize)record->message_len);
        if (message == NULL) {
            built = 0;
        } else {
            (*env)->SetByteArrayRegion(env, message, 0, (jsize)record->message_len, (const jbyte *)record->message);
        }
    }
    if (built) {
        (*env)->CallStaticVoidMethod(env, jni_log_callback_class, jni_log_callback_deliver, (jlong)(intptr_t)user_data, (jlong)record->size, JNI_REACHES(record, sipral_log_record_t, stack) ? (jlong)record->stack : 0, JNI_REACHES(record, sipral_log_record_t, level) ? (jlong)record->level : 0, target, message, JNI_REACHES(record, sipral_log_record_t, suppressed) ? (jlong)record->suppressed : 0);
    }
    /* deliver hands what a listener throws to the thread's own handler, so
     * what is pending here is the JVM's -- an array it could not make --
     * and a callback has no Java frame beneath it to throw into */
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
    if (target != NULL) {
        (*env)->DeleteLocalRef(env, target);
    }
    if (message != NULL) {
        (*env)->DeleteLocalRef(env, message);
    }
    if (attached) {
        (*jni_vm)->DetachCurrentThread(jni_vm);
    }
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
Java_org_sipral_SipralNative_sipral_1stack_1create(JNIEnv *env, jobject self, jlong configEventCallback, jlong configTransport, jbyteArray configBindAddress, jbyteArray configUserAgent, jbyteArray configEntropy, jlong configTimerT1Ms, jlong configTimerT2Ms, jlong configTimerT4Ms, jbyteArray configCodecs, jlong configFrameMs, jlong configOfferDtmf, jlong configOfferRtcpMux, jlong configSilenceSuppression, jlong configMediaStallWatchdog, jlong configMediaStallMs, jlong configMediaClockUnixSeconds, jbyteArray configMediaSeed, jlong configSrtp, jlong configIce, jlong configNat, jbyteArray configStunServer, jlong configG729AnnexB, jbyteArray configTurnServer, jbyteArray configTurnUsername, jbyteArray configTurnPassword, jlong configReferrals, jlong configRegistrarKeepalive, jlong configRegistrarKeepaliveMs, jlong configTurnTransport, jlong configAudio, jlong configAudioActivation, jlong configAudioTransmitCallback, jlong configAudioProbeMs, jlong configAudioDeviceRateHz, jlong configMaxDialogs, jlong configMaxServerTransactions, jlong configDiagnosticDecisions, jlong configDiagnosticRecords, jbyteArray configStunFallbacks, jlong configRtpPortMin, jlong configRtpPortMax, jlong configDtmfDetection, jlongArray stack)
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
    config_value.nat = (uint32_t)configNat;
    jbyte *configStunServer_data = configStunServer ? (*env)->GetByteArrayElements(env, configStunServer, NULL) : NULL;
    jsize configStunServer_size = configStunServer ? (*env)->GetArrayLength(env, configStunServer) : 0;
    config_value.stun_server = (const char *)configStunServer_data;
    config_value.stun_server_len = (size_t)configStunServer_size;
    config_value.g729_annex_b = (uint32_t)configG729AnnexB;
    jbyte *configTurnServer_data = configTurnServer ? (*env)->GetByteArrayElements(env, configTurnServer, NULL) : NULL;
    jsize configTurnServer_size = configTurnServer ? (*env)->GetArrayLength(env, configTurnServer) : 0;
    config_value.turn_server = (const char *)configTurnServer_data;
    config_value.turn_server_len = (size_t)configTurnServer_size;
    jbyte *configTurnUsername_data = configTurnUsername ? (*env)->GetByteArrayElements(env, configTurnUsername, NULL) : NULL;
    jsize configTurnUsername_size = configTurnUsername ? (*env)->GetArrayLength(env, configTurnUsername) : 0;
    config_value.turn_username = (const char *)configTurnUsername_data;
    config_value.turn_username_len = (size_t)configTurnUsername_size;
    jbyte *configTurnPassword_data = configTurnPassword ? (*env)->GetByteArrayElements(env, configTurnPassword, NULL) : NULL;
    jsize configTurnPassword_size = configTurnPassword ? (*env)->GetArrayLength(env, configTurnPassword) : 0;
    config_value.turn_password = (const char *)configTurnPassword_data;
    config_value.turn_password_len = (size_t)configTurnPassword_size;
    config_value.referrals = (uint32_t)configReferrals;
    config_value.registrar_keepalive = (uint32_t)configRegistrarKeepalive;
    config_value.registrar_keepalive_ms = (uint64_t)configRegistrarKeepaliveMs;
    config_value.turn_transport = (uint32_t)configTurnTransport;
    config_value.audio = (uint32_t)configAudio;
    config_value.audio_activation = (uint32_t)configAudioActivation;
    config_value.audio_transmit_callback = configAudioTransmitCallback != 0 ? jni_audio_transmit_callback : NULL;
    config_value.audio_transmit_user_data = (void *)(intptr_t)configAudioTransmitCallback;
    config_value.audio_probe_ms = (uint64_t)configAudioProbeMs;
    config_value.audio_device_rate_hz = (uint32_t)configAudioDeviceRateHz;
    config_value.max_dialogs = (uint32_t)configMaxDialogs;
    config_value.max_server_transactions = (uint32_t)configMaxServerTransactions;
    config_value.diagnostic_decisions = (uint32_t)configDiagnosticDecisions;
    config_value.diagnostic_records = (uint32_t)configDiagnosticRecords;
    jbyte *configStunFallbacks_data = configStunFallbacks ? (*env)->GetByteArrayElements(env, configStunFallbacks, NULL) : NULL;
    jsize configStunFallbacks_size = configStunFallbacks ? (*env)->GetArrayLength(env, configStunFallbacks) : 0;
    config_value.stun_fallbacks = (const char *)configStunFallbacks_data;
    config_value.stun_fallbacks_len = (size_t)configStunFallbacks_size;
    config_value.rtp_port_min = (uint32_t)configRtpPortMin;
    config_value.rtp_port_max = (uint32_t)configRtpPortMax;
    config_value.dtmf_detection = (uint32_t)configDtmfDetection;
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
    if (configStunServer) {
        (*env)->ReleaseByteArrayElements(env, configStunServer, configStunServer_data, JNI_ABORT);
    }
    if (configTurnServer) {
        (*env)->ReleaseByteArrayElements(env, configTurnServer, configTurnServer_data, JNI_ABORT);
    }
    if (configTurnUsername) {
        (*env)->ReleaseByteArrayElements(env, configTurnUsername, configTurnUsername_data, JNI_ABORT);
    }
    if (configTurnPassword) {
        (*env)->ReleaseByteArrayElements(env, configTurnPassword, configTurnPassword_data, JNI_ABORT);
    }
    if (configStunFallbacks) {
        (*env)->ReleaseByteArrayElements(env, configStunFallbacks, configStunFallbacks_data, JNI_ABORT);
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
        jlong slots[21];
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
        slots[12] = (jlong)settings_value.g729_annex_b;
        slots[13] = (jlong)settings_value.referrals;
        slots[14] = (jlong)settings_value.registrar_keepalive_ms;
        slots[15] = (jlong)settings_value.max_dialogs;
        slots[16] = (jlong)settings_value.max_server_transactions;
        slots[17] = (jlong)settings_value.diagnostic_decisions;
        slots[18] = (jlong)settings_value.diagnostic_records;
        slots[19] = (jlong)settings_value.rtp_port_min;
        slots[20] = (jlong)settings_value.rtp_port_max;
        (*env)->SetLongArrayRegion(env, settings, 0, 21, slots);
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
        jlong slots[29];
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
        slots[25] = (jlong)counters_value.requests_retransmitted;
        slots[26] = (jlong)counters_value.responses_retransmitted;
        slots[27] = (jlong)counters_value.transactions_timed_out;
        slots[28] = (jlong)counters_value.requests_refused_at_limit;
        (*env)->SetLongArrayRegion(env, counters, 0, 29, slots);
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
Java_org_sipral_SipralNative_sipral_1account_1add(JNIEnv *env, jobject self, jlong stack, jbyteArray configAor, jbyteArray configRegistrar, jbyteArray configContact, jbyteArray configRegistrarAddress, jbyteArray configDisplayName, jbyteArray configAuthUser, jbyteArray configAuthPassword, jbyteArray configInstanceId, jlong configExpiresSeconds, jbyteArray configHeadersBytes, jlongArray configHeadersLengths, jlong configTransport, jbyteArray configPushProvider, jbyteArray configPushPrid, jbyteArray configPushParam, jlong configPushWakesItself, jbyteArray configQualityReportUri, jlong configSessionTimer, jlong configSessionIntervalSeconds, jlong configPrivacy, jbyteArray configTrustedPeers, jlong configSrtp, jbyteArray configSrtpSuites, jlong configStirVerification, jbyteArray configStirKey, jbyteArray configStirCertificateUrl, jbyteArray configStirOrig, jbyteArray configStirOrigid, jlong configStirAttestation, jlongArray account)
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
    config_value.session_timer = (uint32_t)configSessionTimer;
    config_value.session_interval_seconds = (uint64_t)configSessionIntervalSeconds;
    config_value.privacy = (uint32_t)configPrivacy;
    jbyte *configTrustedPeers_data = configTrustedPeers ? (*env)->GetByteArrayElements(env, configTrustedPeers, NULL) : NULL;
    jsize configTrustedPeers_size = configTrustedPeers ? (*env)->GetArrayLength(env, configTrustedPeers) : 0;
    config_value.trusted_peers = (const char *)configTrustedPeers_data;
    config_value.trusted_peers_len = (size_t)configTrustedPeers_size;
    config_value.srtp = (uint32_t)configSrtp;
    jbyte *configSrtpSuites_data = configSrtpSuites ? (*env)->GetByteArrayElements(env, configSrtpSuites, NULL) : NULL;
    jsize configSrtpSuites_size = configSrtpSuites ? (*env)->GetArrayLength(env, configSrtpSuites) : 0;
    config_value.srtp_suites = (const char *)configSrtpSuites_data;
    config_value.srtp_suites_len = (size_t)configSrtpSuites_size;
    config_value.stir_verification = (uint32_t)configStirVerification;
    jbyte *configStirKey_data = configStirKey ? (*env)->GetByteArrayElements(env, configStirKey, NULL) : NULL;
    jsize configStirKey_size = configStirKey ? (*env)->GetArrayLength(env, configStirKey) : 0;
    config_value.stir_key = (const uint8_t *)configStirKey_data;
    config_value.stir_key_len = (size_t)configStirKey_size;
    jbyte *configStirCertificateUrl_data = configStirCertificateUrl ? (*env)->GetByteArrayElements(env, configStirCertificateUrl, NULL) : NULL;
    jsize configStirCertificateUrl_size = configStirCertificateUrl ? (*env)->GetArrayLength(env, configStirCertificateUrl) : 0;
    config_value.stir_certificate_url = (const char *)configStirCertificateUrl_data;
    config_value.stir_certificate_url_len = (size_t)configStirCertificateUrl_size;
    jbyte *configStirOrig_data = configStirOrig ? (*env)->GetByteArrayElements(env, configStirOrig, NULL) : NULL;
    jsize configStirOrig_size = configStirOrig ? (*env)->GetArrayLength(env, configStirOrig) : 0;
    config_value.stir_orig = (const char *)configStirOrig_data;
    config_value.stir_orig_len = (size_t)configStirOrig_size;
    jbyte *configStirOrigid_data = configStirOrigid ? (*env)->GetByteArrayElements(env, configStirOrigid, NULL) : NULL;
    jsize configStirOrigid_size = configStirOrigid ? (*env)->GetArrayLength(env, configStirOrigid) : 0;
    config_value.stir_origid = (const char *)configStirOrigid_data;
    config_value.stir_origid_len = (size_t)configStirOrigid_size;
    config_value.stir_attestation = (uint32_t)configStirAttestation;
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
    if (configTrustedPeers) {
        (*env)->ReleaseByteArrayElements(env, configTrustedPeers, configTrustedPeers_data, JNI_ABORT);
    }
    if (configSrtpSuites) {
        (*env)->ReleaseByteArrayElements(env, configSrtpSuites, configSrtpSuites_data, JNI_ABORT);
    }
    if (configStirKey) {
        (*env)->ReleaseByteArrayElements(env, configStirKey, configStirKey_data, JNI_ABORT);
    }
    if (configStirCertificateUrl) {
        (*env)->ReleaseByteArrayElements(env, configStirCertificateUrl, configStirCertificateUrl_data, JNI_ABORT);
    }
    if (configStirOrig) {
        (*env)->ReleaseByteArrayElements(env, configStirOrig, configStirOrig_data, JNI_ABORT);
    }
    if (configStirOrigid) {
        (*env)->ReleaseByteArrayElements(env, configStirOrigid, configStirOrigid_data, JNI_ABORT);
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
Java_org_sipral_SipralNative_sipral_1call_1place(JNIEnv *env, jobject self, jlong stack, jlong account, jbyteArray configTarget, jbyteArray configSdp, jbyteArray configDestination, jlong configKeepAllForks, jbyteArray configMediaAddress, jbyteArray configHeadersBytes, jlongArray configHeadersLengths, jlong configSrtp, jlong configTransport, jbyteArray configCodecs, jlong configIce, jbyteArray configTextAddress, jlong configFeedback, jlong configFocus, jlongArray call, jlong nowMs)
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
    jbyte *configTextAddress_data = configTextAddress ? (*env)->GetByteArrayElements(env, configTextAddress, NULL) : NULL;
    jsize configTextAddress_size = configTextAddress ? (*env)->GetArrayLength(env, configTextAddress) : 0;
    config_value.text_address = (const char *)configTextAddress_data;
    config_value.text_address_len = (size_t)configTextAddress_size;
    config_value.feedback = (uint32_t)configFeedback;
    config_value.focus = (uint32_t)configFocus;
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
    if (configTextAddress) {
        (*env)->ReleaseByteArrayElements(env, configTextAddress, configTextAddress_data, JNI_ABORT);
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
Java_org_sipral_SipralNative_sipral_1call_1ring_1media(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray configTarget, jbyteArray configSdp, jbyteArray configDestination, jlong configKeepAllForks, jbyteArray configMediaAddress, jbyteArray configHeadersBytes, jlongArray configHeadersLengths, jlong configSrtp, jlong configTransport, jbyteArray configCodecs, jlong configIce, jbyteArray configTextAddress, jlong configFeedback, jlong configFocus, jlong nowMs)
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
    jbyte *configTextAddress_data = configTextAddress ? (*env)->GetByteArrayElements(env, configTextAddress, NULL) : NULL;
    jsize configTextAddress_size = configTextAddress ? (*env)->GetArrayLength(env, configTextAddress) : 0;
    config_value.text_address = (const char *)configTextAddress_data;
    config_value.text_address_len = (size_t)configTextAddress_size;
    config_value.feedback = (uint32_t)configFeedback;
    config_value.focus = (uint32_t)configFocus;
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
    if (configTextAddress) {
        (*env)->ReleaseByteArrayElements(env, configTextAddress, configTextAddress_data, JNI_ABORT);
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
Java_org_sipral_SipralNative_sipral_1call_1answer_1with(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray configTarget, jbyteArray configSdp, jbyteArray configDestination, jlong configKeepAllForks, jbyteArray configMediaAddress, jbyteArray configHeadersBytes, jlongArray configHeadersLengths, jlong configSrtp, jlong configTransport, jbyteArray configCodecs, jlong configIce, jbyteArray configTextAddress, jlong configFeedback, jlong configFocus, jlong nowMs)
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
    jbyte *configTextAddress_data = configTextAddress ? (*env)->GetByteArrayElements(env, configTextAddress, NULL) : NULL;
    jsize configTextAddress_size = configTextAddress ? (*env)->GetArrayLength(env, configTextAddress) : 0;
    config_value.text_address = (const char *)configTextAddress_data;
    config_value.text_address_len = (size_t)configTextAddress_size;
    config_value.feedback = (uint32_t)configFeedback;
    config_value.focus = (uint32_t)configFocus;
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
        status = sipral_call_answer_with((sipral_handle_t)stack, (sipral_handle_t)call, &config_value, (uint64_t)nowMs);
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
    if (configTextAddress) {
        (*env)->ReleaseByteArrayElements(env, configTextAddress, configTextAddress_data, JNI_ABORT);
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
Java_org_sipral_SipralNative_sipral_1call_1restart_1ice(JNIEnv *env, jobject self, jlong stack, jlong call, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_restart_ice((sipral_handle_t)stack, (sipral_handle_t)call, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1media_1readdress(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray mediaAddress, jbyteArray publicAddress, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *mediaAddress_data = mediaAddress ? (*env)->GetByteArrayElements(env, mediaAddress, NULL) : NULL;
    jsize mediaAddress_size = mediaAddress ? (*env)->GetArrayLength(env, mediaAddress) : 0;
    jbyte *publicAddress_data = publicAddress ? (*env)->GetByteArrayElements(env, publicAddress, NULL) : NULL;
    jsize publicAddress_size = publicAddress ? (*env)->GetArrayLength(env, publicAddress) : 0;
    sipral_status_t status = sipral_call_media_readdress((sipral_handle_t)stack, (sipral_handle_t)call, (const char *)mediaAddress_data, (size_t)mediaAddress_size, (const char *)publicAddress_data, (size_t)publicAddress_size, (uint64_t)nowMs);
    if (mediaAddress) {
        (*env)->ReleaseByteArrayElements(env, mediaAddress, mediaAddress_data, JNI_ABORT);
    }
    if (publicAddress) {
        (*env)->ReleaseByteArrayElements(env, publicAddress, publicAddress_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1hangup_1for(JNIEnv *env, jobject self, jlong stack, jlong call, jlong sipCause, jlong q850Cause, jbyteArray text, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *text_data = text ? (*env)->GetByteArrayElements(env, text, NULL) : NULL;
    jsize text_size = text ? (*env)->GetArrayLength(env, text) : 0;
    sipral_status_t status = sipral_call_hangup_for((sipral_handle_t)stack, (sipral_handle_t)call, (uint32_t)sipCause, (uint32_t)q850Cause, (const char *)text_data, (size_t)text_size, (uint64_t)nowMs);
    if (text) {
        (*env)->ReleaseByteArrayElements(env, text, text_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1redirect(JNIEnv *env, jobject self, jlong stack, jlong call, jlong statusCode, jbyteArray targets, jbyteArray reason, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *targets_data = targets ? (*env)->GetByteArrayElements(env, targets, NULL) : NULL;
    jsize targets_size = targets ? (*env)->GetArrayLength(env, targets) : 0;
    jbyte *reason_data = reason ? (*env)->GetByteArrayElements(env, reason, NULL) : NULL;
    jsize reason_size = reason ? (*env)->GetArrayLength(env, reason) : 0;
    sipral_status_t status = sipral_call_redirect((sipral_handle_t)stack, (sipral_handle_t)call, (uint32_t)statusCode, (const char *)targets_data, (size_t)targets_size, (const char *)reason_data, (size_t)reason_size, (uint64_t)nowMs);
    if (targets) {
        (*env)->ReleaseByteArrayElements(env, targets, targets_data, JNI_ABORT);
    }
    if (reason) {
        (*env)->ReleaseByteArrayElements(env, reason, reason_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1identity_1count(JNIEnv *env, jobject self, jlong stack, jlong call, jlong which, jlongArray count)
{
    (void)env;
    (void)self;
    size_t count_value = 0;
    sipral_status_t status = sipral_call_identity_count((sipral_handle_t)stack, (sipral_handle_t)call, (uint32_t)which, &count_value);
    {
        jlong slot = (jlong)count_value;
        (*env)->SetLongArrayRegion(env, count, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1identity_1text(JNIEnv *env, jobject self, jlong stack, jlong call, jlong which, jlong index, jbyteArray buffer, jlongArray needed)
{
    (void)env;
    (void)self;
    jbyte *buffer_data = buffer ? (*env)->GetByteArrayElements(env, buffer, NULL) : NULL;
    jsize buffer_size = buffer ? (*env)->GetArrayLength(env, buffer) : 0;
    size_t needed_value = 0;
    sipral_status_t status = sipral_call_identity_text((sipral_handle_t)stack, (sipral_handle_t)call, (uint32_t)which, (size_t)index, (char *)buffer_data, (size_t)buffer_size, &needed_value);
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
Java_org_sipral_SipralNative_sipral_1call_1join(JNIEnv *env, jobject self, jlong stack, jlong callA, jlong callB)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_join((sipral_handle_t)stack, (sipral_handle_t)callA, (sipral_handle_t)callB);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1leave(JNIEnv *env, jobject self, jlong stack, jlong call)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_leave((sipral_handle_t)stack, (sipral_handle_t)call);
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
Java_org_sipral_SipralNative_sipral_1call_1consult(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray configTarget, jbyteArray configSdp, jbyteArray configDestination, jlong configKeepAllForks, jbyteArray configMediaAddress, jbyteArray configHeadersBytes, jlongArray configHeadersLengths, jlong configSrtp, jlong configTransport, jbyteArray configCodecs, jlong configIce, jbyteArray configTextAddress, jlong configFeedback, jlong configFocus, jlongArray consultation, jlong nowMs)
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
    jbyte *configTextAddress_data = configTextAddress ? (*env)->GetByteArrayElements(env, configTextAddress, NULL) : NULL;
    jsize configTextAddress_size = configTextAddress ? (*env)->GetArrayLength(env, configTextAddress) : 0;
    config_value.text_address = (const char *)configTextAddress_data;
    config_value.text_address_len = (size_t)configTextAddress_size;
    config_value.feedback = (uint32_t)configFeedback;
    config_value.focus = (uint32_t)configFocus;
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
    if (configTextAddress) {
        (*env)->ReleaseByteArrayElements(env, configTextAddress, configTextAddress_data, JNI_ABORT);
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
Java_org_sipral_SipralNative_sipral_1call_1accept_1transfer(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray configTarget, jbyteArray configSdp, jbyteArray configDestination, jlong configKeepAllForks, jbyteArray configMediaAddress, jbyteArray configHeadersBytes, jlongArray configHeadersLengths, jlong configSrtp, jlong configTransport, jbyteArray configCodecs, jlong configIce, jbyteArray configTextAddress, jlong configFeedback, jlong configFocus, jlongArray placed, jlong nowMs)
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
    jbyte *configTextAddress_data = configTextAddress ? (*env)->GetByteArrayElements(env, configTextAddress, NULL) : NULL;
    jsize configTextAddress_size = configTextAddress ? (*env)->GetArrayLength(env, configTextAddress) : 0;
    config_value.text_address = (const char *)configTextAddress_data;
    config_value.text_address_len = (size_t)configTextAddress_size;
    config_value.feedback = (uint32_t)configFeedback;
    config_value.focus = (uint32_t)configFocus;
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
    if (configTextAddress) {
        (*env)->ReleaseByteArrayElements(env, configTextAddress, configTextAddress_data, JNI_ABORT);
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
        jlong slots[21];
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
        slots[17] = (jlong)info_value.has_text;
        slots[18] = (jlong)info_value.feedback;
        slots[19] = (jlong)info_value.generic_nack;
        slots[20] = (jlong)info_value.reduced_size;
        (*env)->SetLongArrayRegion(env, info, 0, 21, slots);
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
Java_org_sipral_SipralNative_sipral_1media_1path_1candidate_1count(JNIEnv *env, jobject self, jlong media, jlongArray count)
{
    (void)env;
    (void)self;
    size_t count_value = 0;
    sipral_status_t status = sipral_media_path_candidate_count((sipral_handle_t)media, &count_value);
    {
        jlong slot = (jlong)count_value;
        (*env)->SetLongArrayRegion(env, count, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1path_1candidate_1at(JNIEnv *env, jobject self, jlong media, jlong index, jlong outCandidate)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_media_path_candidate_at((sipral_handle_t)media, (size_t)index, (sipral_path_candidate_t *)(intptr_t)outCandidate);
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
        jlong slots[49];
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
        slots[39] = (jlong)stats_value.frames_underrun;
        slots[40] = (jlong)stats_value.feedback;
        slots[41] = (jlong)stats_value.trr_interval_ms;
        slots[42] = (jlong)stats_value.nacks_sent;
        slots[43] = (jlong)stats_value.packets_nacked;
        slots[44] = (jlong)stats_value.nacks_received;
        slots[45] = (jlong)stats_value.packets_asked_for;
        slots[46] = (jlong)stats_value.early_packets;
        slots[47] = (jlong)stats_value.reduced_size_packets;
        slots[48] = (jlong)stats_value.feedback_suppressed;
        (*env)->SetLongArrayRegion(env, stats, 0, 49, slots);
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
Java_org_sipral_SipralNative_sipral_1call_1attach_1processor(JNIEnv *env, jobject self, jlong media, jlong process)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_attach_processor((sipral_handle_t)media, process != 0 ? jni_processor_callback : NULL, (void *)(intptr_t)process);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1detach_1processor(JNIEnv *env, jobject self, jlong media, jlongArray wasAttached)
{
    (void)env;
    (void)self;
    uint32_t wasAttached_value = 0;
    sipral_status_t status = sipral_call_detach_processor((sipral_handle_t)media, &wasAttached_value);
    {
        jlong slot = (jlong)wasAttached_value;
        (*env)->SetLongArrayRegion(env, wasAttached, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1reset_1processor(JNIEnv *env, jobject self, jlong media, jlongArray wasAttached)
{
    (void)env;
    (void)self;
    uint32_t wasAttached_value = 0;
    sipral_status_t status = sipral_call_reset_processor((sipral_handle_t)media, &wasAttached_value);
    {
        jlong slot = (jlong)wasAttached_value;
        (*env)->SetLongArrayRegion(env, wasAttached, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1mix(JNIEnv *env, jobject self, jlong mediaA, jlong mediaB, jlong nowMs, jshortArray mic, jshortArray local, jlong packetA, jlong packetB)
{
    (void)env;
    (void)self;
    jshort *mic_data = mic ? (*env)->GetShortArrayElements(env, mic, NULL) : NULL;
    jsize mic_size = mic ? (*env)->GetArrayLength(env, mic) : 0;
    jshort *local_data = local ? (*env)->GetShortArrayElements(env, local, NULL) : NULL;
    jsize local_size = local ? (*env)->GetArrayLength(env, local) : 0;
    sipral_status_t status = sipral_media_mix((sipral_handle_t)mediaA, (sipral_handle_t)mediaB, (uint64_t)nowMs, (const int16_t *)mic_data, (size_t)mic_size, (int16_t *)local_data, (size_t)local_size, (sipral_media_packet_t *)(intptr_t)packetA, (sipral_media_packet_t *)(intptr_t)packetB);
    if (mic) {
        (*env)->ReleaseShortArrayElements(env, mic, mic_data, JNI_ABORT);
    }
    if (local) {
        (*env)->ReleaseShortArrayElements(env, local, local_data, 0);
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
Java_org_sipral_SipralNative_sipral_1stack_1transport_1failure(JNIEnv *env, jobject self, jlong stack, jlong failureTransport, jlong failureError, jlong failureTls, jbyteArray failureDetail, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_transport_failure_t failure_value;
    memset(&failure_value, 0, sizeof failure_value);
    failure_value.size = sizeof failure_value;
    failure_value.transport = (uint32_t)failureTransport;
    failure_value.error = (uint32_t)failureError;
    failure_value.tls = (uint32_t)failureTls;
    jbyte *failureDetail_data = failureDetail ? (*env)->GetByteArrayElements(env, failureDetail, NULL) : NULL;
    jsize failureDetail_size = failureDetail ? (*env)->GetArrayLength(env, failureDetail) : 0;
    failure_value.detail = (const char *)failureDetail_data;
    failure_value.detail_len = (size_t)failureDetail_size;
    sipral_status_t status = sipral_stack_transport_failure((sipral_handle_t)stack, &failure_value, (uint64_t)nowMs);
    if (failureDetail) {
        (*env)->ReleaseByteArrayElements(env, failureDetail, failureDetail_data, JNI_ABORT);
    }
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

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1stun_1servers(JNIEnv *env, jobject self, jlong stack, jbyteArray servers, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *servers_data = servers ? (*env)->GetByteArrayElements(env, servers, NULL) : NULL;
    jsize servers_size = servers ? (*env)->GetArrayLength(env, servers) : 0;
    sipral_status_t status = sipral_stack_stun_servers((sipral_handle_t)stack, (const char *)servers_data, (size_t)servers_size, (uint64_t)nowMs);
    if (servers) {
        (*env)->ReleaseByteArrayElements(env, servers, servers_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1nat_1map(JNIEnv *env, jobject self, jlong stack, jbyteArray local, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *local_data = local ? (*env)->GetByteArrayElements(env, local, NULL) : NULL;
    jsize local_size = local ? (*env)->GetArrayLength(env, local) : 0;
    sipral_status_t status = sipral_stack_nat_map((sipral_handle_t)stack, (const char *)local_data, (size_t)local_size, (uint64_t)nowMs);
    if (local) {
        (*env)->ReleaseByteArrayElements(env, local, local_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1nat_1unmap(JNIEnv *env, jobject self, jlong stack, jbyteArray local, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *local_data = local ? (*env)->GetByteArrayElements(env, local, NULL) : NULL;
    jsize local_size = local ? (*env)->GetArrayLength(env, local) : 0;
    sipral_status_t status = sipral_stack_nat_unmap((sipral_handle_t)stack, (const char *)local_data, (size_t)local_size, (uint64_t)nowMs);
    if (local) {
        (*env)->ReleaseByteArrayElements(env, local, local_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1poll_1stun(JNIEnv *env, jobject self, jlong stack, jlong transmit)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_poll_stun((sipral_handle_t)stack, (sipral_transmit_t *)(intptr_t)transmit);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1receive_1stun(JNIEnv *env, jobject self, jlong stack, jbyteArray data, jbyteArray from, jbyteArray to, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *data_data = data ? (*env)->GetByteArrayElements(env, data, NULL) : NULL;
    jsize data_size = data ? (*env)->GetArrayLength(env, data) : 0;
    jbyte *from_data = from ? (*env)->GetByteArrayElements(env, from, NULL) : NULL;
    jsize from_size = from ? (*env)->GetArrayLength(env, from) : 0;
    jbyte *to_data = to ? (*env)->GetByteArrayElements(env, to, NULL) : NULL;
    jsize to_size = to ? (*env)->GetArrayLength(env, to) : 0;
    sipral_status_t status = sipral_stack_receive_stun((sipral_handle_t)stack, (const uint8_t *)data_data, (size_t)data_size, (const char *)from_data, (size_t)from_size, (const char *)to_data, (size_t)to_size, (uint64_t)nowMs);
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
Java_org_sipral_SipralNative_sipral_1stack_1turn_1connected(JNIEnv *env, jobject self, jlong stack, jbyteArray local, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *local_data = local ? (*env)->GetByteArrayElements(env, local, NULL) : NULL;
    jsize local_size = local ? (*env)->GetArrayLength(env, local) : 0;
    sipral_status_t status = sipral_stack_turn_connected((sipral_handle_t)stack, (const char *)local_data, (size_t)local_size, (uint64_t)nowMs);
    if (local) {
        (*env)->ReleaseByteArrayElements(env, local, local_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1turn_1receive(JNIEnv *env, jobject self, jlong stack, jbyteArray local, jbyteArray data, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *local_data = local ? (*env)->GetByteArrayElements(env, local, NULL) : NULL;
    jsize local_size = local ? (*env)->GetArrayLength(env, local) : 0;
    jbyte *data_data = data ? (*env)->GetByteArrayElements(env, data, NULL) : NULL;
    jsize data_size = data ? (*env)->GetArrayLength(env, data) : 0;
    sipral_status_t status = sipral_stack_turn_receive((sipral_handle_t)stack, (const char *)local_data, (size_t)local_size, (const uint8_t *)data_data, (size_t)data_size, (uint64_t)nowMs);
    if (local) {
        (*env)->ReleaseByteArrayElements(env, local, local_data, JNI_ABORT);
    }
    if (data) {
        (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1turn_1closed(JNIEnv *env, jobject self, jlong stack, jbyteArray local, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *local_data = local ? (*env)->GetByteArrayElements(env, local, NULL) : NULL;
    jsize local_size = local ? (*env)->GetArrayLength(env, local) : 0;
    sipral_status_t status = sipral_stack_turn_closed((sipral_handle_t)stack, (const char *)local_data, (size_t)local_size, (uint64_t)nowMs);
    if (local) {
        (*env)->ReleaseByteArrayElements(env, local, local_data, JNI_ABORT);
    }
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
Java_org_sipral_SipralNative_sipral_1subscription_1conference(JNIEnv *env, jobject self, jlong stack, jlong subscription, jlongArray conference)
{
    (void)env;
    (void)self;
    sipral_conference_t conference_value;
    memset(&conference_value, 0, sizeof conference_value);
    conference_value.size = sizeof conference_value;
    sipral_status_t status = sipral_subscription_conference((sipral_handle_t)stack, (sipral_handle_t)subscription, &conference_value);
    {
        jlong slots[7];
        slots[0] = (jlong)conference_value.size;
        slots[1] = (jlong)conference_value.version;
        slots[2] = (jlong)conference_value.users;
        slots[3] = (jlong)conference_value.has_user_count;
        slots[4] = (jlong)conference_value.user_count;
        slots[5] = (jlong)conference_value.active;
        slots[6] = (jlong)conference_value.locked;
        (*env)->SetLongArrayRegion(env, conference, 0, 7, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1subscription_1conference_1user_1at(JNIEnv *env, jobject self, jlong stack, jlong subscription, jlong index, jlongArray user)
{
    (void)env;
    (void)self;
    sipral_conference_user_t user_value;
    memset(&user_value, 0, sizeof user_value);
    user_value.size = sizeof user_value;
    sipral_status_t status = sipral_subscription_conference_user_at((sipral_handle_t)stack, (sipral_handle_t)subscription, (size_t)index, &user_value);
    {
        jlong slots[4];
        slots[0] = (jlong)user_value.size;
        slots[1] = (jlong)user_value.endpoints;
        slots[2] = (jlong)user_value.status;
        slots[3] = (jlong)user_value.media;
        (*env)->SetLongArrayRegion(env, user, 0, 4, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1subscription_1conference_1text(JNIEnv *env, jobject self, jlong stack, jlong subscription, jlong index, jlong which, jbyteArray buffer, jlongArray needed)
{
    (void)env;
    (void)self;
    jbyte *buffer_data = buffer ? (*env)->GetByteArrayElements(env, buffer, NULL) : NULL;
    jsize buffer_size = buffer ? (*env)->GetArrayLength(env, buffer) : 0;
    size_t needed_value = 0;
    sipral_status_t status = sipral_subscription_conference_text((sipral_handle_t)stack, (sipral_handle_t)subscription, (size_t)index, (uint32_t)which, (char *)buffer_data, (size_t)buffer_size, &needed_value);
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
Java_org_sipral_SipralNative_sipral_1call_1set_1focus(JNIEnv *env, jobject self, jlong stack, jlong call, jlong focus)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_set_focus((sipral_handle_t)stack, (sipral_handle_t)call, (uint32_t)focus);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1conference_1uri(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray buffer, jlongArray needed)
{
    (void)env;
    (void)self;
    jbyte *buffer_data = buffer ? (*env)->GetByteArrayElements(env, buffer, NULL) : NULL;
    jsize buffer_size = buffer ? (*env)->GetArrayLength(env, buffer) : 0;
    size_t needed_value = 0;
    sipral_status_t status = sipral_call_conference_uri((sipral_handle_t)stack, (sipral_handle_t)call, (char *)buffer_data, (size_t)buffer_size, &needed_value);
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
Java_org_sipral_SipralNative_sipral_1call_1subscribe_1conference(JNIEnv *env, jobject self, jlong stack, jlong call, jlongArray subscription, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_handle_t subscription_value = 0;
    sipral_status_t status = sipral_call_subscribe_conference((sipral_handle_t)stack, (sipral_handle_t)call, &subscription_value, (uint64_t)nowMs);
    {
        jlong slot = (jlong)subscription_value;
        (*env)->SetLongArrayRegion(env, subscription, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1publish_1presence(JNIEnv *env, jobject self, jlong stack, jlong account, jlong presenceBasic, jlong presenceActivity, jbyteArray presenceNote, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_presence_t presence_value;
    memset(&presence_value, 0, sizeof presence_value);
    presence_value.size = sizeof presence_value;
    presence_value.basic = (uint32_t)presenceBasic;
    presence_value.activity = (uint32_t)presenceActivity;
    jbyte *presenceNote_data = presenceNote ? (*env)->GetByteArrayElements(env, presenceNote, NULL) : NULL;
    jsize presenceNote_size = presenceNote ? (*env)->GetArrayLength(env, presenceNote) : 0;
    presence_value.note = (const char *)presenceNote_data;
    presence_value.note_len = (size_t)presenceNote_size;
    sipral_status_t status = sipral_account_publish_presence((sipral_handle_t)stack, (sipral_handle_t)account, &presence_value, (uint64_t)nowMs);
    if (presenceNote) {
        (*env)->ReleaseByteArrayElements(env, presenceNote, presenceNote_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1account_1unpublish_1presence(JNIEnv *env, jobject self, jlong stack, jlong account, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_account_unpublish_presence((sipral_handle_t)stack, (sipral_handle_t)account, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1send_1text(JNIEnv *env, jobject self, jlong media, jbyteArray text)
{
    (void)env;
    (void)self;
    jbyte *text_data = text ? (*env)->GetByteArrayElements(env, text, NULL) : NULL;
    jsize text_size = text ? (*env)->GetArrayLength(env, text) : 0;
    sipral_status_t status = sipral_media_send_text((sipral_handle_t)media, (const char *)text_data, (size_t)text_size);
    if (text) {
        (*env)->ReleaseByteArrayElements(env, text, text_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1poll_1text(JNIEnv *env, jobject self, jlong media, jlong nowMs, jlong packet)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_media_poll_text((sipral_handle_t)media, (uint64_t)nowMs, (sipral_media_packet_t *)(intptr_t)packet);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1receive_1text(JNIEnv *env, jobject self, jlong media, jbyteArray data, jbyteArray from, jlong nowMs, jlongArray taken)
{
    (void)env;
    (void)self;
    jbyte *data_data = data ? (*env)->GetByteArrayElements(env, data, NULL) : NULL;
    jsize data_size = data ? (*env)->GetArrayLength(env, data) : 0;
    jbyte *from_data = from ? (*env)->GetByteArrayElements(env, from, NULL) : NULL;
    jsize from_size = from ? (*env)->GetArrayLength(env, from) : 0;
    uint32_t taken_value = 0;
    sipral_status_t status = sipral_media_receive_text((sipral_handle_t)media, (const uint8_t *)data_data, (size_t)data_size, (const char *)from_data, (size_t)from_size, (uint64_t)nowMs, &taken_value);
    if (data) {
        (*env)->ReleaseByteArrayElements(env, data, data_data, JNI_ABORT);
    }
    if (from) {
        (*env)->ReleaseByteArrayElements(env, from, from_data, JNI_ABORT);
    }
    {
        jlong slot = (jlong)taken_value;
        (*env)->SetLongArrayRegion(env, taken, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1record_1to(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray configServer, jbyteArray configDestination, jlong configTransport, jbyteArray configThisEnd, jbyteArray configFarEnd, jlongArray recording, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_record_config_t config_value;
    memset(&config_value, 0, sizeof config_value);
    config_value.size = sizeof config_value;
    jbyte *configServer_data = configServer ? (*env)->GetByteArrayElements(env, configServer, NULL) : NULL;
    jsize configServer_size = configServer ? (*env)->GetArrayLength(env, configServer) : 0;
    config_value.server = (const char *)configServer_data;
    config_value.server_len = (size_t)configServer_size;
    jbyte *configDestination_data = configDestination ? (*env)->GetByteArrayElements(env, configDestination, NULL) : NULL;
    jsize configDestination_size = configDestination ? (*env)->GetArrayLength(env, configDestination) : 0;
    config_value.destination = (const char *)configDestination_data;
    config_value.destination_len = (size_t)configDestination_size;
    config_value.transport = (uint32_t)configTransport;
    jbyte *configThisEnd_data = configThisEnd ? (*env)->GetByteArrayElements(env, configThisEnd, NULL) : NULL;
    jsize configThisEnd_size = configThisEnd ? (*env)->GetArrayLength(env, configThisEnd) : 0;
    config_value.this_end = (const char *)configThisEnd_data;
    config_value.this_end_len = (size_t)configThisEnd_size;
    jbyte *configFarEnd_data = configFarEnd ? (*env)->GetByteArrayElements(env, configFarEnd, NULL) : NULL;
    jsize configFarEnd_size = configFarEnd ? (*env)->GetArrayLength(env, configFarEnd) : 0;
    config_value.far_end = (const char *)configFarEnd_data;
    config_value.far_end_len = (size_t)configFarEnd_size;
    sipral_handle_t recording_value = 0;
    sipral_status_t status = sipral_call_record_to((sipral_handle_t)stack, (sipral_handle_t)call, &config_value, &recording_value, (uint64_t)nowMs);
    if (configServer) {
        (*env)->ReleaseByteArrayElements(env, configServer, configServer_data, JNI_ABORT);
    }
    if (configDestination) {
        (*env)->ReleaseByteArrayElements(env, configDestination, configDestination_data, JNI_ABORT);
    }
    if (configThisEnd) {
        (*env)->ReleaseByteArrayElements(env, configThisEnd, configThisEnd_data, JNI_ABORT);
    }
    if (configFarEnd) {
        (*env)->ReleaseByteArrayElements(env, configFarEnd, configFarEnd_data, JNI_ABORT);
    }
    {
        jlong slot = (jlong)recording_value;
        (*env)->SetLongArrayRegion(env, recording, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1stop_1recording_1to(JNIEnv *env, jobject self, jlong stack, jlong call, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_stop_recording_to((sipral_handle_t)stack, (sipral_handle_t)call, (uint64_t)nowMs);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1poll_1recording(JNIEnv *env, jobject self, jlong media, jlong packet, jlongArray farEnd)
{
    (void)env;
    (void)self;
    uint32_t farEnd_value = 0;
    sipral_status_t status = sipral_media_poll_recording((sipral_handle_t)media, (sipral_media_packet_t *)(intptr_t)packet, &farEnd_value);
    {
        jlong slot = (jlong)farEnd_value;
        (*env)->SetLongArrayRegion(env, farEnd, 0, 1, &slot);
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

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1refresh(JNIEnv *env, jobject self, jlong stack, jlongArray count)
{
    (void)env;
    (void)self;
    size_t count_value = 0;
    sipral_status_t status = sipral_audio_refresh((sipral_handle_t)stack, &count_value);
    {
        jlong slot = (jlong)count_value;
        (*env)->SetLongArrayRegion(env, count, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1device_1count(JNIEnv *env, jobject self, jlong stack, jlongArray count)
{
    (void)env;
    (void)self;
    size_t count_value = 0;
    sipral_status_t status = sipral_audio_device_count((sipral_handle_t)stack, &count_value);
    {
        jlong slot = (jlong)count_value;
        (*env)->SetLongArrayRegion(env, count, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1device_1at(JNIEnv *env, jobject self, jlong stack, jlong index, jlongArray device, jbyteArray buffer, jlongArray needed)
{
    (void)env;
    (void)self;
    sipral_audio_device_t device_value;
    memset(&device_value, 0, sizeof device_value);
    device_value.size = sizeof device_value;
    jbyte *buffer_data = buffer ? (*env)->GetByteArrayElements(env, buffer, NULL) : NULL;
    jsize buffer_size = buffer ? (*env)->GetArrayLength(env, buffer) : 0;
    size_t needed_value = 0;
    sipral_status_t status = sipral_audio_device_at((sipral_handle_t)stack, (size_t)index, &device_value, (char *)buffer_data, (size_t)buffer_size, &needed_value);
    if (buffer) {
        (*env)->ReleaseByteArrayElements(env, buffer, buffer_data, 0);
    }
    {
        jlong slots[7];
        slots[0] = (jlong)device_value.size;
        slots[1] = (jlong)device_value.id;
        slots[2] = (jlong)device_value.input_channels;
        slots[3] = (jlong)device_value.output_channels;
        slots[4] = (jlong)device_value.default_input;
        slots[5] = (jlong)device_value.default_output;
        slots[6] = (jlong)device_value.present;
        (*env)->SetLongArrayRegion(env, device, 0, 7, slots);
    }
    {
        jlong slot = (jlong)needed_value;
        (*env)->SetLongArrayRegion(env, needed, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1select(JNIEnv *env, jobject self, jlong stack, jlong role, jlong device)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_audio_select((sipral_handle_t)stack, (uint32_t)role, (uint32_t)device);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1selection(JNIEnv *env, jobject self, jlong stack, jlong role, jlongArray selected, jlongArray running)
{
    (void)env;
    (void)self;
    uint32_t selected_value = 0;
    uint32_t running_value = 0;
    sipral_status_t status = sipral_audio_selection((sipral_handle_t)stack, (uint32_t)role, &selected_value, &running_value);
    {
        jlong slot = (jlong)selected_value;
        (*env)->SetLongArrayRegion(env, selected, 0, 1, &slot);
    }
    {
        jlong slot = (jlong)running_value;
        (*env)->SetLongArrayRegion(env, running, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1set_1gain(JNIEnv *env, jobject self, jlong stack, jlong direction, jlong gain)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_audio_set_gain((sipral_handle_t)stack, (uint32_t)direction, (uint32_t)gain);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1gain(JNIEnv *env, jobject self, jlong stack, jlong direction, jlongArray gain)
{
    (void)env;
    (void)self;
    uint32_t gain_value = 0;
    sipral_status_t status = sipral_audio_gain((sipral_handle_t)stack, (uint32_t)direction, &gain_value);
    {
        jlong slot = (jlong)gain_value;
        (*env)->SetLongArrayRegion(env, gain, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1set_1muted(JNIEnv *env, jobject self, jlong stack, jlong direction, jlong muted)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_audio_set_muted((sipral_handle_t)stack, (uint32_t)direction, (uint32_t)muted);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1muted(JNIEnv *env, jobject self, jlong stack, jlong direction, jlongArray muted)
{
    (void)env;
    (void)self;
    uint32_t muted_value = 0;
    sipral_status_t status = sipral_audio_muted((sipral_handle_t)stack, (uint32_t)direction, &muted_value);
    {
        jlong slot = (jlong)muted_value;
        (*env)->SetLongArrayRegion(env, muted, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1level(JNIEnv *env, jobject self, jlong stack, jlong direction, jlongArray peak)
{
    (void)env;
    (void)self;
    uint32_t peak_value = 0;
    sipral_status_t status = sipral_audio_level((sipral_handle_t)stack, (uint32_t)direction, &peak_value);
    {
        jlong slot = (jlong)peak_value;
        (*env)->SetLongArrayRegion(env, peak, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1activate(JNIEnv *env, jobject self, jlong stack)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_audio_activate((sipral_handle_t)stack);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1deactivate(JNIEnv *env, jobject self, jlong stack)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_audio_deactivate((sipral_handle_t)stack);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1ring(JNIEnv *env, jobject self, jlong stack, jshortArray samples, jlong sampleRateHz, jlong looped)
{
    (void)env;
    (void)self;
    jshort *samples_data = samples ? (*env)->GetShortArrayElements(env, samples, NULL) : NULL;
    jsize samples_size = samples ? (*env)->GetArrayLength(env, samples) : 0;
    sipral_status_t status = sipral_audio_ring((sipral_handle_t)stack, (const int16_t *)samples_data, (size_t)samples_size, (uint32_t)sampleRateHz, (uint32_t)looped);
    if (samples) {
        (*env)->ReleaseShortArrayElements(env, samples, samples_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1stop_1ringing(JNIEnv *env, jobject self, jlong stack)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_audio_stop_ringing((sipral_handle_t)stack);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1audio_1info(JNIEnv *env, jobject self, jlong stack, jlongArray info)
{
    (void)env;
    (void)self;
    sipral_audio_info_t info_value;
    memset(&info_value, 0, sizeof info_value);
    info_value.size = sizeof info_value;
    sipral_status_t status = sipral_audio_info((sipral_handle_t)stack, &info_value);
    {
        jlong slots[9];
        slots[0] = (jlong)info_value.size;
        slots[1] = (jlong)info_value.active;
        slots[2] = (jlong)info_value.system_echo_cancellation;
        slots[3] = (jlong)info_value.render_delay_ms;
        slots[4] = (jlong)info_value.microphone_rate_hz;
        slots[5] = (jlong)info_value.speaker_rate_hz;
        slots[6] = (jlong)info_value.microphone;
        slots[7] = (jlong)info_value.speaker;
        slots[8] = (jlong)info_value.ringer;
        (*env)->SetLongArrayRegion(env, info, 0, 9, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1log(JNIEnv *env, jobject self, jlong stack, jlong level, jlong callback)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_log((sipral_handle_t)stack, (uint32_t)level, callback != 0 ? jni_log_callback : NULL, (void *)(intptr_t)callback);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1state(JNIEnv *env, jobject self, jlong stack, jbyteArray buffer, jlongArray len)
{
    (void)env;
    (void)self;
    jbyte *buffer_data = buffer ? (*env)->GetByteArrayElements(env, buffer, NULL) : NULL;
    jsize buffer_size = buffer ? (*env)->GetArrayLength(env, buffer) : 0;
    size_t len_value = 0;
    sipral_status_t status = sipral_stack_state((sipral_handle_t)stack, (char *)buffer_data, (size_t)buffer_size, &len_value);
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
Java_org_sipral_SipralNative_sipral_1stack_1rtp_1port_1reserve(JNIEnv *env, jobject self, jlong stack, jlongArray port)
{
    (void)env;
    (void)self;
    uint32_t port_value = 0;
    sipral_status_t status = sipral_stack_rtp_port_reserve((sipral_handle_t)stack, &port_value);
    {
        jlong slot = (jlong)port_value;
        (*env)->SetLongArrayRegion(env, port, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1rtp_1port_1release(JNIEnv *env, jobject self, jlong stack, jlong port)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_stack_rtp_port_release((sipral_handle_t)stack, (uint32_t)port);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1stack_1stir(JNIEnv *env, jobject self, jlong stack, jbyteArray configAnchors, jlong configFreshnessSeconds, jlong configCertificateWaitMs, jlong configUnixSeconds, jlong nowMs)
{
    (void)env;
    (void)self;
    sipral_stir_config_t config_value;
    memset(&config_value, 0, sizeof config_value);
    config_value.size = sizeof config_value;
    jbyte *configAnchors_data = configAnchors ? (*env)->GetByteArrayElements(env, configAnchors, NULL) : NULL;
    jsize configAnchors_size = configAnchors ? (*env)->GetArrayLength(env, configAnchors) : 0;
    config_value.anchors = (const uint8_t *)configAnchors_data;
    config_value.anchors_len = (size_t)configAnchors_size;
    config_value.freshness_seconds = (uint64_t)configFreshnessSeconds;
    config_value.certificate_wait_ms = (uint64_t)configCertificateWaitMs;
    config_value.unix_seconds = (uint64_t)configUnixSeconds;
    sipral_status_t status = sipral_stack_stir((sipral_handle_t)stack, &config_value, (uint64_t)nowMs);
    if (configAnchors) {
        (*env)->ReleaseByteArrayElements(env, configAnchors, configAnchors_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1stir_1certificate(JNIEnv *env, jobject self, jlong stack, jlong call, jbyteArray chain, jlong nowMs)
{
    (void)env;
    (void)self;
    jbyte *chain_data = chain ? (*env)->GetByteArrayElements(env, chain, NULL) : NULL;
    jsize chain_size = chain ? (*env)->GetArrayLength(env, chain) : 0;
    sipral_status_t status = sipral_call_stir_certificate((sipral_handle_t)stack, (sipral_handle_t)call, (const uint8_t *)chain_data, (size_t)chain_size, (uint64_t)nowMs);
    if (chain) {
        (*env)->ReleaseByteArrayElements(env, chain, chain_data, JNI_ABORT);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1encryption_1count(JNIEnv *env, jobject self, jlong media, jlongArray count)
{
    (void)env;
    (void)self;
    size_t count_value = 0;
    sipral_status_t status = sipral_media_encryption_count((sipral_handle_t)media, &count_value);
    {
        jlong slot = (jlong)count_value;
        (*env)->SetLongArrayRegion(env, count, 0, 1, &slot);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1encryption_1at(JNIEnv *env, jobject self, jlong media, jlong index, jlongArray stream)
{
    (void)env;
    (void)self;
    sipral_stream_encryption_t stream_value;
    memset(&stream_value, 0, sizeof stream_value);
    stream_value.size = sizeof stream_value;
    sipral_status_t status = sipral_media_encryption_at((sipral_handle_t)media, (size_t)index, &stream_value);
    {
        jlong slots[7];
        slots[0] = (jlong)stream_value.size;
        slots[1] = (jlong)stream_value.media;
        slots[2] = (jlong)stream_value.encrypted;
        slots[3] = (jlong)stream_value.key_exchange;
        slots[4] = (jlong)stream_value.suite;
        slots[5] = (jlong)stream_value.authenticated;
        slots[6] = (jlong)stream_value.awaiting_keys;
        (*env)->SetLongArrayRegion(env, stream, 0, 7, slots);
    }
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1dtmf_1detection(JNIEnv *env, jobject self, jlong stack, jlong call, jlong mode)
{
    (void)env;
    (void)self;
    sipral_status_t status = sipral_call_dtmf_detection((sipral_handle_t)stack, (sipral_handle_t)call, (uint32_t)mode);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1detect_1progress(JNIEnv *env, jobject self, jlong stack, jlong call, jlong configListen, jlong configRegion, jlong configAnsweringMachine, jlong configBeep, jlong configBeepWindowMs, jlong configMaxInitialSilenceMs, jlong configMaxGreetingMs, jlong configSilenceAfterGreetingMs, jlong configMaxWords, jlong configMinWordMs, jlong configMinWordGapMs, jlong configMaxDecisionMs, jlong configMinSpeechAboveFloorDb, jlong configBeepMinMs, jlong configBeepMaxMs, jlong configToneCycles)
{
    (void)env;
    (void)self;
    sipral_progress_config_t config_value;
    memset(&config_value, 0, sizeof config_value);
    config_value.size = sizeof config_value;
    config_value.listen = (uint32_t)configListen;
    config_value.region = (uint32_t)configRegion;
    config_value.answering_machine = (uint32_t)configAnsweringMachine;
    config_value.beep = (uint32_t)configBeep;
    config_value.beep_window_ms = (uint32_t)configBeepWindowMs;
    config_value.max_initial_silence_ms = (uint32_t)configMaxInitialSilenceMs;
    config_value.max_greeting_ms = (uint32_t)configMaxGreetingMs;
    config_value.silence_after_greeting_ms = (uint32_t)configSilenceAfterGreetingMs;
    config_value.max_words = (uint32_t)configMaxWords;
    config_value.min_word_ms = (uint32_t)configMinWordMs;
    config_value.min_word_gap_ms = (uint32_t)configMinWordGapMs;
    config_value.max_decision_ms = (uint32_t)configMaxDecisionMs;
    config_value.min_speech_above_floor_db = (uint32_t)configMinSpeechAboveFloorDb;
    config_value.beep_min_ms = (uint32_t)configBeepMinMs;
    config_value.beep_max_ms = (uint32_t)configBeepMaxMs;
    config_value.tone_cycles = (uint32_t)configToneCycles;
    sipral_status_t status = sipral_call_detect_progress((sipral_handle_t)stack, (sipral_handle_t)call, &config_value);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1call_1consent_1tone(JNIEnv *env, jobject self, jlong stack, jlong call, jlong toneEnabled, jlong toneFrequencyHz, jlong toneAttenuationDb, jlong toneLengthMs, jlong toneIntervalMs, jlong toneLocal)
{
    (void)env;
    (void)self;
    sipral_consent_tone_t tone_value;
    memset(&tone_value, 0, sizeof tone_value);
    tone_value.size = sizeof tone_value;
    tone_value.enabled = (uint32_t)toneEnabled;
    tone_value.frequency_hz = (uint32_t)toneFrequencyHz;
    tone_value.attenuation_db = (uint32_t)toneAttenuationDb;
    tone_value.length_ms = (uint32_t)toneLengthMs;
    tone_value.interval_ms = (uint32_t)toneIntervalMs;
    tone_value.local = (uint32_t)toneLocal;
    sipral_status_t status = sipral_call_consent_tone((sipral_handle_t)stack, (sipral_handle_t)call, &tone_value);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_org_sipral_SipralNative_sipral_1media_1record_1start_1with(JNIEnv *env, jobject self, jlong media, jbyteArray path, jlong optionsFormat, jlong optionsLayout, jlong optionsSampleRate, jlong optionsBitrate, jlong optionsCheckpointMs)
{
    (void)env;
    (void)self;
    jbyte *path_data = path ? (*env)->GetByteArrayElements(env, path, NULL) : NULL;
    jsize path_size = path ? (*env)->GetArrayLength(env, path) : 0;
    sipral_recording_options_t options_value;
    memset(&options_value, 0, sizeof options_value);
    options_value.size = sizeof options_value;
    options_value.format = (uint32_t)optionsFormat;
    options_value.layout = (uint32_t)optionsLayout;
    options_value.sample_rate = (uint32_t)optionsSampleRate;
    options_value.bitrate = (uint32_t)optionsBitrate;
    options_value.checkpoint_ms = (uint32_t)optionsCheckpointMs;
    sipral_status_t status = sipral_media_record_start_with((sipral_handle_t)media, (const char *)path_data, (size_t)path_size, &options_value);
    if (path) {
        (*env)->ReleaseByteArrayElements(env, path, path_data, JNI_ABORT);
    }
    return (jint)status;
}

