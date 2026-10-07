// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

/// Sipral for Dart and Flutter: a SIP stack, its accounts and calls, and
/// its events as a stream, over the C ABI through dart:ffi.
///
/// `package:sipral/sipral_abi.dart` is the raw surface this is written
/// against, for what the idiomatic layer does not reach.
library;

export 'src/idiomatic.dart'
    show
        SipralAccount,
        SipralCall,
        SipralException,
        SipralDns,
        SipralLookup,
        SipralMedia,
        SipralMediaStatistics,
        SipralNetworkTestResult,
        SipralPinnedCertificateInfo,
        SipralResolver,
        SipralSettings,
        SipralStack,
        SipralStackEvent,
        advertisedAddress,
        routeHost,
        sipralPinDigest;
export 'src/sipral_abi.dart'
    show
        Sipral,
        SipralCallState,
        SipralChallengeRefusal,
        SipralDnsAnswer,
        SipralDnsRecordType,
        SipralEventKind,
        SipralHeldAudio,
        SipralLoadError,
        SipralLocateFailure,
        SipralNatKind,
        SipralNetworkProbe,
        SipralNetworkVerdict,
        SipralRegistrationFailure,
        SipralRegistrationState,
        SipralServerReach,
        SipralSrtp,
        SipralSrtpSuite,
        SipralStatus,
        SipralToggle,
        SipralTokenError,
        SipralTransport;
