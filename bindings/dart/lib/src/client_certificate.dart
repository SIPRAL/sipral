// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The certificate an account's TLS connection presents when its server asks
// for one, and what a refusal of it is called.

part of 'idiomatic.dart';

/// The certificate this end presents to a server that asks for one (mutual
/// TLS), in PEM: [SipralClientCertificate.pem] from bytes,
/// [SipralClientCertificate.files] from files read again for every
/// connection, so a certificate renewed on disk is presented on the next.
///
/// The chain is the leaf first, then any intermediates; the key is the
/// leaf's, unencrypted or opened with `password`. Dart's TLS signs with the
/// key in this process: a key held by a hardware module or the operating
/// system needs the Swift, Kotlin or .NET layer.
///
/// Before each connection the key is loaded against the leaf and the leaf's
/// dates are read: a key that does not load or belong to it is
/// `SipralTlsFailure.clientKeyUnavailable`, a leaf out of its dates
/// `SipralTlsFailure.clientCertificateExpired`, each raised as
/// `SipralEventKind.transportFailed` with nothing sent to the server.
final class SipralClientCertificate {
  /// The chain and key as PEM bytes.
  SipralClientCertificate.pem(List<int> chain, List<int> key, {this.password})
    : _chain = Uint8List.fromList(chain),
      _key = Uint8List.fromList(key),
      _chainPath = null,
      _keyPath = null;

  /// The chain and key in PEM files at [chainPath] and [keyPath].
  SipralClientCertificate.files(
    String chainPath,
    String keyPath, {
    this.password,
  }) : _chain = null,
       _key = null,
       _chainPath = chainPath,
       _keyPath = keyPath;

  final Uint8List? _chain;
  final Uint8List? _key;
  final String? _chainPath;
  final String? _keyPath;

  /// The password of an encrypted key, or null for none.
  final String? password;

  /// A context presenting it, trusting the platform's authorities or none:
  /// the key is loaded against the leaf and the leaf is within its dates at
  /// [now], or a [_ClientCertificateUnusable] says which is not.
  SecurityContext _context({
    required bool withTrustedRoots,
    required DateTime now,
  }) {
    Uint8List chain;
    Uint8List key;
    try {
      chain = _chain ?? File(_chainPath!).readAsBytesSync();
      key = _key ?? File(_keyPath!).readAsBytesSync();
    } on FileSystemException catch (unread) {
      throw _ClientCertificateUnusable(
        SipralTlsFailure.clientKeyUnavailable,
        'the client certificate could not be read: ${unread.message} '
        '(${unread.path})',
      );
    }
    final context = SecurityContext(withTrustedRoots: withTrustedRoots);
    try {
      context
        ..useCertificateChainBytes(chain)
        ..usePrivateKeyBytes(key, password: password);
    } on TlsException catch (refused) {
      throw _ClientCertificateUnusable(
        SipralTlsFailure.clientKeyUnavailable,
        'the client certificate\'s key cannot be used: ${refused.message} '
        '${refused.osError?.message ?? ''}',
      );
    } on ArgumentError catch (refused) {
      throw _ClientCertificateUnusable(
        SipralTlsFailure.clientKeyUnavailable,
        'the client certificate\'s key cannot be used: ${refused.message}',
      );
    }
    final dates = _leafValidity(chain);
    if (dates == null) {
      throw const _ClientCertificateUnusable(
        SipralTlsFailure.clientKeyUnavailable,
        'the client certificate chain holds no certificate this layer reads',
      );
    }
    if (now.isBefore(dates.$1) || now.isAfter(dates.$2)) {
      throw _ClientCertificateUnusable(
        SipralTlsFailure.clientCertificateExpired,
        'the client certificate is valid from '
        '${dates.$1.toIso8601String()} to ${dates.$2.toIso8601String()}',
      );
    }
    return context;
  }
}

/// A client certificate that cannot be used, found before connecting.
final class _ClientCertificateUnusable implements Exception {
  const _ClientCertificateUnusable(this.tls, this.message);

  /// `SipralTlsFailure.clientKeyUnavailable` or `clientCertificateExpired`.
  final int tls;
  final String message;

  @override
  String toString() => message;
}

/// The validity of the first certificate in a PEM [chain], read from its DER
/// (RFC 5280 §4.1: `tbsCertificate`, past `version`, `serialNumber`,
/// `signature` and `issuer`), or null when there is none to read.
(DateTime, DateTime)? _leafValidity(Uint8List chain) {
  final pem = latin1.decode(chain);
  final found = RegExp(
    r'-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----',
  ).firstMatch(pem);
  if (found == null) {
    return null;
  }
  final Uint8List der;
  try {
    der = base64.decode(found.group(1)!.replaceAll(RegExp(r'\s'), ''));
  } on FormatException {
    return null;
  }
  // one element: its tag, where its content starts and where it ends
  (int, int, int)? element(int at, int limit) {
    if (at + 2 > limit) {
      return null;
    }
    final tag = der[at];
    var length = der[at + 1];
    var start = at + 2;
    if (length & 0x80 != 0) {
      final count = length & 0x7f;
      if (count == 0 || count > 4 || start + count > limit) {
        return null;
      }
      length = 0;
      for (var i = 0; i < count; i++) {
        length = (length << 8) | der[start + i];
      }
      start += count;
    }
    return start + length > limit ? null : (tag, start, start + length);
  }

  final certificate = element(0, der.length);
  final tbs =
      certificate == null ? null : element(certificate.$2, certificate.$3);
  if (tbs == null) {
    return null;
  }
  var item = element(tbs.$2, tbs.$3);
  if (item != null && item.$1 == 0xa0) {
    item = element(item.$3, tbs.$3);
  }
  final signature = item == null ? null : element(item.$3, tbs.$3);
  final issuer = signature == null ? null : element(signature.$3, tbs.$3);
  final validity = issuer == null ? null : element(issuer.$3, tbs.$3);
  if (validity == null || validity.$1 != 0x30) {
    return null;
  }
  final notBefore = element(validity.$2, validity.$3);
  final notAfter =
      notBefore == null ? null : element(notBefore.$3, validity.$3);
  if (notBefore == null || notAfter == null) {
    return null;
  }
  final from = _asn1Time(der, notBefore);
  final to = _asn1Time(der, notAfter);
  return from == null || to == null ? null : (from, to);
}

/// A UTCTime (`YYMMDDHHMMSSZ`, RFC 5280 §4.1.2.5.1) or GeneralizedTime
/// (`YYYYMMDDHHMMSSZ`, §4.1.2.5.2) element as a UTC [DateTime].
DateTime? _asn1Time(Uint8List der, (int, int, int) element) {
  final text = latin1.decode(der.sublist(element.$2, element.$3));
  final match = switch (element.$1) {
    0x17 => RegExp(
      r'^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$',
    ).firstMatch(text),
    0x18 => RegExp(
      r'^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$',
    ).firstMatch(text),
    _ => null,
  };
  if (match == null) {
    return null;
  }
  var year = int.parse(match.group(1)!);
  if (element.$1 == 0x17) {
    year += year < 50 ? 2000 : 1900;
  }
  return DateTime.utc(
    year,
    int.parse(match.group(2)!),
    int.parse(match.group(3)!),
    int.parse(match.group(4)!),
    int.parse(match.group(5)!),
    int.parse(match.group(6)!),
  );
}

/// The alerts a server sends about the client's certificate, as BoringSSL
/// names them: certificate_required (116), bad_certificate (42),
/// unsupported_certificate (43), certificate_revoked (44),
/// certificate_unknown (46), unknown_ca (48) and access_denied (49).
final RegExp _clientCertificateAlert = RegExp(
  r'ALERT_(CERTIFICATE_REQUIRED|BAD_CERTIFICATE|UNSUPPORTED_CERTIFICATE|'
  r'CERTIFICATE_REVOKED|CERTIFICATE_UNKNOWN|UNKNOWN_CA|ACCESS_DENIED)',
);

/// What a TLS failure was about the client certificate, a
/// `SipralTlsFailure` value, or null when it was about something else.
///
/// [presented] says whether this end offered a certificate: an alert about
/// it is then that certificate refused -- certificate_expired (45), expired
/// -- and without one a certificate the server required. These come during
/// the handshake under TLS 1.2 and on the first read after it under TLS
/// 1.3. A bare handshake_failure is not read as one: Dart does not say
/// whether the server had asked for a certificate.
int? _clientCertificateFailure(Object refused, {required bool presented}) {
  if (refused is _ClientCertificateUnusable) {
    return refused.tls;
  }
  final said =
      switch (refused) {
        TlsException(:final message, :final osError) =>
          '$message ${osError?.message ?? ''}',
        SocketException(:final message, :final osError) =>
          '$message ${osError?.message ?? ''}',
        _ => refused.toString(),
      }.toUpperCase();
  if (_clientCertificateAlert.hasMatch(said)) {
    return presented
        ? SipralTlsFailure.clientCertificateRefused
        : SipralTlsFailure.clientCertificateRequired;
  }
  if (presented && said.contains('ALERT_CERTIFICATE_EXPIRED')) {
    return SipralTlsFailure.clientCertificateExpired;
  }
  return null;
}
