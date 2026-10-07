// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Where a stack is reached, and where a server named by a name is.

part of 'idiomatic.dart';

/// A resolver's answer to one lookup: a `SipralDnsAnswer` value and, with
/// `records`, each record as its time-to-live in seconds followed by its data
/// in zone-file form: `300 192.0.2.40`, `300 10 60 5060 sip1.example.com`
/// (`sipral_account_looked_up`).
final class SipralLookup {
  const SipralLookup(this.answer, [this.records = const []]);

  /// The name has no record of that kind, or does not exist.
  static const nothing = SipralLookup(SipralDnsAnswer.nothing);

  /// The resolver could not answer.
  static const failed = SipralLookup(SipralDnsAnswer.failed);

  /// A `SipralDnsAnswer` value.
  final int answer;

  /// The records.
  final List<String> records;
}

/// Answers `SipralEventKind.lookupWanted` for the accounts a stack added
/// with a `serverUri`: the name and the kind of record asked for (a
/// `SipralDnsRecordType` value), and what the DNS said.
typedef SipralResolver = Future<SipralLookup> Function(String name, int record);

/// The resolver a [SipralStack] uses when it is given none.
///
/// `dart:io` only resolves addresses, so A and AAAA come from
/// [InternetAddress.lookup] (hosts file included) with a time-to-live of
/// [addressTtl] seconds. SRV and NAPTR are answered `nothing`, which RFC 3263
/// treats as a domain that publishes none. An application whose server
/// publishes SRV records passes its own resolver.
abstract final class SipralDns {
  /// Seconds an address found by the platform is kept before it is looked up
  /// again.
  static const int addressTtl = 60;

  /// The platform's resolver.
  static Future<SipralLookup> platform(String name, int record) async {
    final type = switch (record) {
      SipralDnsRecordType.a => InternetAddressType.IPv4,
      SipralDnsRecordType.aaaa => InternetAddressType.IPv6,
      _ => null,
    };
    if (type == null) {
      return SipralLookup.nothing;
    }
    final List<InternetAddress> found;
    try {
      found = await InternetAddress.lookup(name, type: type);
    } on SocketException {
      return SipralLookup.nothing;
    }
    final records =
        found
            .where((one) => one.type == type)
            .map((one) => one.address.split('%').first)
            .toSet()
            .map((one) => '$addressTtl $one')
            .toList();
    return records.isEmpty
        ? SipralLookup.nothing
        : SipralLookup(SipralDnsAnswer.records, records);
  }
}

/// `sipral_advertised_address`: the `host:port` to advertise for a socket
/// bound at [bound] whose traffic goes to [peer]. A wildcard bind
/// (`0.0.0.0:5060`) gives the address of the route toward [peer]; a loopback
/// bind toward a peer that is not throws a [SipralException] with
/// `SipralStatus.unreachableAddress`, and no route at all with
/// `SipralStatus.transportDown`. Both are addresses, not names. [library] is
/// the library to use, [Sipral.open]'s by default.
String advertisedAddress(String bound, String peer, {Sipral? library}) {
  final sipral = library ?? _library();
  return using((arena) {
    final boundText = _text(arena, bound);
    final peerText = _text(arena, peer);
    final buffer = arena<ffi.Char>(_addressBytes);
    final needed = arena<ffi.Size>();
    _check(
      sipral,
      'sipral_advertised_address',
      sipral.advertisedAddress(
        boundText.$1,
        boundText.$2,
        peerText.$1,
        peerText.$2,
        buffer,
        _addressBytes,
        needed,
      ),
    );
    return _decode(buffer.cast(), max(0, needed.value - 1));
  });
}

/// The host of this machine's route toward [peer] (`host:port`). Returns
/// `127.0.0.1` when there is no peer, it is a name rather than an address,
/// or no route reaches it.
String routeHost(String? peer, {Sipral? library}) {
  if (peer == null || _parseAddress(peer) == null) {
    return '127.0.0.1';
  }
  try {
    final wildcard = peer.startsWith('[') ? '[::]:0' : '0.0.0.0:0';
    final advertised = advertisedAddress(wildcard, peer, library: library);
    return advertised.substring(0, advertised.lastIndexOf(':'));
  } on SipralException {
    return '127.0.0.1';
  }
}

/// What `sipral_account_check_certificate` found in the certificate an
/// account pins: its dates, in seconds since 1970 (zero when its DER could
/// not be read that far), and whether the clock is past or before them.
/// Accepted either way; an expired one is worth a warning.
final class SipralPinnedCertificateInfo {
  const SipralPinnedCertificateInfo(
    this.notBefore,
    this.notAfter, {
    required this.expired,
    required this.notYetValid,
  });

  final int notBefore;
  final int notAfter;
  final bool expired;
  final bool notYetValid;
}
