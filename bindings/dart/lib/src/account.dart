// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// One `sipral_account_add` handle.

part of 'idiomatic.dart';

/// An identity a stack places and takes calls as, made by
/// [SipralStack.addAccount].
final class SipralAccount {
  SipralAccount._(
    this.stack,
    this.handle,
    this.aor,
    this.registrarAddress,
    this.serverUri,
    this._derivesContact,
    this._advertised,
    this.streamProtocol,
    this._tlsPin,
  );

  /// The `SipralTransport` value of the connection of its own the account's
  /// requests go over, `tcp` or `tls`, or null for the stack's UDP socket.
  final int? streamProtocol;

  /// The certificate pin it was added with, which a TLS connection of its
  /// own is held to.
  final String? _tlsPin;

  /// Where the account's requests go, `host:port`: the address it was added
  /// with, or -- for one added with a [serverUri] -- the address it was last
  /// located at, empty until then.
  String registrarAddress;

  /// The server named by a URI RFC 3263 locates, or null.
  final String? serverUri;

  /// Whether its `Contact` is the one this layer derives, and the
  /// `host:port` it names when this layer chose it.
  final bool _derivesContact;
  String? _advertised;

  /// `sipral_account_check_certificate`: the verdict of this account's
  /// `tlsPin` on [certificate], the DER bytes of the leaf a TLS server
  /// presented, from inside the application's own certificate check. The
  /// certificate's dates when it is the pinned one -- accept the handshake
  /// whoever signed it, an expired one included; null when the account pins
  /// nothing and the platform's own checks decide; a [SipralException] with
  /// `SipralStatus.certificateRefused` when it pins another.
  SipralPinnedCertificateInfo? checkCertificate(
    List<int> certificate, {
    int? unixSeconds,
  }) {
    stack._ensureOpen();
    return using((arena) {
      final bytes = arena<ffi.Uint8>(max(1, certificate.length));
      bytes.asTypedList(certificate.length).setAll(0, certificate);
      final out = arena<SipralPinnedCertificate>();
      out.ref.size = ffi.sizeOf<SipralPinnedCertificate>();
      _check(
        stack._sipral,
        'sipral_account_check_certificate',
        stack._sipral.accountCheckCertificate(
          stack.handle,
          handle,
          bytes,
          certificate.length,
          unixSeconds ?? DateTime.now().millisecondsSinceEpoch ~/ 1000,
          out,
        ),
      );
      final found = out.ref;
      return found.pinned == 0
          ? null
          : SipralPinnedCertificateInfo(
            found.notBefore,
            found.notAfter,
            expired: found.expired != 0,
            notYetValid: found.notYetValid != 0,
          );
    });
  }

  /// The stack it belongs to.
  final SipralStack stack;

  /// The account's handle.
  final int handle;

  /// Its address of record.
  final String aor;

  final StreamController<int> _registration = StreamController.broadcast();

  /// Each `SipralRegistrationState` value the account moves to, as it
  /// moves.
  Stream<int> get registration => _registration.stream;

  /// Where the account's registration is now, a `SipralRegistrationState`
  /// value.
  int get registrationState => using((arena) {
    final out = arena<ffi.Uint32>();
    _check(
      stack._sipral,
      'sipral_account_registration_state',
      stack._sipral.accountRegistrationState(stack.handle, handle, out),
    );
    return out.value;
  });

  /// Start registering, and keep the binding refreshed.
  void register() {
    stack._ensureOpen();
    _checkNow(
      stack._sipral,
      'sipral_account_register',
      () => stack._sipral.accountRegister(stack.handle, handle, stack.nowMs()),
    );
    stack._poll();
  }

  /// Register, and complete once the registrar holds a binding; complete
  /// with a [StateError] if registration fails, and with a
  /// [TimeoutException] after [timeout].
  Future<void> registered({Duration timeout = const Duration(seconds: 10)}) {
    final settled = registration
        .firstWhere(
          (state) =>
              state == SipralRegistrationState.registered ||
              state == SipralRegistrationState.failed,
        )
        .timeout(timeout);
    register();
    return settled.then((state) {
      if (state != SipralRegistrationState.registered) {
        throw StateError('sipral: $aor did not register');
      }
    });
  }

  /// Remove the binding, and stop refreshing it.
  void unregister() {
    stack._ensureOpen();
    _checkNow(
      stack._sipral,
      'sipral_account_unregister',
      () =>
          stack._sipral.accountUnregister(stack.handle, handle, stack.nowMs()),
    );
    stack._poll();
  }

  /// Remove the account from its stack.
  void remove() {
    stack._ensureOpen();
    _check(
      stack._sipral,
      'sipral_account_remove',
      stack._sipral.accountRemove(stack.handle, handle),
    );
    stack._accounts.remove(handle);
    _registration.close();
  }

  void _deliver(SipralStackEvent event) {
    final state = event.registrationState;
    if (state != null && !_registration.isClosed) {
      _registration.add(state);
    }
  }
}
