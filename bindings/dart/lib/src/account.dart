// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
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

  final String? _tlsPin;

  /// Where the account's requests go, `host:port`. For an account added with
  /// a [serverUri], the address it was last located at, empty until then.
  String registrarAddress;

  /// The server URI located by RFC 3263, or null.
  final String? serverUri;

  final bool _derivesContact;
  String? _advertised;

  /// `sipral_account_check_certificate`: checks the DER leaf [certificate] a
  /// TLS server presented against this account's `tlsPin`. Returns the
  /// certificate's dates when it is the pinned one (accept the handshake,
  /// even if expired); null when the account pins nothing and the platform
  /// decides. Throws a [SipralException] with
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

  /// `sipral_account_set_access_token`: sets the OAuth 2.0 access token
  /// (RFC 8898), replacing any previous one; null removes it. This answers
  /// `SipralEventKind.tokenRequired` and is how a renewed token goes in; the
  /// next `Bearer` challenge is answered with it. A registration that failed
  /// for want of a token restarts with [register]. Throws a [SipralException]
  /// with `invalidArgument`, changing nothing, for a token that is not an
  /// RFC 6750 `b64token`.
  void setAccessToken(String? token) {
    stack._ensureOpen();
    using((arena) {
      final (data, length) = _text(arena, token);
      _checkNow(
        stack._sipral,
        'sipral_account_set_access_token',
        () => stack._sipral.accountSetAccessToken(
          stack.handle,
          handle,
          data,
          length,
        ),
      );
      if (length > 0) {
        data.cast<ffi.Uint8>().asTypedList(length).fillRange(0, length, 0);
      }
    });
  }

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

  /// Remove the binding (REGISTER with Expires: 0) and stop refreshing it.
  ///
  /// The state reads unregistered at once; the registrar's answer comes as a
  /// later registration-changed event. Wait for it before closing the stack,
  /// or a challenge to the un-REGISTER goes unanswered.
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
