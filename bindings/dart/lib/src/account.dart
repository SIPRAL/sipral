// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// One `sipral_account_add` handle.

part of 'idiomatic.dart';

/// An identity a stack places and takes calls as, made by
/// [SipralStack.addAccount].
final class SipralAccount {
  SipralAccount._(this.stack, this.handle, this.aor);

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
    _check(
      stack._sipral,
      'sipral_account_register',
      stack._sipral.accountRegister(stack.handle, handle, stack.nowMs()),
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
    _check(
      stack._sipral,
      'sipral_account_unregister',
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
