// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The longest a failed subscription of an account waits before trying again:
// a value the record's 32 bits hold is taken, one past them is refused before
// it reaches the library. The back-off itself is the library's, tested there.

import 'package:sipral/sipral.dart';
import 'package:test/test.dart';

void main() {
  test('a subscription retry limit is taken within 32 bits and refused '
      'past them', () async {
    final stack = await SipralStack.open(bindHost: '127.0.0.1');
    try {
      final account = stack.addAccount(
        'sip:alice@example.com',
        registrarAddress: '127.0.0.1:5060',
        subscriptionRetryMaxSeconds: 120,
      );
      expect(account.handle, isNot(0));
      for (final wrong in [-1, 0x100000000]) {
        expect(
          () => stack.addAccount(
            'sip:bob@example.com',
            registrarAddress: '127.0.0.1:5060',
            subscriptionRetryMaxSeconds: wrong,
          ),
          throwsArgumentError,
        );
      }
    } finally {
      await stack.close();
    }
  });
}
