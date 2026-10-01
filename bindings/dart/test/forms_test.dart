// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// What the layer reads and waits out without a stack: every certificate pin
// form in bindings/fixtures/pin-forms.txt, the list each layer's parser is
// held to, and a clock reading the stack's last one beat, read again.

import 'dart:io';

import 'package:sipral/sipral.dart';
import 'package:sipral/src/idiomatic.dart' show retryingClockBehind;
import 'package:test/test.dart';

void main() {
  test('every form of a fingerprint in pin-forms.txt is read or refused', () {
    // dart test runs from the package's own directory, bindings/dart
    final listed = File('../fixtures/pin-forms.txt');
    var digest = <int>[];
    var checked = 0;
    for (final line in listed.readAsStringSync().split('\n')) {
      if (line.isEmpty || line.startsWith('#')) {
        continue;
      }
      final tab = line.indexOf('\t');
      final verdict = tab < 0 ? line : line.substring(0, tab);
      final text = tab < 0 ? '' : line.substring(tab + 1);
      switch (verdict) {
        case 'digest':
          digest = [
            for (var at = 0; at < text.length; at += 2)
              int.parse(text.substring(at, at + 2), radix: 16),
          ];
        case 'accept':
          expect(sipralPinDigest(text), digest, reason: text);
          checked++;
        default:
          expect(
            () => sipralPinDigest(text),
            throwsArgumentError,
            reason: text,
          );
          checked++;
      }
    }
    expect(digest, hasLength(32));
    expect(checked, greaterThan(20));
  });

  test('a clock behind is read again, and nothing else is', () {
    var attempts = 0;
    final status = retryingClockBehind(() {
      attempts++;
      return attempts < 3 ? SipralStatus.clockBehind : SipralStatus.ok;
    });
    expect(status, SipralStatus.ok);
    expect(attempts, 3);

    attempts = 0;
    final refused = retryingClockBehind(() {
      attempts++;
      return SipralStatus.wrongState;
    });
    expect(refused, SipralStatus.wrongState);
    expect(attempts, 1);
  });
}
