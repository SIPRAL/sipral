// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The printed binding against the library it loads: the ABI check passes,
// and every struct and union dart:ffi lays out here is as long as the
// library compiled it.

import 'dart:convert';
import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart';
import 'package:sipral/sipral_abi.dart';
import 'package:test/test.dart';

void main() {
  final sipral = Sipral.open();

  test('the library serves the ABI this binding was printed from', () {
    final version = calloc<SipralAbiVersion>();
    addTearDown(() => calloc.free(version));
    version.ref.size = ffi.sizeOf<SipralAbiVersion>();
    expect(sipral.abiVersion(version), SipralStatus.ok);
    expect(version.ref.major, Sipral.abiVersionMajor);
    expect(version.ref.minor, greaterThanOrEqualTo(Sipral.abiVersionMinor));
  });

  test('every record is laid out as long as the library compiled it', () {
    final sizes = Sipral.recordSizes();
    expect(sizes, isNotEmpty);
    using((arena) {
      final out = arena<ffi.Size>();
      for (final MapEntry(key: name, value: size) in sizes.entries) {
        final bytes = utf8.encode(name);
        final text = arena<ffi.Uint8>(bytes.length);
        text.asTypedList(bytes.length).setAll(0, bytes);
        expect(
          sipral.abiStructSize(text.cast(), bytes.length, out),
          SipralStatus.ok,
          reason: '$name is not a struct the library knows',
        );
        expect(size, out.value, reason: name);
      }
    });
  });

  test('a status is named by the library', () {
    final name = sipral.statusName(SipralStatus.invalidArgument);
    expect(name.cast<Utf8>().toDartString(), isNotEmpty);
  });
}
