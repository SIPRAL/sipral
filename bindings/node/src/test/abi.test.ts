// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The library loads, serves the ABI this binding was printed from, and lays
// out every record the way koffi was told to: each record's koffi size is
// the 64-bit length tools/abi-gen worked out, and the library's own answer.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import koffi from 'koffi';

import {
  RECORD_LAYOUTS,
  SIPRAL_ABI_VERSION_MAJOR,
  SIPRAL_ABI_VERSION_MINOR,
  Sipral,
  SipralStatus,
} from '../sipral_abi.js';

test('the library serves this binding and lays out every record as koffi does', () => {
  const sipral = Sipral.open();
  assert.equal(sipral.sipral_abi_check(SIPRAL_ABI_VERSION_MAJOR, SIPRAL_ABI_VERSION_MINOR), SipralStatus.Ok);
  assert.notEqual(sipral.sipral_abi_check(SIPRAL_ABI_VERSION_MAJOR + 1, 0), SipralStatus.Ok);
  const names = Object.keys(RECORD_LAYOUTS);
  assert.ok(names.length > 50, `${names.length} records`);
  for (const [name, [p64]] of Object.entries(RECORD_LAYOUTS)) {
    assert.equal(koffi.sizeof(name), p64, `${name} as koffi lays it out`);
  }
  assert.equal(sipral.sipral_status_name(SipralStatus.Ok), 'ok');
});
