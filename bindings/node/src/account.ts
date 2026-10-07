// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// One `sipral_account_add` handle.

import { EventEmitter } from 'node:events';

import type { StackEvent } from './events.js';
import { check, checkNow, within } from './internal.js';
import { SipralRegistrationState } from './sipral_abi.js';
import type { Stack } from './stack.js';

/** What an account emits. */
export interface AccountEvents {
  /** Every `RegistrationChanged` for this account: its new `SipralRegistrationState`. */
  registration: [number, StackEvent];
  /** Every event about this account, in order. */
  event: [StackEvent];
}

/** An account added with {@link Stack.addAccount}. */
export class Account extends EventEmitter<AccountEvents> {
  /** The stack it belongs to. */
  readonly stack: Stack;
  /** The account's handle. */
  readonly handle: bigint;
  /** Its address of record. */
  readonly aor: string;
  /** Where its requests go, `host:port`. */
  readonly registrarAddress: string;

  /** @internal Built by the stack. */
  constructor(stack: Stack, accountHandle: bigint, aor: string, registrarAddress: string) {
    super();
    this.stack = stack;
    this.handle = accountHandle;
    this.aor = aor;
    this.registrarAddress = registrarAddress;
  }

  /** Where its registration is, a `SipralRegistrationState` value. */
  get registrationState(): number {
    const sipral = this.stack.sipral;
    const out = new Uint32Array(1);
    check(
      sipral,
      'sipral_account_registration_state',
      sipral.sipral_account_registration_state(this.stack.handle, this.handle, out),
    );
    return out[0] ?? SipralRegistrationState.Unknown;
  }

  /** Send a REGISTER now (`sipral_account_register`); refreshes follow by themselves. */
  register(): void {
    this.stack.ensureOpen();
    checkNow(this.stack.sipral, 'sipral_account_register', () =>
      this.stack.sipral.sipral_account_register(this.stack.handle, this.handle, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * Register and resolve once the registrar has taken it; reject when the
   * registration failed, with a `TimeoutError` after `timeoutMs`.
   */
  registered(timeoutMs = 10000): Promise<void> {
    const settled = within(
      new Promise<void>((resolve, reject) => {
        const listener = (state: number): void => {
          if (state === SipralRegistrationState.Registered) {
            this.off('registration', listener);
            resolve();
          } else if (state === SipralRegistrationState.Failed) {
            this.off('registration', listener);
            reject(new Error(`sipral: ${this.aor} did not register`));
          }
        };
        this.on('registration', listener);
      }),
      timeoutMs,
      `${this.aor} registering`,
    );
    this.register();
    return settled;
  }

  /** Remove the binding (`sipral_account_unregister`): a REGISTER with `Expires: 0`. */
  unregister(): void {
    this.stack.ensureOpen();
    checkNow(this.stack.sipral, 'sipral_account_unregister', () =>
      this.stack.sipral.sipral_account_unregister(this.stack.handle, this.handle, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /** Forget the account (`sipral_account_remove`). */
  remove(): void {
    this.stack.ensureOpen();
    check(
      this.stack.sipral,
      'sipral_account_remove',
      this.stack.sipral.sipral_account_remove(this.stack.handle, this.handle),
    );
    this.stack.forgetAccount(this);
    this.removeAllListeners();
  }

  /** @internal What the stack hands each event about this account to. */
  deliver(event: StackEvent): void {
    if (event.registrationState !== null) {
      this.emit('registration', event.registrationState, event);
    }
    this.emit('event', event);
  }
}
