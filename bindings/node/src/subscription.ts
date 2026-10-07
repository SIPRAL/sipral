// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Something at the far end this stack watches (RFC 6665): a presentity's
// `presence` (RFC 3856), a focus's `conference` (RFC 4575), a line's
// `dialog` (RFC 4235), or any other package an account subscribes to.

import { check, checkNow, copyText, plain, record, retryingClockBehind } from './internal.js';
import { SipralConferenceText, SipralDialogPhase, SipralDialogText, SipralStatus, SipralSubscriptionState } from './sipral_abi.js';
import type { Stack } from './stack.js';

/** One user of a conference, as its focus describes it (RFC 4575 §5.6). */
export interface Participant {
  /** The address of record it takes part as. */
  readonly entity: string | null;
  /** Its display text. */
  readonly displayText: string | null;
  /** Where its first endpoint is. */
  readonly endpoint: string | null;
  /** That endpoint's status, a `SipralEndpointStatus` value. */
  readonly status: number;
  /** How many endpoints it is in from. */
  readonly endpoints: number;
  /** How many media streams its first endpoint has. */
  readonly media: number;
}

/**
 * A conference as a `conference` subscription holds it (RFC 4575 §5).
 * `userCount` is what `conference-state` said, which may differ from the
 * users listed; `active` and `locked` are null when it said nothing.
 */
export interface ConferencePicture {
  readonly version: number;
  readonly entity: string | null;
  readonly subject: string | null;
  readonly displayText: string | null;
  readonly userCount: number | null;
  readonly active: boolean | null;
  readonly locked: boolean | null;
  readonly users: readonly Participant[];
}

/** One dialog a `dialog` subscription watches (RFC 4235). */
export interface WatchedDialog {
  /** A `SipralDialogPhase` value. */
  readonly phase: number;
  /** A `SipralDialogDirection` value. */
  readonly direction: number;
  /** A `SipralDialogEnded` value. */
  readonly ended: number;
  /** The status the dialog ended with, or zero. */
  readonly statusCode: number;
  /** How long it has lasted, in milliseconds. */
  readonly durationMs: number;
  /** Its `id`, its `Call-ID` and both ends, as the notifier wrote them. */
  readonly id: string | null;
  readonly callId: string | null;
  readonly localIdentity: string | null;
  readonly localDisplay: string | null;
  readonly remoteIdentity: string | null;
  readonly remoteDisplay: string | null;
  readonly localTarget: string | null;
  readonly remoteTarget: string | null;
}

/** `1` true, `2` false, anything else not said. */
function tristate(value: number): boolean | null {
  return value === 1 ? true : value === 2 ? false : null;
}

/**
 * One subscription's handle. Made by {@link Account.subscribe},
 * {@link Account.watchPresence} and {@link Call.subscribeConference}; the
 * stack refreshes it while it is live, and what the notifier says arrives on
 * the stack's events naming {@link handle}: `PresenceChanged` for a
 * presentity, `ConferenceChanged` for a conference, `Notified` for any
 * other package.
 */
export class Subscription {
  /** The stack it belongs to. */
  readonly stack: Stack;
  /** The handle the events about it name. */
  readonly handle: bigint;
  /** The event package, as it went out. */
  readonly package: string;

  /** @internal Built by the account or the call. */
  constructor(stack: Stack, subscriptionHandle: bigint, eventPackage: string) {
    this.stack = stack;
    this.handle = subscriptionHandle;
    this.package = eventPackage;
  }

  /** `sipral_subscription_state`, read fresh: `Unknown` once it has ended. */
  get state(): number {
    const out = new Uint32Array(1);
    const sipral = this.stack.sipral;
    checkNow(sipral, 'sipral_subscription_state', () =>
      sipral.sipral_subscription_state(this.stack.handle, this.handle, out),
    );
    return out[0] ?? SipralSubscriptionState.Unknown;
  }

  /**
   * `sipral_subscription_end`: an unsubscribe goes out, and the
   * subscription is over once the notifier's closing NOTIFY is answered.
   */
  end(): void {
    const sipral = this.stack.sipral;
    checkNow(sipral, 'sipral_subscription_end', () =>
      sipral.sipral_subscription_end(this.stack.handle, this.handle, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * The phase of the line a `dialog` subscription watches, as one lamp
   * would show it (`sipral_subscription_lamp`): a `SipralDialogPhase` value.
   */
  lamp(): number {
    const out = new Uint32Array(1);
    const sipral = this.stack.sipral;
    checkNow(sipral, 'sipral_subscription_lamp', () => sipral.sipral_subscription_lamp(this.stack.handle, this.handle, out));
    return out[0] ?? SipralDialogPhase.Unknown;
  }

  /** Every dialog a `dialog` subscription watches now, with its text. */
  dialogs(): WatchedDialog[] {
    const sipral = this.stack.sipral;
    const count = new BigUint64Array(1);
    checkNow(sipral, 'sipral_subscription_dialog_count', () =>
      sipral.sipral_subscription_dialog_count(this.stack.handle, this.handle, count),
    );
    const found: WatchedDialog[] = [];
    for (let index = 0; index < Number(count[0]); index++) {
      const out = record('sipral_watched_dialog_t');
      checkNow(sipral, 'sipral_subscription_dialog_at', () =>
        sipral.sipral_subscription_dialog_at(this.stack.handle, this.handle, index, out),
      );
      const read = plain(out, 'sipral_watched_dialog_t');
      const said = (which: number): string | null =>
        copyText(sipral, 'sipral_subscription_dialog_text', (buffer, capacity, needed) =>
          sipral.sipral_subscription_dialog_text(this.stack.handle, this.handle, index, which, buffer, capacity, needed),
        ) || null;
      found.push({
        phase: read.phase as number,
        direction: read.direction as number,
        ended: read.ended as number,
        statusCode: read.statusCode as number,
        durationMs: read.durationMs as number,
        id: said(SipralDialogText.Id),
        callId: said(SipralDialogText.CallId),
        localIdentity: said(SipralDialogText.LocalIdentity),
        localDisplay: said(SipralDialogText.LocalDisplay),
        remoteIdentity: said(SipralDialogText.RemoteIdentity),
        remoteDisplay: said(SipralDialogText.RemoteDisplay),
        localTarget: said(SipralDialogText.LocalTarget),
        remoteTarget: said(SipralDialogText.RemoteTarget),
      });
    }
    return found;
  }

  /**
   * The conference as this subscription holds it now, or null when it holds
   * none: another package, no document yet, or ended. Read it again after
   * every `ConferenceChanged` naming {@link handle}.
   */
  conference(): ConferencePicture | null {
    const sipral = this.stack.sipral;
    const out = record('sipral_conference_t');
    const status = retryingClockBehind(() => sipral.sipral_subscription_conference(this.stack.handle, this.handle, out));
    if (status === SipralStatus.NotSupported) {
      return null;
    }
    check(sipral, 'sipral_subscription_conference', status);
    const picture = plain(out, 'sipral_conference_t');
    const users: Participant[] = [];
    for (let index = 0; index < (picture.users as number); index++) {
      const user = record('sipral_conference_user_t');
      checkNow(sipral, 'sipral_subscription_conference_user_at', () =>
        sipral.sipral_subscription_conference_user_at(this.stack.handle, this.handle, index, user),
      );
      const read = plain(user, 'sipral_conference_user_t');
      users.push({
        entity: this.text(SipralConferenceText.UserEntity, index),
        displayText: this.text(SipralConferenceText.UserDisplayText, index),
        endpoint: this.text(SipralConferenceText.UserEndpoint, index),
        status: read.status as number,
        endpoints: read.endpoints as number,
        media: read.media as number,
      });
    }
    return {
      version: picture.version as number,
      entity: this.text(SipralConferenceText.Entity),
      subject: this.text(SipralConferenceText.Subject),
      displayText: this.text(SipralConferenceText.DisplayText),
      userCount: picture.hasUserCount !== 0 ? (picture.userCount as number) : null,
      active: tristate(picture.active as number),
      locked: tristate(picture.locked as number),
      users,
    };
  }

  private text(which: number, index = 0): string | null {
    const sipral = this.stack.sipral;
    return (
      copyText(sipral, 'sipral_subscription_conference_text', (buffer, capacity, needed) =>
        sipral.sipral_subscription_conference_text(this.stack.handle, this.handle, index, which, buffer, capacity, needed),
      ) || null
    );
  }
}
