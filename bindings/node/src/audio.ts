// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// `stack.audio`: the library's own audio engine, in device mode -- devices,
// roles, gain, mute, the meter, activation and the ring.

import type { Call } from './call.js';
import { check, checkNow, copyText, plain, record } from './internal.js';
import { SipralAudioDirection, SipralToggle } from './sipral_abi.js';
import type { Stack } from './stack.js';

/** The engine's gain steps: 256 is unity. */
const GAIN_STEPS = 256;

/** The most gain a direction takes, as a ratio. */
const GAIN_MOST = 4;

/** One audio device the engine has seen, present or not. */
export interface AudioDevice {
  /** The engine's id for it, never reused, kept across a refresh. */
  readonly id: number;
  /** What the platform calls it. */
  readonly name: string;
  /** Its input channels: zero for a speaker. */
  readonly inputChannels: number;
  /** Its output channels: zero for a microphone. */
  readonly outputChannels: number;
  /** Whether it is the system's default input. */
  readonly defaultInput: boolean;
  /** Whether it is the system's default output. */
  readonly defaultOutput: boolean;
  /** Whether it is plugged in now. */
  readonly present: boolean;
}

/** What `sipral_audio_info` says about the engine. */
export interface AudioInfo {
  /** Whether the devices are open. */
  readonly active: boolean;
  /** Whether the platform's echo cancellation runs on them. */
  readonly systemEchoCancellation: boolean;
  /** How late the loudspeaker plays what it is given, in milliseconds. */
  readonly renderDelayMs: number;
  /** The rate the microphone runs at, in hertz. */
  readonly microphoneRateHz: number;
  /** The rate the loudspeaker runs at, in hertz. */
  readonly speakerRateHz: number;
  /** The device the microphone is open on, or null. */
  readonly microphone: number | null;
  /** The device the loudspeaker is open on, or null. */
  readonly speaker: number | null;
  /** The device the ringer is open on, or null. */
  readonly ringer: number | null;
}

/**
 * The library's audio engine, on a stack opened in device mode
 * (`audio: SipralAudio.Device`): every call's audio runs through the
 * platform's microphone and loudspeaker with no audio code in the
 * application, which chooses the devices, the volume, the mute and the ring
 * here. In application mode every entry point here answers
 * `SipralStatus.WrongState`.
 */
export class Audio {
  private readonly stack: Stack;

  /** @internal Built by the stack. */
  constructor(stack: Stack) {
    this.stack = stack;
  }

  /** Ask the platform again, and return the list as it now is. */
  refresh(): AudioDevice[] {
    const count = new BigUint64Array(1);
    const sipral = this.stack.sipral;
    checkNow(sipral, 'sipral_audio_refresh', () => sipral.sipral_audio_refresh(this.stack.handle, count));
    return this.devices();
  }

  /**
   * Every device the engine has seen, present or not, as last listed --
   * asking the platform first when nothing has been listed yet.
   */
  devices(): AudioDevice[] {
    const sipral = this.stack.sipral;
    const count = new BigUint64Array(1);
    checkNow(sipral, 'sipral_audio_device_count', () => sipral.sipral_audio_device_count(this.stack.handle, count));
    if (count[0] === 0n) {
      checkNow(sipral, 'sipral_audio_refresh', () => sipral.sipral_audio_refresh(this.stack.handle, count));
    }
    const listed: AudioDevice[] = [];
    for (let index = 0; index < Number(count[0]); index++) {
      const device = record('sipral_audio_device_t');
      const name = copyText(sipral, 'sipral_audio_device_at', (buffer, capacity, needed) =>
        sipral.sipral_audio_device_at(this.stack.handle, index, device, buffer, capacity, needed),
      );
      const read = plain(device, 'sipral_audio_device_t');
      listed.push({
        id: read.id as number,
        name,
        inputChannels: read.inputChannels as number,
        outputChannels: read.outputChannels as number,
        defaultInput: read.defaultInput !== 0,
        defaultOutput: read.defaultOutput !== 0,
        present: read.present !== 0,
      });
    }
    return listed;
  }

  /**
   * Put `role` (a `SipralAudioRole` value) on `device`, or back on the
   * system's route with null. `SipralStatus.NoSuchDevice` for an id the list
   * never held and `SipralStatus.DeviceUnusable` for a device with no
   * channels in the role's direction, both before any platform call.
   */
  select(role: number, device: number | AudioDevice | null): void {
    const id = device === null ? 0 : typeof device === 'number' ? device : device.id;
    const sipral = this.stack.sipral;
    checkNow(sipral, 'sipral_audio_select', () => sipral.sipral_audio_select(this.stack.handle, role, id));
  }

  /**
   * `[chosen, running]` for `role`: the id {@link select} was given (null for
   * the system's route) and the device the role is open on (null while it
   * is not open).
   */
  selection(role: number): [number | null, number | null] {
    const selected = new Uint32Array(1);
    const running = new Uint32Array(1);
    const sipral = this.stack.sipral;
    checkNow(sipral, 'sipral_audio_selection', () =>
      sipral.sipral_audio_selection(this.stack.handle, role, selected, running),
    );
    return [selected[0] || null, running[0] || null];
  }

  /**
   * Set `direction`'s gain (a `SipralAudioDirection` value) as a ratio: 1 is
   * unity, anything above 4 is 4. With `call`, that call's own gain on top
   * of the direction's.
   */
  setGain(direction: number, gain: number, call?: Call): void {
    if (!(gain >= 0)) {
      throw new RangeError(`sipral: a gain is a ratio of zero or more, not ${gain}`);
    }
    const steps = Math.round(Math.min(gain, GAIN_MOST) * GAIN_STEPS);
    const sipral = this.stack.sipral;
    if (call !== undefined) {
      checkNow(sipral, 'sipral_audio_call_set_gain', () =>
        sipral.sipral_audio_call_set_gain(this.stack.handle, call.handle, direction, steps),
      );
    } else {
      checkNow(sipral, 'sipral_audio_set_gain', () => sipral.sipral_audio_set_gain(this.stack.handle, direction, steps));
    }
  }

  /** `direction`'s gain -- `call`'s own, with one -- as the ratio {@link setGain} takes. */
  gain(direction: number, call?: Call): number {
    const out = new Uint32Array(1);
    const sipral = this.stack.sipral;
    if (call !== undefined) {
      checkNow(sipral, 'sipral_audio_call_gain', () =>
        sipral.sipral_audio_call_gain(this.stack.handle, call.handle, direction, out),
      );
    } else {
      checkNow(sipral, 'sipral_audio_gain', () => sipral.sipral_audio_gain(this.stack.handle, direction, out));
    }
    return (out[0] ?? 0) / GAIN_STEPS;
  }

  /** Mute `direction` or unmute it; with `call`, that call alone. */
  setMuted(direction: number, muted: boolean, call?: Call): void {
    const sipral = this.stack.sipral;
    if (call !== undefined) {
      checkNow(sipral, 'sipral_audio_call_set_muted', () =>
        sipral.sipral_audio_call_set_muted(this.stack.handle, call.handle, direction, muted ? 1 : 0),
      );
    } else {
      checkNow(sipral, 'sipral_audio_set_muted', () =>
        sipral.sipral_audio_set_muted(this.stack.handle, direction, muted ? 1 : 0),
      );
    }
  }

  /** Whether `direction` is muted -- for `call` alone, with one. */
  muted(direction: number, call?: Call): boolean {
    const out = new Uint32Array(1);
    const sipral = this.stack.sipral;
    if (call !== undefined) {
      checkNow(sipral, 'sipral_audio_call_muted', () =>
        sipral.sipral_audio_call_muted(this.stack.handle, call.handle, direction, out),
      );
    } else {
      checkNow(sipral, 'sipral_audio_muted', () => sipral.sipral_audio_muted(this.stack.handle, direction, out));
    }
    return out[0] !== 0;
  }

  /**
   * The meter: the loudest sample of the last tenth of a second in
   * `direction`, 0 to 32767; zero while nothing is open. With `call`, that
   * call's own.
   */
  level(direction: number, call?: Call): number {
    const out = new Uint32Array(1);
    const sipral = this.stack.sipral;
    if (call !== undefined) {
      checkNow(sipral, 'sipral_audio_call_level', () =>
        sipral.sipral_audio_call_level(this.stack.handle, call.handle, direction, out),
      );
    } else {
      checkNow(sipral, 'sipral_audio_level', () => sipral.sipral_audio_level(this.stack.handle, direction, out));
    }
    return out[0] ?? 0;
  }

  /** The microphone's gain, as a ratio. */
  get microphoneGain(): number {
    return this.gain(SipralAudioDirection.Input);
  }

  set microphoneGain(gain: number) {
    this.setGain(SipralAudioDirection.Input, gain);
  }

  /** The loudspeaker's gain, as a ratio. */
  get volume(): number {
    return this.gain(SipralAudioDirection.Output);
  }

  set volume(gain: number) {
    this.setGain(SipralAudioDirection.Output, gain);
  }

  /**
   * Turn the platform's own echo cancellation on or off on the running
   * stack; `SipralStatus.WrongState` in application mode.
   */
  setSystemEchoCancellation(on: boolean): void {
    const sipral = this.stack.sipral;
    checkNow(sipral, 'sipral_audio_set_system_echo_cancellation', () =>
      sipral.sipral_audio_set_system_echo_cancellation(this.stack.handle, on ? SipralToggle.On : SipralToggle.Off),
    );
  }

  /**
   * Open the devices and start the pump now. Under manual activation this
   * is the only thing that does; under automatic activation it opens them
   * early.
   */
  activate(): void {
    const sipral = this.stack.sipral;
    checkNow(sipral, 'sipral_audio_activate', () => sipral.sipral_audio_activate(this.stack.handle));
  }

  /** Close the devices and stop the pump; the calls get their audio back on the next {@link activate}. */
  deactivate(): void {
    const sipral = this.stack.sipral;
    checkNow(sipral, 'sipral_audio_deactivate', () => sipral.sipral_audio_deactivate(this.stack.handle));
  }

  /** `sipral_audio_info`. */
  info(): AudioInfo {
    const out = record('sipral_audio_info_t');
    const sipral = this.stack.sipral;
    checkNow(sipral, 'sipral_audio_info', () => sipral.sipral_audio_info(this.stack.handle, out));
    const read = plain(out, 'sipral_audio_info_t');
    return {
      active: read.active !== 0,
      systemEchoCancellation: read.systemEchoCancellation !== 0,
      renderDelayMs: read.renderDelayMs as number,
      microphoneRateHz: read.microphoneRateHz as number,
      speakerRateHz: read.speakerRateHz as number,
      microphone: (read.microphone as number) || null,
      speaker: (read.speaker as number) || null,
      ringer: (read.ringer as number) || null,
    };
  }

  /**
   * Play `pcm` (16-bit mono at `sampleRate`) on the ringer's device until
   * {@link stopRinging}, or once through with `looped` false.
   */
  ring(pcm: Int16Array, sampleRate: number, looped = true): void {
    const samples = Int16Array.from(pcm);
    const sipral = this.stack.sipral;
    checkNow(sipral, 'sipral_audio_ring', () =>
      sipral.sipral_audio_ring(this.stack.handle, samples, samples.length, sampleRate, looped ? 1 : 0),
    );
  }

  /** Stop the tone {@link ring} started. */
  stopRinging(): void {
    const sipral = this.stack.sipral;
    check(sipral, 'sipral_audio_stop_ringing', sipral.sipral_audio_stop_ringing(this.stack.handle));
  }
}
