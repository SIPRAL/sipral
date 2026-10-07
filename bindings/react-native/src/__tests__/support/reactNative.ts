// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// `react-native` under jest: TurboModuleRegistry returns a marker naming the
// module asked for, so a test can check which name the spec looks up.

export const asked: string[] = [];

export const TurboModuleRegistry = {
  getEnforcing<T>(name: string): T {
    asked.push(name);
    return {moduleName: name} as unknown as T;
  },
};
