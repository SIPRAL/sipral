// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// What `react-native` is under jest: the one export this package imports at
// run time, TurboModuleRegistry, answering with a marker that names the
// module asked for, so a test can see which name the spec looks up.

export const asked: string[] = [];

export const TurboModuleRegistry = {
  getEnforcing<T>(name: string): T {
    asked.push(name);
    return {moduleName: name} as unknown as T;
  },
};
