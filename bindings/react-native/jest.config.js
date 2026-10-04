// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The TypeScript layer on Node, against a fake of the native module:
// Babel only strips the types (tsc checks them, `npm run typecheck`), and
// `react-native` is a stand-in that answers TurboModuleRegistry the way
// the real one does, so nothing of React Native's runtime is needed here.

module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  moduleNameMapper: {
    '^react-native$': '<rootDir>/src/__tests__/support/reactNative.ts',
  },
  transform: {
    '^.+\\.ts$': [
      'babel-jest',
      {
        babelrc: false,
        configFile: false,
        presets: ['@babel/preset-typescript'],
        plugins: ['@babel/plugin-transform-modules-commonjs'],
      },
    ],
  },
};
