# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The browser of scripts/lab.sh's `browser` step: Playwright's own image,
# which carries the Chromium build that Playwright release drives and the
# libraries it needs, plus the three packages package-lock.json pins --
# Playwright itself, JsSIP for the page's SIP over WebSocket, and esbuild,
# which bundles phone.js with JsSIP into the one script the page loads.
# Playwright and Chromium are Apache-2.0 and BSD, JsSIP and esbuild MIT; none
# of it is shipped, it is the far end of a lab call the way Asterisk is.

FROM mcr.microsoft.com/playwright:v1.64.1-noble

WORKDIR /lab
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY phone.js run.mjs ./
RUN npx esbuild phone.js --bundle --format=iife --platform=browser --outfile=phone.bundle.js

ENTRYPOINT ["node", "/lab/run.mjs"]
