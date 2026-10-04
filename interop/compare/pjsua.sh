#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Runs the distribution's pjsua binary with its console on a named pipe, so
# interop/compare/compare.sh can type at it (`docker exec ... sh -c 'echo dq
# >/tmp/in'`) the way a person would at a terminal: pjsua reads its commands
# from standard input and quits when that input ends. The writer held open
# here keeps it from ending between two commands. Every argument is pjsua's
# own, passed through untouched; the process becomes pjsua, so it is the
# container's PID 1 and its memory and CPU are read at /proc/1.
set -eu
mkfifo /tmp/in
sleep 2147483647 >/tmp/in &
exec pjsua "$@" </tmp/in
