# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# Where the Kotlin binding's lab agent runs (scripts/lab.sh, kotlin_agent):
# the JDK, whose own jni.h the JNI shim is compiled against, and a C compiler
# to compile it with. Built once and reused, so a lab run does not fetch a
# compiler from Debian's mirrors every time the step starts -- a slow mirror
# used to eat the whole of the step's wait for the agent to register.

FROM eclipse-temurin:21-jdk

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
