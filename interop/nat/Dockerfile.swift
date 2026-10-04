# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The host behind the NAT (Dockerfile's own second use), for the Swift
# binding's lab agent instead of the Rust harness: the same `swift:6.1`
# image `swift_agent` already runs $SWIFT_AGENT in, `ip` added on top --
# `inside` has no route out to anywhere at all, so this has to be built
# rather than fetched once the container is placed there, the same
# reasoning Dockerfile.python gives for Python and cffi. Nothing else is
# added: $SWIFT_AGENT is built once, outside this image, the same binary
# `swift_agent` runs.

FROM swift:6.1

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*
