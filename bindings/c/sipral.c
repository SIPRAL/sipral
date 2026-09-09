/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Tiberiu Balasea
 *
 * The C target of the Swift package needs one translation unit, and this is
 * the one worth having: it compiles the generated header, so a header that
 * will not compile is found by building the package rather than by an
 * application that tried to use it.
 */

#include "include/sipral.h"
