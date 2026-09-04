// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! NAT traversal.
//!
//! STUN and TURN clients and ICE-lite. Symmetric RTP with rport covers most
//! carriers on its own; the rest is what this crate is for.
