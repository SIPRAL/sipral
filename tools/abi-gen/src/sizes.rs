// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The pinned lengths, written out so that changing one is visible.
//!
//! Every other file this tool prints exists because a person would otherwise
//! have to keep it in step with the declarations by hand. This one exists for
//! the opposite reason: the numbers in it are *supposed* to stand still, and
//! printing them into a committed file is what makes a change to one of them
//! appear in a diff instead of inside a constant nobody re-reads.
//!
//! Two numbers per struct, not one. The pinned length is what a caller
//! compiled against the first published header declared, and the current
//! length is what this build compiled to; the first must never move and the
//! second is expected to, one appended member at a time. A line where they
//! are equal is a struct that has not grown yet. A line where the pinned one
//! has moved is either a mistake or the one legitimate correction, and either
//! way it is now a change somebody has to sign.

use sipral_ffi::abi::{FILLED_BY_US, MIN_SIZES, Surface};

/// One line per versioned struct, sorted by its C name.
pub(crate) fn rendered(surface: &Surface) -> String {
    let mut lines: Vec<String> = Vec::new();
    for record in surface
        .records
        .iter()
        .filter(|record| record.is_versioned())
    {
        let pinned = MIN_SIZES
            .iter()
            .find(|(name, _)| *name == record.name)
            .map(|(_, size)| *size);
        let note = match pinned {
            Some(pinned) => format!("{pinned} {}", record.size),
            // named in the surface as one the library fills itself, so there
            // is no caller-declared size to refuse and nothing to pin
            None if FILLED_BY_US.contains(&record.name) => {
                format!("- {}", record.size)
            }
            // unreachable while the completeness test in sipral-ffi stands,
            // and printed rather than skipped so that a run of this tool says
            // so out loud if it ever stops standing
            None => format!("UNPINNED {}", record.size),
        };
        lines.push(format!("{} {note}", record.c_name()));
    }
    lines.sort();
    let mut out = String::from(
        "# Printed by tools/abi-gen. Do not edit.\n\
         #\n\
         # <struct> <first published length> <length in this build>\n\
         #\n\
         # The first number is pinned in crates/sipral-ffi and must not move:\n\
         # it is what a caller built against the oldest header declares, and\n\
         # a library that stopped accepting it would break that caller from a\n\
         # change meant to be additive. The second grows by one appended\n\
         # member at a time. A dash means the library fills that struct in\n\
         # itself and no caller ever declares one.\n",
    );
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }
    out
}
