// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The pinned lengths and the layouts, written out so that changing one is
//! visible, and a C file that makes a C compiler say they are right.
//!
//! Every other file this tool prints exists because a person would otherwise
//! have to keep it in step with the declarations by hand. `abi-sizes.txt`
//! exists for the opposite reason: the pinned lengths in it are *supposed*
//! to stand still, and printing them into a committed file is what makes a
//! change to one of them appear in a diff instead of inside a constant nobody
//! re-reads.
//!
//! A pin is a member, not a number: the oldest version of a struct the frozen
//! ABI publishes ends with it, and where it ends is a different number on a
//! 32-bit target than on a 64-bit one. So each line names the member and
//! then, for each of the three layouts, the length the pin comes to and the
//! length the struct is now. The first must never move and the second is
//! expected to, one appended member at a time.
//!
//! `abi-layout.c` says the same numbers again, member by member, as
//! `_Static_assert`s over the header, and `scripts/check.sh` compiles it for
//! 64-bit and 32-bit x86, ARM and Windows. A header that disagrees with what
//! is printed here, or a C compiler that lays a struct out differently from
//! how [`crate::layout`] does, fails the build there rather than a caller on
//! a phone.

use std::fmt::Write as _;

use sipral_ffi::abi::{FILLED_BY_US, MIN_SIZES, Surface};

use crate::layout::{Class, Laid, of};
use crate::model::Refused;

/// One line per versioned struct, sorted by its C name.
pub(crate) fn rendered(surface: &Surface) -> Result<String, Refused> {
    let mut lines: Vec<String> = Vec::new();
    for record in surface
        .records
        .iter()
        .filter(|record| record.is_versioned())
    {
        let pinned = MIN_SIZES
            .iter()
            .find(|(name, _, _)| *name == record.name)
            .map(|(_, member, _)| *member);
        let mut line = format!("{} {}", record.c_name(), pinned.unwrap_or("-"));
        for class in Class::ALL {
            let laid = of(surface, record, class)?;
            let pin = match pinned {
                Some(member) => laid.end_of(record, member).map_or_else(
                    || {
                        Err(Refused::about(&format!(
                            "{} is pinned through {member}, which it does not have",
                            record.name
                        )))
                    },
                    |end| Ok(end.to_string()),
                )?,
                // named in the surface as one the library fills itself, so
                // there is no caller-declared size to refuse and nothing to pin
                None if FILLED_BY_US.contains(&record.name) => "-".to_owned(),
                // unreachable while the completeness test in sipral-ffi stands,
                // and printed rather than skipped so that a run of this tool
                // says so out loud if it ever stops standing
                None => "UNPINNED".to_owned(),
            };
            let _ = write!(line, " {pin} {}", laid.size);
        }
        lines.push(line);
    }
    lines.sort();
    let mut out = String::from(
        "# Printed by tools/abi-gen. Do not edit.\n\
         #\n\
         # <struct> <pinned member> then, for each layout, <pin> <length>:\n\
         #   p64    64-bit pointers (x86-64, ARM64, on every system)\n\
         #   p32a4  32-bit pointers, 64-bit integers 4-aligned (i386 System V)\n\
         #   p32a8  32-bit pointers, 64-bit integers 8-aligned (ARM EABI, Windows x86)\n\
         #\n\
         # The pin is where the named member ends: the length of the oldest\n\
         # version of the struct the frozen ABI publishes, and the least a\n\
         # caller may declare. It must not move. The length grows by one\n\
         # appended member at a time. A dash means the library fills that\n\
         # struct in itself and no caller ever declares one.\n",
    );
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// The C file that holds a C compiler to every number [`rendered`] prints,
/// member by member, on whichever of the three layouts it compiles for.
pub(crate) fn layout_check(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::from(
        "/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial\n\
         \x20* Copyright (c) 2026 Sytek\n\
         \x20*\n\
         \x20* Printed from the declarations in crates/sipral-ffi by tools/abi-gen.\n\
         \x20* Do not edit.\n\
         \x20*\n\
         \x20* Every length and every offset tools/abi-gen works out for sipral.h,\n\
         \x20* on the three layouts the ABI ships for, as assertions a C compiler\n\
         \x20* checks against the header itself. Nothing here runs: compiling it\n\
         \x20* for a target is the test. scripts/check.sh compiles it for 64-bit\n\
         \x20* and 32-bit x86 Linux, 64-bit and 32-bit ARM Linux, and 64-bit and\n\
         \x20* 32-bit Windows. The pins are the least a caller may declare, and\n\
         \x20* are what the library derives its own minimum from on each target.\n\
         \x20*/\n\n\
         #include <stddef.h>\n\
         #include <stdint.h>\n\n\
         #include \"sipral.h\"\n\n\
         /* Where a 64-bit integer lands after one byte: four on i386, eight on\n\
         \x20* ARM and on Windows. */\n\
         struct sipral_layout_probe {\n\
         \x20   char before;\n\
         \x20   uint64_t value;\n\
         };\n\n\
         #define SIPRAL_LAYOUT(p64, p32a4, p32a8) \\\n\
         \x20   (sizeof(void *) == 8 ? (p64) \\\n\
         \x20    : offsetof(struct sipral_layout_probe, value) == 4 ? (p32a4) : (p32a8))\n\n\
         _Static_assert(sizeof(void *) == 8 || sizeof(void *) == 4,\n\
         \x20              \"a target with neither 64-bit nor 32-bit pointers has no layout here\");\n\n",
    );
    for record in surface.records {
        let laid = Class::ALL.map(|class| of(surface, record, class));
        let [p64, p32a4, p32a8] = laid;
        let (p64, p32a4, p32a8) = (p64?, p32a4?, p32a8?);
        let c_name = record.c_name();
        let _ = writeln!(
            out,
            "_Static_assert(sizeof({c_name}) == SIPRAL_LAYOUT({}, {}, {}), \"{c_name}\");",
            p64.size, p32a4.size, p32a8.size
        );
        for (index, field) in record.fields.iter().enumerate() {
            let at = |laid: &Laid| laid.offsets.get(index).copied().unwrap_or(0);
            let _ = writeln!(
                out,
                "_Static_assert(offsetof({c_name}, {name}) == SIPRAL_LAYOUT({}, {}, {}), \
                 \"{c_name}::{name}\");",
                at(&p64),
                at(&p32a4),
                at(&p32a8),
                name = field.name
            );
        }
        if let Some((_, member, _)) = MIN_SIZES.iter().find(|(name, _, _)| *name == record.name) {
            let pin = |laid: &Laid| laid.end_of(record, member).unwrap_or(0);
            let _ = writeln!(
                out,
                "_Static_assert(offsetof({c_name}, {member}) + sizeof((({c_name} *)0)->{member}) \
                 == SIPRAL_LAYOUT({}, {}, {}), \"{c_name} is pinned through {member}\");",
                pin(&p64),
                pin(&p32a4),
                pin(&p32a8)
            );
        }
        out.push('\n');
    }
    Ok(out)
}
