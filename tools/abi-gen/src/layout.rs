// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Where every member of every record sits, on every layout the ABI ships
//! for, worked out from the declarations rather than read off this build.
//!
//! The compiler that builds this tool answers for one target: the one it runs
//! on. The library is also built for 32-bit Android, and a struct of pointers
//! is one length there and another here, so a number read off this build and
//! printed as "the" length is right on half the targets and a refusal of every
//! caller on the other half. The C rules for laying out a struct are few and
//! the same everywhere this ABI goes; what differs is three numbers: how wide
//! a pointer is, and how a 64-bit integer is aligned inside a struct. Those
//! three numbers make three layouts, and every target falls in one of them:
//!
//! - [`Class::P64`]: 64-bit pointers. Linux, Android, macOS, iOS and Windows
//!   on x86-64 and on ARM64 alike.
//! - [`Class::P32A4`]: 32-bit pointers and a 64-bit integer aligned to four
//!   bytes inside a struct, which is the i386 System V rule (32-bit x86
//!   Linux and Android).
//! - [`Class::P32A8`]: 32-bit pointers and a 64-bit integer aligned to eight,
//!   which is ARM's EABI (armeabi-v7a) and 32-bit Windows.
//!
//! What is worked out here is checked three ways: against this build for the
//! layout it is on (`tests`), against a C compiler for every layout
//! (`bindings/c/abi-layout.c`, which `scripts/check.sh` compiles for six
//! targets), and against each generated binding's own idea of how long each
//! struct is, in that binding's size test.

use sipral_ffi::abi::{Record, Shape, Stands, Surface};

use crate::model::{Base, Int, Refused, Type, read_all};

/// One of the three ways the targets this ABI ships for lay a struct out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// 64-bit pointers.
    P64,
    /// 32-bit pointers, 64-bit integers aligned to four inside a struct.
    P32A4,
    /// 32-bit pointers, 64-bit integers aligned to eight inside a struct.
    P32A8,
}

impl Class {
    /// Every layout, in the order every printed table lists them.
    pub(crate) const ALL: [Self; 3] = [Self::P64, Self::P32A4, Self::P32A8];

    /// What a printed table calls this layout.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::P64 => "p64",
            Self::P32A4 => "p32a4",
            Self::P32A8 => "p32a8",
        }
    }

    const fn pointer(self) -> usize {
        match self {
            Self::P64 => 8,
            Self::P32A4 | Self::P32A8 => 4,
        }
    }

    const fn wide_alignment(self) -> usize {
        match self {
            Self::P64 | Self::P32A8 => 8,
            Self::P32A4 => 4,
        }
    }
}

/// A record laid out on one layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Laid {
    /// `sizeof`, padding at the end included.
    pub(crate) size: usize,
    /// The strictest alignment of any member.
    pub(crate) align: usize,
    /// Where each member starts, in declaration order.
    pub(crate) offsets: Vec<usize>,
    /// Where each member ends, in declaration order.
    pub(crate) ends: Vec<usize>,
}

impl Laid {
    /// Where the member named `name` ends, if the record has one.
    pub(crate) fn end_of(&self, record: &Record, name: &str) -> Option<usize> {
        let index = record.fields.iter().position(|field| field.name == name)?;
        self.ends.get(index).copied()
    }

    /// Padding after the last member: what a member appended to the record
    /// would land in.
    pub(crate) fn tail(&self) -> usize {
        self.size - self.ends.iter().copied().max().unwrap_or(0)
    }
}

const fn round_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

/// How long a type is and how it is aligned, on one layout.
fn scalar(surface: &Surface, ty: &Type, class: Class) -> Result<(usize, usize), Refused> {
    if ty.pointer.is_some() {
        return Ok((class.pointer(), class.pointer()));
    }
    match &ty.base {
        Base::Int(Int { bits: 0, .. }) => Ok((class.pointer(), class.pointer())),
        Base::Int(Int { bits: 64, .. }) | Base::Float(64) => Ok((8, class.wide_alignment())),
        Base::Int(Int { bits, .. }) | Base::Float(bits) => {
            let bytes = usize::try_from(*bits / 8).unwrap_or(0);
            if bytes == 0 || !bytes.is_power_of_two() {
                return Err(Refused::about(&format!(
                    "a {bits}-bit number has no layout rule in tools/abi-gen/src/layout.rs"
                )));
            }
            Ok((bytes, bytes))
        }
        Base::Named(name) => named(surface, name, class),
        Base::Opaque | Base::Char => Err(Refused::about(
            "a `c_void` or a `c_char` held by value has no layout; only behind a pointer",
        )),
    }
}

fn named(surface: &Surface, name: &str, class: Class) -> Result<(usize, usize), Refused> {
    if let Some(alias) = surface.aliases.iter().find(|alias| alias.name == name) {
        return match alias.stands {
            Stands::For(target) => scalar(surface, &Type::read(target)?, class),
            Stands::Callback(_, _) => Ok((class.pointer(), class.pointer())),
        };
    }
    if let Some(enumeration) = surface.enumerations.iter().find(|e| e.name == name) {
        return scalar(surface, &Type::read(enumeration.width)?, class);
    }
    if let Some(record) = surface.records.iter().find(|record| record.name == name) {
        let laid = of(surface, record, class)?;
        return Ok((laid.size, laid.align));
    }
    Err(Refused::about(&format!(
        "{name} is not a type the surface declares, so it has no layout"
    )))
}

/// Lay a record out on one layout, by the rules every C compiler this ABI
/// meets follows: each member at the next multiple of its alignment, a union's
/// members all at zero, and the whole rounded up to the strictest alignment.
pub(crate) fn of(surface: &Surface, record: &Record, class: Class) -> Result<Laid, Refused> {
    let fields = read_all(record.name, record.fields)?;
    let mut offsets = Vec::with_capacity(fields.len());
    let mut ends = Vec::with_capacity(fields.len());
    let mut at = 0;
    let mut align = 1;
    let mut widest = 0;
    for field in &fields {
        let (size, alignment) = scalar(surface, &field.ty, class).map_err(|why| {
            Refused::about(&format!("{}::{}: {why}", record.name, field.member.name))
        })?;
        align = align.max(alignment);
        let offset = match record.shape {
            Shape::Struct => round_up(at, alignment),
            Shape::Union => 0,
        };
        offsets.push(offset);
        ends.push(offset + size);
        at = offset + size;
        widest = widest.max(size);
    }
    let used = match record.shape {
        Shape::Struct => at,
        Shape::Union => widest,
    };
    Ok(Laid {
        size: round_up(used, align),
        align,
        offsets,
        ends,
    })
}

/// Refuse a surface in which a struct that carries its own size ends in
/// padding on any layout.
///
/// The padding at the end of a length a caller already declares is where the
/// next member appended to the struct would start on that layout, and the
/// caller built against the shorter header never wrote those bytes: the
/// library would read whatever the caller's stack held there as a value it
/// set. Every member appended since the first version of a struct was
/// appended to a length without such padding, as long as no printed length
/// ever had any; this is what keeps it so, by refusing to print one.
pub(crate) fn no_tail_padding(surface: &Surface) -> Result<(), Refused> {
    for record in surface
        .records
        .iter()
        .filter(|record| record.is_versioned())
    {
        for class in Class::ALL {
            let laid = of(surface, record, class)?;
            if laid.tail() != 0 {
                return Err(Refused::about(&format!(
                    "{} ends in {} bytes of padding on the {} layout, so the next member \
                     appended to it would start inside a length callers already declare; give \
                     it a `reserved: u32` or move a member so it ends where its last member does \
                     on every layout",
                    record.name,
                    laid.tail(),
                    class.label()
                )));
            }
        }
    }
    Ok(())
}

/// One record's lengths, for the table every binding prints so that its own
/// size test can hold its own layout of each record to them.
pub(crate) struct Lengths {
    /// The record as the surface declares it.
    pub(crate) record: &'static Record,
    /// Its length on each layout, in [`Class::ALL`]'s order.
    pub(crate) sizes: [usize; 3],
}

/// Every record the surface declares, in its order, with its length on each
/// layout.
pub(crate) fn table(surface: &Surface) -> Result<Vec<Lengths>, Refused> {
    surface
        .records
        .iter()
        .map(|record| {
            let mut sizes = [0; 3];
            for (slot, class) in sizes.iter_mut().zip(Class::ALL) {
                *slot = of(surface, record, class)?.size;
            }
            Ok(Lengths { record, sizes })
        })
        .collect()
}

/// The sentence every printed table carries above it.
pub(crate) const TABLE_DOC: &[&str] = &[
    "Every struct and union the header declares, with how long tools/abi-gen",
    "worked it out to be on each of the three layouts the ABI ships for:",
    "64-bit pointers (p64), then 32-bit pointers with 64-bit integers aligned",
    "to four (p32a4, i386) and to eight (p32a8, ARM and Windows x86). A size",
    "test holds this binding's own layout of each record, and the library's",
    "answer from sipral_abi_struct_size, to the number for the layout it runs",
    "on; bindings/c/abi-layout.c holds a C compiler to all three.",
];

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use sipral_ffi::abi::{MIN_SIZES, Member, Record, SURFACE, Shape, Surface};

    use super::{Class, no_tail_padding, of};

    const fn member(name: &'static str, rust_type: &'static str) -> Member {
        Member {
            name,
            rust_type,
            doc: &[],
        }
    }

    const NOTHING: Surface = Surface {
        version: (0, 0, 0),
        aliases: &[],
        enumerations: &[],
        records: &[],
        constants: &[],
        functions: &[],
    };

    /// The layout this build is on, which is the one `size_of` answers for.
    const HERE: Class = if cfg!(target_pointer_width = "64") {
        Class::P64
    } else if cfg!(target_arch = "x86") {
        Class::P32A4
    } else {
        Class::P32A8
    };

    /// The compiler that built the library laid every record out; the rules
    /// here have to come to the same answer on the layout it was built for,
    /// or everything they say about the other two is guesswork.
    #[test]
    fn every_record_is_as_long_as_this_build_compiled_it() {
        for record in SURFACE.records {
            let laid = of(&SURFACE, record, HERE).expect("every record has a layout");
            assert_eq!(laid.size, record.size, "{}", record.name);
        }
    }

    /// The library derives its minimum from the pinned member with
    /// `offset_of!`; the table printed for callers derives it from the same
    /// member with these rules. On this build's layout the two are one
    /// number.
    #[test]
    fn every_pin_is_where_the_library_puts_it() {
        for (name, member, end) in MIN_SIZES {
            let record = SURFACE.records.iter().find(|r| r.name == *name).unwrap();
            let laid = of(&SURFACE, record, HERE).unwrap();
            assert_eq!(laid.end_of(record, member), Some(*end), "{name}");
        }
    }

    #[test]
    fn the_surface_ends_no_versioned_struct_in_padding() {
        no_tail_padding(&SURFACE).expect("every versioned struct ends with its last member");
    }

    /// `size` then one `u32`: four bytes of padding after it on a 64-bit
    /// target, none on a 32-bit one. That is `sipral_abi_version_t` before
    /// the freeze gave it `reserved`, and the member the next minor would
    /// have appended would have started inside a length every caller of
    /// this one declared.
    #[test]
    fn a_struct_padded_only_on_a_64_bit_target_is_refused() {
        const PADDED: Surface = Surface {
            records: &[Record {
                name: "SipralOdd",
                doc: &[],
                shape: Shape::Struct,
                fields: &[member("size", "usize"), member("major", "u32")],
                size: 16,
            }],
            ..NOTHING
        };
        let why = no_tail_padding(&PADDED).expect_err("four bytes of padding on p64");
        assert!(why.to_string().contains("SipralOdd"), "{why}");
        assert!(why.to_string().contains("p64"), "{why}");
    }

    /// A `u64`, a `u32` and a piece of text after the size: no padding at
    /// the end on a 64-bit target or on i386, and four bytes of it on 32-bit
    /// ARM, where a `u64` is aligned to eight and a pointer is four bytes.
    /// That is `sipral_path_candidate_t` before the freeze. A check that only
    /// looked at the build it ran on would pass this on every machine it is
    /// ever run on.
    #[test]
    fn a_struct_padded_only_on_32_bit_arm_is_refused() {
        const PADDED: Surface = Surface {
            records: &[Record {
                name: "SipralOdd",
                doc: &[],
                shape: Shape::Struct,
                fields: &[
                    member("size", "usize"),
                    member("when", "u64"),
                    member("what", "u32"),
                    member("name", "*const c_char"),
                    member("name_len", "usize"),
                ],
                size: 40,
            }],
            ..NOTHING
        };
        let record = &PADDED.records[0];
        assert_eq!(of(&PADDED, record, Class::P64).unwrap().tail(), 0);
        assert_eq!(of(&PADDED, record, Class::P32A4).unwrap().tail(), 0);
        let arm = of(&PADDED, record, Class::P32A8).unwrap();
        assert_eq!((arm.size, arm.tail()), (32, 4));
        let why = no_tail_padding(&PADDED).expect_err("four bytes of padding on p32a8");
        assert!(why.to_string().contains("p32a8"), "{why}");
    }

    /// A struct with no size never grows, so padding at its end is nobody's
    /// business.
    #[test]
    fn a_struct_without_a_size_may_end_in_padding() {
        const ELEMENT: Surface = Surface {
            records: &[Record {
                name: "SipralOdd",
                doc: &[],
                shape: Shape::Struct,
                fields: &[member("name", "*const c_char"), member("kind", "u32")],
                size: 16,
            }],
            ..NOTHING
        };
        assert!(no_tail_padding(&ELEMENT).is_ok());
    }

    /// The i386 rule, which is the one a 64-bit build never shows: a `u64`
    /// after a four-byte size starts at four, not eight.
    #[test]
    fn a_wide_member_is_aligned_to_four_on_i386_and_to_eight_on_arm() {
        const WIDE: Surface = Surface {
            records: &[Record {
                name: "SipralOdd",
                doc: &[],
                shape: Shape::Struct,
                fields: &[member("size", "usize"), member("when", "u64")],
                size: 16,
            }],
            ..NOTHING
        };
        let record = &WIDE.records[0];
        assert_eq!(of(&WIDE, record, Class::P64).unwrap().offsets, [0, 8]);
        assert_eq!(of(&WIDE, record, Class::P32A4).unwrap().offsets, [0, 4]);
        assert_eq!(of(&WIDE, record, Class::P32A8).unwrap().offsets, [0, 8]);
        assert_eq!(of(&WIDE, record, Class::P32A4).unwrap().size, 12);
        assert_eq!(of(&WIDE, record, Class::P32A8).unwrap().size, 16);
    }
}
