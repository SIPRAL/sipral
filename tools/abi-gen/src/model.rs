// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a declaration means once it has been read, and what each language
//! calls it.
//!
//! The descriptors carry Rust type expressions because that is what the
//! declaration was written in. Everything downstream works from [`Type`],
//! which is the same information with the spelling taken off, so that a
//! language back end asks "is this a pointer to bytes" rather than matching on
//! a string.

use sipral_ffi::abi::{Function, Member, Record, Surface};
// the rule for turning `SipralStackConfig` into `sipral_stack_config` is the
// library's, because the library answers questions about the C names too
pub(crate) use sipral_ffi::abi::snake;

/// Something the generator will not guess about.
#[derive(Debug)]
pub(crate) struct Refused(String);

impl Refused {
    pub(crate) fn about(what: &str) -> Self {
        Self(what.to_owned())
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.0)
    }
}

/// A type that crosses the boundary, with the pointer separated from what it
/// points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Type {
    /// Whether it is behind a pointer, and whether that pointer is writable.
    pub(crate) pointer: Option<Writable>,
    /// What it is, or what it points at.
    pub(crate) base: Base,
}

/// Whether a pointer may be written through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Writable {
    /// `*const T`.
    No,
    /// `*mut T`.
    Yes,
}

/// The thing a type is, with no indirection left.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Base {
    /// `c_void`, which only ever appears behind a pointer.
    Opaque,
    /// A character, which is how UTF-8 crosses.
    Char,
    /// An integer of a fixed width.
    Int(Int),
    /// A float of a fixed width.
    Float(u32),
    /// A handle, an enumeration, a record or the callback.
    Named(String),
}

/// One of the integer widths this ABI uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Int {
    /// How wide, or zero for `usize`, whose width is the target's.
    pub(crate) bits: u32,
    /// Whether it carries a sign.
    pub(crate) signed: bool,
}

impl Int {
    /// `usize`, the one width that is not written down.
    const SIZE: Self = Self {
        bits: 0,
        signed: false,
    };

    fn of(spelling: &str) -> Option<Self> {
        let (signed, rest) = match spelling.split_at_checked(1) {
            Some(("u", rest)) => (false, rest),
            Some(("i", rest)) => (true, rest),
            _ => return None,
        };
        if rest == "size" {
            return Some(Self { bits: 0, signed });
        }
        rest.parse().ok().map(|bits| Self { bits, signed })
    }
}

impl Type {
    /// Read a Rust type expression as the declaration spelled it.
    ///
    /// The spelling comes from `stringify!`, which puts its own spaces in —
    /// `* const c_char` — so the spaces are taken out before anything is read
    /// off it.
    pub(crate) fn read(spelling: &str) -> Result<Self, Refused> {
        let tightened = spelling.replace("* ", "*");
        let spelling = tightened.trim();
        let (pointer, rest) = if let Some(rest) = spelling.strip_prefix("*const ") {
            (Some(Writable::No), rest)
        } else if let Some(rest) = spelling.strip_prefix("*mut ") {
            (Some(Writable::Yes), rest)
        } else {
            (None, spelling)
        };
        if rest.starts_with('*') {
            return Err(Refused::about(&format!(
                "{spelling} is a pointer to a pointer, which this ABI does not have and this \
                 generator therefore does not print"
            )));
        }
        let base = match rest {
            "c_void" => Base::Opaque,
            "c_char" => Base::Char,
            "f32" => Base::Float(32),
            "f64" => Base::Float(64),
            other if other.starts_with("Sipral") => Base::Named(other.to_owned()),
            other => match Int::of(other) {
                Some(int) => Base::Int(int),
                None => {
                    return Err(Refused::about(&format!(
                        "{spelling} is a type this generator has no rule for; give it one in \
                         tools/abi-gen/src/model.rs rather than guessing"
                    )));
                }
            },
        };
        Ok(Self { pointer, base })
    }

    /// Whether this is `usize`, which is the length beside every buffer.
    pub(crate) fn is_length(&self) -> bool {
        self.pointer.is_none() && self.base == Base::Int(Int::SIZE)
    }

    /// What it points at, when it points at bytes a caller supplies.
    pub(crate) fn points_at_bytes(&self) -> bool {
        matches!(
            (self.pointer, &self.base),
            (Some(_), Base::Char | Base::Int(Int { bits: 8 | 16, .. }))
        )
    }
}

/// A parameter, or a member, with its type read.
pub(crate) struct Read<'a> {
    /// The declaration it came from.
    pub(crate) member: &'a Member,
    /// What its type turned out to be.
    pub(crate) ty: Type,
}

/// Read every member of a list, saying which one could not be read.
pub(crate) fn read_all<'a>(owner: &str, members: &'a [Member]) -> Result<Vec<Read<'a>>, Refused> {
    members
        .iter()
        .map(|member| {
            Type::read(member.rust_type)
                .map(|ty| Read { member, ty })
                .map_err(|why| Refused::about(&format!("{owner}::{}: {why}", member.name)))
        })
        .collect()
}

/// What a parameter is for, once the ABI's own conventions have been read off
/// it.
pub(crate) enum Role<'a> {
    /// A plain value: a handle, a number, or a pointer no convention covers.
    Plain(&'a Read<'a>),
    /// Bytes or samples the caller hands in, with the length beside them.
    Buffer {
        /// The pointer.
        data: &'a Read<'a>,
        /// The length that follows it.
        len: &'a Read<'a>,
    },
    /// A buffer the caller brings for the library to fill, with the room in
    /// it. What was written comes back in the `out_` that follows.
    Fill {
        /// The pointer.
        data: &'a Read<'a>,
        /// The `capacity` that follows it.
        capacity: &'a Read<'a>,
    },
    /// A struct the caller fills in and the library only reads.
    Config(&'a Read<'a>),
    /// A struct the library fills in whole, which a binding can return.
    Given(&'a Read<'a>),
    /// A struct the caller part-fills — with its own buffers — and the library
    /// finishes.
    Shared(&'a Read<'a>),
    /// One value written back.
    Out(&'a Read<'a>),
}

/// Read a parameter list as the conventions in `docs/08-ffi.md` describe it.
///
/// Four conventions, and all four are the ABI's own rather than this
/// generator's: a pointer followed by a length is one buffer going in; a
/// pointer followed by `capacity` is one buffer being filled; a writable
/// pointer named `out_` is one value coming back; and a pointer to a versioned
/// struct is a struct going in, coming back, or both, depending on which way
/// the pointer goes and on whether the struct holds buffers of the caller's.
pub(crate) fn roles<'a>(surface: &Surface, parameters: &'a [Read<'a>]) -> Vec<Role<'a>> {
    let mut out = Vec::new();
    let mut index = 0;
    while let Some(parameter) = parameters.get(index) {
        let following = parameters
            .get(index + 1)
            .filter(|next| next.ty.is_length() && parameter.ty.pointer.is_some());
        if let Some(next) = following {
            if next.member.name == "capacity" {
                out.push(Role::Fill {
                    data: parameter,
                    capacity: next,
                });
                index += 2;
                continue;
            }
            if parameter.ty.points_at_bytes() && !next.member.name.starts_with("out_") {
                out.push(Role::Buffer {
                    data: parameter,
                    len: next,
                });
                index += 2;
                continue;
            }
        }
        out.push(role_of(surface, parameter));
        index += 1;
    }
    out
}

fn role_of<'a>(surface: &Surface, parameter: &'a Read<'a>) -> Role<'a> {
    if let (Some(writable), Base::Named(name)) = (parameter.ty.pointer, &parameter.ty.base)
        && let Some(record) = record_named(surface, name)
    {
        if writable == Writable::No {
            return Role::Config(parameter);
        }
        let brings_buffers = record
            .fields
            .iter()
            .any(|field| Type::read(field.rust_type).is_ok_and(|ty| ty.pointer.is_some()));
        return if brings_buffers {
            Role::Shared(parameter)
        } else {
            Role::Given(parameter)
        };
    }
    if parameter.ty.pointer == Some(Writable::Yes) && parameter.member.name.starts_with("out_") {
        return Role::Out(parameter);
    }
    Role::Plain(parameter)
}

/// `InvalidArgument` becomes `INVALID_ARGUMENT`.
pub(crate) fn screaming(name: &str) -> String {
    snake(name).to_ascii_uppercase()
}

/// The words a name is made of, lower case, however the declaration spelled
/// it: `bind_address_len`, `BindAddressLen` and `BIND_ADDRESS_LEN` all give
/// the same three.
///
/// The boundaries are [`snake`]'s own, letter for letter, and
/// `tests::the_words_a_name_is_made_of_join_back_into_snake` holds the two to
/// each other over every name the ABI spells: the words joined back with `_`
/// and lowered are what `snake` produces. A derivation written twice is a
/// derivation that can disagree with itself.
///
/// They part over one shape, and only one: an underscore that borders nothing
/// -- a leading one, or two in a row -- is a boundary `snake` keeps and this
/// drops. No name in the ABI has one and none can, because C reserves those
/// spellings to the implementation and the `refuses` rule [`crate::c::Names`]
/// carries stops them at the gate.
pub(crate) fn words(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut previous_lower = false;
    for letter in name.chars() {
        if letter == '_' {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            previous_lower = false;
            continue;
        }
        if letter.is_ascii_uppercase() && previous_lower && !word.is_empty() {
            out.push(std::mem::take(&mut word));
        }
        previous_lower = letter.is_ascii_lowercase() || letter.is_ascii_digit();
        word.push(letter);
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// One word with its first letter up and the rest down: `ADDRESS` and
/// `address` both give `Address`.
fn capitalised(word: &str) -> String {
    let mut characters = word.chars();
    match characters.next() {
        Some(first) => {
            first.to_ascii_uppercase().to_string() + &characters.as_str().to_ascii_lowercase()
        }
        None => String::new(),
    }
}

/// `bind_address_len` becomes `bindAddressLen`, `InvalidArgument` becomes
/// `invalidArgument`, and `FEATURE_OPUS` becomes `featureOpus`.
///
/// The third case is the one this was got wrong for: a name already in
/// capitals has no lower-case letter for a boundary to be found beside, and a
/// rule that only looked for `_` and for a capital left `SIPRAL_FEATURE_OPUS`
/// as `fEATUREOPUS` in the Swift binding.
pub(crate) fn lower_camel(name: &str) -> String {
    let words = words(name);
    let mut out = String::new();
    for (index, word) in words.iter().enumerate() {
        if index == 0 {
            out.push_str(&word.to_ascii_lowercase());
        } else {
            out.push_str(&capitalised(word));
        }
    }
    out
}

/// `bind_address_len` becomes `BindAddressLen`, and `FEATURE_OPUS` becomes
/// `FeatureOpus`.
pub(crate) fn upper_camel(name: &str) -> String {
    words(name).iter().map(|word| capitalised(word)).collect()
}

/// The name an entry point takes once the library's prefix is off, in the
/// case a method wants: `sipral_call_send_dtmf` becomes `callSendDtmf`.
pub(crate) fn without_prefix(name: &str) -> String {
    lower_camel(name.strip_prefix("sipral_").unwrap_or(name))
}

/// The record a name refers to, if the surface has one.
pub(crate) fn record_named<'a>(surface: &'a Surface, name: &str) -> Option<&'a Record> {
    surface.records.iter().find(|record| record.name == name)
}

/// Documentation as the declaration wrote it, with the Rust link brackets
/// taken off: a binding's reader has no `rustdoc` to follow them with.
///
/// What was inside the brackets goes through `rename`, so that a C programmer
/// reading the header is sent to `sipral_event_t::kind` rather than to a Rust
/// name that appears nowhere in front of them.
pub(crate) fn plain_named(doc: &[&str], rename: &dyn Fn(&str) -> String) -> Vec<String> {
    let mut out = Vec::new();
    for line in doc {
        let mut text = String::new();
        let mut rest = line.trim_end();
        while let Some(open) = rest.find("[`") {
            let Some(close) = rest[open..].find("`]") else {
                break;
            };
            let Some(before) = rest.get(..open) else {
                break;
            };
            let Some(inside) = rest.get(open + 2..open + close) else {
                break;
            };
            text.push_str(before);
            text.push_str(&rename(inside));
            let after = open + close + 2;
            rest = rest.get(after..).unwrap_or("");
            // an intra-doc link may carry a path in brackets behind it
            if rest.starts_with('(')
                && let Some(end) = rest.find(')')
            {
                rest = rest.get(end + 1..).unwrap_or("");
            }
        }
        text.push_str(rest);
        let text = text.trim_end();
        // a markdown heading is rustdoc's; every language below reads it as a
        // line of prose
        let heading = text.strip_prefix(" # ").map(|rest| format!(" {rest}"));
        let text = heading.as_deref().unwrap_or(text);
        out.push(text.trim_end().to_owned());
    }
    while out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out
}

/// A linked path split into the type it names and the member of it, when it
/// names one.
pub(crate) fn linked<'a>(
    surface: &Surface,
    path: &'a str,
) -> Option<(Linked<'a>, Option<&'a str>)> {
    let (head, member) = match path.split_once("::") {
        Some((head, member)) => (head, Some(member)),
        None => (path, None),
    };
    if let Some(enumeration) = surface.enumerations.iter().find(|e| e.name == head) {
        let code = member.filter(|name| enumeration.codes.iter().any(|c| c.name == *name));
        return Some((Linked::Enumeration(head), code));
    }
    if surface.records.iter().any(|record| record.name == head)
        || surface.aliases.iter().any(|alias| alias.name == head)
    {
        return Some((Linked::Type(head), member));
    }
    None
}

/// What a documentation link turned out to point at.
pub(crate) enum Linked<'a> {
    /// An enumeration, whose members are constants rather than fields.
    Enumeration(&'a str),
    /// A record or an alias.
    Type(&'a str),
}

/// Every function whose parameters could be read, in the surface's order.
pub(crate) fn functions(surface: &Surface) -> Result<Vec<(&Function, Vec<Read<'_>>)>, Refused> {
    surface
        .functions
        .iter()
        .map(|function| read_all(function.name, function.parameters).map(|read| (function, read)))
        .collect()
}
