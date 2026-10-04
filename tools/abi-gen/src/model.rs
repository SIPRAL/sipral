// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a declaration means once it has been read, and what each language
//! calls it.
//!
//! The descriptors carry Rust type expressions because that is what the
//! declaration was written in. Everything downstream works from [`Type`],
//! which is the same information with the spelling taken off, so that a
//! language back end asks "is this a pointer to bytes" rather than matching on
//! a string.

use std::collections::BTreeSet;

use sipral_ffi::abi::{Alias, Function, Member, Record, Shape, Stands, Surface, Value};
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

/// What a binding checks itself against at load, as the surface declares it:
/// the entry point that says whether this library can serve a binding
/// generated against a version, and the two constants that are that
/// version.
///
/// A back end prints the call from these rather than writing it out, because
/// a call written out names whatever the declarations were called the day it
/// was written: rename the entry point or a constant and the binding calls
/// something it no longer has, which nothing notices until somebody compiles
/// it. A surface without all of them is refused, since a binding that cannot
/// check the ABI at load is not one to print.
pub(crate) struct LoadCheck<'a> {
    /// The entry point.
    pub(crate) function: &'a Function,
    /// The major version the surface is.
    pub(crate) major: &'a Value,
    /// The minor version the surface is.
    pub(crate) minor: &'a Value,
}

/// The load check a surface declares, or which part of it is missing.
pub(crate) fn load_check<'a>(
    surface: &'a Surface,
    language: &str,
) -> Result<LoadCheck<'a>, Refused> {
    const CHECK: &str = "sipral_abi_check";
    let Some(function) = surface
        .functions
        .iter()
        .find(|function| function.name == CHECK)
    else {
        return Err(Refused::about(&format!(
            "the surface declares no {CHECK}, so the {language} binding has nothing to check \
             the ABI with at load"
        )));
    };
    let version = Type::read("u32")?;
    let [major_parameter, minor_parameter] = function.parameters else {
        return Err(Refused::about(&format!(
            "{CHECK} takes a major and a minor version, and its declaration has {} parameters",
            function.parameters.len()
        )));
    };
    if Type::read(major_parameter.rust_type)? != version
        || Type::read(minor_parameter.rust_type)? != version
    {
        return Err(Refused::about(&format!(
            "{CHECK} takes a major and a minor version as two u32, and its declaration takes \
             {} and {}",
            major_parameter.rust_type, minor_parameter.rust_type
        )));
    }
    let constant = |name: &str| {
        surface
            .constants
            .iter()
            .flat_map(|group| group.iter())
            .find(|value| value.name == name)
            .ok_or_else(|| {
                Refused::about(&format!(
                    "the surface declares no {name}, which the {language} binding hands to \
                     {CHECK} at load"
                ))
            })
    };
    Ok(LoadCheck {
        function,
        major: constant("SIPRAL_ABI_VERSION_MAJOR")?,
        minor: constant("SIPRAL_ABI_VERSION_MINOR")?,
    })
}

/// A type that crosses the boundary, with the pointer separated from what it
/// points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Type {
    /// Whether it is behind a pointer, and whether that pointer is writable.
    pub(crate) pointer: Option<Writable>,
    /// What it is, or what it points at.
    pub(crate) base: Base,
    /// The enumeration whose numbers it holds, when the declaration said so
    /// with `Number<E>`. The base is then `E`'s integer, which is what every
    /// binding hands over; the name is what C spells it with.
    pub(crate) enumeration: Option<String>,
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
        // `isize` has no C spelling here: `size_t` is unsigned, and printing a
        // signed length as one is a sign lost without a word
        if rest == "size" {
            return (!signed).then_some(Self::SIZE);
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
        let packed: String = rest.chars().filter(|c| !c.is_whitespace()).collect();
        let last = packed.rsplit("::").next().unwrap_or(&packed);
        if let Some(inner) = last.strip_prefix("Number<") {
            let Some(name) = inner
                .strip_suffix('>')
                .filter(|name| name.starts_with("Sipral"))
            else {
                return Err(Refused::about(&format!(
                    "{spelling} is a Number of something that is not one of the ABI's \
                     enumerations"
                )));
            };
            return Ok(Self {
                pointer,
                base: Base::Int(Int {
                    bits: 32,
                    signed: false,
                }),
                enumeration: Some(name.to_owned()),
            });
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
        Ok(Self {
            pointer,
            base,
            enumeration: None,
        })
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

/// What a callback answers with, once its return type has been read: a
/// plain integer, or nothing, which every callback declared today answers
/// with.
///
/// A pointer, a float, a character or a named type is refused by name here,
/// once, rather than separately by whichever back end happens to print the
/// callback's signature first: none of the four languages has a rule yet for
/// reading one back off a listener's return, and a half-printed binding is
/// worse than a refusal that says what about the declaration cannot be
/// printed.
pub(crate) fn callback_answer(alias: &Alias) -> Result<Option<Type>, Refused> {
    let Stands::Callback(_, answer) = alias.stands else {
        return Ok(None);
    };
    let Some(spelling) = answer else {
        return Ok(None);
    };
    let ty = Type::read(spelling)
        .map_err(|why| Refused::about(&format!("{} answers with {why}", alias.name)))?;
    if ty.pointer.is_some() || !matches!(ty.base, Base::Int(_)) {
        return Err(Refused::about(&format!(
            "{} answers with {spelling}, which is not a plain integer, and this generator \
             prints a callback's answer as one of those or as nothing; give {spelling} a shape \
             in tools/abi-gen/src/model.rs",
            alias.name
        )));
    }
    Ok(Some(ty))
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
    /// Records the caller hands in, an array of them, with the `_len` after
    /// the pointer saying how many.
    Records {
        /// The pointer to the first.
        data: &'a Read<'a>,
        /// How many there are.
        len: &'a Read<'a>,
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
    /// A listener the caller installs on something the library already holds:
    /// the callback, and the pointer handed back to it untouched on every
    /// call, which is where a binding that keeps its own listener puts the
    /// key it finds that listener by.
    Listener {
        /// The function pointer.
        callback: &'a Read<'a>,
        /// The `*mut c_void` after it.
        user_data: &'a Read<'a>,
        /// What the callback is, for the back end that has to print a
        /// listener of its own for it.
        alias: &'static Alias,
    },
}

/// The callback a name refers to, if the surface declares one under it.
pub(crate) fn callback_named(surface: &Surface, name: &str) -> Option<&'static Alias> {
    surface
        .aliases
        .iter()
        .find(|alias| alias.name == name && matches!(alias.stands, Stands::Callback(_, _)))
}

/// The pointer a callback's user data travels in.
pub(crate) fn user_pointer() -> Type {
    Type {
        pointer: Some(Writable::Yes),
        base: Base::Opaque,
        enumeration: None,
    }
}

/// Refuse a `Number<E>` whose `E` is not an enumeration the surface declares
/// with the width the number crosses as.
///
/// `Number<E>` reads as a `u32` before the surface is at hand, since the alias
/// is `E`'s integer and every enumeration a parameter holds is one; one of
/// another width would be printed as a `u32` beside a `typedef` that says
/// otherwise, so it is refused here, once, rather than by the first back end
/// to print it.
pub(crate) fn numbers_named(surface: &Surface) -> Result<(), Refused> {
    let members = surface
        .records
        .iter()
        .flat_map(|record| record.fields.iter().map(move |field| (record.name, field)))
        .chain(surface.functions.iter().flat_map(|function| {
            function
                .parameters
                .iter()
                .map(move |parameter| (function.name, parameter))
        }));
    for (owner, member) in members {
        let ty = Type::read(member.rust_type)
            .map_err(|why| Refused::about(&format!("{owner}::{}: {why}", member.name)))?;
        let Some(name) = ty.enumeration else {
            continue;
        };
        let Some(enumeration) = surface.enumerations.iter().find(|e| e.name == name) else {
            return Err(Refused::about(&format!(
                "{owner}::{} holds a Number<{name}>, and the surface declares no enumeration \
                 {name}",
                member.name
            )));
        };
        if enumeration.width != "u32" {
            return Err(Refused::about(&format!(
                "{owner}::{} holds a Number<{name}>, which crosses as a u32, and {name} is a {}",
                member.name, enumeration.width
            )));
        }
    }
    Ok(())
}

/// Whether a parameter, or a member, is a callback the surface declares.
fn is_callback(surface: &Surface, read: &Read<'_>) -> Option<&'static Alias> {
    match (&read.ty.pointer, &read.ty.base) {
        (None, Base::Named(name)) => callback_named(surface, name),
        _ => None,
    }
}

/// Read a parameter list as the conventions in `docs/08-ffi.md` describe it.
///
/// Six conventions, and all six are the ABI's own rather than this
/// generator's: a pointer followed by a length is one buffer going in; a
/// `const` pointer to a record followed by the `_len` named for it is an array
/// of records going in; a pointer followed by `capacity` is one buffer being
/// filled; a writable pointer named `out_` is one value coming back; a
/// pointer to a versioned struct is a struct going in, coming back, or both,
/// depending on which way the pointer goes and on whether the struct holds
/// buffers of the caller's; and a callback followed by a `*mut c_void` is one
/// listener, the same pair a struct going in already means by it.
pub(crate) fn roles<'a>(surface: &Surface, parameters: &'a [Read<'a>]) -> Vec<Role<'a>> {
    let mut out = Vec::new();
    let mut index = 0;
    while let Some(parameter) = parameters.get(index) {
        let following = parameters
            .get(index + 1)
            .filter(|next| next.ty.is_length() && parameter.ty.pointer.is_some());
        if let Some(next) = following {
            if counts_records(surface, parameter, next) {
                out.push(Role::Records {
                    data: parameter,
                    len: next,
                });
                index += 2;
                continue;
            }
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
        if let Some(alias) = is_callback(surface, parameter)
            && let Some(next) = parameters
                .get(index + 1)
                .filter(|after| after.ty == user_pointer())
        {
            out.push(Role::Listener {
                callback: parameter,
                user_data: next,
                alias,
            });
            index += 2;
            continue;
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

/// Whether a pointer and the member after it are an array of records going
/// in: a `const` pointer to a record the surface declares, and a `usize` named
/// for it with `_len`.
///
/// The name is part of the rule, for parameters and struct members alike. A
/// struct going in is also a `const` pointer to a record, and a length beside
/// one that is not named for it is some other number: read as a count, it
/// hands the library a length nobody meant for the array, which is the one
/// mistake this shape exists to rule out.
pub(crate) fn counts_records(surface: &Surface, data: &Read<'_>, next: &Read<'_>) -> bool {
    data.ty.pointer == Some(Writable::No)
        && matches!(&data.ty.base, Base::Named(name) if record_named(surface, name).is_some())
        && next.ty.is_length()
        && next.member.name == format!("{}_len", data.member.name)
}

/// Refuse, naming the declaration, an entry point a binding that builds its
/// own values would hand C something other than what the declaration says.
///
/// A callback parameter with no `*mut c_void` after it is the first of them.
/// Kotlin's listener never leaves the JVM and is found again by a key that
/// travels in exactly that pointer, so a callback taken without one is a
/// listener that could be installed and never reached.
///
/// A pointer to a record with a length after it that [`counts_records`] did
/// not read as an array going in is one of two things, and neither is one
/// struct. With the `_len` named for it behind a pointer the library may write
/// through, it is an array coming back, which no back end builds. Pointing at
/// a record with no size member, it is the element of an array whatever the
/// length is called, since a struct handed over alone carries its size. Read
/// as one struct, either hands C the address of a single element and a length
/// the caller chose, which C reads past. And a call that answers with text is
/// printed with its parameters handed through as they came, so an array of
/// records it takes, directly or inside a struct, would cross as whatever the
/// caller supplied beside it.
pub(crate) fn unprintable(
    surface: &Surface,
    function: &Function,
    parameters: &[Read<'_>],
    language: &str,
) -> Result<(), Refused> {
    let refuse = |why: String| {
        Err(Refused::about(&format!(
            "{why}, so the {language} binding has no way to hand it over; give it a shape in \
             tools/abi-gen/src/model.rs"
        )))
    };
    for (index, parameter) in parameters.iter().enumerate() {
        if is_callback(surface, parameter).is_none() {
            continue;
        }
        if parameters
            .get(index + 1)
            .is_none_or(|after| after.ty != user_pointer())
        {
            return refuse(format!(
                "{}::{} is a callback with no `*mut c_void` after it to carry the listener a \
                 binding of its own keeps",
                function.name, parameter.member.name
            ));
        }
    }
    for pair in parameters.windows(2) {
        let [data, next] = pair else {
            continue;
        };
        let (Some(writable), Base::Named(name)) = (data.ty.pointer, &data.ty.base) else {
            continue;
        };
        let Some(record) = record_named(surface, name) else {
            continue;
        };
        if !next.ty.is_length() || counts_records(surface, data, next) {
            continue;
        }
        let wanted = format!("{}_len", data.member.name);
        if writable == Writable::Yes && next.member.name == wanted {
            return refuse(format!(
                "{}::{} points at {} with `{wanted}` after it, which is an array the library \
                 writes back",
                function.name, data.member.name, record.name
            ));
        }
        if !record.is_versioned() {
            return refuse(format!(
                "{}::{} points at {}, which has no size member and so is the element of an \
                 array, and `{}` after it is not the `{wanted}` that says how many",
                function.name, data.member.name, record.name, next.member.name
            ));
        }
    }
    let answers = Type::read(function.returns)
        .map_err(|why| Refused::about(&format!("{} answers with {why}", function.name)))?;
    if answers.pointer.is_none() || answers.base != Base::Char {
        return Ok(());
    }
    for role in roles(surface, parameters) {
        let listed = match role {
            Role::Records { .. } => true,
            Role::Config(read) => !listed_in(surface, read, language)?.is_empty(),
            _ => false,
        };
        if listed {
            return refuse(format!(
                "{} answers with text and takes an array of records, and a call that answers \
                 with text is printed with its parameters handed through as they came",
                function.name
            ));
        }
    }
    Ok(())
}

/// A record as the element of an array going in, for a binding that builds
/// every element out of values of its own rather than handing the caller's
/// pointers through.
pub(crate) struct Element {
    /// The record.
    pub(crate) record: &'static Record,
    /// Its members, each a piece of text and the length after it, in the
    /// order the record declares them.
    pub(crate) texts: Vec<Text>,
}

/// One member of an element: a pointer to UTF-8 and its `_len`.
pub(crate) struct Text {
    /// The pointer.
    pub(crate) data: Read<'static>,
    /// The length that follows it.
    pub(crate) len: Read<'static>,
}

/// Read the record an array of records going in is made of, or say why a
/// binding in `language` cannot build one.
///
/// Every refusal names the declaration. An element is strided by its own
/// length, so a `size` member would move every element after the first the
/// day it grew; a union has no member a binding could say it set; and a
/// member that is not text is a shape no back end builds an element out of
/// yet, which is a decision for this file rather than a guess in three
/// others.
pub(crate) fn element_of(record: &'static Record, language: &str) -> Result<Element, Refused> {
    let refuse = |why: String| {
        Refused::about(&format!(
            "{why}, so the {language} binding has no way to build one; give it a shape in \
             tools/abi-gen/src/model.rs"
        ))
    };
    if record.shape != Shape::Struct {
        return Err(refuse(format!(
            "{} is handed over as the element of an array and is a union",
            record.name
        )));
    }
    if record.is_versioned() {
        return Err(refuse(format!(
            "{} is handed over as the element of an array and carries a size member, which an \
             array strided by the element's length cannot grow",
            record.name
        )));
    }
    let fields = read_all(record.name, record.fields)?;
    if fields.is_empty() {
        return Err(refuse(format!(
            "{} is handed over as the element of an array and has no members",
            record.name
        )));
    }
    let mut texts = Vec::new();
    let mut members = fields.into_iter().peekable();
    while let Some(data) = members.next() {
        let text = data.ty.pointer == Some(Writable::No) && data.ty.base == Base::Char;
        let wanted = format!("{}_len", data.member.name);
        let Some(len) =
            members.next_if(|after| text && after.ty.is_length() && after.member.name == wanted)
        else {
            return Err(refuse(format!(
                "{}::{} is not a piece of text with `{wanted}` after it, and a record handed \
                 over as the element of an array holds nothing else here",
                record.name, data.member.name
            )));
        };
        texts.push(Text { data, len });
    }
    Ok(Element { record, texts })
}

/// Every record the surface hands over as the element of an array going in,
/// once each and in the order the surface declares the records: through an
/// entry point's parameters, or through a member of a struct one of them takes.
pub(crate) fn elements(surface: &Surface, language: &str) -> Result<Vec<Element>, Refused> {
    let mut named = BTreeSet::new();
    for (_, read) in functions(surface)? {
        for role in roles(surface, &read) {
            match role {
                Role::Records { data, .. } => {
                    if let Base::Named(name) = &data.ty.base {
                        named.insert(name.clone());
                    }
                }
                Role::Config(config) => {
                    for listed in listed_in(surface, config, language)? {
                        named.insert(listed.element.record.name.to_owned());
                    }
                }
                _ => {}
            }
        }
    }
    surface
        .records
        .iter()
        .filter(|record| named.contains(record.name))
        .map(|record| element_of(record, language))
        .collect()
}

/// The element a pointer to records going in points at.
pub(crate) fn element(
    surface: &Surface,
    data: &Read<'_>,
    language: &str,
) -> Result<Element, Refused> {
    let found = match &data.ty.base {
        Base::Named(name) => surface.records.iter().find(|record| record.name == name),
        _ => None,
    };
    let Some(record) = found else {
        return Err(Refused::about(&format!(
            "{} is taken as an array of records and points at no record the surface declares",
            data.member.name
        )));
    };
    element_of(record, language)
}

/// An array of records going in that a struct holds.
pub(crate) struct Listed {
    /// The pointer member.
    pub(crate) data: Read<'static>,
    /// The `_len` member after it.
    pub(crate) len: Read<'static>,
    /// What each element is.
    pub(crate) element: Element,
}

/// Every array of records going in held by the struct a parameter points at,
/// in the order the struct declares them. A parameter that points at no
/// record holds none.
pub(crate) fn listed_in(
    surface: &Surface,
    parameter: &Read<'_>,
    language: &str,
) -> Result<Vec<Listed>, Refused> {
    let Base::Named(name) = &parameter.ty.base else {
        return Ok(Vec::new());
    };
    let Some(record) = surface.records.iter().find(|record| record.name == name) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let mut members = read_all(record.name, record.fields)?.into_iter().peekable();
    while let Some(data) = members.next() {
        let Some(len) = members.next_if(|after| counts_records(surface, &data, after)) else {
            continue;
        };
        let element = element(surface, &data, language)?;
        out.push(Listed { data, len, element });
    }
    Ok(out)
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
    let mut previous_upper = false;
    let mut letters = name.chars().peekable();
    while let Some(letter) = letters.next() {
        if letter == '_' {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            previous_lower = false;
            previous_upper = false;
            continue;
        }
        let next_lower = letters.peek().is_some_and(char::is_ascii_lowercase);
        if letter.is_ascii_uppercase()
            && (previous_lower || (previous_upper && next_lower))
            && !word.is_empty()
        {
            out.push(std::mem::take(&mut word));
        }
        previous_lower = letter.is_ascii_lowercase() || letter.is_ascii_digit();
        previous_upper = letter.is_ascii_uppercase();
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
            // `crate::event::SipralEventKind` is a path rustdoc needs and no
            // other reader has; the item at its end is what the link names
            let inside = inside
                .strip_prefix("crate::")
                .and_then(|rest| rest.split_once("::"))
                .map_or(inside, |(_, item)| item);
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
        let text = rust_names_renamed(&text, rename);
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

/// A line with every `` `SipralFoo` `` in code quotes that is not a link
/// spelled the way `rename` spells a link to it, in its quotes still.
///
/// A declaration's prose says "as a `SipralToggle`" as often as it links one,
/// and a reader of the header meets that name nowhere else; a quoted name
/// `rename` does not know comes back as it was.
fn rust_names_renamed(line: &str, rename: &dyn Fn(&str) -> String) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some(open) = rest.find('`') {
        let (before, quoted) = rest.split_at(open);
        out.push_str(before);
        let Some(close) = quoted[1..].find('`') else {
            out.push_str(quoted);
            return out;
        };
        let inside = &quoted[1..=close];
        let rust_name = inside.starts_with("Sipral")
            && inside
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == ':');
        if rust_name {
            out.push('`');
            out.push_str(&rename(inside));
            out.push('`');
        } else {
            out.push_str(&quoted[..close + 2]);
        }
        rest = &quoted[close + 2..];
    }
    out.push_str(rest);
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
