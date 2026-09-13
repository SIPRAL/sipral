// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The Kotlin binding, and the JNI shim underneath it.
//!
//! Android has no way to call C but JNI, so this back end prints two files
//! that have to agree with each other as well as with the ABI: `SipralNative`,
//! one `external fun` per entry point, and the C that implements them. Both
//! come out of the same walk over the same declarations, which is the only
//! reason it is safe to have two of them.
//!
//! Structs are the part JNI makes awkward, and the way out of it is never to
//! let a struct's layout cross. A struct the library fills in whole is handed
//! back a member at a time in a `long[]` the shim writes, with a float carried
//! as its own bits, so nothing on the Kotlin side has to know a field offset —
//! which it could not, since Android builds for two pointer widths. A struct
//! the caller fills in and the library only reads is a Kotlin class instead,
//! whose fields the wrapper hands over one argument each and the shim copies
//! into a zeroed C struct with the size member set. A struct the caller
//! part-fills with buffers the library writes into is the one shape left
//! over, and it crosses as an address: `docs/08-ffi.md` says so and says what
//! it costs.
//!
//! The callback goes the other way, and the listener behind it never leaves
//! the JVM. A struct going in that holds the callback holds a Kotlin listener
//! in its place; the wrapper keeps the listener under a key, and what reaches
//! C is the key, as the callback's user pointer, beside a C function the shim
//! prints for the callback to land in. That function attaches the polling
//! thread to the JVM when it is not attached already, hands over the event,
//! deletes every local reference it made, and detaches only what it attached.
//! The listener is let go of by the entry point that destroys the handle the
//! struct was handed to, so an event that arrives for a stack already
//! destroyed finds no listener rather than a freed one.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use sipral_ffi::abi::{
    Alias, Code, Enumeration, Function, Member, Record, Shape, Stands, Surface, Value,
};

use crate::c;
use crate::model::{
    Base, Element, Int, Linked, Read, Refused, Role, Text, Type, Writable, counts_records, element,
    elements, functions, linked, lower_camel, plain_named, read_all, record_named, roles,
    screaming, snake, unprintable, upper_camel, without_prefix,
};
use crate::names::{Layout, Named, Spelling, audit};

/// What a name inside a documentation link is called in Kotlin.
fn spelled(surface: &Surface, path: &str) -> String {
    match linked(surface, path) {
        Some((Linked::Enumeration(name), Some(code))) => {
            format!("{name}.{}", screaming(code))
        }
        Some((Linked::Enumeration(name) | Linked::Type(name), None)) => name.to_owned(),
        Some((Linked::Type(name), Some(member))) => {
            format!("{name}.{}", lower_camel(member))
        }
        None => path.to_owned(),
    }
}

/// Documentation with every link in it spelled the Kotlin way.
fn lines(surface: &Surface, doc: &[&str]) -> Vec<String> {
    plain_named(doc, &|path| spelled(surface, path))
}

/// The name a value coming back takes.
fn returned(name: &str) -> String {
    lower_camel(name.strip_prefix("out_").unwrap_or(name))
}

/// Words Kotlin will not take as a name.
///
/// The hard keywords only. Kotlin's soft and modifier keywords -- `data`,
/// `value`, `operator` and the rest -- are ordinary names everywhere but the
/// one place they modify a declaration, and refusing them would refuse
/// declarations that are perfectly good.
const RESERVED: &[&str] = &[
    "as",
    "break",
    "class",
    "continue",
    "do",
    "else",
    "false",
    "for",
    "fun",
    "if",
    "in",
    "interface",
    "is",
    "null",
    "object",
    "package",
    "return",
    "super",
    "this",
    "throw",
    "true",
    "try",
    "typealias",
    "typeof",
    "val",
    "var",
    "when",
    "while",
];

/// How Kotlin spells a name it would otherwise refuse. The C below has no
/// such thing, which is why [`Names::refuses`] asks C about the shim.
fn safe(name: &str) -> String {
    if RESERVED.contains(&name) {
        format!("`{name}`")
    } else {
        name.to_owned()
    }
}

/// The one spelling of a parameter's name on the Kotlin side.
fn held(read: &Read<'_>) -> String {
    safe(&lower_camel(read.member.name))
}

/// The same parameter on the C side of JNI, where there are no backticks.
fn c_held(read: &Read<'_>) -> String {
    lower_camel(read.member.name)
}

/// The one spelling of the name a value written back takes, Kotlin side.
fn written(read: &Read<'_>) -> String {
    safe(&returned(read.member.name))
}

/// One local the wrapper writes beside a parameter, escaped as a whole: the
/// backticks go round the finished name, never round a piece of it.
fn beside(base: &str, suffix: &str) -> String {
    safe(&format!("{base}{suffix}"))
}

/// The one spelling of what an entry point is called here.
fn called(function: &Function) -> String {
    safe(&without_prefix(function.name))
}

fn doc(out: &mut String, indent: &str, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    let _ = writeln!(out, "{indent}/**");
    for line in lines {
        if line.is_empty() {
            let _ = writeln!(out, "{indent} *");
        } else {
            let _ = writeln!(out, "{indent} *{line}");
        }
    }
    let _ = writeln!(out, "{indent} */");
}

/// Whether a record can be handed back a member at a time, which it can when
/// nothing in it is a buffer of the caller's.
fn is_given(record: &Record) -> bool {
    record.is_versioned()
        && record
            .fields
            .iter()
            .all(|field| Type::read(field.rust_type).is_ok_and(|ty| ty.pointer.is_none()))
}

/// The Kotlin type one member of such a record reads back as.
fn slot_type(ty: &Type) -> &'static str {
    match ty.base {
        Base::Float(_) => "Float",
        _ => "Long",
    }
}

/// The Kotlin array an array-shaped parameter arrives in.
fn array_of(ty: &Type) -> &'static str {
    match ty.base {
        Base::Int(Int { bits: 16, .. }) => "ShortArray",
        Base::Int(Int { bits: 32, .. }) => "IntArray",
        _ => "ByteArray",
    }
}

/// The JNI array type that goes with it.
fn jni_array_of(ty: &Type) -> &'static str {
    match ty.base {
        Base::Int(Int { bits: 16, .. }) => "jshortArray",
        Base::Int(Int { bits: 32, .. }) => "jintArray",
        _ => "jbyteArray",
    }
}

/// The JNI element type that goes with it.
fn jni_element_of(ty: &Type) -> (&'static str, &'static str) {
    match ty.base {
        Base::Int(Int { bits: 16, .. }) => ("jshort", "Short"),
        Base::Int(Int { bits: 32, .. }) => ("jint", "Int"),
        _ => ("jbyte", "Byte"),
    }
}

/// How the JVM writes that array's type in a method descriptor.
fn descriptor_of_array(ty: &Type) -> &'static str {
    match ty.base {
        Base::Int(Int { bits: 16, .. }) => "[S",
        Base::Int(Int { bits: 32, .. }) => "[I",
        _ => "[B",
    }
}

/// What a plain value crosses as. Everything integral is a `Long`, because a
/// binding that argued about widths at this seam would be arguing with the
/// header rather than with the ABI.
fn plain_kotlin(ty: &Type) -> &'static str {
    match ty.base {
        Base::Float(_) => "Double",
        _ => "Long",
    }
}

fn plain_jni(ty: &Type) -> &'static str {
    match ty.base {
        Base::Float(_) => "jdouble",
        _ => "jlong",
    }
}

/// How the JVM writes a plain value's type in a method descriptor.
fn plain_descriptor(ty: &Type) -> &'static str {
    match ty.base {
        Base::Float(_) => "D",
        _ => "J",
    }
}

/// What a plain field of a class defaults to, which is the zero the C struct
/// would have held.
fn zero_of(ty: &Type) -> &'static str {
    match ty.base {
        Base::Float(_) => "0.0",
        _ => "0",
    }
}

// ------------------------------------------------------------ records as classes

/// One member of a record as a Kotlin class holds it.
enum Part<'a> {
    /// A number, which is a `Long` or a `Double` here as everywhere else.
    Plain(&'a Read<'a>),
    /// A pointer and the `_len` after it: a `String` when it points at
    /// characters, an array otherwise, and null for a null pointer.
    Buffer {
        /// The pointer.
        data: &'a Read<'a>,
        /// The length that follows it.
        len: &'a Read<'a>,
    },
    /// A pointer to records and the `_len` after it: a list of the class
    /// the element is built from, and null for a null pointer.
    Records {
        /// The pointer.
        data: &'a Read<'a>,
        /// The length that follows it.
        len: &'a Read<'a>,
        /// What each element is.
        element: Element,
    },
    /// The callback and the user pointer after it, which together are one
    /// listener.
    Listener {
        /// The function pointer.
        callback: &'a Read<'a>,
        /// The pointer handed back to it, which carries the listener's key.
        user_data: &'a Read<'a>,
        /// What the callback is.
        alias: &'static Alias,
    },
    /// A union held by value, whose live arm another member names.
    Arm(&'a Read<'a>),
}

/// The callback a name refers to, if the surface has one.
fn callback_named(surface: &Surface, name: &str) -> Option<&'static Alias> {
    surface
        .aliases
        .iter()
        .find(|alias| alias.name == name && matches!(alias.stands, Stands::Callback(_)))
}

/// The pointer a callback's user data travels in.
fn user_pointer() -> Type {
    Type {
        pointer: Some(Writable::Yes),
        base: Base::Opaque,
    }
}

/// Read the members of a record, from `first` on, as a Kotlin class holds
/// them.
///
/// The conventions are the ones a parameter list follows, read off a struct:
/// a pointer followed by its `_len` is one buffer, or a list when it points
/// at records, and the callback followed by a `*mut c_void` is one listener.
/// Anything else that is not a number is refused, naming the member, rather
/// than crossing as an address nobody on the Kotlin side has a way to make.
fn parts<'a>(
    surface: &Surface,
    record: &Record,
    fields: &'a [Read<'a>],
    first: usize,
) -> Result<Vec<Part<'a>>, Refused> {
    let mut out = Vec::new();
    let mut index = first;
    while let Some(field) = fields.get(index) {
        let next = fields.get(index + 1);
        if let Some(len) = next.filter(|after| counts_records(surface, field, after)) {
            out.push(Part::Records {
                data: field,
                len,
                element: element(surface, field, "Kotlin")?,
            });
            index += 2;
            continue;
        }
        let refuse = |why: &str| {
            Refused::about(&format!(
                "{}::{} {why}, which a Kotlin class has no field for; give it one in \
                 tools/abi-gen/src/kotlin.rs",
                record.name, field.member.name
            ))
        };
        match (field.ty.pointer, &field.ty.base) {
            (None, Base::Named(name)) => {
                if let Some(alias) = callback_named(surface, name) {
                    let Some(user_data) = next.filter(|after| after.ty == user_pointer()) else {
                        return Err(refuse(
                            "is a callback with no `*mut c_void` after it to carry its listener",
                        ));
                    };
                    out.push(Part::Listener {
                        callback: field,
                        user_data,
                        alias,
                    });
                    index += 2;
                    continue;
                }
                match surface.records.iter().find(|inner| inner.name == *name) {
                    Some(inner) if inner.shape == Shape::Union => out.push(Part::Arm(field)),
                    Some(_) => return Err(refuse("holds a struct by value")),
                    None => out.push(Part::Plain(field)),
                }
            }
            (None, _) => out.push(Part::Plain(field)),
            (Some(Writable::No), _) if field.ty.points_at_bytes() => {
                let wanted = format!("{}_len", field.member.name);
                let Some(len) =
                    next.filter(|after| after.ty.is_length() && after.member.name == wanted)
                else {
                    return Err(refuse(&format!(
                        "points at bytes with no `{wanted}` after it"
                    )));
                };
                out.push(Part::Buffer { data: field, len });
                index += 2;
                continue;
            }
            _ => {
                return Err(refuse(
                    "is a pointer that is neither a buffer going in nor a callback's user pointer",
                ));
            }
        }
        index += 1;
    }
    Ok(out)
}

/// A struct going in holds a union, which a caller could not set.
fn not_built(record: &Record, field: &Read<'_>) -> Refused {
    Refused::about(&format!(
        "{}::{} is a union inside a struct a caller builds, and a Kotlin class has no way to \
         say which arm it set; give it one in tools/abi-gen/src/kotlin.rs",
        record.name, field.member.name
    ))
}

/// A struct handed to a listener holds a callback, which nothing would call.
fn not_handed(record: &Record, field: &Read<'_>) -> Refused {
    Refused::about(&format!(
        "{}::{} is a callback inside a struct the library hands to a listener, and a listener \
         has nothing to do with one; give it a shape in tools/abi-gen/src/kotlin.rs",
        record.name, field.member.name
    ))
}

/// A struct handed to a listener holds an array of records, which nothing here
/// reads back.
fn records_not_handed(record: &Record, field: &Read<'_>) -> Refused {
    Refused::about(&format!(
        "{}::{} is an array of records inside a struct the library hands to a listener, and \
         this back end builds such arrays but reads none back; give it a shape in \
         tools/abi-gen/src/kotlin.rs",
        record.name, field.member.name
    ))
}

/// The two arguments a list crosses JNI in, spelled from `base` the Kotlin
/// way: the packed text, and the length of each piece of it.
fn packed_names(base: &str) -> (String, String) {
    (beside(base, "Bytes"), beside(base, "Lengths"))
}

/// The record a struct going in names.
fn config_record(surface: &Surface, read: &Read<'_>) -> Result<&'static Record, Refused> {
    let Base::Named(name) = &read.ty.base else {
        return Err(Refused::about("a struct with no name"));
    };
    surface
        .records
        .iter()
        .find(|record| record.name == name)
        .ok_or_else(|| Refused::about(&format!("{name} is not a record the surface declares")))
}

/// Every record an entry point takes behind a `const` pointer: the structs a
/// Kotlin caller builds, in the order the surface declares them.
fn built(surface: &Surface) -> Result<Vec<&'static Record>, Refused> {
    let mut named = BTreeSet::new();
    for (_, read) in functions(surface)? {
        for role in roles(surface, &read) {
            if let Role::Config(parameter) = role
                && let Base::Named(name) = &parameter.ty.base
            {
                named.insert(name.clone());
            }
        }
    }
    let mut out = Vec::new();
    for record in surface.records {
        if !named.contains(record.name) {
            continue;
        }
        if !record.is_versioned() {
            return Err(Refused::about(&format!(
                "{} goes in behind a const pointer and has no size member for the shim to fill \
                 in",
                record.name
            )));
        }
        if is_given(record) {
            return Err(Refused::about(&format!(
                "{} goes in behind a const pointer and holds nothing but numbers, so it would be \
                 printed twice: as a class to build and as a data class to read back. Give it one \
                 shape in tools/abi-gen/src/kotlin.rs",
                record.name
            )));
        }
        out.push(record);
    }
    Ok(out)
}

/// The Kotlin name of the field a listener takes: `event_callback` is
/// `eventListener`.
fn listener_field(callback: &Read<'_>) -> String {
    let name = callback.member.name;
    let listening = match name.strip_suffix("callback") {
        Some(stem) => format!("{stem}listener"),
        None => format!("{name}_listener"),
    };
    safe(&lower_camel(&listening))
}

/// One member of a struct going in, as the argument it crosses JNI in:
/// `config` and `bind_address` are `configBindAddress`.
fn flat(parameter: &Read<'_>, member: &Read<'_>) -> String {
    lower_camel(&format!("{}_{}", parameter.member.name, member.member.name))
}

// ------------------------------------------------------------ the callback

/// A callback, and what a Kotlin listener is handed when it is called: the
/// record its first parameter points at.
struct Landing {
    alias: &'static Alias,
    /// The parameter the record arrives in.
    event: &'static Member,
    /// The user pointer, which carries the key the listener is kept under.
    user_data: &'static Member,
    record: &'static Record,
}

impl Landing {
    /// Read a callback, refusing one that is not a pointer to a record and a
    /// user pointer: that is the one shape this back end lands in Kotlin.
    fn of(surface: &Surface, alias: &'static Alias) -> Result<Self, Refused> {
        let refuse = || {
            Refused::about(&format!(
                "{} is a callback that does not take a pointer to a versioned struct and a \
                 `*mut c_void`, which is the one shape this back end hands to a Kotlin \
                 listener; give it another in tools/abi-gen/src/kotlin.rs",
                alias.name
            ))
        };
        let Stands::Callback(arguments) = alias.stands else {
            return Err(refuse());
        };
        let [event, user_data] = arguments else {
            return Err(refuse());
        };
        let pointed = Type::read(event.rust_type)?;
        if Type::read(user_data.rust_type)? != user_pointer()
            || pointed.pointer != Some(Writable::No)
        {
            return Err(refuse());
        }
        let Base::Named(name) = &pointed.base else {
            return Err(refuse());
        };
        let Some(record) = surface.records.iter().find(|record| {
            record.name == name && record.shape == Shape::Struct && record.is_versioned()
        }) else {
            return Err(refuse());
        };
        Ok(Self {
            alias,
            event,
            user_data,
            record,
        })
    }

    /// `SipralEventCallback` is `SipralEventListener`.
    fn listener(&self) -> String {
        let name = self.alias.name;
        format!("{}Listener", name.strip_suffix("Callback").unwrap_or(name))
    }

    /// And the object those are kept in, `SipralEventListeners`.
    fn keeper(&self) -> String {
        format!("{}s", self.listener())
    }

    /// The one method a listener has, named for what it is handed: `onEvent`.
    fn method(&self) -> String {
        format!("on{}", upper_camel(self.event.name))
    }

    /// The C function the callback lands in: `jni_event_callback`.
    fn function(&self) -> String {
        let name = snake(self.alias.name);
        format!("jni_{}", name.strip_prefix("sipral_").unwrap_or(&name))
    }

    /// Where the shim keeps the keeper's class.
    fn class(&self) -> String {
        format!("{}_class", self.function())
    }

    /// And the method it hands events to.
    fn deliver(&self) -> String {
        format!("{}_deliver", self.function())
    }
}

/// Every callback the surface declares, each as it lands in Kotlin.
fn landings(surface: &Surface) -> Result<Vec<Landing>, Refused> {
    surface
        .aliases
        .iter()
        .filter(|alias| matches!(alias.stands, Stands::Callback(_)))
        .map(|alias| Landing::of(surface, alias))
        .collect()
}

/// The locals the landing function writes beside its two parameters.
const LANDING_LOCALS: &[(&str, &str)] = &[
    ("env", "the JNI environment the landing function looks up"),
    (
        "attached",
        "whether the landing function attached this thread",
    ),
    (
        "built",
        "whether every array the event is handed over in was made",
    ),
    ("found", "what the JVM said about the calling thread"),
];

/// The file-scope names the shim writes once, whatever the surface holds.
const SHIM_FILE: &[(&str, &str)] = &[
    ("jni_vm", "the JVM the shim was loaded into"),
    ("JNI_REACHES", "the size check the landing functions make"),
    ("JNI_OnLoad", "the load hook"),
    ("JNI_OnUnload", "the unload hook"),
];

/// The fixed names inside the keeper's `deliver`, beside the key and the
/// members it is handed.
const DELIVER_LOCALS: &[(&str, &str)] = &[
    ("key", "the key the shim hands back"),
    ("listening", "the map deliver finds the listener in"),
    ("listener", "the listener the key names"),
    ("failure", "what the listener threw"),
    ("thread", "the thread it threw on"),
];

/// One member of a struct handed to a listener: as `deliver` takes it, as the
/// class declares it, and as the landing function passes it.
struct Handed {
    /// The member it came from, as the declaration spelled it.
    from: &'static str,
    /// Its documentation.
    doc: &'static [&'static str],
    /// The name, Kotlin side.
    kotlin: String,
    /// The parameter `deliver` declares.
    parameter: String,
    /// What the class is built with from that parameter.
    argument: String,
    /// The field the class declares.
    field: String,
    /// The type in the JVM descriptor.
    descriptor: String,
    /// The local the landing function makes an array in, and its type.
    c_local: Option<(&'static str, String)>,
    /// What the landing function does before the call to make that array.
    c_make: String,
    /// What it passes.
    c_passed: String,
}

/// Every member the listener is handed, with the ones left out named.
fn handed(
    surface: &Surface,
    landing: &Landing,
    fields: &[Read<'_>],
) -> Result<(Vec<Handed>, Vec<String>), Refused> {
    let record = landing.record;
    let event = landing.event.name;
    let spelled = c::named(record.name);
    let mut out = Vec::new();
    let mut left_out = Vec::new();
    for part in parts(surface, record, fields, 0)? {
        match part {
            Part::Plain(field) => {
                let kotlin = held(field);
                let name = field.member.name;
                let (cast, zero) = match field.ty.base {
                    Base::Float(_) => ("jdouble", "0.0"),
                    _ => ("jlong", "0"),
                };
                // the size member is there in every length the struct has
                // had; every other one is read only when the size says so
                let c_passed = if name == "size" {
                    format!("({cast}){event}->size")
                } else {
                    format!(
                        "JNI_REACHES({event}, {spelled}, {name}) ? ({cast}){event}->{name} : {zero}"
                    )
                };
                out.push(Handed {
                    from: field.member.name,
                    doc: field.member.doc,
                    parameter: format!("{kotlin}: {}", plain_kotlin(&field.ty)),
                    argument: kotlin.clone(),
                    field: format!("val {kotlin}: {}", plain_kotlin(&field.ty)),
                    descriptor: plain_descriptor(&field.ty).to_owned(),
                    kotlin,
                    c_local: None,
                    c_make: String::new(),
                    c_passed,
                });
            }
            Part::Buffer { data, len } => {
                let kotlin = held(data);
                let text = data.ty.base == Base::Char;
                let name = data.member.name;
                let len = len.member.name;
                let (element, kind) = jni_element_of(&data.ty);
                let c_make = format!(
                    "    if (built && JNI_REACHES({event}, {spelled}, {len}) && {event}->{name} != NULL) {{\n\
                     \x20       {name} = (*env)->New{kind}Array(env, (jsize){event}->{len});\n\
                     \x20       if ({name} == NULL) {{\n\
                     \x20           built = 0;\n\
                     \x20       }} else {{\n\
                     \x20           (*env)->Set{kind}ArrayRegion(env, {name}, 0, (jsize){event}->{len}, (const {element} *){event}->{name});\n\
                     \x20       }}\n\
                     \x20   }}\n"
                );
                out.push(Handed {
                    from: data.member.name,
                    doc: data.member.doc,
                    parameter: format!("{kotlin}: {}?", array_of(&data.ty)),
                    argument: if text {
                        format!("{kotlin}?.let {{ String(it, Charsets.UTF_8) }}")
                    } else {
                        kotlin.clone()
                    },
                    field: if text {
                        format!("val {kotlin}: String?")
                    } else {
                        format!("val {kotlin}: {}?", array_of(&data.ty))
                    },
                    descriptor: descriptor_of_array(&data.ty).to_owned(),
                    kotlin,
                    c_local: Some((name, jni_array_of(&data.ty).to_owned())),
                    c_make,
                    c_passed: name.to_owned(),
                });
            }
            Part::Records { data, .. } => return Err(records_not_handed(record, data)),
            Part::Listener { callback, .. } => return Err(not_handed(record, callback)),
            Part::Arm(field) => left_out.push(field.member.name.to_owned()),
        }
    }
    Ok((out, left_out))
}

/// The JVM descriptor of a keeper's `deliver`: the key, then every member.
fn deliver_descriptor(members: &[Handed]) -> String {
    let inside: String = members.iter().map(|one| one.descriptor.as_str()).collect();
    format!("(J{inside})V")
}

/// The listener each struct going in to an entry point holds, by the object
/// it is kept in.
fn kept_by(surface: &Surface, roles: &[Role<'_>]) -> Result<Vec<String>, Refused> {
    let mut out = Vec::new();
    for role in roles {
        let Role::Config(read) = role else {
            continue;
        };
        let record = config_record(surface, read)?;
        let fields = read_all(record.name, record.fields)?;
        for part in parts(surface, record, &fields, 1)? {
            if let Part::Listener { alias, .. } = part {
                out.push(Landing::of(surface, alias)?.keeper());
            }
        }
    }
    Ok(out)
}

/// The entry point that takes apart what `maker` made, and the one value
/// `maker` writes back.
///
/// It is the one named for the same thing with `_destroy` in place of the
/// last word, taking the handle `maker` writes back and nothing else:
/// `sipral_stack_create` is undone by `sipral_stack_destroy`. A listener is
/// let go of there, and an entry point that keeps one without such a partner
/// is refused rather than printed with a listener nothing lets go of.
fn destroyer(surface: &Surface, maker: &Function) -> Result<&'static Function, Refused> {
    let refuse = || {
        Refused::about(&format!(
            "{} takes a listener, and the surface has no entry point named for the same thing \
             with `_destroy` that takes the one handle it writes back, which is where the \
             listener would be let go of",
            maker.name
        ))
    };
    let read = read_all(maker.name, maker.parameters)?;
    let made: Vec<&Read<'_>> = roles(surface, &read)
        .into_iter()
        .filter_map(|role| match role {
            Role::Out(value) => Some(value),
            _ => None,
        })
        .collect();
    let [made] = made.as_slice() else {
        return Err(refuse());
    };
    let Some((stem, _)) = maker.name.rsplit_once('_') else {
        return Err(refuse());
    };
    let wanted = format!("{stem}_destroy");
    let Some(found) = surface
        .functions
        .iter()
        .find(|function| function.name == wanted)
    else {
        return Err(refuse());
    };
    let [handle] = found.parameters else {
        return Err(refuse());
    };
    let handle = Type::read(handle.rust_type)?;
    if handle.pointer.is_some() || handle.base != made.ty.base {
        return Err(refuse());
    }
    Ok(found)
}

/// The objects whose listeners an entry point lets go of: every one a struct
/// going in to another entry point held, when this is that one's destroyer.
fn released_by(surface: &Surface, function: &Function) -> Result<Vec<String>, Refused> {
    let mut out = Vec::new();
    for (maker, read) in functions(surface)? {
        let keepers = kept_by(surface, &roles(surface, &read))?;
        if keepers.is_empty() || destroyer(surface, maker)?.name != function.name {
            continue;
        }
        out.extend(keepers);
    }
    Ok(out)
}

// ------------------------------------------------------------ the declarations

/// How one parameter appears on each side of JNI: what is declared, and the
/// bare identifiers, which the uniqueness pass reads rather than deriving
/// them a second time.
#[derive(Default)]
struct Crossing {
    kotlin: Vec<String>,
    jni: Vec<String>,
    names: Vec<(String, String)>,
    shim: Vec<(String, String)>,
}

impl Crossing {
    /// A list, which crosses as two arguments: every piece of text in it
    /// packed into one `ByteArray`, and the length of each piece in a
    /// `LongArray`. `base` is the name the Kotlin side derives both from, and
    /// `from` the declaration it stands for.
    fn packed(&mut self, base: &str, from: &str) {
        let (bytes, lengths) = packed_names(base);
        for (kotlin, suffix, kotlin_type, jni_type) in [
            (bytes, "Bytes", "ByteArray?", "jbyteArray"),
            (lengths, "Lengths", "LongArray?", "jlongArray"),
        ] {
            let c_name = format!("{base}{suffix}");
            self.kotlin.push(format!("{kotlin}: {kotlin_type}"));
            self.jni.push(format!("{jni_type} {c_name}"));
            self.names.push((kotlin, from.to_owned()));
            self.shim.push((c_name, from.to_owned()));
        }
    }
}

fn crossing(surface: &Surface, role: &Role<'_>) -> Result<Crossing, Refused> {
    let (kotlin_type, jni_type, read, kotlin_name, c_name) = match role {
        Role::Records { data, .. } => {
            let mut out = Crossing::default();
            out.packed(&lower_camel(data.member.name), data.member.name);
            return Ok(out);
        }
        Role::Plain(read) => (
            plain_kotlin(&read.ty).to_owned(),
            plain_jni(&read.ty).to_owned(),
            read,
            held(read),
            c_held(read),
        ),
        Role::Buffer { data, .. } | Role::Fill { data, .. } => (
            array_of(&data.ty).to_owned(),
            jni_array_of(&data.ty).to_owned(),
            data,
            held(data),
            c_held(data),
        ),
        Role::Config(read) => return fields_crossing(surface, read),
        Role::Shared(read) => (
            "Long".to_owned(),
            "jlong".to_owned(),
            read,
            held(read),
            c_held(read),
        ),
        Role::Given(read) | Role::Out(read) => (
            "LongArray".to_owned(),
            "jlongArray".to_owned(),
            read,
            written(read),
            returned(read.member.name),
        ),
    };
    Ok(Crossing {
        kotlin: vec![format!("{kotlin_name}: {kotlin_type}")],
        jni: vec![format!("{jni_type} {c_name}")],
        names: vec![(kotlin_name, read.member.name.to_owned())],
        shim: vec![(c_name, read.member.name.to_owned())],
    })
}

/// A struct going in crosses one argument per member of the class it was
/// built from, in the order the struct declares them.
fn fields_crossing(surface: &Surface, read: &Read<'_>) -> Result<Crossing, Refused> {
    let record = config_record(surface, read)?;
    let fields = read_all(record.name, record.fields)?;
    let mut out = Crossing::default();
    for part in parts(surface, record, &fields, 1)? {
        let (member, kotlin_type, jni_type) = match part {
            Part::Records { data, .. } => {
                out.packed(
                    &flat(read, data),
                    &format!("{}::{}", record.name, data.member.name),
                );
                continue;
            }
            Part::Plain(field) => (
                field,
                plain_kotlin(&field.ty).to_owned(),
                plain_jni(&field.ty).to_owned(),
            ),
            Part::Buffer { data, .. } => (
                data,
                format!("{}?", array_of(&data.ty)),
                jni_array_of(&data.ty).to_owned(),
            ),
            Part::Listener { callback, .. } => (callback, "Long".to_owned(), "jlong".to_owned()),
            Part::Arm(field) => return Err(not_built(record, field)),
        };
        let name = flat(read, member);
        let from = format!("{}::{}", record.name, member.member.name);
        out.kotlin.push(format!("{}: {kotlin_type}", safe(&name)));
        out.jni.push(format!("{jni_type} {name}"));
        out.names.push((safe(&name), from.clone()));
        out.shim.push((name, from));
    }
    Ok(out)
}

fn returns_kotlin(function: &Function) -> Result<&'static str, Refused> {
    let ty = Type::read(function.returns)?;
    Ok(if ty.pointer.is_some() && ty.base == Base::Char {
        "String?"
    } else {
        "Int"
    })
}

/// The JNI symbol a method of `SipralNative` is looked up under.
fn symbol(name: &str) -> String {
    format!("Java_org_sipral_SipralNative_{}", name.replace('_', "_1"))
}

fn data_classes(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::new();
    for record in surface.records {
        if !is_given(record) {
            continue;
        }
        doc(&mut out, "", &lines(surface, record.doc));
        let _ = writeln!(out, "data class {}(", record.name);
        for field in read_all(record.name, record.fields)? {
            doc(&mut out, "    ", &lines(surface, field.member.doc));
            let _ = writeln!(out, "    val {}: {},", held(&field), slot_type(&field.ty));
        }
        out.push_str(") {\n    internal companion object {\n");
        let _ = writeln!(
            out,
            "        const val SLOTS: Int = {}\n",
            record.fields.len()
        );
        let _ = writeln!(
            out,
            "        fun of(slots: LongArray): {} = {}(",
            record.name, record.name
        );
        for (index, field) in read_all(record.name, record.fields)?.iter().enumerate() {
            let read = if field.ty.base == Base::Float(32) || field.ty.base == Base::Float(64) {
                format!("Float.fromBits(slots[{index}].toInt())")
            } else {
                format!("slots[{index}]")
            };
            let _ = writeln!(out, "            {read},");
        }
        out.push_str("        )\n    }\n}\n\n");
    }
    Ok(out)
}

/// The class a caller builds each struct going in from: one field per member,
/// a buffer and its length as one, the callback and its user pointer as one
/// listener, and every field defaulting to the zero the struct would hold.
fn built_classes(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::new();
    for record in built(surface)? {
        let mut about = lines(surface, record.doc);
        about.push(String::new());
        about.push(
            " Built here and copied into the C struct by the JNI shim, which sets the".to_owned(),
        );
        about.push(
            " size member itself: a field left at its default is the zero the struct".to_owned(),
        );
        about.push(" would have held.".to_owned());
        doc(&mut out, "", &about);
        let _ = writeln!(out, "class {}(", record.name);
        let fields = read_all(record.name, record.fields)?;
        for part in parts(surface, record, &fields, 1)? {
            let (field, declared) = match part {
                Part::Plain(field) => (
                    field,
                    format!(
                        "val {}: {} = {}",
                        held(field),
                        plain_kotlin(&field.ty),
                        zero_of(&field.ty)
                    ),
                ),
                Part::Buffer { data, .. } => {
                    let ty = if data.ty.base == Base::Char {
                        "String"
                    } else {
                        array_of(&data.ty)
                    };
                    (data, format!("val {}: {ty}? = null", held(data)))
                }
                Part::Records { data, element, .. } => (
                    data,
                    format!("val {}: List<{}>? = null", held(data), element.record.name),
                ),
                Part::Listener {
                    callback, alias, ..
                } => (
                    callback,
                    format!(
                        "val {}: {}? = null",
                        listener_field(callback),
                        Landing::of(surface, alias)?.listener()
                    ),
                ),
                Part::Arm(field) => return Err(not_built(record, field)),
            };
            doc(&mut out, "    ", &lines(surface, field.member.doc));
            let _ = writeln!(out, "    {declared},");
        }
        out.push_str(")\n\n");
    }
    Ok(out)
}

/// The locals `packed` writes, beside one per piece of text.
const PACKED_LOCALS: &[(&str, &str)] = &[
    ("list", "the list packed is handed"),
    ("run", "the bytes packed writes every piece of text into"),
    ("lengths", "the length of each piece of text"),
    ("part", "which length packed writes next"),
    ("element", "the element packed is reading"),
];

/// The local `packed` holds one piece of text's bytes in.
fn text_bytes(text: &Text) -> String {
    beside(&lower_camel(text.data.member.name), "Bytes")
}

/// For each record handed over as the element of an array: the class a caller
/// builds one from, and `packed`, which turns a list of them into the two
/// arguments the JNI shim takes.
///
/// A list crosses packed rather than as an array of objects the shim walks.
/// Walking one would mean a class and a field looked up for every member, and
/// a local reference made for every string, which a list of any length turns
/// into more than the JVM promises a native call; packed, it is two arrays
/// the shim fetches the way it fetches every other buffer, and one loop that
/// checks every length before it makes a pointer from it.
fn element_classes(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::new();
    for element in elements(surface, "Kotlin")? {
        let record = element.record;
        let pieces = element.texts.len();
        let mut about = lines(surface, record.doc);
        about.push(String::new());
        for line in [
            " Handed over in a list, which the JNI shim makes into a C array for the",
            " length of the call. `packed` copies every piece of text into one array of",
            " UTF-8 first, and the shim checks every length against that array before",
            " it points into it. An empty piece of text crosses as a null pointer with",
            " a length of zero.",
        ] {
            about.push(line.to_owned());
        }
        doc(&mut out, "", &about);
        let _ = writeln!(out, "class {}(", record.name);
        for text in &element.texts {
            doc(&mut out, "    ", &lines(surface, text.data.member.doc));
            let _ = writeln!(out, "    val {}: String,", held(&text.data));
        }
        let _ = write!(
            out,
            ") {{\n\
             \x20   internal companion object {{\n\
             \x20       /**\n\
             \x20        * A list of them as the JNI shim takes it: every piece of text in\n\
             \x20        * every element, in order, as one run of UTF-8, and how many bytes\n\
             \x20        * each took, {pieces} to an element. A null list is two nulls, which the\n\
             \x20        * shim reads as no elements.\n\
             \x20        */\n\
             \x20       fun packed(list: List<{name}>?): Pair<ByteArray?, LongArray?> {{\n\
             \x20           if (list == null) {{\n\
             \x20               return Pair(null, null)\n\
             \x20           }}\n\
             \x20           val run = java.io.ByteArrayOutputStream()\n\
             \x20           val lengths = LongArray(Math.multiplyExact(list.size, {pieces}))\n\
             \x20           var part = 0\n\
             \x20           for (element in list) {{\n",
            name = record.name,
        );
        for text in &element.texts {
            let bytes = text_bytes(text);
            let _ = write!(
                out,
                "                val {bytes} = element.{}.toByteArray(Charsets.UTF_8)\n\
                 \x20               run.write({bytes}, 0, {bytes}.size)\n\
                 \x20               lengths[part] = {bytes}.size.toLong()\n\
                 \x20               part += 1\n",
                held(&text.data)
            );
        }
        out.push_str(
            "            }\n\
             \x20           return Pair(run.toByteArray(), lengths)\n\
             \x20       }\n\
             \x20   }\n\
             }\n\n",
        );
    }
    Ok(out)
}

/// For each callback: the class its record is handed over as, the listener
/// interface, and the object listeners are kept in until the handle they were
/// made with is destroyed.
fn listeners(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::new();
    for landing in landings(surface)? {
        let record = landing.record;
        let fields = read_all(record.name, record.fields)?;
        let (members, left_out) = handed(surface, &landing, &fields)?;

        let mut about = lines(surface, record.doc);
        for name in &left_out {
            about.push(String::new());
            about.push(format!(
                " `{name}` is not carried here. Which of its arms the library wrote is named"
            ));
            about.push(
                " by another member, and nothing in the declarations says which value names"
                    .to_owned(),
            );
            about.push(" which arm, so this binding does not guess.".to_owned());
        }
        doc(&mut out, "", &about);
        let _ = writeln!(out, "class {}(", record.name);
        for member in &members {
            doc(&mut out, "    ", &lines(surface, member.doc));
            let _ = writeln!(out, "    {},", member.field);
        }
        out.push_str(")\n\n");

        let listener = landing.listener();
        let mut about = lines(surface, landing.alias.doc);
        about.push(String::new());
        about.push(
            " In Kotlin it is this interface, called on the thread that polls. The JNI".to_owned(),
        );
        about.push(
            " shim attaches that thread to the JVM for the length of the call when it".to_owned(),
        );
        about.push(
            " is not attached already. What a listener throws goes to that thread's".to_owned(),
        );
        about.push(
            " uncaught exception handler, and the poll carries on once the handler".to_owned(),
        );
        about.push(
            " returns. Android's default handler does not return: it ends the process.".to_owned(),
        );
        doc(&mut out, "", &about);
        let _ = writeln!(
            out,
            "fun interface {listener} {{\n    fun {}({}: {})\n}}\n",
            landing.method(),
            safe(&lower_camel(landing.event.name)),
            record.name
        );

        out.push_str(&keeper_object(&landing, &members));
    }
    Ok(out)
}

/// The object a callback's listeners are kept in, and the `deliver` the JNI
/// shim hands each event to.
fn keeper_object(landing: &Landing, members: &[Handed]) -> String {
    let listener = landing.listener();
    let keeper = landing.keeper();
    let record = landing.record;
    let parameters: Vec<&str> = members
        .iter()
        .map(|member| member.parameter.as_str())
        .collect();
    let arguments: Vec<&str> = members
        .iter()
        .map(|member| member.argument.as_str())
        .collect();
    let mut out = String::new();
    {
        let _ = writeln!(
            out,
            "/**\n\
             \x20* Every {listener} a live handle was made with, under the key the JNI\n\
             \x20* shim hands back with each event. The native side holds no reference\n\
             \x20* to a listener at all: an event for a handle already destroyed finds\n\
             \x20* nothing here and goes nowhere.\n\
             \x20*/\n\
             internal object {keeper} {{\n\
             \x20   private val listening = HashMap<Long, {listener}>()\n\
             \x20   private val handles = HashMap<Long, Long>()\n\
             \x20   private var last = 0L\n\n\
             \x20   /** Keep a listener, and say what key the shim will hand it back under: zero for none. */\n\
             \x20   fun register(listener: {listener}?): Long {{\n\
             \x20       if (listener == null) {{\n\
             \x20           return 0\n\
             \x20       }}\n\
             \x20       synchronized(this) {{\n\
             \x20           // the key crosses as a C pointer, which is 32 bits wide on half of Android\n\
             \x20           check(last < Int.MAX_VALUE) {{ \"every key a listener can be kept under has been handed out\" }}\n\
             \x20           last += 1\n\
             \x20           listening[last] = listener\n\
             \x20           return last\n\
             \x20       }}\n\
             \x20   }}\n\n\
             \x20   /** Tie a kept listener to the handle the call made, or let it go when the call failed. */\n\
             \x20   fun made(key: Long, status: Int, handle: Long) {{\n\
             \x20       if (key == 0L) {{\n\
             \x20           return\n\
             \x20       }}\n\
             \x20       synchronized(this) {{\n\
             \x20           if (status == SipralStatus.OK.value) {{\n\
             \x20               handles[handle] = key\n\
             \x20           }} else {{\n\
             \x20               listening.remove(key)\n\
             \x20           }}\n\
             \x20       }}\n\
             \x20   }}\n\n\
             \x20   /** Let go of the listener a destroyed handle was made with. */\n\
             \x20   fun gone(handle: Long) {{\n\
             \x20       synchronized(this) {{\n\
             \x20           val key = handles.remove(handle) ?: return\n\
             \x20           listening.remove(key)\n\
             \x20       }}\n\
             \x20   }}\n\n\
             \x20   /** Called by the JNI shim, once per event, on the thread that polls. */\n\
             \x20   @JvmStatic\n\
             \x20   fun deliver(key: Long, {}) {{\n\
             \x20       val listener = synchronized(this) {{ listening[key] }} ?: return\n\
             \x20       try {{\n\
             \x20           listener.{}({}({}))\n\
             \x20       }} catch (failure: Throwable) {{\n\
             \x20           val thread = Thread.currentThread()\n\
             \x20           thread.uncaughtExceptionHandler.uncaughtException(thread, failure)\n\
             \x20       }}\n\
             \x20   }}\n\
             }}\n",
            parameters.join(", "),
            landing.method(),
            record.name,
            arguments.join(", ")
        );
    }
    out
}

/// A call that answers with a static string rather than a status.
fn naming(function: &Function, read: &[Read<'_>]) -> String {
    let mut out = String::new();
    let arguments: Vec<String> = read
        .iter()
        .map(|parameter| format!("{}: {}", held(parameter), plain_kotlin(&parameter.ty)))
        .collect();
    let passed: Vec<String> = read.iter().map(held).collect();
    let _ = writeln!(
        out,
        "    fun {}({}): String? =\n        SipralNative.{}({})\n",
        called(function),
        arguments.join(", "),
        function.name,
        passed.join(", ")
    );
    out
}

/// What one call needs written around it: the parameters it takes, what goes
/// to the declaration, what has to be prepared first, what has to happen
/// between the call and the status check, and what comes back.
#[derive(Default)]
struct Handover {
    arguments: Vec<String>,
    passed: Vec<String>,
    prologue: String,
    /// Keeping every listener the call is handed, written after everything
    /// else the call needs, so that nothing which can throw sits between a
    /// listener being kept and the call that lets it go again.
    keeping: String,
    /// Written in a `finally` around the call, with its status in `status`:
    /// a listener handed over is tied to the handle the call made or let go
    /// of, and a call that throws rather than answers leaves no status, so it
    /// is let go of then too.
    settled: String,
    /// Written after the call with its status held in `status`, before that
    /// status is turned into a throw: letting go of a listener whose handle
    /// was destroyed happens whatever the call answered.
    epilogue: String,
    results: Vec<(String, String)>,
    /// Every identifier the wrapper puts in its own scope, reported so the
    /// uniqueness pass reads what was written rather than deriving it again.
    names: Vec<Named>,
}

fn hand_over(
    surface: &Surface,
    function: &Function,
    parts_of_call: &[Role<'_>],
) -> Result<Handover, Refused> {
    let mut out = Handover::default();
    let Handover {
        arguments,
        passed,
        prologue,
        keeping,
        settled,
        epilogue,
        results,
        names,
    } = &mut out;
    let mut kept = Vec::new();
    for role in parts_of_call {
        match role {
            Role::Plain(read) => {
                let held = held(read);
                names.push(Named::new("the wrapper", held.clone(), read.member.name));
                arguments.push(format!("{held}: {}", plain_kotlin(&read.ty)));
                passed.push(held);
            }
            Role::Buffer { data, .. } => {
                let held = held(data);
                names.push(Named::new("the wrapper", held.clone(), data.member.name));
                if data.ty.base == Base::Char && data.ty.pointer == Some(Writable::No) {
                    let bytes = beside(&lower_camel(data.member.name), "Bytes");
                    names.push(Named::new("the wrapper", bytes.clone(), data.member.name));
                    arguments.push(format!("{held}: String"));
                    let _ = writeln!(
                        prologue,
                        "        val {bytes} = {held}.toByteArray(Charsets.UTF_8)"
                    );
                    passed.push(bytes);
                } else {
                    arguments.push(format!("{held}: {}", array_of(&data.ty)));
                    passed.push(held);
                }
            }
            Role::Fill { data, .. } => {
                let held = held(data);
                names.push(Named::new("the wrapper", held.clone(), data.member.name));
                arguments.push(format!("{held}: {}", array_of(&data.ty)));
                passed.push(held);
            }
            Role::Records { data, .. } => {
                let built = list_argument(surface, data)?;
                arguments.push(built.argument);
                passed.extend(built.passed);
                prologue.push_str(&built.prologue);
                names.extend(built.names);
            }
            Role::Config(read) => {
                let built = built_argument(surface, read)?;
                arguments.push(built.argument);
                passed.extend(built.passed);
                prologue.push_str(&built.prologue);
                keeping.push_str(&built.keeping);
                names.extend(built.names);
                kept.extend(built.kept);
            }
            Role::Shared(read) => {
                let held = held(read);
                names.push(Named::new("the wrapper", held.clone(), read.member.name));
                arguments.push(format!("{held}: Long"));
                passed.push(held);
            }
            Role::Given(read) => {
                let Base::Named(record) = &read.ty.base else {
                    return Err(Refused::about("a struct with no name"));
                };
                let slots = beside(&returned(read.member.name), "Slots");
                names.push(Named::new("the wrapper", slots.clone(), read.member.name));
                let _ = writeln!(prologue, "        val {slots} = LongArray({record}.SLOTS)");
                passed.push(slots.clone());
                results.push((format!("{record}.of({slots})"), record.clone()));
            }
            Role::Out(read) => {
                let slot = beside(&returned(read.member.name), "Slot");
                names.push(Named::new("the wrapper", slot.clone(), read.member.name));
                let _ = writeln!(prologue, "        val {slot} = LongArray(1)");
                passed.push(slot.clone());
                results.push((format!("{slot}[0]"), "Long".to_owned()));
            }
        }
    }

    let (tied, released) = listeners_after(surface, function, parts_of_call, &kept)?;
    settled.push_str(&tied);
    epilogue.push_str(&released);
    if !settled.is_empty() || !epilogue.is_empty() {
        names.push(Named::new(
            "the wrapper",
            "status".to_owned(),
            "the status the wrapper holds on to",
        ));
    }
    Ok(out)
}

/// What a struct going in adds to the wrapper around a call.
struct BuiltArgument {
    /// The class the wrapper takes.
    argument: String,
    /// One argument per field, in the order the declaration takes them.
    passed: Vec<String>,
    /// The locals a text field needs before the call.
    prologue: String,
    /// The local each listener's key is kept in, written last before the
    /// call.
    keeping: String,
    names: Vec<Named>,
    /// Every listener the class held: the object it is kept in, and the
    /// local its key is in.
    kept: Vec<(String, String)>,
}

/// What a list going in adds to the wrapper around a call: the list it takes,
/// and the line that packs it into the two arguments the shim takes.
fn list_argument(surface: &Surface, data: &Read<'_>) -> Result<BuiltArgument, Refused> {
    let element = element(surface, data, "Kotlin")?;
    let held = held(data);
    let (bytes, lengths) = packed_names(&lower_camel(data.member.name));
    let names = [&held, &bytes, &lengths]
        .into_iter()
        .map(|name| Named::new("the wrapper", name.clone(), data.member.name))
        .collect();
    Ok(BuiltArgument {
        argument: format!("{held}: List<{}>", element.record.name),
        prologue: format!(
            "        val ({bytes}, {lengths}) = {}.packed({held})\n",
            element.record.name
        ),
        passed: vec![bytes, lengths],
        keeping: String::new(),
        names,
        kept: Vec::new(),
    })
}

fn built_argument(surface: &Surface, read: &Read<'_>) -> Result<BuiltArgument, Refused> {
    let record = config_record(surface, read)?;
    let whole = held(read);
    let mut out = BuiltArgument {
        argument: format!("{whole}: {}", record.name),
        passed: Vec::new(),
        prologue: String::new(),
        keeping: String::new(),
        names: vec![Named::new("the wrapper", whole.clone(), read.member.name)],
        kept: Vec::new(),
    };
    let fields = read_all(record.name, record.fields)?;
    for part in parts(surface, record, &fields, 1)? {
        match part {
            Part::Plain(field) => out.passed.push(format!("{whole}.{}", held(field))),
            Part::Buffer { data, .. } if data.ty.base == Base::Char => {
                let local = safe(&flat(read, data));
                out.names.push(Named::new(
                    "the wrapper",
                    local.clone(),
                    format!("{}::{}", record.name, data.member.name),
                ));
                let _ = writeln!(
                    out.prologue,
                    "        val {local} = {whole}.{}?.toByteArray(Charsets.UTF_8)",
                    held(data)
                );
                out.passed.push(local);
            }
            Part::Buffer { data, .. } => out.passed.push(format!("{whole}.{}", held(data))),
            Part::Records { data, element, .. } => {
                let (bytes, lengths) = packed_names(&flat(read, data));
                let from = format!("{}::{}", record.name, data.member.name);
                for name in [&bytes, &lengths] {
                    out.names
                        .push(Named::new("the wrapper", name.clone(), from.clone()));
                }
                let _ = writeln!(
                    out.prologue,
                    "        val ({bytes}, {lengths}) = {}.packed({whole}.{})",
                    element.record.name,
                    held(data)
                );
                out.passed.push(bytes);
                out.passed.push(lengths);
            }
            Part::Listener {
                callback, alias, ..
            } => {
                let keeper = Landing::of(surface, alias)?.keeper();
                let local = safe(&flat(read, callback));
                out.names.push(Named::new(
                    "the wrapper",
                    local.clone(),
                    format!("{}::{}", record.name, callback.member.name),
                ));
                let _ = writeln!(
                    out.keeping,
                    "        val {local} = {keeper}.register({whole}.{})",
                    listener_field(callback)
                );
                out.passed.push(local.clone());
                out.kept.push((keeper, local));
            }
            Part::Arm(field) => return Err(not_built(record, field)),
        }
    }
    Ok(out)
}

/// What a wrapper does with listeners once the call is over: ties each one it
/// handed over to the handle the call made, or lets it go when there is none,
/// and then lets go of every one the handle it destroys was made with. The
/// first is written in a `finally`, the second after it.
fn listeners_after(
    surface: &Surface,
    function: &Function,
    parts_of_call: &[Role<'_>],
    kept: &[(String, String)],
) -> Result<(String, String), Refused> {
    let mut tied = String::new();
    let mut out = String::new();
    if !kept.is_empty() {
        // the handle a listener is tied to is the one value this call writes
        // back, and destroyer() refuses a call that writes back more, or has
        // nothing that undoes it
        destroyer(surface, function)?;
        let Some(slot) = parts_of_call.iter().find_map(|role| match role {
            Role::Out(read) => Some(beside(&returned(read.member.name), "Slot")),
            _ => None,
        }) else {
            return Err(Refused::about(&format!(
                "{} takes a listener and writes back no handle to tie it to",
                function.name
            )));
        };
        for (keeper, local) in kept {
            let _ = writeln!(
                tied,
                "            {keeper}.made({local}, status, {slot}[0])"
            );
        }
    }
    let released = released_by(surface, function)?;
    if !released.is_empty() {
        let Some(Role::Plain(handle)) = parts_of_call.first() else {
            return Err(Refused::about(&format!(
                "{} lets go of a listener and takes no handle to find it by",
                function.name
            )));
        };
        for keeper in released {
            let _ = writeln!(out, "        {keeper}.gone({})", held(handle));
        }
    }
    Ok((tied, out))
}

fn wrapper(surface: &Surface, function: &Function, read: &[Read<'_>]) -> Result<String, Refused> {
    let ty = Type::read(function.returns)?;
    if ty.pointer.is_some() && ty.base == Base::Char {
        return Ok(naming(function, read));
    }
    let mut out = String::new();
    let name = called(function);
    let Handover {
        arguments,
        passed,
        prologue,
        keeping,
        settled,
        epilogue,
        results,
        names: _,
    } = hand_over(surface, function, &roles(surface, read))?;
    let returns = match results.len() {
        0 => String::new(),
        1 => results
            .first()
            .map(|(_, ty)| format!(": {ty}"))
            .unwrap_or_default(),
        2 => format!(
            ": Pair<{}, {}>",
            results
                .first()
                .map(|(_, ty)| ty.clone())
                .unwrap_or_default(),
            results.get(1).map(|(_, ty)| ty.clone()).unwrap_or_default()
        ),
        _ => {
            return Err(Refused::about(&format!(
                "{} writes back more than two values, which this generator has no Kotlin shape \
                 for; give it one in tools/abi-gen/src/kotlin.rs",
                function.name
            )));
        }
    };
    let _ = writeln!(out, "    fun {name}({}){returns} {{", arguments.join(", "));
    out.push_str(&prologue);
    let call = format!("SipralNative.{}({})", function.name, passed.join(", "));
    if !settled.is_empty() {
        out.push_str(&keeping);
        // -1 is no status the library answers with, so a call that threw
        // reaches the finally as a call that failed
        let _ = writeln!(
            out,
            "        var status = -1\n        try {{\n            status = {call}\n        }} finally {{"
        );
        out.push_str(&settled);
        out.push_str("        }\n");
        out.push_str(&epilogue);
        out.push_str("        check(status)\n");
    } else if epilogue.is_empty() {
        let _ = writeln!(out, "        check({call})");
    } else {
        let _ = writeln!(out, "        val status = {call}");
        out.push_str(&epilogue);
        out.push_str("        check(status)\n");
    }
    match results.len() {
        0 => {}
        1 => {
            if let Some((expression, _)) = results.first() {
                let _ = writeln!(out, "        return {expression}");
            }
        }
        _ => {
            let _ = writeln!(
                out,
                "        return Pair({}, {})",
                results.first().map(|(e, _)| e.clone()).unwrap_or_default(),
                results.get(1).map(|(e, _)| e.clone()).unwrap_or_default()
            );
        }
    }
    out.push_str("    }\n\n");
    Ok(out)
}

/// The enumerations, each with a way back from the number on the wire.
fn enumerations(surface: &Surface) -> String {
    let mut out = String::new();
    for enumeration in surface.enumerations {
        let mut about = lines(surface, enumeration.doc);
        if !enumeration.reserved.is_empty() {
            about.push(String::new());
            about.push(" Numbers already spent on features this build does not have:".to_owned());
            for held in enumeration.reserved {
                about.push(format!(" - {}: {}", held.value, held.feature));
            }
        }
        doc(&mut out, "", &about);
        let _ = writeln!(out, "enum class {}(val value: Int) {{", enumeration.name);
        for code in enumeration.codes {
            doc(&mut out, "    ", &lines(surface, code.doc));
            let _ = writeln!(out, "    {}({}),", screaming(code.name), code.value);
        }
        out.push_str("    ;\n\n    companion object {\n");
        let _ = writeln!(
            out,
            "        fun of(value: Int): {}? = entries.firstOrNull {{ it.value == value }}",
            enumeration.name
        );
        out.push_str("    }\n}\n\n");
    }

    out
}

/// One `external fun` per entry point, which is the declaration the JNI
/// below has to match.
fn natives(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::new();
    for (function, read) in functions(surface)? {
        let mut arguments = Vec::new();
        for role in roles(surface, &read) {
            arguments.extend(crossing(surface, &role)?.kotlin);
        }
        let _ = writeln!(
            out,
            "    external fun {}({}): {}",
            function.name,
            arguments.join(", "),
            returns_kotlin(function)?
        );
    }
    Ok(out)
}

/// The entry point a binding asks at load whether the library speaks its
/// ABI, when the surface has one: two plain numbers, the major and the minor.
fn abi_check(surface: &Surface) -> Result<Option<&'static Function>, Refused> {
    let Some(function) = surface
        .functions
        .iter()
        .find(|function| function.name == "sipral_abi_check")
    else {
        return Ok(None);
    };
    let read = read_all(function.name, function.parameters)?;
    let plain = read.iter().all(|parameter| {
        parameter.ty.pointer.is_none() && matches!(parameter.ty.base, Base::Int(_))
    });
    if read.len() != 2 || !plain {
        return Err(Refused::about(
            "sipral_abi_check does not take a major and a minor, which is what the Kotlin \
             binding asks it with at load; give the new shape a call in \
             tools/abi-gen/src/kotlin.rs",
        ));
    }
    Ok(Some(function))
}

/// Print the Kotlin binding.
pub(crate) fn binding(surface: &Surface) -> Result<String, Refused> {
    audit(surface, &Names)?;
    let mut out = String::new();
    out.push_str(
        "// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial\n\
         // Copyright (c) 2026 Tiberiu Balasea\n\
         //\n\
         // Printed from the declarations in crates/sipral-ffi by tools/abi-gen.\n\
         // Do not edit: `cargo run -p sipral-abi-gen` writes it again, and\n\
         // `scripts/check.sh` fails when what is committed is not what came out.\n\n\
         package org.sipral\n\n",
    );

    out.push_str(&enumerations(surface));
    out.push_str(&data_classes(surface)?);
    out.push_str(&element_classes(surface)?);
    out.push_str(&built_classes(surface)?);
    out.push_str(&listeners(surface)?);

    out.push_str(
        "/**\n\
         \x20* What a call across the boundary answered, when it did not answer\n\
         \x20* OK. The message is the calling thread's last error, read before\n\
         \x20* anything else on this thread could replace it.\n\
         \x20*/\n\
         class SipralException(val status: SipralStatus?, message: String) :\n\
         \x20   RuntimeException(if (message.isEmpty()) status.toString() else \"$status: $message\")\n\n",
    );

    out.push_str(
        "/**\n\
         \x20* The ABI as JNI declares it. Every integer crosses as a Long, every\n\
         \x20* struct the library fills in comes back in a LongArray, and every\n\
         \x20* struct a caller builds crosses one field at a time, so nothing here\n\
         \x20* depends on a field offset that the two Android pointer widths would\n\
         \x20* disagree about.\n\
         \x20*/\n\
         internal object SipralNative {\n\
         \x20   init {\n\
         \x20       System.loadLibrary(\"sipral_jni\")\n",
    );
    let checked = abi_check(surface)?;
    if checked.is_some() {
        let (major, minor, _) = surface.version;
        let _ = writeln!(out, "        agree({major}, {minor})");
    }
    out.push_str("    }\n\n");
    if checked.is_some() {
        out.push_str(
            "    /**\n\
             \x20    * Throw unless the library that loaded serves a binding printed\n\
             \x20    * against major.minor. Called once, as this object is initialised,\n\
             \x20    * with the version this file was printed from, so a package whose\n\
             \x20    * native library came from another build fails here with both\n\
             \x20    * versions named rather than in whichever call first disagrees.\n\
             \x20    */\n\
             \x20   fun agree(major: Long, minor: Long) {\n\
             \x20       val status = sipral_abi_check(major, minor)\n\
             \x20       if (status != SipralStatus.OK.value) {\n\
             \x20           throw SipralException(SipralStatus.of(status), Sipral.lastErrorMessage())\n\
             \x20       }\n\
             \x20   }\n\n",
        );
    }
    out.push_str(&natives(surface)?);
    out.push_str("}\n\n");

    out.push_str(
        "/** Everything the library does, with the C conventions read off it. */\n\
         object Sipral {\n",
    );

    for group in surface.constants {
        for value in *group {
            doc(&mut out, "    ", &lines(surface, value.doc));
            let name = screaming(value.name.strip_prefix("SIPRAL_").unwrap_or(value.name));
            let _ = writeln!(out, "    const val {name}: Long = {}\n", value.value);
        }
    }

    out.push_str(
        "    /**\n\
         \x20    * The calling thread's last error, or an empty string when it has\n\
         \x20    * none. Read the way C reads it: ask for the length, then for the\n\
         \x20    * bytes.\n\
         \x20    */\n\
         \x20   fun lastErrorMessage(): String {\n\
         \x20       val needed = LongArray(1)\n\
         \x20       SipralNative.sipral_last_error_message(ByteArray(0), needed)\n\
         \x20       val room = needed[0].toInt()\n\
         \x20       if (room <= 1) {\n\
         \x20           return \"\"\n\
         \x20       }\n\
         \x20       val buffer = ByteArray(room)\n\
         \x20       if (SipralNative.sipral_last_error_message(buffer, needed) != SipralStatus.OK.value) {\n\
         \x20           return \"\"\n\
         \x20       }\n\
         \x20       val end = buffer.indexOf(0)\n\
         \x20       return String(buffer, 0, if (end < 0) buffer.size else end, Charsets.UTF_8)\n\
         \x20   }\n\n\
         \x20   /** Turn a status into an exception, and nothing into nothing. */\n\
         \x20   private fun check(status: Int) {\n\
         \x20       if (status != SipralStatus.OK.value) {\n\
         \x20           throw SipralException(SipralStatus.of(status), lastErrorMessage())\n\
         \x20       }\n\
         \x20   }\n\n",
    );

    for (function, read) in functions(surface)? {
        if function.name == "sipral_last_error_message" {
            continue;
        }
        doc(&mut out, "    ", &lines(surface, function.doc));
        out.push_str(&wrapper(surface, function, &read)?);
    }

    out.push_str("}\n");
    Ok(out)
}

// ------------------------------------------------------------ the shim

/// What the C around one call has to say: the arguments it passes, the
/// arrays it fetches and gives back, and the values it writes into the
/// caller's `long[]`.
#[derive(Default)]
struct Around {
    passed: Vec<String>,
    fetches: String,
    /// Every list made into an array, written after every fetch: making one
    /// can leave an exception pending, and no JNI call that fetches may be
    /// made after that. Empty when the call takes no list, and then the call
    /// is made unconditionally, as it always was.
    prepares: String,
    releases: String,
    writes: String,
    /// Every identifier the shim writes in the C function's own scope. C has
    /// no backticks, so these are the names as they are, and the uniqueness
    /// pass reads them against C's keywords rather than Kotlin's.
    names: Vec<Named>,
}

impl Around {
    /// One array argument, fetched on the way in and released on the way
    /// out; what comes back is the pointer and the length, for the caller to
    /// put wherever the declaration wants them.
    fn fetch(&mut self, name: &str, ty: &Type, from: &str) -> (String, String) {
        for suffix in ["_data", "_size"] {
            self.names
                .push(Named::new("the shim", format!("{name}{suffix}"), from));
        }
        let (element, kind) = jni_element_of(ty);
        let writable = ty.pointer == Some(Writable::Yes);
        let _ = writeln!(
            self.fetches,
            "    {element} *{name}_data = {name} ? (*env)->Get{kind}ArrayElements(env, \
             {name}, NULL) : NULL;"
        );
        let _ = writeln!(
            self.fetches,
            "    jsize {name}_size = {name} ? (*env)->GetArrayLength(env, {name}) : 0;"
        );
        let mode = if writable { "0" } else { "JNI_ABORT" };
        let _ = writeln!(
            self.releases,
            "    if ({name}) {{\n        (*env)->Release{kind}ArrayElements(env, \
             {name}, {name}_data, {mode});\n    }}"
        );
        (format!("{name}_data"), format!("{name}_size"))
    }

    /// One array parameter, passed as a pointer and a length like every
    /// other buffer.
    fn array(&mut self, data: &Read<'_>) {
        let (pointer, size) = self.fetch(&c_held(data), &data.ty, data.member.name);
        self.passed
            .push(format!("({}){pointer}", c::spell(&data.ty)));
        self.passed.push(format!("(size_t){size}"));
    }

    /// One list, made into the array the library reads out of the two
    /// arguments it crossed as, and let go of again after the call. What comes
    /// back is the array and its count, which is the list's own.
    fn records(&mut self, base: &str, element: &Element, from: &str) -> (String, String) {
        let (make, release) = element_helpers(element.record);
        let pinned = format!("{base}_pinned");
        let array = format!("{base}_array");
        let count = format!("{base}_count");
        for name in [&pinned, &array, &count] {
            self.names
                .push(Named::new("the shim", name.clone(), from.to_owned()));
        }
        self.names.push(Named::new(
            "the shim",
            "ready".to_owned(),
            "whether every list this shim was handed made an array",
        ));
        let _ = write!(
            self.prepares,
            "    jbyte *{pinned} = NULL;\n\
             \x20   {} *{array} = NULL;\n\
             \x20   size_t {count} = 0;\n\
             \x20   ready = ready && {make}(env, {base}Bytes, {base}Lengths, &{pinned}, &{array}, &{count});\n",
            c::named(element.record.name)
        );
        let _ = writeln!(
            self.releases,
            "    {release}(env, {base}Bytes, {pinned}, {array});"
        );
        (array, count)
    }

    /// One value written back, which crosses in a `long[]` of one.
    fn out(&mut self, read: &Read<'_>) {
        let name = returned(read.member.name);
        self.names.push(Named::new(
            "the shim",
            format!("{name}_value"),
            read.member.name,
        ));
        self.names.push(Named::new(
            "the shim",
            "slot".to_owned(),
            "the long this shim hands one value back in",
        ));
        let mut written = read.ty.clone();
        written.pointer = None;
        let _ = writeln!(self.fetches, "    {} {name}_value = 0;", c::spell(&written));
        self.passed.push(format!("&{name}_value"));
        let _ = writeln!(
            self.writes,
            "    {{\n        jlong slot = (jlong){name}_value;\n        \
             (*env)->SetLongArrayRegion(env, {name}, 0, 1, &slot);\n    }}"
        );
    }

    /// One struct the library fills in whole, handed back a member at a time.
    fn given(&mut self, surface: &Surface, read: &Read<'_>) -> Result<(), Refused> {
        let name = returned(read.member.name);
        self.names.push(Named::new(
            "the shim",
            format!("{name}_value"),
            read.member.name,
        ));
        self.names.push(Named::new(
            "the shim",
            "slots".to_owned(),
            "the array this shim hands a struct back in",
        ));
        let Base::Named(record_name) = &read.ty.base else {
            return Err(Refused::about("a struct with no name"));
        };
        let Some(record) = record_named(surface, record_name) else {
            return Err(Refused::about(&format!(
                "{record_name} is handed back a member at a time and the surface does not \
                 declare it"
            )));
        };
        let spelled = c::named(record_name);
        let _ = writeln!(self.fetches, "    {spelled} {name}_value;");
        let _ = writeln!(
            self.fetches,
            "    memset(&{name}_value, 0, sizeof {name}_value);"
        );
        let _ = writeln!(self.fetches, "    {name}_value.size = sizeof {name}_value;");
        self.passed.push(format!("&{name}_value"));
        self.writes.push_str(&slots(&name, record_name, record)?);
        Ok(())
    }

    /// One struct a caller built in Kotlin: zeroed, sized by this shim's own
    /// header, and filled in a member at a time from the arguments the class
    /// crossed as.
    fn built(&mut self, surface: &Surface, read: &Read<'_>) -> Result<(), Refused> {
        let record = config_record(surface, read)?;
        let value = format!("{}_value", c_held(read));
        self.names
            .push(Named::new("the shim", value.clone(), read.member.name));
        let _ = writeln!(self.fetches, "    {} {value};", c::named(record.name));
        let _ = writeln!(self.fetches, "    memset(&{value}, 0, sizeof {value});");
        let _ = writeln!(self.fetches, "    {value}.size = sizeof {value};");
        let fields = read_all(record.name, record.fields)?;
        for part in parts(surface, record, &fields, 1)? {
            match part {
                Part::Plain(field) => {
                    let _ = writeln!(
                        self.fetches,
                        "    {value}.{} = ({}){};",
                        field.member.name,
                        c::spell(&field.ty),
                        flat(read, field)
                    );
                }
                Part::Buffer { data, len } => {
                    let from = format!("{}::{}", record.name, data.member.name);
                    let (pointer, size) = self.fetch(&flat(read, data), &data.ty, &from);
                    let _ = writeln!(
                        self.fetches,
                        "    {value}.{} = ({}){pointer};",
                        data.member.name,
                        c::spell(&data.ty)
                    );
                    let _ = writeln!(
                        self.fetches,
                        "    {value}.{} = (size_t){size};",
                        len.member.name
                    );
                }
                Part::Records { data, len, element } => {
                    let from = format!("{}::{}", record.name, data.member.name);
                    let (array, count) = self.records(&flat(read, data), &element, &from);
                    let _ = write!(
                        self.prepares,
                        "    {value}.{} = {array};\n    {value}.{} = {count};\n",
                        data.member.name, len.member.name
                    );
                }
                Part::Listener {
                    callback,
                    user_data,
                    alias,
                } => {
                    let landing = Landing::of(surface, alias)?;
                    let key = flat(read, callback);
                    let _ = writeln!(
                        self.fetches,
                        "    {value}.{} = {key} != 0 ? {} : NULL;",
                        callback.member.name,
                        landing.function()
                    );
                    let _ = writeln!(
                        self.fetches,
                        "    {value}.{} = (void *)(intptr_t){key};",
                        user_data.member.name
                    );
                }
                Part::Arm(field) => return Err(not_built(record, field)),
            }
        }
        self.passed.push(format!("&{value}"));
        Ok(())
    }
}

fn around(surface: &Surface, parts_of_call: &[Role<'_>]) -> Result<Around, Refused> {
    let mut out = Around::default();
    for role in parts_of_call {
        match role {
            Role::Plain(read) => {
                out.passed
                    .push(format!("({}){}", c::spell(&read.ty), c_held(read)));
            }
            Role::Buffer { data, .. } | Role::Fill { data, .. } => out.array(data),
            Role::Records { data, .. } => {
                let element = element(surface, data, "Kotlin")?;
                let (array, count) = out.records(&c_held(data), &element, data.member.name);
                out.passed.push(array);
                out.passed.push(count);
            }
            Role::Config(read) => out.built(surface, read)?,
            Role::Shared(read) => {
                out.passed.push(format!(
                    "({})(intptr_t){}",
                    c::spell(&read.ty),
                    c_held(read)
                ));
            }
            Role::Out(read) => out.out(read),
            Role::Given(read) => out.given(surface, read)?,
        }
    }
    Ok(out)
}

/// A struct read back one member at a time, with a float carried as the bits
/// it is: nothing on the Kotlin side can know a field offset, so nothing on
/// the Kotlin side is told one.
fn slots(name: &str, record_name: &str, record: &Record) -> Result<String, Refused> {
    let mut out = String::new();
    let _ = writeln!(out, "    {{\n        jlong slots[{}];", record.fields.len());
    for (index, field) in read_all(record_name, record.fields)?.iter().enumerate() {
        if matches!(field.ty.base, Base::Float(_)) {
            let _ = writeln!(
                out,
                "        {{\n            uint32_t bits;\n            \
                 memcpy(&bits, &{name}_value.{}, sizeof bits);\n            \
                 slots[{index}] = (jlong)bits;\n        }}",
                field.member.name
            );
        } else {
            let _ = writeln!(
                out,
                "        slots[{index}] = (jlong){name}_value.{};",
                field.member.name
            );
        }
    }
    let _ = writeln!(
        out,
        "        (*env)->SetLongArrayRegion(env, {name}, 0, {}, slots);\n    }}",
        record.fields.len()
    );
    Ok(out)
}

/// The C behind one `external fun`: the casts, the arrays it has to fetch
/// and release, and what it writes back.
fn implementation(
    surface: &Surface,
    function: &Function,
    read: &[Read<'_>],
) -> Result<String, Refused> {
    let mut out = String::new();
    let parts_of_call = roles(surface, read);
    let mut arguments = Vec::new();
    for role in &parts_of_call {
        arguments.extend(crossing(surface, role)?.jni);
    }
    let returns = Type::read(function.returns)?;
    let answers_text = returns.pointer.is_some() && returns.base == Base::Char;
    let head = if answers_text { "jstring" } else { "jint" };
    let _ = writeln!(out, "JNIEXPORT {head} JNICALL");
    let _ = writeln!(
        out,
        "{}(JNIEnv *env, jobject self{}{})",
        symbol(function.name),
        if arguments.is_empty() { "" } else { ", " },
        arguments.join(", ")
    );
    out.push_str("{\n    (void)env;\n    (void)self;\n");

    let Around {
        passed,
        fetches,
        prepares,
        releases,
        writes,
        names: _,
    } = around(surface, &parts_of_call)?;
    out.push_str(&fetches);
    let call = format!("{}({})", function.name, passed.join(", "));
    if answers_text {
        let _ = writeln!(out, "    const char *text = {call};");
        out.push_str(&releases);
        out.push_str("    return text ? (*env)->NewStringUTF(env, text) : NULL;\n}\n\n");
        return Ok(out);
    }
    if prepares.is_empty() {
        let _ = writeln!(out, "    sipral_status_t status = {call};");
        out.push_str(&releases);
        out.push_str(&writes);
        out.push_str("    return (jint)status;\n}\n\n");
        return Ok(out);
    }
    // A list that does not make an array leaves an exception pending, and
    // then neither the call nor anything that writes back may be made; what
    // was fetched is released either way, which JNI allows with one pending
    out.push_str("    int ready = 1;\n");
    out.push_str(&prepares);
    let _ = writeln!(
        out,
        "    /* -1 is no status the library answers with, and it is never read: a list\n\
         \x20    * that did not make an array left an exception pending, and the JVM\n\
         \x20    * throws that instead */\n\
         \x20   sipral_status_t status = -1;\n\
         \x20   if (ready) {{\n\
         \x20       status = {call};\n\
         \x20   }}"
    );
    out.push_str(&releases);
    if !writes.is_empty() {
        out.push_str("    if (ready) {\n");
        for line in writes.lines() {
            let _ = writeln!(out, "    {line}");
        }
        out.push_str("    }\n");
    }
    out.push_str("    return (jint)status;\n}\n\n");
    Ok(out)
}

/// The C functions that make a list of an element into the array the library
/// reads and let go of it again: `jni_header_array` and `jni_header_release`
/// for `SipralHeader`.
fn element_helpers(record: &Record) -> (String, String) {
    let name = snake(record.name);
    let stem = name.strip_prefix("sipral_").unwrap_or(&name);
    (format!("jni_{stem}_array"), format!("jni_{stem}_release"))
}

/// The one function every list helper refuses through.
const REFUSE: &str = "jni_refuse";

/// The locals the function that makes a list into an array writes, beside its
/// parameters.
const ARRAY_LOCALS: &[(&str, &str)] = &[
    ("env", "the JNI environment the list helper is handed"),
    ("bytes", "the packed text the list helper is handed"),
    ("lengths", "the lengths the list helper is handed"),
    ("out_pinned", "where the list helper says what it pinned"),
    ("out_array", "where the list helper says what array it made"),
    (
        "out_count",
        "where the list helper says how long the array is",
    ),
    ("parts", "how many lengths the list helper was handed"),
    ("room", "how many bytes the list helper was handed"),
    ("count", "how many elements the list helper makes"),
    ("index", "the element the list helper is making"),
    ("at", "how far into the bytes the list helper has pointed"),
    ("length", "the length the list helper is checking"),
    ("given", "the lengths as the list helper fetched them"),
    ("pinned", "the bytes as the list helper fetched them"),
    ("array", "the array the list helper makes"),
];

/// What every list the surface takes needs in the shim: a function that turns
/// what `packed` made into the array the library reads, one that lets go of
/// it, and the function both refuse through.
///
/// The bytes are pinned rather than copied, and each length is read once, out
/// of the shim's own fetch of the lengths, and checked against what is left of
/// the bytes before any pointer is made from it; so a length that reaches past
/// them, a negative one, a count that is not a whole number of elements and
/// bytes the lengths do not account for are all an exception in Kotlin, and
/// none of them a read past the end of an array. Nothing here makes a local
/// reference except the class an exception is thrown with, which is deleted
/// at once.
fn list_helpers(surface: &Surface) -> Result<String, Refused> {
    let found = elements(surface, "Kotlin")?;
    if found.is_empty() {
        return Ok(String::new());
    }
    let mut out = String::new();
    let _ = write!(
        out,
        "/* Throw a new exception of the class named. What is wrong with a list the\n\
         \x20* shim was handed is the JVM's to report: a status would be read as the\n\
         \x20* library's answer, and the library was never called. */\n\
         static void\n\
         {REFUSE}(JNIEnv *env, const char *thrown, const char *why)\n\
         {{\n\
         \x20   jclass found = (*env)->FindClass(env, thrown);\n\
         \x20   if (found != NULL) {{\n\
         \x20       (*env)->ThrowNew(env, found, why);\n\
         \x20       (*env)->DeleteLocalRef(env, found);\n\
         \x20   }}\n\
         }}\n\n"
    );
    for element in &found {
        out.push_str(&list_functions(element));
    }
    Ok(out)
}

/// The two functions one element's lists go through.
fn list_functions(element: &Element) -> String {
    let record = element.record;
    let spelled = c::named(record.name);
    let (make, release) = element_helpers(record);
    let pieces = element.texts.len();
    let mut out = String::new();
    let _ = write!(
        out,
        "/* A list of {spelled} as {class}.packed hands it over, made into the\n\
         \x20* array the library reads. `bytes` is every piece of text in every element,\n\
         \x20* one after another, and `lengths` how many bytes each took, {pieces} to an\n\
         \x20* element in the order the struct declares them. The bytes are pinned, and\n\
         \x20* every length is read once and checked against what is left of them before\n\
         \x20* a pointer is made from it, so no element reaches past the array it came\n\
         \x20* in; an empty piece of text is a null pointer with a length of zero. Answers\n\
         \x20* 1 with what {release} lets go of in the three out parameters, or 0\n\
         \x20* with an exception pending and nothing held. */\n\
         static int\n\
         {make}(JNIEnv *env, jbyteArray bytes, jlongArray lengths, jbyte **out_pinned, {spelled} **out_array, size_t *out_count)\n\
         {{\n\
         \x20   jsize parts;\n\
         \x20   jsize room;\n\
         \x20   size_t count;\n\
         \x20   size_t index;\n\
         \x20   size_t at = 0;\n\
         \x20   jlong length;\n\
         \x20   jlong *given;\n\
         \x20   jbyte *pinned = NULL;\n\
         \x20   {spelled} *array;\n\n\
         \x20   *out_pinned = NULL;\n\
         \x20   *out_array = NULL;\n\
         \x20   *out_count = 0;\n\
         \x20   parts = lengths != NULL ? (*env)->GetArrayLength(env, lengths) : 0;\n\
         \x20   room = bytes != NULL ? (*env)->GetArrayLength(env, bytes) : 0;\n\
         \x20   if (parts % {pieces} != 0) {{\n\
         \x20       {REFUSE}(env, \"java/lang/IllegalArgumentException\", \"the lengths of a list of {spelled} are not {pieces} to an element\");\n\
         \x20       return 0;\n\
         \x20   }}\n\
         \x20   count = (size_t)parts / {pieces};\n\
         \x20   if (count == 0) {{\n\
         \x20       if (room != 0) {{\n\
         \x20           {REFUSE}(env, \"java/lang/IllegalArgumentException\", \"the lengths of a list of {spelled} do not account for its bytes\");\n\
         \x20           return 0;\n\
         \x20       }}\n\
         \x20       return 1;\n\
         \x20   }}\n\
         \x20   if (count > SIZE_MAX / sizeof *array) {{\n\
         \x20       {REFUSE}(env, \"java/lang/OutOfMemoryError\", \"a list of {spelled} longer than memory can hold\");\n\
         \x20       return 0;\n\
         \x20   }}\n\
         \x20   array = malloc(count * sizeof *array);\n\
         \x20   if (array == NULL) {{\n\
         \x20       {REFUSE}(env, \"java/lang/OutOfMemoryError\", \"no memory for a list of {spelled}\");\n\
         \x20       return 0;\n\
         \x20   }}\n\
         \x20   given = (*env)->GetLongArrayElements(env, lengths, NULL);\n\
         \x20   if (given == NULL) {{\n\
         \x20       free(array);\n\
         \x20       return 0;\n\
         \x20   }}\n\
         \x20   if (room > 0) {{\n\
         \x20       pinned = (*env)->GetByteArrayElements(env, bytes, NULL);\n\
         \x20       if (pinned == NULL) {{\n\
         \x20           (*env)->ReleaseLongArrayElements(env, lengths, given, JNI_ABORT);\n\
         \x20           free(array);\n\
         \x20           return 0;\n\
         \x20       }}\n\
         \x20   }}\n\
         \x20   for (index = 0; index < count; index++) {{\n",
        class = record.name,
    );
    for (position, text) in element.texts.iter().enumerate() {
        let _ = write!(
            out,
            "        length = given[index * {pieces} + {position}];\n\
             \x20       if (length < 0 || (uint64_t)length > (uint64_t)((size_t)room - at)) {{\n\
             \x20           break;\n\
             \x20       }}\n\
             \x20       array[index].{data} = length == 0 ? NULL : ({pointer})pinned + at;\n\
             \x20       array[index].{len} = (size_t)length;\n\
             \x20       at += (size_t)length;\n",
            data = text.data.member.name,
            len = text.len.member.name,
            pointer = c::spell(&text.data.ty),
        );
    }
    let _ = write!(
        out,
        "    }}\n\
         \x20   (*env)->ReleaseLongArrayElements(env, lengths, given, JNI_ABORT);\n\
         \x20   if (index != count || at != (size_t)room) {{\n\
         \x20       if (pinned != NULL) {{\n\
         \x20           (*env)->ReleaseByteArrayElements(env, bytes, pinned, JNI_ABORT);\n\
         \x20       }}\n\
         \x20       free(array);\n\
         \x20       {REFUSE}(env, \"java/lang/IllegalArgumentException\", \"the lengths of a list of {spelled} do not account for its bytes\");\n\
         \x20       return 0;\n\
         \x20   }}\n\
         \x20   *out_pinned = pinned;\n\
         \x20   *out_array = array;\n\
         \x20   *out_count = count;\n\
         \x20   return 1;\n\
         }}\n\n"
    );
    out.push_str(&list_release(element));
    out
}

/// The function that lets go of what the one before it made.
fn list_release(element: &Element) -> String {
    let (make, release) = element_helpers(element.record);
    let spelled = c::named(element.record.name);
    format!(
        "/* Let go of what {make} made, which is nothing when it answered 0. */\n\
         static void\n\
         {release}(JNIEnv *env, jbyteArray bytes, jbyte *pinned, {spelled} *array)\n\
         {{\n\
         \x20   if (pinned != NULL) {{\n\
         \x20       (*env)->ReleaseByteArrayElements(env, bytes, pinned, JNI_ABORT);\n\
         \x20   }}\n\
         \x20   free(array);\n\
         }}\n\n"
    )
}

/// The hooks the JVM calls as it loads and unloads the shim, which is where
/// every class and method a callback hands events to is looked up.
fn load_hooks(surface: &Surface, landings: &[Landing]) -> Result<String, Refused> {
    let mut out = String::new();
    out.push_str(
        "/* The JVM this library was loaded into, and for each callback the class and\n\
         \x20* method its events are handed to. They are looked up as the library loads,\n\
         \x20* on the thread that loaded it, because a thread attached later looks a\n\
         \x20* class up through the system class loader, which on Android cannot see\n\
         \x20* the application's. */\n\
         static JavaVM *jni_vm;\n",
    );
    for landing in landings {
        let _ = writeln!(out, "static jclass {};", landing.class());
        let _ = writeln!(out, "static jmethodID {};", landing.deliver());
    }
    out.push_str(
        "\n/* Whether the struct a callback was handed reaches as far as one of its\n\
         \x20* members: the library fills in no more of it than its size member says. */\n\
         #define JNI_REACHES(pointer, type, member) \\\n\
         \x20   ((pointer)->size >= offsetof(type, member) + sizeof (pointer)->member)\n\n\
         JNIEXPORT jint JNICALL\n\
         JNI_OnLoad(JavaVM *vm, void *reserved)\n\
         {\n\
         \x20   JNIEnv *env = NULL;\n\n\
         \x20   (void)reserved;\n\
         \x20   if ((*vm)->GetEnv(vm, (void *)&env, JNI_VERSION_1_6) != JNI_OK) {\n\
         \x20       return JNI_ERR;\n\
         \x20   }\n",
    );
    for landing in landings {
        let fields = read_all(landing.record.name, landing.record.fields)?;
        let (handed_over, _) = handed(surface, landing, &fields)?;
        let members = deliver_descriptor(&handed_over);
        let _ = writeln!(
            out,
            "    {{\n\
             \x20       jclass found = (*env)->FindClass(env, \"org/sipral/{keeper}\");\n\
             \x20       if (found == NULL) {{\n\
             \x20           return JNI_ERR;\n\
             \x20       }}\n\
             \x20       {class} = (jclass)(*env)->NewGlobalRef(env, found);\n\
             \x20       (*env)->DeleteLocalRef(env, found);\n\
             \x20       if ({class} == NULL) {{\n\
             \x20           return JNI_ERR;\n\
             \x20       }}\n\
             \x20       {deliver} = (*env)->GetStaticMethodID(env, {class}, \"deliver\", \"{members}\");\n\
             \x20       if ({deliver} == NULL) {{\n\
             \x20           return JNI_ERR;\n\
             \x20       }}\n\
             \x20   }}",
            keeper = landing.keeper(),
            class = landing.class(),
            deliver = landing.deliver(),
        );
    }
    out.push_str(
        "    jni_vm = vm;\n\
         \x20   return JNI_VERSION_1_6;\n\
         }\n\n\
         JNIEXPORT void JNICALL\n\
         JNI_OnUnload(JavaVM *vm, void *reserved)\n\
         {\n\
         \x20   JNIEnv *env = NULL;\n\n\
         \x20   (void)reserved;\n\
         \x20   jni_vm = NULL;\n\
         \x20   if ((*vm)->GetEnv(vm, (void *)&env, JNI_VERSION_1_6) != JNI_OK) {\n\
         \x20       return;\n\
         \x20   }\n",
    );
    for landing in landings {
        let _ = writeln!(
            out,
            "    if ({class} != NULL) {{\n\
             \x20       (*env)->DeleteGlobalRef(env, {class});\n\
             \x20       {class} = NULL;\n\
             \x20   }}",
            class = landing.class()
        );
    }
    out.push_str("}\n\n");
    Ok(out)
}

/// The C function one callback lands in.
fn landing_function(surface: &Surface, landing: &Landing) -> Result<String, Refused> {
    let record = landing.record;
    let fields = read_all(record.name, record.fields)?;
    let (members, _) = handed(surface, landing, &fields)?;
    let event = landing.event.name;
    let user_data = landing.user_data.name;
    let pointed = c::spell(&Type::read(landing.event.rust_type)?);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "/* Where a {callback} lands. The event is handed to\n\
         \x20* {keeper}.deliver under the key its user pointer carries, on a\n\
         \x20* thread attached to the JVM for the length of the call when it was not\n\
         \x20* attached already, and every local reference made here is deleted\n\
         \x20* before it returns: a poll delivers all its events inside one native\n\
         \x20* call, and nothing made here would be released until that call ended. */",
        callback = c::named(landing.alias.name),
        keeper = landing.keeper()
    );
    let _ = writeln!(
        out,
        "static void\n{}({pointed}{event}, void *{user_data})\n{{",
        landing.function()
    );
    out.push_str(
        "    JNIEnv *env = NULL;\n    int attached = 0;\n    int built = 1;\n    jint found;\n",
    );
    for member in &members {
        if let Some((name, ty)) = &member.c_local {
            let _ = writeln!(out, "    {ty} {name} = NULL;");
        }
    }
    let _ = writeln!(
        out,
        "\n    if (jni_vm == NULL || {event} == NULL) {{\n        return;\n    }}"
    );
    out.push_str(
        "    found = (*jni_vm)->GetEnv(jni_vm, (void *)&env, JNI_VERSION_1_6);\n\
         \x20   if (found == JNI_EDETACHED) {\n\
         \x20       if ((*jni_vm)->AttachCurrentThread(jni_vm, (void *)&env, NULL) != JNI_OK) {\n\
         \x20           return;\n\
         \x20       }\n\
         \x20       attached = 1;\n\
         \x20   } else if (found != JNI_OK) {\n\
         \x20       return;\n\
         \x20   }\n",
    );
    for member in &members {
        out.push_str(&member.c_make);
    }
    let mut passed = vec![format!("(jlong)(intptr_t){user_data}")];
    passed.extend(members.iter().map(|member| member.c_passed.clone()));
    let _ = writeln!(
        out,
        "    if (built) {{\n        (*env)->CallStaticVoidMethod(env, {}, {}, {});\n    }}",
        landing.class(),
        landing.deliver(),
        passed.join(", ")
    );
    out.push_str(
        "    /* deliver hands what a listener throws to the thread's own handler, so\n\
         \x20    * what is pending here is the JVM's -- an array it could not make --\n\
         \x20    * and a callback has no Java frame beneath it to throw into */\n\
         \x20   if ((*env)->ExceptionCheck(env)) {\n\
         \x20       (*env)->ExceptionDescribe(env);\n\
         \x20       (*env)->ExceptionClear(env);\n\
         \x20   }\n",
    );
    for member in &members {
        if let Some((name, _)) = &member.c_local {
            let _ = writeln!(
                out,
                "    if ({name} != NULL) {{\n        (*env)->DeleteLocalRef(env, {name});\n    }}"
            );
        }
    }
    out.push_str(
        "    if (attached) {\n        (*jni_vm)->DetachCurrentThread(jni_vm);\n    }\n}\n\n",
    );
    Ok(out)
}

/// Print the C that implements the declarations above.
pub(crate) fn shim(surface: &Surface) -> Result<String, Refused> {
    audit(surface, &Names)?;
    let mut out = String::new();
    out.push_str(
        "/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial\n\
         \x20* Copyright (c) 2026 Tiberiu Balasea\n\
         \x20*\n\
         \x20* Printed from the declarations in crates/sipral-ffi by tools/abi-gen.\n\
         \x20* Do not edit: `cargo run -p sipral-abi-gen` writes it again, and\n\
         \x20* `scripts/check.sh` fails when what is committed is not what came out.\n\
         \x20*\n\
         \x20* One function per entry point, one function per callback for it to land\n\
         \x20* in, and the load hook that finds what those hand events to. All of it\n\
         \x20* is printed from the same walk as the Kotlin beside it, so that the two\n\
         \x20* halves of the binding cannot drift apart without the generator saying so.\n\
         \x20*/\n\n\
         #include <jni.h>\n#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>\n\n#include \"sipral.h\"\n\n",
    );
    let landings = landings(surface)?;
    if !landings.is_empty() {
        out.push_str(&load_hooks(surface, &landings)?);
        for landing in &landings {
            out.push_str(&landing_function(surface, landing)?);
        }
    }
    out.push_str(&list_helpers(surface)?);
    for (function, read) in functions(surface)? {
        out.push_str(&implementation(surface, function, &read)?);
    }
    Ok(out)
}

/// Every name the lists a surface takes put into files of this back end's: the
/// class each element is built from and its fields, the locals of `packed`,
/// and the functions the shim makes arrays with and the locals of those.
fn own_lists(surface: &Surface, top: &str, file: &str) -> Result<Vec<(String, Named)>, Refused> {
    let mut out = Vec::new();
    let listed = elements(surface, "Kotlin")?;
    for element in &listed {
        let record = element.record;
        out.push((
            top.to_owned(),
            Named::new("", record.name.to_owned(), record.name),
        ));
        let class = format!("{}, the class", record.name);
        let packed = format!("{}.packed", record.name);
        for (name, what) in PACKED_LOCALS {
            out.push((
                packed.clone(),
                Named::new("the wrapper", (*name).to_owned(), *what),
            ));
        }
        for text in &element.texts {
            let from = format!("{}::{}", record.name, text.data.member.name);
            out.push((
                class.clone(),
                Named::new("the class", held(&text.data), from.clone()),
            ));
            out.push((
                packed.clone(),
                Named::new("the wrapper", text_bytes(text), from),
            ));
        }
        let (make, release) = element_helpers(record);
        for emitted in [make.clone(), release] {
            out.push((
                file.to_owned(),
                Named::new("the shim", emitted, record.name),
            ));
        }
        for (name, what) in ARRAY_LOCALS {
            out.push((
                format!("{make}, the shim"),
                Named::new("the shim", (*name).to_owned(), *what),
            ));
        }
    }
    if !listed.is_empty() {
        out.push((
            file.to_owned(),
            Named::new(
                "the shim",
                REFUSE.to_owned(),
                "the function every list helper refuses through",
            ),
        ));
    }
    Ok(out)
}

/// What Kotlin calls what the surface declares.
pub(crate) struct Names;

impl Spelling for Names {
    fn language(&self) -> &'static str {
        "Kotlin"
    }

    fn reserved(&self) -> &'static [&'static str] {
        RESERVED
    }

    /// Kotlin can be made to take any of its own keywords, in backticks, and
    /// [`safe`] does that. The shim is the exception and the reason this is
    /// overridden: it is C, it has no escape of any kind, and it is printed
    /// from the same walk. So the names in it are read against C's keywords.
    fn refuses(&self, place: &str, emitted: &str) -> Option<String> {
        if place == "the shim" {
            return crate::c::Names.refuses(place, emitted);
        }
        RESERVED
            .contains(&emitted)
            .then(|| format!("`{emitted}` is a keyword in Kotlin"))
    }

    fn layout(&self) -> Layout {
        Layout::Nested
    }

    fn types(&self, surface: &Surface) -> Vec<(String, String)> {
        let mut out = vec![
            ("SipralException".to_owned(), "this back end".to_owned()),
            ("SipralNative".to_owned(), "this back end".to_owned()),
            ("Sipral".to_owned(), "this back end".to_owned()),
        ];
        for enumeration in surface.enumerations {
            out.push((enumeration.name.to_owned(), enumeration.name.to_owned()));
        }
        for record in surface.records {
            if is_given(record) {
                out.push((record.name.to_owned(), record.name.to_owned()));
            }
        }
        out
    }

    fn members(&self, record: &Record) -> Result<Vec<(String, String)>, Refused> {
        // only the records that come back a member at a time are printed
        // member for member; a struct going in and a struct a listener is
        // handed are classes whose fields depend on how the surface uses
        // them, and `own` answers for those
        if !is_given(record) {
            return Ok(Vec::new());
        }
        Ok(read_all(record.name, record.fields)?
            .iter()
            .map(|field| {
                (
                    held(field),
                    format!("{}::{}", record.name, field.member.name),
                )
            })
            .collect())
    }

    fn code(&self, enumeration: &Enumeration, code: &Code) -> String {
        let _ = enumeration;
        screaming(code.name)
    }

    fn constant(&self, value: &Value) -> String {
        screaming(value.name.strip_prefix("SIPRAL_").unwrap_or(value.name))
    }

    fn entry(&self, function: &Function) -> String {
        called(function)
    }

    fn written_by_hand(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("lastErrorMessage", "sipral_last_error_message"),
            ("check", "the status check this back end writes"),
        ]
    }

    /// The C function a callback lands in, which names its two parameters as
    /// the declaration spelled them -- in C, where there is no escape -- and
    /// the listener's one method, which names the first the Kotlin way.
    fn signature(&self, alias: &Alias, read: &[Read<'_>]) -> Vec<Named> {
        let _ = alias;
        let mut out: Vec<Named> = read
            .iter()
            .map(|parameter| {
                Named::new(
                    "the shim",
                    parameter.member.name.to_owned(),
                    parameter.member.name,
                )
            })
            .collect();
        if let Some(first) = read.first() {
            out.push(Named::new("the listener", held(first), first.member.name));
        }
        out
    }

    fn inside(
        &self,
        surface: &Surface,
        function: &Function,
        read: &[Read<'_>],
        parts_of_call: &[Role<'_>],
    ) -> Result<Vec<Named>, Refused> {
        unprintable(surface, function, read, "Kotlin")?;
        let mut out = Vec::new();
        for role in parts_of_call {
            let crossing = crossing(surface, role)?;
            out.extend(
                crossing
                    .names
                    .into_iter()
                    .map(|(name, from)| Named::new("the declaration", name, from)),
            );
            out.extend(
                crossing
                    .shim
                    .into_iter()
                    .map(|(name, from)| Named::new("the shim", name, from)),
            );
        }
        // the shim's own locals, the same ones for every entry point
        for (name, what) in [
            ("env", "the JNI environment every shim function is handed"),
            ("self", "the object every shim function is handed"),
        ] {
            out.push(Named::new("the shim", name.to_owned(), what));
        }
        let ty = Type::read(function.returns)?;
        if ty.pointer.is_some() && ty.base == Base::Char {
            out.push(Named::new(
                "the shim",
                "text".to_owned(),
                "the string the shim reads back",
            ));
            out.extend(read.iter().map(|parameter| {
                Named::new("the wrapper", held(parameter), parameter.member.name)
            }));
            return Ok(out);
        }
        out.push(Named::new(
            "the shim",
            "status".to_owned(),
            "the status the shim holds on to",
        ));
        out.extend(around(surface, parts_of_call)?.names);
        out.extend(hand_over(surface, function, parts_of_call)?.names);
        Ok(out)
    }

    /// The classes a struct going in and a struct a listener is handed are
    /// printed as, the listener and the object listeners are kept in, the
    /// landing function and the names the shim declares once for the whole
    /// file, and the load-time check.
    fn own(&self, surface: &Surface) -> Result<Vec<(String, Named)>, Refused> {
        let top = "the top of the file";
        let file = "sipral_jni.c";
        let mut out = Vec::new();
        for record in built(surface)? {
            out.push((
                top.to_owned(),
                Named::new("", record.name.to_owned(), record.name),
            ));
            let class = format!("{}, the class", record.name);
            let fields = read_all(record.name, record.fields)?;
            for part in parts(surface, record, &fields, 1)? {
                let (emitted, from) = match part {
                    Part::Plain(field) => (held(field), field.member.name),
                    Part::Buffer { data, .. } | Part::Records { data, .. } => {
                        (held(data), data.member.name)
                    }
                    Part::Listener { callback, .. } => {
                        (listener_field(callback), callback.member.name)
                    }
                    Part::Arm(field) => return Err(not_built(record, field)),
                };
                out.push((
                    class.clone(),
                    Named::new("the class", emitted, format!("{}::{from}", record.name)),
                ));
            }
        }
        out.extend(own_lists(surface, top, file)?);
        let landings = landings(surface)?;
        for landing in &landings {
            let record = landing.record;
            let alias = landing.alias.name;
            out.push((
                top.to_owned(),
                Named::new("", record.name.to_owned(), record.name),
            ));
            for emitted in [landing.listener(), landing.keeper()] {
                out.push((top.to_owned(), Named::new("", emitted, alias)));
            }
            out.push((
                landing.listener(),
                Named::new("the listener", landing.method(), alias),
            ));
            let class = format!("{}, the class", record.name);
            let deliver = format!("{}.deliver", landing.keeper());
            let landed = format!("{alias}, the shim");
            for (name, what) in DELIVER_LOCALS {
                out.push((
                    deliver.clone(),
                    Named::new("the wrapper", (*name).to_owned(), *what),
                ));
            }
            for (name, what) in LANDING_LOCALS {
                out.push((
                    landed.clone(),
                    Named::new("the shim", (*name).to_owned(), *what),
                ));
            }
            let fields = read_all(record.name, record.fields)?;
            let (members, _) = handed(surface, landing, &fields)?;
            for member in &members {
                let from = format!("{}::{}", record.name, member.from);
                out.push((
                    class.clone(),
                    Named::new("the class", member.kotlin.clone(), from.clone()),
                ));
                out.push((
                    deliver.clone(),
                    Named::new("the wrapper", member.kotlin.clone(), from.clone()),
                ));
                if let Some((local, _)) = &member.c_local {
                    out.push((
                        landed.clone(),
                        Named::new("the shim", (*local).to_owned(), from),
                    ));
                }
            }
            for emitted in [landing.function(), landing.class(), landing.deliver()] {
                out.push((file.to_owned(), Named::new("the shim", emitted, alias)));
            }
        }
        if !landings.is_empty() {
            for (name, what) in SHIM_FILE {
                out.push((
                    file.to_owned(),
                    Named::new("the shim", (*name).to_owned(), *what),
                ));
            }
        }
        if abi_check(surface)?.is_some() {
            out.push((
                "SipralNative".to_owned(),
                Named::new(
                    "the declaration",
                    "agree".to_owned(),
                    "the check this back end makes at load",
                ),
            ));
        }
        Ok(out)
    }
}
