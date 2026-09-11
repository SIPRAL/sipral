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
//! Structs are the part JNI makes awkward, and the way out of it is not to let
//! a struct cross at all. A struct the library fills in whole is handed back a
//! member at a time in a `long[]` the shim writes, with a float carried as its
//! own bits, so nothing on the Kotlin side has to know a field offset — which
//! it could not, since Android builds for two pointer widths. A struct the
//! caller part-fills is the one shape left over, and it crosses as an address:
//! `docs/08-ffi.md` says so and says what it costs.

use std::fmt::Write as _;

use sipral_ffi::abi::{Alias, Code, Enumeration, Function, Record, Surface, Value};

use crate::c;
use crate::model::{
    Base, Int, Linked, Read, Refused, Role, Type, Writable, functions, linked, lower_camel,
    plain_named, read_all, record_named, roles, screaming, without_prefix,
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

/// How one parameter appears on each side of JNI: what is declared, and the
/// bare identifiers, which the uniqueness pass reads rather than deriving
/// them a second time.
struct Crossing {
    kotlin: Vec<String>,
    jni: Vec<String>,
    names: Vec<(String, String)>,
    shim: Vec<(String, String)>,
}

fn crossing(role: &Role<'_>) -> Crossing {
    let (kotlin_type, jni_type, read, kotlin_name, c_name) = match role {
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
        Role::Config(read) | Role::Shared(read) => (
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
    Crossing {
        kotlin: vec![format!("{kotlin_name}: {kotlin_type}")],
        jni: vec![format!("{jni_type} {c_name}")],
        names: vec![(kotlin_name, read.member.name.to_owned())],
        shim: vec![(c_name, read.member.name.to_owned())],
    }
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
/// to the declaration, what has to be prepared first, and what comes back.
#[derive(Default)]
struct Handover {
    arguments: Vec<String>,
    passed: Vec<String>,
    prologue: String,
    results: Vec<(String, String)>,
    /// Every identifier the wrapper puts in its own scope, reported so the
    /// uniqueness pass reads what was written rather than deriving it again.
    names: Vec<Named>,
}

fn hand_over(parts: &[Role<'_>]) -> Result<Handover, Refused> {
    let mut out = Handover::default();
    let Handover {
        arguments,
        passed,
        prologue,
        results,
        names,
    } = &mut out;
    for role in parts {
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
            Role::Config(read) | Role::Shared(read) => {
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
    Ok(out)
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
        results,
        names: _,
    } = hand_over(&roles(surface, read))?;
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
    let _ = writeln!(
        out,
        "        check(SipralNative.{}({}))",
        function.name,
        passed.join(", ")
    );
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
        let parts = roles(surface, &read);
        let arguments: Vec<String> = parts
            .iter()
            .flat_map(|role| crossing(role).kotlin)
            .collect();
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
         \x20* The ABI as JNI declares it. Every integer crosses as a Long and\n\
         \x20* every struct the library fills in comes back in a LongArray, so\n\
         \x20* nothing here depends on a field offset that the two Android\n\
         \x20* pointer widths would disagree about.\n\
         \x20*/\n\
         internal object SipralNative {\n\
         \x20   init {\n\
         \x20       System.loadLibrary(\"sipral_jni\")\n\
         \x20   }\n\n",
    );
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

/// What the C around one call has to say: the arguments it passes, the
/// arrays it fetches and gives back, and the values it writes into the
/// caller's `long[]`.
#[derive(Default)]
struct Around {
    passed: Vec<String>,
    fetches: String,
    releases: String,
    writes: String,
    /// Every identifier the shim writes in the C function's own scope. C has
    /// no backticks, so these are the names as they are, and the uniqueness
    /// pass reads them against C's keywords rather than Kotlin's.
    names: Vec<Named>,
}

impl Around {
    /// One array parameter: fetched on the way in, released on the way out,
    /// and passed as a pointer and a length like every other buffer.
    fn array(&mut self, data: &Read<'_>) {
        let name = c_held(data);
        for suffix in ["_data", "_size"] {
            self.names.push(Named::new(
                "the shim",
                format!("{name}{suffix}"),
                data.member.name,
            ));
        }
        let (element, kind) = jni_element_of(&data.ty);
        let writable = data.ty.pointer == Some(Writable::Yes);
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
        self.passed
            .push(format!("({}){name}_data", c::spell(&data.ty)));
        self.passed.push(format!("(size_t){name}_size"));
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
}

fn around(surface: &Surface, parts: &[Role<'_>]) -> Result<Around, Refused> {
    let mut out = Around::default();
    for role in parts {
        match role {
            Role::Plain(read) => {
                out.passed
                    .push(format!("({}){}", c::spell(&read.ty), c_held(read)));
            }
            Role::Buffer { data, .. } | Role::Fill { data, .. } => out.array(data),
            Role::Config(read) | Role::Shared(read) => {
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
    let parts = roles(surface, read);
    let arguments: Vec<String> = parts.iter().flat_map(|role| crossing(role).jni).collect();
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
        releases,
        writes,
        names: _,
    } = around(surface, &parts)?;
    out.push_str(&fetches);
    if answers_text {
        let _ = writeln!(
            out,
            "    const char *text = {}({});",
            function.name,
            passed.join(", ")
        );
        out.push_str(&releases);
        out.push_str("    return text ? (*env)->NewStringUTF(env, text) : NULL;\n}\n\n");
        return Ok(out);
    }
    let _ = writeln!(
        out,
        "    sipral_status_t status = {}({});",
        function.name,
        passed.join(", ")
    );
    out.push_str(&releases);
    out.push_str(&writes);
    out.push_str("    return (jint)status;\n}\n\n");
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
         \x20* One function per entry point, and nothing else: the casts are the\n\
         \x20* whole of what it does, so that the two halves of the Kotlin binding\n\
         \x20* cannot drift apart without the generator saying so.\n\
         \x20*/\n\n\
         #include <jni.h>\n#include <string.h>\n\n#include \"sipral.h\"\n\n",
    );

    for (function, read) in functions(surface)? {
        out.push_str(&implementation(surface, function, &read)?);
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
        // only the records that come back a member at a time are printed;
        // the rest cross as an address and have no Kotlin shape at all
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

    /// Nothing. This binding never prints the callback: the settings struct
    /// crosses JNI as an address, so the function pointer inside it is never
    /// spelled on the Kotlin side, and the shim includes `sipral.h` rather
    /// than declaring a typedef of its own. The only spelling of these
    /// parameters anywhere this back end writes is the header's, and
    /// [`crate::c::Names`] reads that one. The day a Kotlin-side callback is
    /// printed, it is named here.
    fn signature(&self, alias: &Alias, read: &[Read<'_>]) -> Vec<Named> {
        let _ = (alias, read);
        Vec::new()
    }

    fn inside(
        &self,
        surface: &Surface,
        function: &Function,
        read: &[Read<'_>],
        parts: &[Role<'_>],
    ) -> Result<Vec<Named>, Refused> {
        let mut out = Vec::new();
        for role in parts {
            let crossing = crossing(role);
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
        out.extend(around(surface, parts)?.names);
        out.extend(hand_over(parts)?.names);
        Ok(out)
    }
}
