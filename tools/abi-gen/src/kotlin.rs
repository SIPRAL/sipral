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

use sipral_ffi::abi::{Function, Record, Surface};

use crate::c;
use crate::model::{
    Base, Int, Linked, Read, Refused, Role, Type, Writable, functions, linked, lower_camel,
    plain_named, read_all, record_named, roles, screaming, without_prefix,
};

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

/// How one parameter appears on each side of JNI.
struct Crossing {
    kotlin: Vec<String>,
    jni: Vec<String>,
}

fn crossing(role: &Role<'_>) -> Crossing {
    match role {
        Role::Plain(read) => {
            let name = lower_camel(read.member.name);
            Crossing {
                kotlin: vec![format!("{name}: {}", plain_kotlin(&read.ty))],
                jni: vec![format!("{} {name}", plain_jni(&read.ty))],
            }
        }
        Role::Buffer { data, .. } | Role::Fill { data, .. } => {
            let name = lower_camel(data.member.name);
            Crossing {
                kotlin: vec![format!("{name}: {}", array_of(&data.ty))],
                jni: vec![format!("{} {name}", jni_array_of(&data.ty))],
            }
        }
        Role::Config(read) | Role::Shared(read) => {
            let name = lower_camel(read.member.name);
            Crossing {
                kotlin: vec![format!("{name}: Long")],
                jni: vec![format!("jlong {name}")],
            }
        }
        Role::Given(read) | Role::Out(read) => {
            let name = returned(read.member.name);
            Crossing {
                kotlin: vec![format!("{name}: LongArray")],
                jni: vec![format!("jlongArray {name}")],
            }
        }
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
            let _ = writeln!(
                out,
                "    val {}: {},",
                lower_camel(field.member.name),
                slot_type(&field.ty)
            );
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
        .map(|parameter| {
            format!(
                "{}: {}",
                lower_camel(parameter.member.name),
                plain_kotlin(&parameter.ty)
            )
        })
        .collect();
    let passed: Vec<String> = read
        .iter()
        .map(|parameter| lower_camel(parameter.member.name))
        .collect();
    let _ = writeln!(
        out,
        "    fun {}({}): String? =\n        SipralNative.{}({})\n",
        without_prefix(function.name),
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
}

fn hand_over(parts: &[Role<'_>]) -> Result<Handover, Refused> {
    let mut out = Handover::default();
    let Handover {
        arguments,
        passed,
        prologue,
        results,
    } = &mut out;
    for role in parts {
        match role {
            Role::Plain(read) => {
                let held = lower_camel(read.member.name);
                arguments.push(format!("{held}: {}", plain_kotlin(&read.ty)));
                passed.push(held);
            }
            Role::Buffer { data, .. } => {
                let held = lower_camel(data.member.name);
                if data.ty.base == Base::Char && data.ty.pointer == Some(Writable::No) {
                    arguments.push(format!("{held}: String"));
                    let _ = writeln!(
                        prologue,
                        "        val {held}Bytes = {held}.toByteArray(Charsets.UTF_8)"
                    );
                    passed.push(format!("{held}Bytes"));
                } else {
                    arguments.push(format!("{held}: {}", array_of(&data.ty)));
                    passed.push(held);
                }
            }
            Role::Fill { data, .. } => {
                let held = lower_camel(data.member.name);
                arguments.push(format!("{held}: {}", array_of(&data.ty)));
                passed.push(held);
            }
            Role::Config(read) | Role::Shared(read) => {
                let held = lower_camel(read.member.name);
                arguments.push(format!("{held}: Long"));
                passed.push(held);
            }
            Role::Given(read) => {
                let held = returned(read.member.name);
                let Base::Named(record) = &read.ty.base else {
                    return Err(Refused::about("a struct with no name"));
                };
                let _ = writeln!(
                    prologue,
                    "        val {held}Slots = LongArray({record}.SLOTS)"
                );
                passed.push(format!("{held}Slots"));
                results.push((format!("{record}.of({held}Slots)"), record.clone()));
            }
            Role::Out(read) => {
                let held = returned(read.member.name);
                let _ = writeln!(prologue, "        val {held}Slot = LongArray(1)");
                passed.push(format!("{held}Slot"));
                results.push((format!("{held}Slot[0]"), "Long".to_owned()));
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
    let name = without_prefix(function.name);
    let Handover {
        arguments,
        passed,
        prologue,
        results,
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
}

fn around(surface: &Surface, parts: &[Role<'_>]) -> Result<Around, Refused> {
    let mut out = Around::default();
    let Around {
        passed,
        fetches,
        releases,
        writes,
    } = &mut out;
    for role in parts {
        match role {
            Role::Plain(read) => {
                passed.push(format!(
                    "({}){}",
                    c::spell(&read.ty),
                    lower_camel(read.member.name)
                ));
            }
            Role::Buffer { data, .. } | Role::Fill { data, .. } => {
                let name = lower_camel(data.member.name);
                let (element, kind) = jni_element_of(&data.ty);
                let writable = data.ty.pointer == Some(Writable::Yes);
                let _ = writeln!(
                    fetches,
                    "    {element} *{name}_data = {name} ? (*env)->Get{kind}ArrayElements(env, \
                     {name}, NULL) : NULL;"
                );
                let _ = writeln!(
                    fetches,
                    "    jsize {name}_size = {name} ? (*env)->GetArrayLength(env, {name}) : 0;"
                );
                let mode = if writable { "0" } else { "JNI_ABORT" };
                let _ = writeln!(
                    releases,
                    "    if ({name}) {{\n        (*env)->Release{kind}ArrayElements(env, \
                     {name}, {name}_data, {mode});\n    }}"
                );
                passed.push(format!("({}){name}_data", c::spell(&data.ty)));
                passed.push(format!("(size_t){name}_size"));
            }
            Role::Config(read) | Role::Shared(read) => {
                passed.push(format!(
                    "({})(intptr_t){}",
                    c::spell(&read.ty),
                    lower_camel(read.member.name)
                ));
            }
            Role::Out(read) => {
                let name = returned(read.member.name);
                let mut written = read.ty.clone();
                written.pointer = None;
                let _ = writeln!(fetches, "    {} {name}_value = 0;", c::spell(&written));
                passed.push(format!("&{name}_value"));
                let _ = writeln!(
                    writes,
                    "    {{\n        jlong slot = (jlong){name}_value;\n        \
                     (*env)->SetLongArrayRegion(env, {name}, 0, 1, &slot);\n    }}"
                );
            }
            Role::Given(read) => {
                let name = returned(read.member.name);
                let Base::Named(record_name) = &read.ty.base else {
                    return Err(Refused::about("a struct with no name"));
                };
                let Some(record) = record_named(surface, record_name) else {
                    return Err(Refused::about(record_name));
                };
                let spelled = c::named(record_name);
                let _ = writeln!(fetches, "    {spelled} {name}_value;");
                let _ = writeln!(
                    fetches,
                    "    memset(&{name}_value, 0, sizeof {name}_value);"
                );
                let _ = writeln!(fetches, "    {name}_value.size = sizeof {name}_value;");
                passed.push(format!("&{name}_value"));
                writes.push_str(&slots(&name, record_name, record)?);
            }
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
