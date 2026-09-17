// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The C header, which is what the other three bindings are written against.
//!
//! Enumerations come out as a typedef of the exact integer width plus the
//! names as an anonymous enum, rather than as a C enum of their own. A C
//! compiler picks the width of an enum itself, and a struct member whose width
//! the two ends disagree about is the whole of what the size member exists to
//! prevent.

use std::fmt::Write as _;

use sipral_ffi::abi::{Alias, Code, Enumeration, Function, Record, Shape, Stands, Surface, Value};

use crate::model::{
    Base, Int, Linked, Read, Refused, Role, Type, Writable, callback_answer, linked, plain_named,
    read_all, screaming, snake,
};
use crate::names::{Layout, Named, Spelling, audit};

/// What a name inside a documentation link is called in C.
fn spelled(surface: &Surface, path: &str) -> String {
    match linked(surface, path) {
        Some((Linked::Enumeration(name), Some(code))) => {
            format!("{}_{}", screaming_prefix(name), screaming(code))
        }
        Some((Linked::Enumeration(name) | Linked::Type(name), None)) => named(name),
        Some((Linked::Type(name), Some(member))) => format!("{}::{member}", named(name)),
        None => path.to_owned(),
    }
}

/// Documentation with every link in it spelled the C way.
fn lines(surface: &Surface, doc: &[&str]) -> Vec<String> {
    plain_named(doc, &|path| spelled(surface, path))
}

/// The name a type takes in C.
pub(crate) fn named(name: &str) -> String {
    format!("{}_t", snake(name))
}

/// The C spelling of a type, with the pointer put where C puts it.
pub(crate) fn spell(ty: &Type) -> String {
    let base = match &ty.base {
        Base::Opaque => "void".to_owned(),
        Base::Char => "char".to_owned(),
        Base::Float(32) => "float".to_owned(),
        Base::Float(_) => "double".to_owned(),
        Base::Int(Int { bits: 0, .. }) => "size_t".to_owned(),
        Base::Int(Int { bits, signed }) => {
            let sign = if *signed { "int" } else { "uint" };
            format!("{sign}{bits}_t")
        }
        Base::Named(name) => named(name),
    };
    match ty.pointer {
        None => base,
        Some(Writable::No) => format!("const {base} *"),
        Some(Writable::Yes) => format!("{base} *"),
    }
}

fn block(out: &mut String, indent: &str, doc: &[String]) {
    if doc.is_empty() {
        return;
    }
    let _ = writeln!(out, "{indent}/**");
    for line in doc {
        if line.is_empty() {
            let _ = writeln!(out, "{indent} *");
        } else {
            let _ = writeln!(out, "{indent} *{line}");
        }
    }
    let _ = writeln!(out, "{indent} */");
}

fn parameters(read: &[Read<'_>]) -> String {
    if read.is_empty() {
        return "void".to_owned();
    }
    read.iter()
        .map(|parameter| {
            let ty = spell(&parameter.ty);
            if ty.ends_with('*') {
                format!("{ty}{}", parameter.member.name)
            } else {
                format!("{ty} {}", parameter.member.name)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The names a plain integer answers to.
fn aliases(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    for alias in surface.aliases {
        let Stands::For(target) = alias.stands else {
            continue;
        };
        block(out, "", &lines(surface, alias.doc));
        let ty = Type::read(target)?;
        let _ = writeln!(out, "typedef {} {};\n", spell(&ty), named(alias.name));
    }
    Ok(())
}

/// The published constants, as macros: a cast of a literal is a constant
/// expression, so one of these still sizes an array.
fn values(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    for group in surface.constants {
        for value in *group {
            block(out, "", &lines(surface, value.doc));
            let ty = Type::read(value.rust_type)?;
            let _ = writeln!(
                out,
                "#define {} (({}){})\n",
                value.name,
                spell(&ty),
                value.value
            );
        }
    }
    Ok(())
}

/// Every record named before any is defined, so that no declaration has to
/// come before the one it mentions.
fn forwards(out: &mut String, surface: &Surface) {
    out.push_str("/* Every record, named before any of them is defined, so that a\n");
    out.push_str(" * declaration never has to come before the one it mentions. */\n");
    for record in surface.records {
        let keyword = match record.shape {
            Shape::Struct => "struct",
            Shape::Union => "union",
        };
        let tag = snake(record.name);
        let _ = writeln!(out, "typedef {keyword} {tag} {};", named(record.name));
    }
    out.push('\n');
}

fn enumerations(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    for enumeration in surface.enumerations {
        let mut doc = lines(surface, enumeration.doc);
        if !enumeration.reserved.is_empty() {
            doc.push(String::new());
            doc.push(" Numbers already spent on features this build does not have:".to_owned());
            for held in enumeration.reserved {
                doc.push(format!(" - {}: {}", held.value, held.feature));
            }
        }
        block(out, "", &doc);
        let width = Type::read(enumeration.width)?;
        let _ = writeln!(
            out,
            "typedef {} {};",
            spell(&width),
            named(enumeration.name)
        );
        out.push_str("enum {\n");
        let prefix = screaming_prefix(enumeration.name);
        for code in enumeration.codes {
            block(out, "    ", &lines(surface, code.doc));
            let _ = writeln!(
                out,
                "    {prefix}_{} = {},",
                screaming(code.name),
                code.value
            );
        }
        out.push_str("};\n\n");
    }
    Ok(())
}

fn callbacks(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    for alias in surface.aliases {
        let Stands::Callback(arguments, _) = alias.stands else {
            continue;
        };
        block(out, "", &lines(surface, alias.doc));
        let read = read_all(alias.name, arguments)?;
        let returns = match callback_answer(alias)? {
            Some(ty) => spell(&ty),
            None => "void".to_owned(),
        };
        let _ = writeln!(
            out,
            "typedef {returns} (*{})({});\n",
            named(alias.name),
            parameters(&read)
        );
    }
    Ok(())
}

fn structures(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    for record in surface.records {
        let keyword = match record.shape {
            Shape::Struct => "struct",
            Shape::Union => "union",
        };
        block(out, "", &lines(surface, record.doc));
        let _ = writeln!(out, "{keyword} {} {{", snake(record.name));
        for field in read_all(record.name, record.fields)? {
            block(out, "    ", &lines(surface, field.member.doc));
            let ty = spell(&field.ty);
            if ty.ends_with('*') {
                let _ = writeln!(out, "    {ty}{};", field.member.name);
            } else {
                let _ = writeln!(out, "    {ty} {};", field.member.name);
            }
        }
        out.push_str("};\n\n");
    }
    Ok(())
}

/// Print the header.
pub(crate) fn header(surface: &Surface) -> Result<String, Refused> {
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
         \x20* Every function here returns a sipral_status_t except where its own\n\
         \x20* comment says otherwise, sets the calling thread's last error on\n\
         \x20* failure, and catches any panic rather than letting one reach C. A\n\
         \x20* stack may be used from any thread but only one at a time: a second\n\
         \x20* thread gets SIPRAL_STATUS_BUSY rather than a wait. The event callback\n\
         \x20* runs with nothing held, so the library may be called from inside it.\n\
         \x20* A call's media is reached through a handle of its own, from\n\
         \x20* sipral_call_media, and never waits on the stack.\n\
         \x20*/\n\n",
    );
    out.push_str("#ifndef SIPRAL_H\n#define SIPRAL_H\n\n");
    out.push_str("#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n\n");
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");

    aliases(&mut out, surface)?;
    values(&mut out, surface)?;
    forwards(&mut out, surface);
    enumerations(&mut out, surface)?;
    callbacks(&mut out, surface)?;
    structures(&mut out, surface)?;

    for (function, read) in crate::model::functions(surface)? {
        block(&mut out, "", &lines(surface, function.doc));
        let returns = spell(&Type::read(function.returns)?);
        let space = if returns.ends_with('*') { "" } else { " " };
        let _ = writeln!(
            out,
            "{returns}{space}{}({});\n",
            function.name,
            parameters(&read)
        );
    }

    out.push_str("#ifdef __cplusplus\n} /* extern \"C\" */\n#endif\n\n");
    out.push_str("#endif /* SIPRAL_H */\n");
    Ok(out)
}

/// `SipralStatus` gives `SIPRAL_STATUS`, which every one of its names starts
/// with.
pub(crate) fn screaming_prefix(name: &str) -> String {
    snake(name).to_ascii_uppercase()
}

/// Words C will not take as a name, and the words C++ will not take either.
///
/// Both lists, because the header wraps itself in `extern "C"` for a C++
/// compiler and is included from C++ as often as from C -- a member called
/// `class` or `new` costs nothing in C and costs the C++ half of the
/// consumers everything. C's own reserved spellings (`_Bool` and the rest)
/// are in here too, and the identifiers the standard reserves to the
/// implementation are caught by the rule below rather than by this list,
/// since no list can hold them.
const RESERVED: &[&str] = &[
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_BitInt",
    "_Bool",
    "_Complex",
    "_Decimal128",
    "_Decimal32",
    "_Decimal64",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
    "alignas",
    "alignof",
    "and",
    "and_eq",
    "asm",
    "auto",
    "bitand",
    "bitor",
    "bool",
    "break",
    "case",
    "catch",
    "char",
    "char16_t",
    "char32_t",
    "char8_t",
    "class",
    "co_await",
    "co_return",
    "co_yield",
    "compl",
    "concept",
    "const",
    "const_cast",
    "consteval",
    "constexpr",
    "constinit",
    "continue",
    "decltype",
    "default",
    "delete",
    "do",
    "double",
    "dynamic_cast",
    "else",
    "enum",
    "explicit",
    "export",
    "extern",
    "false",
    "float",
    "for",
    "friend",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "mutable",
    "namespace",
    "new",
    "noexcept",
    "not",
    "not_eq",
    "nullptr",
    "operator",
    "or",
    "or_eq",
    "private",
    "protected",
    "public",
    "register",
    "reinterpret_cast",
    "requires",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "static_cast",
    "struct",
    "switch",
    "template",
    "this",
    "thread_local",
    "throw",
    "true",
    "try",
    "typedef",
    "typeid",
    "typename",
    "typeof",
    "typeof_unqual",
    "union",
    "unsigned",
    "using",
    "virtual",
    "void",
    "volatile",
    "wchar_t",
    "while",
    "xor",
    "xor_eq",
];

/// What C calls what the surface declares.
pub(crate) struct Names;

impl Spelling for Names {
    fn language(&self) -> &'static str {
        "C"
    }

    fn reserved(&self) -> &'static [&'static str] {
        RESERVED
    }

    /// C has no way at all to spell a keyword as a name -- no `@`, no
    /// backticks -- so a keyword here is the end of it. The second half is
    /// §7.1.3: a name that starts with an underscore, or holds two in a row,
    /// belongs to the implementation, and a header that takes one has taken
    /// something that was never its to take.
    fn refuses(&self, place: &str, emitted: &str) -> Option<String> {
        let _ = place;
        if RESERVED.contains(&emitted) {
            return Some(format!("`{emitted}` is a keyword in C or in C++"));
        }
        (emitted.starts_with('_') || emitted.contains("__")).then(|| {
            format!("`{emitted}` is a name C reserves to the implementation (ISO C §7.1.3)")
        })
    }

    fn layout(&self) -> Layout {
        Layout::Flat
    }

    fn types(&self, surface: &Surface) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for alias in surface.aliases {
            out.push((named(alias.name), alias.name.to_owned()));
        }
        for enumeration in surface.enumerations {
            out.push((named(enumeration.name), enumeration.name.to_owned()));
        }
        for record in surface.records {
            out.push((named(record.name), record.name.to_owned()));
        }
        out
    }

    fn members(&self, record: &Record) -> Result<Vec<(String, String)>, Refused> {
        Ok(record
            .fields
            .iter()
            .map(|field| {
                (
                    field.name.to_owned(),
                    format!("{}::{}", record.name, field.name),
                )
            })
            .collect())
    }

    fn code(&self, enumeration: &Enumeration, code: &Code) -> String {
        format!(
            "{}_{}",
            screaming_prefix(enumeration.name),
            screaming(code.name)
        )
    }

    fn constant(&self, value: &Value) -> String {
        value.name.to_owned()
    }

    fn entry(&self, function: &Function) -> String {
        function.name.to_owned()
    }

    fn written_by_hand(&self) -> &'static [(&'static str, &'static str)] {
        // the include guard is a name in the same namespace as everything else
        &[("SIPRAL_H", "the include guard")]
    }

    /// The header prints the callback as a function pointer, and names its
    /// parameters exactly as the declaration spelled them -- the same rule
    /// [`Spelling::inside`] follows for an entry point, through the same
    /// printer.
    fn signature(&self, alias: &Alias, read: &[Read<'_>]) -> Vec<Named> {
        let _ = alias;
        read.iter()
            .map(|parameter| {
                Named::new(
                    "the declaration",
                    parameter.member.name.to_owned(),
                    parameter.member.name,
                )
            })
            .collect()
    }

    fn inside(
        &self,
        surface: &Surface,
        function: &Function,
        read: &[Read<'_>],
        parts: &[Role<'_>],
    ) -> Result<Vec<Named>, Refused> {
        // C prints the parameters as the declaration spelled them and writes
        // no local of its own, so the conventions the roles carry change
        // nothing here
        let _ = (surface, function, parts);
        Ok(read
            .iter()
            .map(|parameter| {
                Named::new(
                    "the declaration",
                    parameter.member.name.to_owned(),
                    parameter.member.name,
                )
            })
            .collect())
    }
}
