// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The Swift binding, over the C target the header is the interface of.
//!
//! Swift calls C directly, so nothing here is a shim: it is the C surface with
//! the ABI's own conventions read off it. A status becomes a thrown error with
//! the last message in it, a pointer and a length become a `String` or an
//! array, a buffer the caller brings becomes an `inout` array, and a struct the
//! library fills in whole becomes what the call returns.

use std::fmt::Write as _;

use sipral_ffi::abi::{Alias, Code, Enumeration, Function, Record, Stands, Surface, Value};

use crate::c;
use crate::model::{
    Base, Int, Linked, Read, Refused, Role, Type, Writable, functions, linked, lower_camel,
    plain_named, record_named, roles, without_prefix,
};
use crate::names::{Layout, Named, Spelling, audit};

/// What a name inside a documentation link is called in Swift.
fn spelled(surface: &Surface, path: &str) -> String {
    match linked(surface, path) {
        Some((Linked::Enumeration(name), Some(code))) => {
            format!("{name}.{}", lower_camel(code))
        }
        Some((Linked::Enumeration(name), None)) => name.to_owned(),
        Some((Linked::Type(name), member)) => match member {
            Some(field) => format!("{}.{field}", c::named(name)),
            None if name == "SipralHandle" => name.to_owned(),
            None => c::named(name),
        },
        None => path.to_owned(),
    }
}

/// Documentation with every link in it spelled the Swift way.
fn lines(surface: &Surface, doc: &[&str]) -> Vec<String> {
    plain_named(doc, &|path| spelled(surface, path))
}

/// Words Swift will not take as a name.
const RESERVED: &[&str] = &[
    "as",
    "any",
    "associatedtype",
    "break",
    "case",
    "catch",
    "class",
    "continue",
    "default",
    "defer",
    "deinit",
    "do",
    "else",
    "enum",
    "extension",
    "fallthrough",
    "false",
    "for",
    "func",
    "guard",
    "if",
    "import",
    "in",
    "init",
    "inout",
    "internal",
    "is",
    "let",
    "nil",
    "operator",
    "private",
    "protocol",
    "public",
    "repeat",
    "return",
    "self",
    "some",
    "static",
    "struct",
    "subscript",
    "super",
    "switch",
    "throw",
    "throws",
    "true",
    "try",
    "typealias",
    "var",
    "where",
    "while",
];

fn safe(name: &str) -> String {
    if RESERVED.contains(&name) {
        format!("`{name}`")
    } else {
        name.to_owned()
    }
}

fn doc(out: &mut String, indent: &str, lines: &[String]) {
    for line in lines {
        if line.is_empty() {
            let _ = writeln!(out, "{indent}///");
        } else {
            let _ = writeln!(out, "{indent}///{line}");
        }
    }
}

/// What Swift calls a type that is not behind a pointer.
fn scalar(ty: &Type) -> String {
    match &ty.base {
        Base::Opaque => "UnsafeMutableRawPointer".to_owned(),
        Base::Char => "CChar".to_owned(),
        Base::Float(32) => "Float".to_owned(),
        Base::Float(_) => "Double".to_owned(),
        Base::Int(Int { bits: 0, .. }) => "Int".to_owned(),
        Base::Int(Int { bits, signed }) => {
            let sign = if *signed { "Int" } else { "UInt" };
            format!("{sign}{bits}")
        }
        Base::Named(name) if name == "SipralHandle" => "SipralHandle".to_owned(),
        Base::Named(name) => c::named(name),
    }
}

/// A value of the type, with nothing in it, for an out parameter to be
/// written over.
fn empty(surface: &Surface, ty: &Type) -> String {
    if let Base::Named(name) = &ty.base
        && record_named(surface, name).is_some()
    {
        return format!("{}.sized()", c::named(name));
    }
    format!("{}()", scalar(ty))
}

/// The label a returned out parameter takes.
fn returned(name: &str) -> String {
    lower_camel(name.strip_prefix("out_").unwrap_or(name))
}

/// The one spelling of a parameter's name, used everywhere it is spelled.
fn held(read: &Read<'_>) -> String {
    safe(&lower_camel(read.member.name))
}

/// The one spelling of the name a value written back takes.
fn written(read: &Read<'_>) -> String {
    safe(&returned(read.member.name))
}

/// The one spelling of what an entry point is called here.
fn called(function: &Function) -> String {
    safe(&without_prefix(function.name))
}

/// One wrapping closure around the call, for a buffer that has to stay alive
/// while C reads it.
struct Wrap {
    opening: String,
    binding: String,
    /// The name the closure introduces, which is a name in the function's
    /// scope like any other and is claimed as one.
    bound: String,
}

fn wrapping(index: usize, role: &Role<'_>) -> Vec<Wrap> {
    let (name, ty, writable) = match role {
        Role::Buffer { data, .. } => (
            held(data),
            data.ty.clone(),
            data.ty.pointer == Some(Writable::Yes),
        ),
        Role::Fill { data, .. } => (held(data), data.ty.clone(), true),
        _ => return Vec::new(),
    };
    let pointer = format!("p{index}");
    let method = if writable {
        "withUnsafeMutableBufferPointer"
    } else {
        "withUnsafeBufferPointer"
    };
    if ty.base == Base::Char && !writable {
        // a String has to become bytes before it has an address, and those
        // bytes are unsigned where C's are not
        return vec![
            Wrap {
                opening: format!("Array({name}.utf8).withUnsafeBufferPointer {{ raw{index} in"),
                binding: String::new(),
                bound: format!("raw{index}"),
            },
            Wrap {
                opening: format!("raw{index}.withMemoryRebound(to: CChar.self) {{ {pointer} in"),
                binding: pointer.clone(),
                bound: pointer,
            },
        ];
    }
    vec![Wrap {
        opening: format!("{name}.{method} {{ {pointer} in"),
        binding: pointer.clone(),
        bound: pointer,
    }]
}

fn signature(function: &Function, parts: &[Role<'_>]) -> String {
    let mut arguments = Vec::new();
    let mut results = Vec::new();
    for role in parts {
        match role {
            Role::Plain(read) | Role::Config(read) => {
                arguments.push(format!("{}: {}", held(read), scalar(&read.ty)));
            }
            Role::Buffer { data, .. } => {
                let name = held(data);
                let element = scalar(&data.ty);
                let held = match (&data.ty.base, data.ty.pointer) {
                    (Base::Char, Some(Writable::No)) => "String".to_owned(),
                    (_, Some(Writable::Yes)) => format!("inout [{element}]"),
                    _ => format!("[{element}]"),
                };
                arguments.push(format!("{name}: {held}"));
            }
            Role::Fill { data, .. } => {
                arguments.push(format!("{}: inout [{}]", held(data), scalar(&data.ty)));
            }
            Role::Shared(read) => {
                arguments.push(format!("{}: inout {}", held(read), scalar(&read.ty)));
            }
            Role::Given(read) | Role::Out(read) => {
                results.push((written(read), scalar(&read.ty)));
            }
        }
    }
    let returns = match results.len() {
        0 => String::new(),
        1 => results
            .first()
            .map(|(_, ty)| format!(" -> {ty}"))
            .unwrap_or_default(),
        _ => {
            let inner = results
                .iter()
                .map(|(name, ty)| format!("{name}: {ty}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(" -> ({inner})")
        }
    };
    format!(
        "    public static func {}({}) throws{returns} {{",
        called(function),
        arguments.join(", ")
    )
}

fn call_arguments(parts: &[Role<'_>], wraps: &[Vec<Wrap>]) -> Vec<String> {
    let mut arguments = Vec::new();
    for (index, role) in parts.iter().enumerate() {
        let pointer = wraps
            .get(index)
            .and_then(|group| group.last())
            .map(|wrap| wrap.binding.clone())
            .unwrap_or_default();
        match role {
            Role::Plain(read) => arguments.push(held(read)),
            Role::Buffer { .. } | Role::Fill { .. } => {
                arguments.push(format!("{pointer}.baseAddress"));
                arguments.push(format!("{pointer}.count"));
            }
            Role::Config(read) | Role::Shared(read) => {
                arguments.push(format!("&{}", held(read)));
            }
            Role::Given(read) | Role::Out(read) => {
                arguments.push(format!("&{}", written(read)));
            }
        }
    }
    arguments
}

fn body(surface: &Surface, function: &Function, parts: &[Role<'_>]) -> String {
    let mut out = String::new();
    for role in parts {
        match role {
            Role::Config(read) => {
                let name = held(read);
                let _ = writeln!(out, "        var {name} = {name}");
            }
            Role::Given(read) | Role::Out(read) => {
                let _ = writeln!(
                    out,
                    "        var {} = {}",
                    written(read),
                    empty(surface, &read.ty)
                );
            }
            _ => {}
        }
    }
    let wraps: Vec<Vec<Wrap>> = parts
        .iter()
        .enumerate()
        .map(|(index, role)| wrapping(index, role))
        .collect();
    let arguments = call_arguments(parts, &wraps);
    let mut depth = 2;
    let opened: Vec<&Wrap> = wraps.iter().flatten().collect();
    if opened.is_empty() {
        let _ = writeln!(
            out,
            "{}let status = {}({})",
            "    ".repeat(depth),
            function.name,
            arguments.join(", ")
        );
    } else {
        let _ = writeln!(out, "{}let status =", "    ".repeat(depth));
        for wrap in &opened {
            depth += 1;
            let _ = writeln!(out, "{}{}", "    ".repeat(depth), wrap.opening);
        }
        let _ = writeln!(
            out,
            "{}{}({})",
            "    ".repeat(depth + 1),
            function.name,
            arguments.join(", ")
        );
        for _ in &opened {
            let _ = writeln!(out, "{}}}", "    ".repeat(depth));
            depth -= 1;
        }
    }
    out.push_str("        try check(status)\n");
    let results: Vec<String> = parts
        .iter()
        .filter_map(|role| match role {
            Role::Given(read) | Role::Out(read) => Some(written(read)),
            _ => None,
        })
        .collect();
    match results.len() {
        0 => {}
        1 => {
            let _ = writeln!(out, "        return {}", results.join(""));
        }
        _ => {
            let inner = results
                .iter()
                .map(|name| format!("{name}: {name}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "        return ({inner})");
        }
    }
    out
}

/// A call that answers with a static string rather than a status.
fn naming(function: &Function, read: &[Read<'_>]) -> String {
    let arguments = read
        .iter()
        .map(|parameter| format!("{}: {}", held(parameter), scalar(&parameter.ty)))
        .collect::<Vec<_>>()
        .join(", ");
    let passed = read.iter().map(held).collect::<Vec<_>>().join(", ");
    let mut out = String::new();
    let _ = writeln!(
        out,
        "    public static func {}({arguments}) -> String? {{",
        called(function)
    );
    let _ = writeln!(
        out,
        "        guard let text = {}({passed}) else {{ return nil }}",
        function.name
    );
    out.push_str("        return String(cString: text)\n    }\n");
    out
}

/// The names, then the enumerations. A Swift enumeration carries the width
/// its `repr` fixed, so a value that arrives outside it is `nil` rather than
/// a case that was never declared.
fn names(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::new();
    for alias in surface.aliases {
        let Stands::For(_) = alias.stands else {
            continue;
        };
        doc(&mut out, "", &lines(surface, alias.doc));
        let _ = writeln!(
            out,
            "public typealias {} = {}\n",
            alias.name,
            c::named(alias.name)
        );
    }

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
        let width = scalar(&Type::read(enumeration.width)?);
        let _ = writeln!(
            out,
            "public enum {}: {width}, Sendable {{",
            enumeration.name
        );
        for code in enumeration.codes {
            doc(&mut out, "    ", &lines(surface, code.doc));
            let _ = writeln!(
                out,
                "    case {} = {}",
                safe(&lower_camel(code.name)),
                code.value
            );
        }
        out.push_str("}\n\n");
    }

    Ok(out)
}

/// One initialiser per versioned struct, because the size member is what
/// makes handing one over safe and no caller should have to remember it.
fn sized(surface: &Surface) -> String {
    let mut out = String::new();
    for record in surface.records {
        if !record.is_versioned() {
            continue;
        }
        let name = c::named(record.name);
        let _ = writeln!(out, "public extension {name} {{");
        out.push_str(
            "    /// A zeroed one with its size filled in, which is what every\n\
             \x20   /// struct here has to be handed over as.\n",
        );
        let _ = writeln!(out, "    static func sized() -> Self {{");
        out.push_str("        var value = Self()\n");
        out.push_str("        value.size = MemoryLayout<Self>.size\n");
        out.push_str("        return value\n    }\n}\n\n");
    }

    out
}

/// Print the Swift binding.
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
         import CSipral\n\n",
    );

    out.push_str(&names(surface)?);

    out.push_str(
        "/// What a call across the boundary answered, when it did not answer\n\
         /// `ok`. The message is the calling thread's last error, read before\n\
         /// anything else on this thread could replace it.\n\
         public struct SipralError: Error, CustomStringConvertible, Sendable {\n\
         \x20   /// The code C would have switched on.\n\
         \x20   public let status: SipralStatus\n\
         \x20   /// The sentence that goes with it.\n\
         \x20   public let message: String\n\n\
         \x20   public var description: String {\n\
         \x20       message.isEmpty ? \"\\(status)\" : \"\\(status): \\(message)\"\n\
         \x20   }\n\
         }\n\n",
    );

    out.push_str(&sized(surface));

    out.push_str(
        "/// Everything the library does, with the C conventions read off it.\n\
         public enum Sipral {\n",
    );

    for group in surface.constants {
        for value in *group {
            doc(&mut out, "    ", &lines(surface, value.doc));
            let ty = scalar(&Type::read(value.rust_type)?);
            let name = safe(&lower_camel(
                value.name.strip_prefix("SIPRAL_").unwrap_or(value.name),
            ));
            let _ = writeln!(
                out,
                "    public static let {name}: {ty} = {}\n",
                value.value
            );
        }
    }

    out.push_str(
        "    /// The calling thread's last error, or an empty string when it\n\
         \x20   /// has none. Read the way C reads it: ask for the length, then\n\
         \x20   /// for the bytes.\n\
         \x20   public static func lastErrorMessage() -> String {\n\
         \x20       var needed = 0\n\
         \x20       _ = sipral_last_error_message(nil, 0, &needed)\n\
         \x20       guard needed > 1 else { return \"\" }\n\
         \x20       var buffer = [CChar](repeating: 0, count: needed)\n\
         \x20       let status = buffer.withUnsafeMutableBufferPointer {\n\
         \x20           sipral_last_error_message($0.baseAddress, $0.count, nil)\n\
         \x20       }\n\
         \x20       guard status == SIPRAL_STATUS_OK else { return \"\" }\n\
         \x20       return String(cString: buffer)\n\
         \x20   }\n\n\
         \x20   /// Turn a status into a thrown error, and nothing into nothing.\n\
         \x20   static func check(_ status: sipral_status_t) throws {\n\
         \x20       guard status != SIPRAL_STATUS_OK else { return }\n\
         \x20       throw SipralError(\n\
         \x20           status: SipralStatus(rawValue: status) ?? .panic,\n\
         \x20           message: lastErrorMessage()\n\
         \x20       )\n\
         \x20   }\n\n",
    );

    for (function, read) in functions(surface)? {
        if function.name == "sipral_last_error_message" {
            continue;
        }
        doc(&mut out, "    ", &lines(surface, function.doc));
        // through Type::read, like the other three back ends: a declaration
        // that spells the same type differently -- `*const i8`, or a space
        // where this one had none -- is the same type, and a string compare
        // against one spelling of it silently prints the wrong shape
        let returns = Type::read(function.returns)?;
        if returns.pointer.is_some() && returns.base == Base::Char {
            out.push_str(&naming(function, &read));
            out.push('\n');
            continue;
        }
        let parts = roles(surface, &read);
        let _ = writeln!(out, "{}", signature(function, &parts));
        out.push_str(&body(surface, function, &parts));
        out.push_str("    }\n\n");
    }

    out.push_str("}\n");
    Ok(out)
}

/// What Swift calls what the surface declares.
pub(crate) struct Names;

impl Spelling for Names {
    fn language(&self) -> &'static str {
        "Swift"
    }

    fn reserved(&self) -> &'static [&'static str] {
        RESERVED
    }

    fn layout(&self) -> Layout {
        Layout::Nested
    }

    fn types(&self, surface: &Surface) -> Vec<(String, String)> {
        // the records and the callback are the C target's, imported rather
        // than printed; what this back end names for itself is the
        // typealiases, the enumerations, the error and the container
        let mut out = vec![
            ("SipralError".to_owned(), "this back end".to_owned()),
            ("Sipral".to_owned(), "this back end".to_owned()),
        ];
        for alias in surface.aliases {
            if matches!(alias.stands, Stands::For(_)) {
                out.push((alias.name.to_owned(), alias.name.to_owned()));
            }
        }
        for enumeration in surface.enumerations {
            out.push((enumeration.name.to_owned(), enumeration.name.to_owned()));
        }
        out
    }

    fn members(&self, record: &Record) -> Result<Vec<(String, String)>, Refused> {
        // a record's members are C's, spelled as C spells them; the one name
        // this back end adds to a record is the initialiser
        Ok(if record.is_versioned() {
            vec![(
                "sized".to_owned(),
                format!("the initialiser this back end gives {}", record.name),
            )]
        } else {
            Vec::new()
        })
    }

    fn code(&self, enumeration: &Enumeration, code: &Code) -> String {
        let _ = enumeration;
        safe(&lower_camel(code.name))
    }

    fn constant(&self, value: &Value) -> String {
        safe(&lower_camel(
            value.name.strip_prefix("SIPRAL_").unwrap_or(value.name),
        ))
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

    /// Nothing. The callback is the C target's, imported rather than
    /// printed -- which is what [`Spelling::types`] says about it too -- and
    /// a C function pointer reaches Swift as `@convention(c)` with its
    /// parameter names dropped. So this back end spells none of them, and
    /// [`crate::c::Names`] reads the one spelling there is.
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
        let _ = surface;
        let here = "the wrapper";
        let ty = Type::read(function.returns)?;
        if ty.pointer.is_some() && ty.base == Base::Char {
            let mut out: Vec<Named> = read
                .iter()
                .map(|parameter| Named::new(here, held(parameter), parameter.member.name))
                .collect();
            out.push(Named::new(
                here,
                "text".to_owned(),
                "the string this back end reads back",
            ));
            return Ok(out);
        }
        let mut out = vec![Named::new(
            here,
            "status".to_owned(),
            "the status this back end holds on to",
        )];
        for (index, role) in parts.iter().enumerate() {
            match role {
                Role::Plain(read) | Role::Config(read) | Role::Shared(read) => {
                    out.push(Named::new(here, held(read), read.member.name));
                }
                Role::Buffer { data, .. } | Role::Fill { data, .. } => {
                    out.push(Named::new(here, held(data), data.member.name));
                    for wrap in wrapping(index, role) {
                        out.push(Named::new(here, wrap.bound, data.member.name));
                    }
                }
                Role::Given(read) | Role::Out(read) => {
                    out.push(Named::new(here, written(read), read.member.name));
                }
            }
        }
        Ok(out)
    }
}
