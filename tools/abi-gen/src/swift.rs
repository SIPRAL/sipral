// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
    Base, Int, Linked, Read, Refused, Role, Text, Type, Writable, element, elements, functions,
    linked, listed_in, lower_camel, plain_named, record_named, roles, unprintable, upper_camel,
    without_prefix,
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

/// One wrapping closure around the call, for memory that has to stay alive
/// while C reads it.
struct Wrap {
    /// What the closure is handed to, up to its opening brace.
    head: String,
    /// What the call reads the pointer and the count out of, when it reads
    /// them through this closure.
    binding: String,
    /// The name the closure introduces, which is a name in the function's
    /// scope like any other and is claimed as one.
    bound: String,
    /// What has to be set before the call, inside the innermost closure,
    /// where every pointer the call reads is still alive.
    setup: Vec<String>,
}

/// One member of a struct going in, as the argument a list for it is taken
/// in: `config` and `headers` are `configHeaders`.
fn flat(parameter: &Read<'_>, member: &Read<'_>) -> String {
    safe(&lower_camel(&format!(
        "{}_{}",
        parameter.member.name, member.member.name
    )))
}

fn wrapping(surface: &Surface, index: usize, role: &Role<'_>) -> Result<Vec<Wrap>, Refused> {
    let (name, ty, writable) = match role {
        Role::Buffer { data, .. } => (
            held(data),
            data.ty.clone(),
            data.ty.pointer == Some(Writable::Yes),
        ),
        Role::Fill { data, .. } => (held(data), data.ty.clone(), true),
        Role::Records { data, .. } => {
            let element = element(surface, data, "Swift")?;
            let pointer = format!("p{index}");
            return Ok(vec![Wrap {
                head: format!("{}.withUnsafeArray({})", element.record.name, held(data)),
                binding: pointer.clone(),
                bound: pointer,
                setup: Vec::new(),
            }]);
        }
        Role::Config(read) => {
            // the struct is the caller's, and every list it holds is taken
            // beside it and set into it inside the closure, so that the
            // pointer and the count C reads are the list's own and alive
            let config = held(read);
            return Ok(listed_in(surface, read, "Swift")?
                .into_iter()
                .map(|listed| {
                    let pointer = format!("p{index}{}", upper_camel(listed.data.member.name));
                    Wrap {
                        head: format!(
                            "{}.withUnsafeArray({})",
                            listed.element.record.name,
                            flat(read, &listed.data)
                        ),
                        binding: String::new(),
                        setup: vec![
                            format!(
                                "{config}.{} = {pointer}.baseAddress",
                                safe(listed.data.member.name)
                            ),
                            format!(
                                "{config}.{} = {pointer}.count",
                                safe(listed.len.member.name)
                            ),
                        ],
                        bound: pointer,
                    }
                })
                .collect());
        }
        _ => return Ok(Vec::new()),
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
        return Ok(vec![
            Wrap {
                head: format!("Array({name}.utf8).withUnsafeBufferPointer"),
                binding: String::new(),
                bound: format!("raw{index}"),
                setup: Vec::new(),
            },
            Wrap {
                head: format!("raw{index}.withMemoryRebound(to: CChar.self)"),
                binding: pointer.clone(),
                bound: pointer,
                setup: Vec::new(),
            },
        ]);
    }
    Ok(vec![Wrap {
        head: format!("{name}.{method}"),
        binding: pointer.clone(),
        bound: pointer,
        setup: Vec::new(),
    }])
}

fn signature(
    surface: &Surface,
    function: &Function,
    parts: &[Role<'_>],
) -> Result<String, Refused> {
    let mut arguments = Vec::new();
    let mut results = Vec::new();
    for role in parts {
        match role {
            Role::Plain(read) => {
                arguments.push(format!("{}: {}", held(read), scalar(&read.ty)));
            }
            Role::Config(read) => {
                arguments.push(format!("{}: {}", held(read), scalar(&read.ty)));
                for listed in listed_in(surface, read, "Swift")? {
                    arguments.push(format!(
                        "{}: [{}]",
                        flat(read, &listed.data),
                        listed.element.record.name
                    ));
                }
            }
            Role::Records { data, .. } => {
                let element = element(surface, data, "Swift")?;
                arguments.push(format!("{}: [{}]", held(data), element.record.name));
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
            // a C function pointer is a type Swift spells, and the pointer
            // after it is the caller's own: both are handed through as they
            // come, which is what every other language does with a listener
            // installed on a handle the caller already has. Both optional,
            // because a null callback is how C says "turn it off" and a null
            // pointer is what a listener with nothing to carry hands over
            Role::Listener {
                callback,
                user_data,
                ..
            } => {
                for read in [callback, user_data] {
                    arguments.push(format!("{}: {}?", held(read), scalar(&read.ty)));
                }
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
    Ok(format!(
        "    public static func {}({}) throws{returns} {{",
        called(function),
        arguments.join(", ")
    ))
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
            Role::Buffer { .. } | Role::Fill { .. } | Role::Records { .. } => {
                arguments.push(format!("{pointer}.baseAddress"));
                arguments.push(format!("{pointer}.count"));
            }
            Role::Config(read) | Role::Shared(read) => {
                arguments.push(format!("&{}", held(read)));
            }
            Role::Given(read) | Role::Out(read) => {
                arguments.push(format!("&{}", written(read)));
            }
            Role::Listener {
                callback,
                user_data,
                ..
            } => {
                arguments.push(held(callback));
                arguments.push(held(user_data));
            }
        }
    }
    arguments
}

fn body(surface: &Surface, function: &Function, parts: &[Role<'_>]) -> Result<String, Refused> {
    let mut out = String::new();
    out.push_str("        try ensureAbi()\n");
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
        .map(|(index, role)| wrapping(surface, index, role))
        .collect::<Result<_, _>>()?;
    let arguments = call_arguments(parts, &wraps);
    let mut depth = 2;
    let opened: Vec<&Wrap> = wraps.iter().flatten().collect();
    let setup: Vec<&String> = opened.iter().flat_map(|wrap| wrap.setup.iter()).collect();
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
        for (index, wrap) in opened.iter().enumerate() {
            depth += 1;
            // a closure of more than one statement says what it answers
            // with, which is the status, rather than leave a toolchain older
            // than the one that infers it to guess
            let answers = if index + 1 == opened.len() && !setup.is_empty() {
                format!(" -> {}", scalar(&Type::read(function.returns)?))
            } else {
                String::new()
            };
            let _ = writeln!(
                out,
                "{}{} {{ {}{answers} in",
                "    ".repeat(depth),
                wrap.head,
                wrap.bound
            );
        }
        for line in &setup {
            let _ = writeln!(out, "{}{line}", "    ".repeat(depth + 1));
        }
        let _ = writeln!(
            out,
            "{}{}{}({})",
            "    ".repeat(depth + 1),
            if setup.is_empty() { "" } else { "return " },
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
    Ok(out)
}

/// The locals `withUnsafeArray` writes, beside one per piece of text.
const ARRAY_LOCALS: &[(&str, &str)] = &[
    ("list", "the list withUnsafeArray is handed"),
    ("body", "the closure withUnsafeArray is handed"),
    ("run", "the buffer every piece of text is copied into"),
    ("lengths", "the length of each piece of text"),
    ("element", "the element withUnsafeArray is reading"),
    ("bytes", "the buffer, while it has an address"),
    ("array", "the records C reads"),
    ("at", "how far into the buffer withUnsafeArray has pointed"),
    ("part", "which length withUnsafeArray reads next"),
    ("record", "the record withUnsafeArray is filling in"),
    ("Answer", "what withUnsafeArray answers with"),
];

/// The local `withUnsafeArray` holds one piece of text's bytes in.
fn text_bytes(text: &Text) -> String {
    safe(&format!("{}Bytes", lower_camel(text.data.member.name)))
}

/// For each record handed over as the element of an array: a struct a caller
/// builds one from, and `withUnsafeArray`, which makes a list of them into the
/// array C reads for as long as one closure runs.
///
/// Every piece of text is copied into one buffer, and every pointer in the
/// array points into it, so that nothing a caller holds is pointed at and
/// nothing pointed at outlives the closure. The count is the list's own.
fn element_structs(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::new();
    for element in elements(surface, "Swift")? {
        let record = element.record;
        let spelled = c::named(record.name);
        let mut about = lines(surface, record.doc);
        about.push(String::new());
        for line in [
            " Built here and handed to C in a list. `withUnsafeArray` copies every",
            " piece of text in every element into one buffer, points an array of",
        ] {
            about.push(line.to_owned());
        }
        about.push(format!(
            " {spelled} into it and hands that array on for as long as one closure"
        ));
        for line in [
            " runs, with the list's own count. An empty piece of text crosses as a",
            " null pointer with a length of zero, and an empty list as a null",
            " pointer with a count of zero.",
        ] {
            about.push(line.to_owned());
        }
        doc(&mut out, "", &about);
        let _ = writeln!(out, "public struct {}: Sendable {{", record.name);
        for text in &element.texts {
            doc(&mut out, "    ", &lines(surface, text.data.member.doc));
            let _ = writeln!(out, "    public var {}: String", held(&text.data));
        }
        let parameters: Vec<String> = element
            .texts
            .iter()
            .map(|text| format!("{}: String", held(&text.data)))
            .collect();
        let _ = writeln!(out, "\n    public init({}) {{", parameters.join(", "));
        for text in &element.texts {
            let name = held(&text.data);
            let _ = writeln!(out, "        self.{name} = {name}");
        }
        let _ = write!(
            out,
            "    }}\n\n\
             \x20   /// A list of them as the array of {spelled} C reads, for as long as\n\
             \x20   /// `body` runs and no longer: every pointer in it points into a buffer\n\
             \x20   /// that is gone when `body` returns.\n\
             \x20   static func withUnsafeArray<Answer>(_ list: [{name}], _ body: (UnsafeBufferPointer<{spelled}>) throws -> Answer) rethrows -> Answer {{\n\
             \x20       var run: [CChar] = []\n\
             \x20       var lengths: [Int] = []\n\
             \x20       for element in list {{\n",
            name = record.name,
        );
        for text in &element.texts {
            let bytes = text_bytes(text);
            let _ = write!(
                out,
                "            let {bytes} = element.{}.utf8.map {{ CChar(bitPattern: $0) }}\n\
                 \x20           run.append(contentsOf: {bytes})\n\
                 \x20           lengths.append({bytes}.count)\n",
                held(&text.data)
            );
        }
        let _ = write!(
            out,
            "        }}\n\
             \x20       return try run.withUnsafeBufferPointer {{ bytes -> Answer in\n\
             \x20           var array: [{spelled}] = []\n\
             \x20           var at = 0\n\
             \x20           var part = 0\n\
             \x20           for _ in list {{\n\
             \x20               var record = {spelled}()\n"
        );
        for text in &element.texts {
            let _ = write!(
                out,
                "                record.{data} = lengths[part] == 0 ? nil : bytes.baseAddress.map {{ $0 + at }}\n\
                 \x20               record.{len} = lengths[part]\n\
                 \x20               at += lengths[part]\n\
                 \x20               part += 1\n",
                data = safe(text.data.member.name),
                len = safe(text.len.member.name),
            );
        }
        // an empty Swift array may still have a buffer, and C reads a list
        // of none as a null pointer and a count of zero: an entry point that
        // takes no list at all refuses any pointer
        out.push_str(
            "                array.append(record)\n\
             \x20           }\n\
             \x20           if array.isEmpty {\n\
             \x20               return try body(UnsafeBufferPointer(start: nil, count: 0))\n\
             \x20           }\n\
             \x20           return try array.withUnsafeBufferPointer(body)\n\
             \x20       }\n\
             \x20   }\n\
             }\n\n",
        );
    }
    Ok(out)
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
        "    public static func {}({arguments}) throws -> String? {{",
        called(function)
    );
    out.push_str("        try ensureAbi()\n");
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

/// Everything a call reaches before it reaches C: the raw read of the last
/// error, the ABI check `abiMismatch` runs once and `ensureAbi` throws from,
/// and `check`, which turns an ordinary status into a thrown error.
///
/// Split out of [`binding`] only because clippy counts lines for a function
/// that prints a whole file in one breath; nothing here reads differently
/// for being its own function.
fn plumbing(check: &crate::model::LoadCheck<'_>) -> String {
    let constant = |value: &Value| {
        safe(&lower_camel(
            value.name.strip_prefix("SIPRAL_").unwrap_or(value.name),
        ))
    };
    format!(
        "    /// The calling thread's last error, or an empty string when it\n\
         \x20   /// has none. Read the way C reads it: ask for the length, then\n\
         \x20   /// for the bytes.\n\
         \x20   ///\n\
         \x20   /// Not behind `ensureAbi`. This is what a mismatch's own message\n\
         \x20   /// is read with, while `abiMismatch` is still being computed, and\n\
         \x20   /// going through the check to reach it would be this property\n\
         \x20   /// reading itself before it has a value.\n\
         \x20   static func rawLastErrorMessage() -> String {{\n\
         \x20       var needed = 0\n\
         \x20       _ = sipral_last_error_message(nil, 0, &needed)\n\
         \x20       guard needed > 1 else {{ return \"\" }}\n\
         \x20       var buffer = [CChar](repeating: 0, count: needed)\n\
         \x20       let status = buffer.withUnsafeMutableBufferPointer {{\n\
         \x20           sipral_last_error_message($0.baseAddress, $0.count, nil)\n\
         \x20       }}\n\
         \x20       guard status == SIPRAL_STATUS_OK else {{ return \"\" }}\n\
         \x20       return String(cString: buffer)\n\
         \x20   }}\n\n\
         \x20   /// The calling thread's last error, or an empty string when it\n\
         \x20   /// has none.\n\
         \x20   public static func lastErrorMessage() throws -> String {{\n\
         \x20       try ensureAbi()\n\
         \x20       return rawLastErrorMessage()\n\
         \x20   }}\n\n\
         \x20   /// Whether the library this binding loaded can serve the ABI this\n\
         \x20   /// file was printed against, checked once. A static stored\n\
         \x20   /// property's initializer in Swift runs at most once and\n\
         \x20   /// finishes before the first read of it returns, on whichever\n\
         \x20   /// thread reaches it first, which is what makes this safe to\n\
         \x20   /// read from every one of them without a lock of its own.\n\
         \x20   static let abiMismatch: SipralError? = {{\n\
         \x20       let status = {call}({major}, {minor})\n\
         \x20       guard status != SIPRAL_STATUS_OK else {{ return nil }}\n\
         \x20       return SipralError(code: status, message: rawLastErrorMessage())\n\
         \x20   }}()\n\n\
         \x20   /// Throws what `abiMismatch` found, if it found one. Every call\n\
         \x20   /// below reaches this before it reaches C, so a binding loaded\n\
         \x20   /// over the wrong library fails here, in whichever call the\n\
         \x20   /// application happens to make first, rather than in whichever\n\
         \x20   /// one first happens to disagree about a struct's layout.\n\
         \x20   static func ensureAbi() throws {{\n\
         \x20       if let mismatch = abiMismatch {{\n\
         \x20           throw mismatch\n\
         \x20       }}\n\
         \x20   }}\n\n\
         \x20   /// Turn a status into a thrown error, and nothing into nothing.\n\
         \x20   static func check(_ status: sipral_status_t) throws {{\n\
         \x20       guard status != SIPRAL_STATUS_OK else {{ return }}\n\
         \x20       throw SipralError(code: status, message: rawLastErrorMessage())\n\
         \x20   }}\n\n",
        call = check.function.name,
        major = constant(check.major),
        minor = constant(check.minor),
    )
}

/// Print the Swift binding.
pub(crate) fn binding(surface: &Surface) -> Result<String, Refused> {
    audit(surface, &Names)?;
    let mut out = String::new();
    out.push_str(
        "// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial\n\
         // Copyright (c) 2026 Sytek\n\
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
         \x20   /// The number C would have switched on, whether or not this\n\
         \x20   /// binding has a name for it.\n\
         \x20   public let code: Int32\n\
         \x20   /// Its name, or nil for a status a newer library returned that\n\
         \x20   /// this binding was printed too early to know: a failure like\n\
         \x20   /// any other, and not one it may be mistaken for.\n\
         \x20   public let status: SipralStatus?\n\
         \x20   /// The sentence that goes with it.\n\
         \x20   public let message: String\n\n\
         \x20   /// An error with a status this binding names.\n\
         \x20   public init(status: SipralStatus, message: String) {\n\
         \x20       self.init(code: status.rawValue, message: message)\n\
         \x20   }\n\n\
         \x20   /// An error with whatever number the library answered.\n\
         \x20   public init(code: Int32, message: String) {\n\
         \x20       self.code = code\n\
         \x20       self.status = SipralStatus(rawValue: code)\n\
         \x20       self.message = message\n\
         \x20   }\n\n\
         \x20   public var description: String {\n\
         \x20       let name = status.map { \"\\($0)\" } ?? \"status \\(code)\"\n\
         \x20       return message.isEmpty ? name : \"\\(name): \\(message)\"\n\
         \x20   }\n\
         }\n\n",
    );

    out.push_str(&sized(surface));
    out.push_str(&element_structs(surface)?);

    // the call `abiMismatch` makes on this file's own behalf, spelled the way
    // the entry point and the constants below are spelled, from the
    // declarations they are printed from
    let check = crate::model::load_check(surface, "Swift")?;
    out.push_str(
        "/// Everything the library does, with the C conventions read off it.\n\
         ///\n\
         /// Swift gives a namespace `enum` like this one no load hook: there is\n\
         /// no module initializer and nothing else the runtime guarantees to run\n\
         /// before first use, the way a static constructor does for the .NET\n\
         /// binding or an `init` block does for the Kotlin one. What Swift does\n\
         /// guarantee is narrower, and it is enough: a static stored property's\n\
         /// initializer runs at most once, and finishes before the first read of\n\
         /// it returns, on whichever thread reaches it first — the same promise\n\
         /// `dispatch_once` made in Objective-C. `abiMismatch` below is one such\n\
         /// property, and every call in this `enum` reads it, through\n\
         /// `ensureAbi`, before it does anything else. So the check runs the\n\
         /// first time this module is asked to do anything at all, on whichever\n\
         /// thread makes that first call — not at import, which Swift gives no\n\
         /// hook for, but before that first call reaches C, which is the promise\n\
         /// this makes instead.\n\
         ///\n\
         /// Skipping it is not something a caller can do: there is no call here\n\
         /// that reaches C without going through `ensureAbi` first. The `size`\n\
         /// every struct here carries settles how long a struct is, not what is\n\
         /// in it: a header and a library that disagree about the order or the\n\
         /// meaning of members can still agree about the length, and then every\n\
         /// size rule passes while the library reads a pointer out of whatever\n\
         /// was put in its place. No entry point can catch that on its own,\n\
         /// because whether a pointer is readable is the caller's promise, not\n\
         /// something the library can check. This is what finds the\n\
         /// disagreement before anything is read, and a mismatch is what it\n\
         /// throws — a SipralError, from whichever call the application happens\n\
         /// to make first, not a warning that is easy to miss.\n\
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

    out.push_str(&plumbing(&check));

    for line in crate::layout::TABLE_DOC {
        let _ = writeln!(out, "    /// {line}");
    }
    out.push_str(
        "    public static let recordLayouts: [(name: String, imported: Int, p64: Int, p32a4: Int, p32a8: Int)] = [\n",
    );
    for lengths in crate::layout::table(surface)? {
        let [p64, p32a4, p32a8] = lengths.sizes;
        let c_name = lengths.record.c_name();
        let _ = writeln!(
            out,
            "        (\"{c_name}\", MemoryLayout<{c_name}>.size, {p64}, {p32a4}, {p32a8}),"
        );
    }
    out.push_str("    ]\n\n");

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
        let _ = writeln!(out, "{}", signature(surface, function, &parts)?);
        out.push_str(&body(surface, function, &parts)?);
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
            (
                "rawLastErrorMessage",
                "the raw error read this back end writes",
            ),
            (
                "abiMismatch",
                "the ABI check this back end runs once, on first use",
            ),
            ("ensureAbi", "the ABI check this back end writes"),
            ("check", "the status check this back end writes"),
            ("recordLayouts", "the layout table this back end writes"),
        ]
    }

    /// Nothing. The callback is the C target's, imported rather than
    /// printed -- which is what [`Spelling::types`] says about it too -- and
    /// a C function pointer reaches Swift as `@convention(c)` with its
    /// parameter names dropped and its result carried through untouched, an
    /// answering callback's included. So this back end spells none of them,
    /// and [`crate::c::Names`] reads the one spelling there is.
    fn signature(&self, alias: &Alias, read: &[Read<'_>]) -> Vec<Named> {
        let _ = (alias, read);
        Vec::new()
    }

    /// The struct each element of an array going in is built from, its
    /// members and its initialiser's parameters, and the locals of
    /// `withUnsafeArray`.
    fn own(&self, surface: &Surface) -> Result<Vec<(String, Named)>, Refused> {
        let mut out = Vec::new();
        for element in elements(surface, "Swift")? {
            let record = element.record.name;
            out.push((
                "the top of the file".to_owned(),
                Named::new("", record.to_owned(), record),
            ));
            let array = format!("{record}.withUnsafeArray");
            out.push((
                record.to_owned(),
                Named::new(
                    "",
                    "withUnsafeArray".to_owned(),
                    format!("the function this back end gives {record}"),
                ),
            ));
            for (name, what) in ARRAY_LOCALS {
                out.push((
                    array.clone(),
                    Named::new("the wrapper", (*name).to_owned(), *what),
                ));
            }
            for text in &element.texts {
                let from = format!("{record}::{}", text.data.member.name);
                out.push((
                    record.to_owned(),
                    Named::new("", held(&text.data), from.clone()),
                ));
                out.push((
                    format!("{record}.init"),
                    Named::new("the wrapper", held(&text.data), from.clone()),
                ));
                out.push((
                    array.clone(),
                    Named::new("the wrapper", text_bytes(text), from),
                ));
            }
        }
        Ok(out)
    }

    fn inside(
        &self,
        surface: &Surface,
        function: &Function,
        read: &[Read<'_>],
        parts: &[Role<'_>],
    ) -> Result<Vec<Named>, Refused> {
        unprintable(surface, function, read, "Swift")?;
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
                Role::Plain(read) | Role::Shared(read) => {
                    out.push(Named::new(here, held(read), read.member.name));
                }
                Role::Config(read) => {
                    out.push(Named::new(here, held(read), read.member.name));
                    for listed in listed_in(surface, read, "Swift")? {
                        let from = format!("{}::{}", read.member.name, listed.data.member.name);
                        out.push(Named::new(here, flat(read, &listed.data), from));
                    }
                    for wrap in wrapping(surface, index, role)? {
                        out.push(Named::new(here, wrap.bound, read.member.name));
                    }
                }
                Role::Buffer { data, .. }
                | Role::Fill { data, .. }
                | Role::Records { data, .. } => {
                    out.push(Named::new(here, held(data), data.member.name));
                    for wrap in wrapping(surface, index, role)? {
                        out.push(Named::new(here, wrap.bound, data.member.name));
                    }
                }
                Role::Given(read) | Role::Out(read) => {
                    out.push(Named::new(here, written(read), read.member.name));
                }
                Role::Listener {
                    callback,
                    user_data,
                    ..
                } => {
                    for read in [callback, user_data] {
                        out.push(Named::new(here, held(read), read.member.name));
                    }
                }
            }
        }
        Ok(out)
    }
}
