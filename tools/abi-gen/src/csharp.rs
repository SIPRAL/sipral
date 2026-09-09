// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The .NET binding.
//!
//! Two layers, both printed. `NativeMethods` is the ABI as P/Invoke declares
//! it — every pointer written as `in`, `ref`, `out` or an array, so that the
//! package needs no unsafe block and the runtime does the pinning. `Sipral` is
//! the layer above it, where a status becomes an exception, a byte pointer and
//! its length become a `string`, and everything written back becomes what the
//! call returns.

use std::fmt::Write as _;

use sipral_ffi::abi::{Function, Shape, Stands, Surface};

use crate::model::{
    Base, Int, Linked, Read, Refused, Role, Type, Writable, functions, linked, lower_camel,
    plain_named, read_all, roles, upper_camel,
};

/// What a name inside a documentation link is called in C#.
fn spelled(surface: &Surface, path: &str) -> String {
    match linked(surface, path) {
        Some((Linked::Enumeration(name), Some(code))) => format!("{name}.{code}"),
        Some((Linked::Enumeration(name) | Linked::Type(name), None)) => name.to_owned(),
        Some((Linked::Type(name), Some(member))) => {
            format!("{name}.{}", upper_camel(member))
        }
        None => path.to_owned(),
    }
}

/// Documentation with every link in it spelled the C# way.
fn lines(surface: &Surface, doc: &[&str]) -> Vec<String> {
    plain_named(doc, &|path| spelled(surface, path))
}

/// Words C# will not take as a name.
const RESERVED: &[&str] = &[
    "abstract",
    "as",
    "base",
    "bool",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "checked",
    "class",
    "const",
    "continue",
    "decimal",
    "default",
    "delegate",
    "do",
    "double",
    "else",
    "enum",
    "event",
    "explicit",
    "extern",
    "false",
    "finally",
    "fixed",
    "float",
    "for",
    "foreach",
    "goto",
    "if",
    "implicit",
    "in",
    "int",
    "interface",
    "internal",
    "is",
    "lock",
    "long",
    "namespace",
    "new",
    "null",
    "object",
    "operator",
    "out",
    "override",
    "params",
    "private",
    "protected",
    "public",
    "readonly",
    "ref",
    "return",
    "sbyte",
    "sealed",
    "short",
    "sizeof",
    "stackalloc",
    "static",
    "string",
    "struct",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "uint",
    "ulong",
    "unchecked",
    "unsafe",
    "ushort",
    "using",
    "virtual",
    "void",
    "volatile",
    "while",
];

fn safe(name: &str) -> String {
    if RESERVED.contains(&name) {
        format!("@{name}")
    } else {
        name.to_owned()
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn doc(out: &mut String, indent: &str, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    let _ = writeln!(out, "{indent}/// <summary>");
    for line in lines {
        let _ = writeln!(out, "{indent}///{}", escape(line));
    }
    let _ = writeln!(out, "{indent}/// </summary>");
}

/// What C# calls a type that is not behind a pointer.
fn scalar(ty: &Type) -> String {
    match &ty.base {
        Base::Opaque => "IntPtr".to_owned(),
        Base::Char => "sbyte".to_owned(),
        Base::Float(32) => "float".to_owned(),
        Base::Float(_) => "double".to_owned(),
        Base::Int(Int { bits: 0, signed }) => if *signed { "nint" } else { "nuint" }.to_owned(),
        Base::Int(Int { bits, signed }) => match (bits, signed) {
            (8, false) => "byte".to_owned(),
            (8, true) => "sbyte".to_owned(),
            (16, false) => "ushort".to_owned(),
            (16, true) => "short".to_owned(),
            (32, false) => "uint".to_owned(),
            (32, true) => "int".to_owned(),
            (64, false) => "ulong".to_owned(),
            _ => "long".to_owned(),
        },
        Base::Named(name) if name == "SipralHandle" => "ulong".to_owned(),
        Base::Named(name) if name == "SipralEventCallback" => "IntPtr".to_owned(),
        Base::Named(name) => name.clone(),
    }
}

/// What a struct member is, which is the same except that a pointer inside a
/// struct has nowhere to be `ref`.
fn member(ty: &Type) -> String {
    if ty.pointer.is_some() {
        return "IntPtr".to_owned();
    }
    scalar(ty)
}

/// The name a value coming back takes.
fn returned(name: &str) -> String {
    lower_camel(name.strip_prefix("out_").unwrap_or(name))
}

/// How the declaration hands one parameter over to P/Invoke.
fn declared(role: &Role<'_>) -> Vec<String> {
    match role {
        Role::Plain(read) => vec![format!(
            "{} {}",
            scalar(&read.ty),
            safe(&lower_camel(read.member.name))
        )],
        Role::Buffer { data, len } => vec![
            format!(
                "{}[] {}",
                scalar(&data.ty),
                safe(&lower_camel(data.member.name))
            ),
            format!("nuint {}", safe(&lower_camel(len.member.name))),
        ],
        Role::Fill { data, capacity } => vec![
            format!(
                "{}[] {}",
                scalar(&data.ty),
                safe(&lower_camel(data.member.name))
            ),
            format!("nuint {}", safe(&lower_camel(capacity.member.name))),
        ],
        Role::Config(read) => vec![format!(
            "in {} {}",
            scalar(&read.ty),
            safe(&lower_camel(read.member.name))
        )],
        Role::Shared(read) | Role::Given(read) => vec![format!(
            "ref {} {}",
            scalar(&read.ty),
            safe(&lower_camel(read.member.name))
        )],
        Role::Out(read) => vec![format!(
            "out {} {}",
            scalar(&read.ty),
            safe(&returned(read.member.name))
        )],
    }
}

fn returns_of(function: &Function) -> Result<String, Refused> {
    let ty = Type::read(function.returns)?;
    Ok(match (&ty.pointer, &ty.base) {
        (Some(_), Base::Char) => "IntPtr".to_owned(),
        _ => scalar(&ty),
    })
}

fn native(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::new();
    out.push_str(
        "/// <summary>\n\
         /// The ABI as the runtime calls it. Every pointer is written as an\n\
         /// array or as in, ref or out, so nothing here needs an unsafe block\n\
         /// and the runtime pins what it passes.\n\
         /// </summary>\n\
         internal static class NativeMethods\n{\n\
         \x20   /// <summary>What the native library is called, before the\n\
         \x20   /// platform puts its own prefix and suffix on it.</summary>\n\
         \x20   internal const string Library = \"sipral\";\n\n",
    );
    for (function, read) in functions(surface)? {
        let parts = roles(surface, &read);
        let arguments: Vec<String> = parts.iter().flat_map(declared).collect();
        let _ = writeln!(
            out,
            "    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, \
             ExactSpelling = true)]"
        );
        let _ = writeln!(
            out,
            "    internal static extern {} {}({});\n",
            returns_of(function)?,
            function.name,
            arguments.join(", ")
        );
    }
    out.push_str("}\n\n");
    Ok(out)
}

/// A call that answers with a static string rather than a status, which is
/// the one shape that has nothing to check and nothing to write back.
fn naming(function: &Function, read: &[Read<'_>]) -> String {
    let mut out = String::new();
    let name = upper_camel(
        function
            .name
            .strip_prefix("sipral_")
            .unwrap_or(function.name),
    );
    let arguments: Vec<String> = read
        .iter()
        .map(|parameter| {
            format!(
                "{} {}",
                scalar(&parameter.ty),
                safe(&lower_camel(parameter.member.name))
            )
        })
        .collect();
    let passed: Vec<String> = read
        .iter()
        .map(|parameter| safe(&lower_camel(parameter.member.name)))
        .collect();
    let _ = writeln!(
        out,
        "    public static string? {name}({}) =>",
        arguments.join(", ")
    );
    let _ = writeln!(
        out,
        "        Marshal.PtrToStringUTF8(NativeMethods.{}({}));\n",
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

fn hand_over(parts: &[Role<'_>]) -> Handover {
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
                let held = safe(&lower_camel(read.member.name));
                arguments.push(format!("{} {held}", scalar(&read.ty)));
                passed.push(held);
            }
            Role::Buffer { data, .. } => {
                let held = safe(&lower_camel(data.member.name));
                if data.ty.base == Base::Char && data.ty.pointer == Some(Writable::No) {
                    arguments.push(format!("string {held}"));
                    let _ = writeln!(
                        prologue,
                        "        var {held}Bytes = Encoding.UTF8.GetBytes({held});"
                    );
                    let _ = writeln!(
                        prologue,
                        "        var {held}Signed = new sbyte[{held}Bytes.Length];"
                    );
                    let _ = writeln!(
                        prologue,
                        "        Buffer.BlockCopy({held}Bytes, 0, {held}Signed, 0, \
                         {held}Bytes.Length);"
                    );
                    passed.push(format!("{held}Signed"));
                    passed.push(format!("(nuint){held}Signed.Length"));
                } else {
                    arguments.push(format!("{}[] {held}", scalar(&data.ty)));
                    passed.push(held.clone());
                    passed.push(format!("(nuint){held}.Length"));
                }
            }
            Role::Fill { data, .. } => {
                let held = safe(&lower_camel(data.member.name));
                arguments.push(format!("{}[] {held}", scalar(&data.ty)));
                passed.push(held.clone());
                passed.push(format!("(nuint){held}.Length"));
            }
            Role::Config(read) => {
                let held = safe(&lower_camel(read.member.name));
                arguments.push(format!("in {} {held}", scalar(&read.ty)));
                passed.push(format!("in {held}"));
            }
            Role::Shared(read) => {
                let held = safe(&lower_camel(read.member.name));
                arguments.push(format!("ref {} {held}", scalar(&read.ty)));
                passed.push(format!("ref {held}"));
            }
            Role::Given(read) => {
                let held = returned(read.member.name);
                let _ = writeln!(
                    prologue,
                    "        var {held} = {}.Sized();",
                    scalar(&read.ty)
                );
                passed.push(format!("ref {held}"));
                results.push((held, scalar(&read.ty)));
            }
            Role::Out(read) => {
                let held = safe(&returned(read.member.name));
                passed.push(format!("out var {held}"));
                results.push((held, scalar(&read.ty)));
            }
        }
    }
    out
}

fn wrapper(surface: &Surface, function: &Function, read: &[Read<'_>]) -> Result<String, Refused> {
    let ty = Type::read(function.returns)?;
    if ty.pointer.is_some() && ty.base == Base::Char {
        return Ok(naming(function, read));
    }
    let mut out = String::new();
    let name = upper_camel(
        function
            .name
            .strip_prefix("sipral_")
            .unwrap_or(function.name),
    );
    let Handover {
        arguments,
        passed,
        prologue,
        results,
    } = hand_over(&roles(surface, read));
    let returns = match results.len() {
        0 => "void".to_owned(),
        1 => results
            .first()
            .map_or_else(|| "void".to_owned(), |(_, ty)| ty.clone()),
        _ => format!(
            "({})",
            results
                .iter()
                .map(|(held, ty)| format!("{ty} {}", upper_camel(held)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let _ = writeln!(
        out,
        "    public static {returns} {name}({})\n    {{",
        arguments.join(", ")
    );
    out.push_str(&prologue);
    let _ = writeln!(
        out,
        "        Check(NativeMethods.{}({}));",
        function.name,
        passed.join(", ")
    );
    match results.len() {
        0 => {}
        1 => {
            if let Some((held, _)) = results.first() {
                let _ = writeln!(out, "        return {held};");
            }
        }
        _ => {
            let inner = results
                .iter()
                .map(|(held, _)| held.clone())
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "        return ({inner});");
        }
    }
    out.push_str("    }\n\n");
    Ok(out)
}

/// The enumerations, the callback delegate and the structs, in that order,
/// because a struct member may be an enumeration and C# reads a file in one
/// pass no more than C does.
fn declarations(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::new();
    for enumeration in surface.enumerations {
        let mut about = lines(surface, enumeration.doc);
        if !enumeration.reserved.is_empty() {
            about.push(" Numbers already spent on features this build does not have:".to_owned());
            for held in enumeration.reserved {
                about.push(format!(" - {}: {}", held.value, held.feature));
            }
        }
        doc(&mut out, "", &about);
        let width = scalar(&Type::read(enumeration.width)?);
        let _ = writeln!(out, "public enum {} : {width}\n{{", enumeration.name);
        for code in enumeration.codes {
            doc(&mut out, "    ", &lines(surface, code.doc));
            let _ = writeln!(out, "    {} = {},", code.name, code.value);
        }
        out.push_str("}\n\n");
    }

    for alias in surface.aliases {
        let Stands::Callback(arguments) = alias.stands else {
            continue;
        };
        let mut about = lines(surface, alias.doc);
        about.push(String::new());
        about
            .push(" Hand it over as a function pointer: keep the delegate alive for as".to_owned());
        about.push(
            " long as the stack is, and pass Marshal.GetFunctionPointerForDelegate.".to_owned(),
        );
        doc(&mut out, "", &about);
        out.push_str("[UnmanagedFunctionPointer(CallingConvention.Cdecl)]\n");
        let read = read_all(alias.name, arguments)?;
        let declared: Vec<String> = read
            .iter()
            .map(|parameter| format!("IntPtr {}", safe(&lower_camel(parameter.member.name))))
            .collect();
        let _ = writeln!(
            out,
            "public delegate void {}({});\n",
            alias.name,
            declared.join(", ")
        );
    }

    for record in surface.records {
        doc(&mut out, "", &lines(surface, record.doc));
        let layout = match record.shape {
            Shape::Struct => "LayoutKind.Sequential",
            Shape::Union => "LayoutKind.Explicit",
        };
        let _ = writeln!(out, "[StructLayout({layout})]");
        let _ = writeln!(out, "public struct {}\n{{", record.name);
        for field in read_all(record.name, record.fields)? {
            doc(&mut out, "    ", &lines(surface, field.member.doc));
            if record.shape == Shape::Union {
                out.push_str("    [FieldOffset(0)]\n");
            }
            let _ = writeln!(
                out,
                "    public {} {};",
                member(&field.ty),
                upper_camel(field.member.name)
            );
        }
        if record.is_versioned() {
            out.push_str(
                "\n    /// <summary>A zeroed one with its size filled in, which is\n\
                 \x20   /// what every struct here has to be handed over as.</summary>\n",
            );
            let _ = writeln!(out, "    public static {} Sized()\n    {{", record.name);
            let _ = writeln!(out, "        var value = default({});", record.name);
            let _ = writeln!(
                out,
                "        value.Size = (nuint)Marshal.SizeOf<{}>();",
                record.name
            );
            out.push_str("        return value;\n    }\n");
        }
        out.push_str("}\n\n");
    }

    Ok(out)
}

/// Print the .NET binding.
pub(crate) fn binding(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::new();
    out.push_str(
        "// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial\n\
         // Copyright (c) 2026 Tiberiu Balasea\n\
         //\n\
         // Printed from the declarations in crates/sipral-ffi by tools/abi-gen.\n\
         // Do not edit: `cargo run -p sipral-abi-gen` writes it again, and\n\
         // `scripts/check.sh` fails when what is committed is not what came out.\n\n\
         using System;\n\
         using System.Runtime.InteropServices;\n\
         using System.Text;\n\n\
         namespace Sipral;\n\n",
    );

    out.push_str(&declarations(surface)?);

    out.push_str(
        "/// <summary>What a call across the boundary answered, when it did not\n\
         /// answer Ok. The message is the calling thread's last error, read\n\
         /// before anything else on this thread could replace it.</summary>\n\
         public sealed class SipralException : Exception\n{\n\
         \x20   internal SipralException(SipralStatus status, string message)\n\
         \x20       : base(message.Length == 0 ? status.ToString() : $\"{status}: {message}\")\n\
         \x20   {\n\
         \x20       Status = status;\n\
         \x20   }\n\n\
         \x20   /// <summary>The code C would have switched on.</summary>\n\
         \x20   public SipralStatus Status { get; }\n\
         }\n\n",
    );

    out.push_str(&native(surface)?);

    out.push_str(
        "/// <summary>Everything the library does, with the C conventions read\n\
         /// off it.</summary>\n\
         public static class Sipral\n{\n",
    );

    for group in surface.constants {
        for value in *group {
            doc(&mut out, "    ", &lines(surface, value.doc));
            let ty = scalar(&Type::read(value.rust_type)?);
            let name = upper_camel(value.name.strip_prefix("SIPRAL_").unwrap_or(value.name));
            let keyword = if ty == "nuint" || ty == "nint" {
                "static readonly"
            } else {
                "const"
            };
            let _ = writeln!(out, "    public {keyword} {ty} {name} = {};\n", value.value);
        }
    }

    out.push_str(
        "    /// <summary>The calling thread's last error, or an empty string\n\
         \x20   /// when it has none. Read the way C reads it: ask for the\n\
         \x20   /// length, then for the bytes.</summary>\n\
         \x20   public static string LastErrorMessage()\n\
         \x20   {\n\
         \x20       NativeMethods.sipral_last_error_message(Array.Empty<sbyte>(), 0, out var needed);\n\
         \x20       if (needed <= 1)\n\
         \x20       {\n\
         \x20           return string.Empty;\n\
         \x20       }\n\n\
         \x20       var buffer = new sbyte[(int)needed];\n\
         \x20       var status = NativeMethods.sipral_last_error_message(buffer, needed, out _);\n\
         \x20       if (status != SipralStatus.Ok)\n\
         \x20       {\n\
         \x20           return string.Empty;\n\
         \x20       }\n\n\
         \x20       var bytes = new byte[buffer.Length];\n\
         \x20       Buffer.BlockCopy(buffer, 0, bytes, 0, buffer.Length);\n\
         \x20       var end = Array.IndexOf(bytes, (byte)0);\n\
         \x20       return Encoding.UTF8.GetString(bytes, 0, end < 0 ? bytes.Length : end);\n\
         \x20   }\n\n\
         \x20   /// <summary>Turn a status into an exception, and nothing into\n\
         \x20   /// nothing.</summary>\n\
         \x20   internal static void Check(SipralStatus status)\n\
         \x20   {\n\
         \x20       if (status == SipralStatus.Ok)\n\
         \x20       {\n\
         \x20           return;\n\
         \x20       }\n\n\
         \x20       throw new SipralException(status, LastErrorMessage());\n\
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
