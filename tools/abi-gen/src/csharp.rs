// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The .NET binding.
//!
//! Two layers, both printed. `NativeMethods` is the ABI as P/Invoke declares
//! it — every pointer written as `in`, `ref`, `out` or an array, so that the
//! package needs no unsafe block and the runtime does the pinning. The one
//! exception is an array of records, which crosses as an `IntPtr` to records
//! the wrapper pinned itself: what they point at has to stay pinned too, and
//! the runtime would pin the records alone. `Sipral` is the layer above it,
//! where a status becomes an exception, a byte pointer and its length become a
//! `string`, a list of records becomes an array of tuples, and everything
//! written back becomes what the call returns.

use std::fmt::Write as _;

use sipral_ffi::abi::{
    Alias, Code, Enumeration, Function, Member, Record, Shape, Stands, Surface, Value,
};

use crate::model::{
    Base, Element, Int, Linked, Read, Refused, Role, Type, Writable, callback_answer,
    callback_named, element, elements, functions, linked, listed_in, lower_camel, plain_named,
    read_all, roles, unprintable, upper_camel,
};
use crate::names::{Layout, Named, Spelling, audit};

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
fn scalar(surface: &Surface, ty: &Type) -> String {
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
        // every callback, whatever it is called: a delegate-typed member
        // makes the struct holding it stop being blittable, and a
        // function pointer is what C holds in either place
        Base::Named(name) if callback_named(surface, name).is_some() => "IntPtr".to_owned(),
        Base::Named(name) => name.clone(),
    }
}

/// What a struct member is, which is the same except that a pointer inside a
/// struct has nowhere to be `ref`.
fn member(surface: &Surface, ty: &Type) -> String {
    if ty.pointer.is_some() {
        return "IntPtr".to_owned();
    }
    scalar(surface, ty)
}

/// The name a value coming back takes.
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

/// One parameter as P/Invoke declares it, and the member it came from.
struct Declared<'a> {
    kind: String,
    name: String,
    member: &'a Member,
}

impl Declared<'_> {
    fn spelled(&self) -> String {
        format!("{} {}", self.kind, self.name)
    }
}

/// How the declaration hands one parameter over to P/Invoke.
fn declared<'a>(surface: &Surface, role: &Role<'a>) -> Vec<Declared<'a>> {
    let one = |kind: String, read: &Read<'a>, name: String| Declared {
        kind,
        name,
        member: read.member,
    };
    match role {
        Role::Plain(read) => vec![one(scalar(surface, &read.ty), read, held(read))],
        Role::Buffer { data, len } => vec![
            one(format!("{}[]", scalar(surface, &data.ty)), data, held(data)),
            one("nuint".to_owned(), len, held(len)),
        ],
        Role::Fill { data, capacity } => vec![
            one(format!("{}[]", scalar(surface, &data.ty)), data, held(data)),
            one("nuint".to_owned(), capacity, held(capacity)),
        ],
        Role::Records { data, len } => vec![
            one("IntPtr".to_owned(), data, held(data)),
            one("nuint".to_owned(), len, held(len)),
        ],
        Role::Config(read) => vec![one(
            format!("in {}", scalar(surface, &read.ty)),
            read,
            held(read),
        )],
        Role::Shared(read) | Role::Given(read) => {
            vec![one(
                format!("ref {}", scalar(surface, &read.ty)),
                read,
                held(read),
            )]
        }
        Role::Out(read) => vec![one(
            format!("out {}", scalar(surface, &read.ty)),
            read,
            written(read),
        )],
        // the delegate and the pointer handed back to it, each as it comes:
        // a caller that installs one keeps it alive itself, which the
        // callback's own summary says in the sentence above its declaration
        Role::Listener {
            callback,
            user_data,
            ..
        } => vec![
            one(scalar(surface, &callback.ty), callback, held(callback)),
            one(scalar(surface, &user_data.ty), user_data, held(user_data)),
        ],
    }
}

fn returns_of(surface: &Surface, function: &Function) -> Result<String, Refused> {
    let ty = Type::read(function.returns)?;
    Ok(match (&ty.pointer, &ty.base) {
        (Some(_), Base::Char) => "IntPtr".to_owned(),
        _ => scalar(surface, &ty),
    })
}

fn native(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::new();
    out.push_str(
        "/// <summary>\n\
         /// The ABI as the runtime calls it. Every pointer is written as an\n\
         /// array or as in, ref or out, so nothing here needs an unsafe block\n\
         /// and the runtime pins what it passes. An array of records is the\n\
         /// one IntPtr: the wrapper pins the records and the text they point\n\
         /// at itself, for the length of the call.\n\
         /// </summary>\n\
         internal static class NativeMethods\n{\n\
         \x20   /// <summary>What the native library is called, before the\n\
         \x20   /// platform puts its own prefix and suffix on it.</summary>\n\
         \x20   internal const string Library = \"sipral_ffi\";\n\n",
    );
    for (function, read) in functions(surface)? {
        let parts = roles(surface, &read);
        let arguments: Vec<String> = parts
            .iter()
            .flat_map(|role| declared(surface, role))
            .map(|parameter| parameter.spelled())
            .collect();
        let _ = writeln!(
            out,
            "    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, \
             ExactSpelling = true)]"
        );
        let _ = writeln!(
            out,
            "    internal static extern {} {}({});\n",
            returns_of(surface, function)?,
            function.name,
            arguments.join(", ")
        );
    }
    out.push_str("}\n\n");
    Ok(out)
}

/// A call that answers with a static string rather than a status, which is
/// the one shape that has nothing to check and nothing to write back.
fn naming(surface: &Surface, function: &Function, read: &[Read<'_>]) -> String {
    let mut out = String::new();
    let name = upper_camel(
        function
            .name
            .strip_prefix("sipral_")
            .unwrap_or(function.name),
    );
    let arguments: Vec<String> = read
        .iter()
        .map(|parameter| format!("{} {}", scalar(surface, &parameter.ty), held(parameter)))
        .collect();
    let passed: Vec<String> = read.iter().map(held).collect();
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
    /// Every identifier the wrapper puts in its own scope, reported so the
    /// uniqueness pass reads what was written rather than deriving it again.
    names: Vec<Named>,
}

/// The class a list of an element is pinned in for the length of a call.
fn array_class(element: &Element) -> String {
    format!("{}Array", element.record.name)
}

/// The names a tuple element may not take in C#, at any position.
const TUPLE_RESERVED: &[&str] = &[
    "CompareTo",
    "Deconstruct",
    "Equals",
    "GetHashCode",
    "Rest",
    "ToString",
];

/// The tuple a C# caller hands one element over as: `(string Name, string
/// Value)`.
///
/// A tuple rather than a type printed for the purpose, because the name such
/// a type would take is the record's, and the record's is already the struct
/// the library reads. A tuple has no spelling for one member, and C# will not
/// take some names for an element of one; both are refused by name.
fn tuple_of(element: &Element) -> Result<String, Refused> {
    let record = element.record.name;
    let refuse = |why: String| {
        Refused::about(&format!(
            "{why}; give it a shape in tools/abi-gen/src/csharp.rs"
        ))
    };
    if element.texts.len() < 2 {
        return Err(refuse(format!(
            "{record} is handed over as the element of an array and has one member, and C# has \
             no tuple of one to take it in"
        )));
    }
    let mut named = Vec::new();
    for (position, text) in element.texts.iter().enumerate() {
        let name = upper_camel(text.data.member.name);
        let numbered = name
            .strip_prefix("Item")
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()));
        if TUPLE_RESERVED.contains(&name.as_str())
            || (numbered && name != format!("Item{}", position + 1))
        {
            return Err(refuse(format!(
                "{record}::{} is `{name}` in C#, which an element of a tuple may not be called \
                 there",
                text.data.member.name
            )));
        }
        named.push(format!("string {name}"));
    }
    Ok(format!("({})", named.join(", ")))
}

/// The locals the constructor of a list's class writes.
const ARRAY_LOCALS: &[(&str, &str)] = &[
    ("list", "the list the class is made from"),
    ("parts", "every piece of text, encoded"),
    ("index", "the element being read"),
    ("total", "how many bytes every piece of text takes"),
    ("part", "the piece of text being counted"),
    ("bytes", "the buffer every piece of text is copied into"),
    ("records", "the records the library reads"),
    ("at", "how far into the buffer the class has written"),
    ("start", "where the pinned buffer is"),
];

/// The members of a list's class, beside the constructor.
const ARRAY_MEMBERS: &[(&str, &str)] = &[
    ("bytesPinned", "the pin on the buffer"),
    ("recordsPinned", "the pin on the records"),
    ("Address", "where the records are"),
    ("Count", "how many records there are"),
    ("Dispose", "what lets go of both pins"),
];

/// For each record handed over as the element of an array, the class a list of
/// them is pinned in for the length of one call.
///
/// Every piece of text is encoded and copied into one buffer before anything
/// is pinned, so that nothing which can throw sits between pinning and the
/// `using` that lets go; the second pin undoes the first when it cannot be
/// made. The wrapper declares the class with `using`, so both pins go when the
/// call returns or throws, and no pointer into them is left behind.
fn list_classes(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::new();
    for element in elements(surface, "C#")? {
        let record = element.record.name;
        let class = array_class(&element);
        let tuple = tuple_of(&element)?;
        let pieces = element.texts.len();
        let _ = write!(
            out,
            "/// <summary>\n\
             /// A list of {record} as the array the library reads, for the length of\n\
             /// one call. Every piece of text in every element is copied into one\n\
             /// buffer, the records point into it, and both are pinned until Dispose,\n\
             /// which the wrapper that made this runs as the call returns or throws.\n\
             /// The count the library is given is the list's own, and an empty piece\n\
             /// of text crosses as a null pointer with a length of zero.\n\
             /// </summary>\n\
             internal sealed class {class} : IDisposable\n\
             {{\n\
             \x20   private GCHandle bytesPinned;\n\
             \x20   private GCHandle recordsPinned;\n\n\
             \x20   internal {class}({tuple}[]? list)\n\
             \x20   {{\n\
             \x20       if (list is null || list.Length == 0)\n\
             \x20       {{\n\
             \x20           return;\n\
             \x20       }}\n\n\
             \x20       var parts = new byte[checked(list.Length * {pieces})][];\n\
             \x20       for (var index = 0; index < list.Length; index++)\n\
             \x20       {{\n"
        );
        for (position, text) in element.texts.iter().enumerate() {
            let _ = writeln!(
                out,
                "            parts[index * {pieces} + {position}] = \
                 Encoding.UTF8.GetBytes(list[index].{});",
                upper_camel(text.data.member.name)
            );
        }
        let _ = write!(
            out,
            "        }}\n\n\
             \x20       var total = 0;\n\
             \x20       foreach (var part in parts)\n\
             \x20       {{\n\
             \x20           total = checked(total + part.Length);\n\
             \x20       }}\n\n\
             \x20       var bytes = new byte[total];\n\
             \x20       var records = new {record}[list.Length];\n\
             \x20       var at = 0;\n\
             \x20       for (var index = 0; index < list.Length; index++)\n\
             \x20       {{\n"
        );
        for (position, text) in element.texts.iter().enumerate() {
            let piece = format!("parts[index * {pieces} + {position}]");
            let _ = write!(
                out,
                "            Buffer.BlockCopy({piece}, 0, bytes, at, {piece}.Length);\n\
                 \x20           records[index].{} = (nuint){piece}.Length;\n\
                 \x20           at += {piece}.Length;\n",
                upper_camel(text.len.member.name)
            );
        }
        out.push_str(
            "        }\n\n\
             \x20       bytesPinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);\n\
             \x20       try\n\
             \x20       {\n\
             \x20           recordsPinned = GCHandle.Alloc(records, GCHandleType.Pinned);\n\
             \x20       }\n\
             \x20       catch\n\
             \x20       {\n\
             \x20           bytesPinned.Free();\n\
             \x20           throw;\n\
             \x20       }\n\n\
             \x20       var start = bytesPinned.AddrOfPinnedObject();\n\
             \x20       at = 0;\n\
             \x20       for (var index = 0; index < records.Length; index++)\n\
             \x20       {\n",
        );
        for text in &element.texts {
            let data = upper_camel(text.data.member.name);
            let len = upper_camel(text.len.member.name);
            let _ = write!(
                out,
                "            records[index].{data} = records[index].{len} == 0 ? IntPtr.Zero : start + at;\n\
                 \x20           at += (int)records[index].{len};\n"
            );
        }
        out.push_str(LIST_CLASS_TAIL);
    }
    Ok(out)
}

/// The end of every list's class, which is the same whatever the element:
/// the address and the count the wrapper hands over, and the Dispose that
/// lets go of both pins.
const LIST_CLASS_TAIL: &str = "        }\n\n\
     \x20       Address = recordsPinned.AddrOfPinnedObject();\n\
     \x20       Count = (nuint)records.Length;\n\
     \x20   }\n\n\
     \x20   /// <summary>Where the first record is, or zero for no list.</summary>\n\
     \x20   internal IntPtr Address { get; }\n\n\
     \x20   /// <summary>How many records there are, which is how long the list\n\
     \x20   /// is.</summary>\n\
     \x20   internal nuint Count { get; }\n\n\
     \x20   /// <summary>Let go of the buffer and the records.</summary>\n\
     \x20   public void Dispose()\n\
     \x20   {\n\
     \x20       if (recordsPinned.IsAllocated)\n\
     \x20       {\n\
     \x20           recordsPinned.Free();\n\
     \x20       }\n\n\
     \x20       if (bytesPinned.IsAllocated)\n\
     \x20       {\n\
     \x20           bytesPinned.Free();\n\
     \x20       }\n\
     \x20   }\n\
     }\n\n";

// one arm per parameter convention, the same shape the Kotlin back end's own
// hand_over has, and split up by arm it reads worse than it does whole
#[allow(clippy::too_many_lines)]
fn hand_over(surface: &Surface, parts: &[Role<'_>]) -> Result<Handover, Refused> {
    let mut out = Handover::default();
    let Handover {
        arguments,
        passed,
        prologue,
        results,
        names,
    } = &mut out;
    let mut claimed = Vec::new();
    let mut wrote = |name: &str, member: &Member| {
        claimed.push(Named::new("the wrapper", name.to_owned(), member.name));
    };
    for role in parts {
        match role {
            Role::Records { data, .. } => {
                let fragment = list_argument(&element(surface, data, "C#")?, data)?;
                absorb(fragment, arguments, passed, prologue, names);
            }
            Role::Plain(read) => {
                let held = held(read);
                wrote(&held, read.member);
                arguments.push(format!("{} {held}", scalar(surface, &read.ty)));
                passed.push(held);
            }
            Role::Buffer { data, .. } => {
                let held = held(data);
                wrote(&held, data.member);
                if data.ty.base == Base::Char && data.ty.pointer == Some(Writable::No) {
                    wrote(&format!("{held}Bytes"), data.member);
                    wrote(&format!("{held}Signed"), data.member);
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
                    arguments.push(format!("{}[] {held}", scalar(surface, &data.ty)));
                    passed.push(held.clone());
                    passed.push(format!("(nuint){held}.Length"));
                }
            }
            Role::Fill { data, .. } => {
                let held = held(data);
                wrote(&held, data.member);
                arguments.push(format!("{}[] {held}", scalar(surface, &data.ty)));
                passed.push(held.clone());
                passed.push(format!("(nuint){held}.Length"));
            }
            Role::Config(read) => {
                let fragment = config_argument(surface, read)?;
                absorb(fragment, arguments, passed, prologue, names);
            }
            Role::Shared(read) => {
                let held = held(read);
                wrote(&held, read.member);
                arguments.push(format!("ref {} {held}", scalar(surface, &read.ty)));
                passed.push(format!("ref {held}"));
            }
            Role::Given(read) => {
                let held = written(read);
                wrote(&held, read.member);
                let _ = writeln!(
                    prologue,
                    "        var {held} = {}.Sized();",
                    scalar(surface, &read.ty)
                );
                passed.push(format!("ref {held}"));
                results.push((held, scalar(surface, &read.ty)));
            }
            Role::Out(read) => {
                let held = written(read);
                wrote(&held, read.member);
                passed.push(format!("out var {held}"));
                results.push((held, scalar(surface, &read.ty)));
            }
            Role::Listener {
                callback,
                user_data,
                ..
            } => {
                for read in [callback, user_data] {
                    wrote(&held(read), read.member);
                    arguments.push(format!("{} {}", scalar(surface, &read.ty), held(read)));
                    passed.push(held(read));
                }
            }
        }
    }
    names.extend(claimed);
    Ok(out)
}

/// Add what one parameter contributes to the wrapper around a call.
fn absorb(
    fragment: Handover,
    arguments: &mut Vec<String>,
    passed: &mut Vec<String>,
    prologue: &mut String,
    names: &mut Vec<Named>,
) {
    arguments.extend(fragment.arguments);
    passed.extend(fragment.passed);
    prologue.push_str(&fragment.prologue);
    names.extend(fragment.names);
}

/// What an array of records going in adds to the wrapper: the tuples it
/// takes, the class that pins them for the length of the call, and that
/// class's address and count.
fn list_argument(element: &Element, data: &Read<'_>) -> Result<Handover, Refused> {
    let held = held(data);
    let array = safe(&format!("{}Array", lower_camel(data.member.name)));
    let mut out = Handover::default();
    for name in [&held, &array] {
        out.names
            .push(Named::new("the wrapper", name.clone(), data.member.name));
    }
    out.arguments
        .push(format!("{}[] {held}", tuple_of(element)?));
    let _ = writeln!(
        out.prologue,
        "        using var {array} = new {}({held});",
        array_class(element)
    );
    out.passed.push(format!("{array}.Address"));
    out.passed.push(format!("{array}.Count"));
    Ok(out)
}

/// What a struct going in adds to the wrapper. Every array of records it
/// holds is taken beside it and set into a copy of it, so that the pointer
/// and the count the library reads are the list's own, pinned until the call
/// is over, whatever the caller left in the struct.
fn config_argument(surface: &Surface, read: &Read<'_>) -> Result<Handover, Refused> {
    let held = held(read);
    let mut out = Handover::default();
    out.names
        .push(Named::new("the wrapper", held.clone(), read.member.name));
    out.arguments
        .push(format!("in {} {held}", scalar(surface, &read.ty)));
    let listed = listed_in(surface, read, "C#")?;
    if listed.is_empty() {
        out.passed.push(format!("in {held}"));
        return Ok(out);
    }
    let value = safe(&format!("{}Value", lower_camel(read.member.name)));
    let mut filled = String::new();
    for one in &listed {
        let base = lower_camel(&format!("{}_{}", read.member.name, one.data.member.name));
        let list = safe(&base);
        let array = safe(&format!("{base}Array"));
        for name in [&list, &array] {
            out.names.push(Named::new(
                "the wrapper",
                name.clone(),
                one.data.member.name,
            ));
        }
        out.arguments
            .push(format!("{}[]? {list}", tuple_of(&one.element)?));
        let _ = writeln!(
            out.prologue,
            "        using var {array} = new {}({list});",
            array_class(&one.element)
        );
        let _ = writeln!(
            filled,
            "        {value}.{} = {array}.Address;\n        {value}.{} = {array}.Count;",
            upper_camel(one.data.member.name),
            upper_camel(one.len.member.name)
        );
    }
    out.names
        .push(Named::new("the wrapper", value.clone(), read.member.name));
    let _ = writeln!(out.prologue, "        var {value} = {held};");
    out.prologue.push_str(&filled);
    out.passed.push(format!("in {value}"));
    Ok(out)
}

fn wrapper(surface: &Surface, function: &Function, read: &[Read<'_>]) -> Result<String, Refused> {
    let ty = Type::read(function.returns)?;
    if ty.pointer.is_some() && ty.base == Base::Char {
        return Ok(naming(surface, function, read));
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
        names: _,
    } = hand_over(surface, &roles(surface, read))?;
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
        let width = scalar(surface, &Type::read(enumeration.width)?);
        let _ = writeln!(out, "public enum {} : {width}\n{{", enumeration.name);
        for code in enumeration.codes {
            doc(&mut out, "    ", &lines(surface, code.doc));
            let _ = writeln!(out, "    {} = {},", code.name, code.value);
        }
        out.push_str("}\n\n");
    }

    for alias in surface.aliases {
        let Stands::Callback(arguments, _) = alias.stands else {
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
            .map(|parameter| format!("IntPtr {}", held(parameter)))
            .collect();
        let returns = match callback_answer(alias)? {
            Some(ty) => scalar(surface, &ty),
            None => "void".to_owned(),
        };
        let _ = writeln!(
            out,
            "public delegate {returns} {}({});\n",
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
                member(surface, &field.ty),
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

/// The opening of `Sipral`, with the static constructor that checks the ABI
/// at load. The call in it is spelled the way the wrapper and the constants
/// printed after it are spelled, from the declarations they are printed from.
fn class_opening(surface: &Surface) -> Result<String, Refused> {
    let check = crate::model::load_check(surface, "C#")?;
    let constant =
        |value: &Value| upper_camel(value.name.strip_prefix("SIPRAL_").unwrap_or(value.name));
    Ok(format!(
        "/// <summary>Everything the library does, with the C conventions read\n\
         /// off it.</summary>\n\
         public static partial class Sipral\n{{\n\
         \x20   /// <summary>\n\
         \x20   /// Whatever has to happen before the first call reaches the\n\
         \x20   /// native library: finding it, for a layer that knows where to\n\
         \x20   /// look. Run first by the static constructor, so a caller whose\n\
         \x20   /// first use of the library is this class is served as one\n\
         \x20   /// whose first use is anything else; with no body written\n\
         \x20   /// anywhere, the compiler drops the call.\n\
         \x20   /// </summary>\n\
         \x20   static partial void BeforeLoad();\n\n\
         \x20   /// <summary>\n\
         \x20   /// Fails fast, before any of the rest of this class can be used,\n\
         \x20   /// if the native library loaded under this assembly cannot serve\n\
         \x20   /// the ABI it was generated against. A static constructor is\n\
         \x20   /// guaranteed by the runtime to run before this type's first use,\n\
         \x20   /// which is the closest a managed assembly has to \"at load\"\n\
         \x20   /// without asking every caller to remember it themselves.\n\
         \x20   ///\n\
         \x20   /// The runtime wraps what a static constructor throws, so a\n\
         \x20   /// mismatch does not arrive as a SipralException: the first use\n\
         \x20   /// of this class throws TypeInitializationException, whose\n\
         \x20   /// InnerException is the SipralException naming both versions,\n\
         \x20   /// and every later use throws that TypeInitializationException\n\
         \x20   /// again without running the check a second time.\n\
         \x20   /// </summary>\n\
         \x20   static Sipral()\n\
         \x20   {{\n\
         \x20       BeforeLoad();\n\
         \x20       {}({}, {});\n\
         \x20   }}\n\n",
        upper_camel(
            check
                .function
                .name
                .strip_prefix("sipral_")
                .unwrap_or(check.function.name),
        ),
        constant(check.major),
        constant(check.minor),
    ))
}

/// Print the .NET binding.
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
         using System;\n\
         using System.Runtime.InteropServices;\n\
         using System.Text;\n\n\
         namespace Sipral;\n\n",
    );

    out.push_str(&declarations(surface)?);
    out.push_str(&list_classes(surface)?);

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

    out.push_str(&class_opening(surface)?);

    for group in surface.constants {
        for value in *group {
            doc(&mut out, "    ", &lines(surface, value.doc));
            let ty = scalar(surface, &Type::read(value.rust_type)?);
            let name = upper_camel(value.name.strip_prefix("SIPRAL_").unwrap_or(value.name));
            let _ = writeln!(out, "    public const {ty} {name} = {};\n", value.value);
        }
    }

    out.push_str("    /// <summary>\n");
    for line in crate::layout::TABLE_DOC {
        let _ = writeln!(out, "    /// {line}");
    }
    out.push_str(
        "    /// </summary>\n\
         \x20   public static (string Name, int Marshalled, int P64, int P32A4, int P32A8)[] \
         RecordLayouts() => new[]\n\
         \x20   {\n",
    );
    for lengths in crate::layout::table(surface)? {
        let [p64, p32a4, p32a8] = lengths.sizes;
        let _ = writeln!(
            out,
            "        (\"{}\", Marshal.SizeOf<{}>(), {p64}, {p32a4}, {p32a8}),",
            lengths.record.c_name(),
            lengths.record.name
        );
    }
    out.push_str("    };\n\n");

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

/// What C# calls what the surface declares.
pub(crate) struct Names;

impl Spelling for Names {
    fn language(&self) -> &'static str {
        "C#"
    }

    fn reserved(&self) -> &'static [&'static str] {
        RESERVED
    }

    fn layout(&self) -> Layout {
        Layout::Nested
    }

    fn types(&self, surface: &Surface) -> Vec<(String, String)> {
        let mut out = vec![
            ("SipralException".to_owned(), "this back end".to_owned()),
            ("NativeMethods".to_owned(), "this back end".to_owned()),
            ("Sipral".to_owned(), "this back end".to_owned()),
        ];
        for enumeration in surface.enumerations {
            out.push((enumeration.name.to_owned(), enumeration.name.to_owned()));
        }
        for alias in surface.aliases {
            if matches!(alias.stands, Stands::Callback(_, _)) {
                out.push((alias.name.to_owned(), alias.name.to_owned()));
            }
        }
        for record in surface.records {
            out.push((record.name.to_owned(), record.name.to_owned()));
        }
        out
    }

    fn members(&self, record: &Record) -> Result<Vec<(String, String)>, Refused> {
        let mut out: Vec<(String, String)> = record
            .fields
            .iter()
            .map(|field| {
                (
                    upper_camel(field.name),
                    format!("{}::{}", record.name, field.name),
                )
            })
            .collect();
        if record.is_versioned() {
            out.push((
                "Sized".to_owned(),
                format!("the initialiser this back end gives {}", record.name),
            ));
        }
        Ok(out)
    }

    fn code(&self, enumeration: &Enumeration, code: &Code) -> String {
        let _ = enumeration;
        code.name.to_owned()
    }

    fn constant(&self, value: &Value) -> String {
        upper_camel(value.name.strip_prefix("SIPRAL_").unwrap_or(value.name))
    }

    fn entry(&self, function: &Function) -> String {
        upper_camel(
            function
                .name
                .strip_prefix("sipral_")
                .unwrap_or(function.name),
        )
    }

    fn written_by_hand(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("LastErrorMessage", "sipral_last_error_message"),
            ("Check", "the status check this back end writes"),
            ("RecordLayouts", "the layout table this back end writes"),
        ]
    }

    /// The delegate this back end prints, one `IntPtr` for each parameter,
    /// named through the same [`held`] every other parameter here goes
    /// through -- which is what puts `@event` in front of the reader rather
    /// than a keyword.
    fn signature(&self, alias: &Alias, read: &[Read<'_>]) -> Vec<Named> {
        let _ = alias;
        read.iter()
            .map(|parameter| Named::new("the delegate", held(parameter), parameter.member.name))
            .collect()
    }

    /// The class a list of each element is pinned in, its members, and the
    /// locals of its constructor.
    fn own(&self, surface: &Surface) -> Result<Vec<(String, Named)>, Refused> {
        let mut out = Vec::new();
        for element in elements(surface, "C#")? {
            let class = array_class(&element);
            out.push((
                "the top of the file".to_owned(),
                Named::new("", class.clone(), element.record.name),
            ));
            for (name, what) in ARRAY_MEMBERS {
                out.push((class.clone(), Named::new("", (*name).to_owned(), *what)));
            }
            for (name, what) in ARRAY_LOCALS {
                out.push((
                    format!("{class}, the constructor"),
                    Named::new("the wrapper", (*name).to_owned(), *what),
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
        unprintable(surface, function, read, "C#")?;
        let mut out: Vec<Named> = parts
            .iter()
            .flat_map(|role| declared(surface, role))
            .map(|parameter| Named::new("the declaration", parameter.name, parameter.member.name))
            .collect();
        let ty = Type::read(function.returns)?;
        if ty.pointer.is_some() && ty.base == Base::Char {
            // a call that answers with a static string takes its parameters
            // as they came and writes no local
            out.extend(read.iter().map(|parameter| {
                Named::new("the wrapper", held(parameter), parameter.member.name)
            }));
            return Ok(out);
        }
        out.extend(hand_over(surface, parts)?.names);
        Ok(out)
    }
}
