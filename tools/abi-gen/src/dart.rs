// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The Dart binding, printed as `bindings/dart/lib/src/sipral_abi.dart`.
//!
//! `dart:ffi` lays a struct out itself, from the class that declares it, so
//! every record becomes a `final class` extending `Struct` or `Union` with
//! one `external` field per member, annotated with its exact width where the
//! field is an integer. A type alias of a plain integer becomes a `typedef`
//! of the native integer, which a signature can name and an annotation
//! cannot, so a field is annotated with the integer the alias stands for.
//! An enumeration becomes an `abstract final class` of `static const int`
//! values: what crosses is the integer, a value this binding has no name for
//! included. A callback becomes two `typedef`s, the native function type a
//! `NativeCallable` is built over and the Dart function type it is built
//! from.
//!
//! The entry points are looked up by name from a `DynamicLibrary`, lazily,
//! as the fields of one class, `Sipral`, beside the published constants; the
//! library is opened and the ABI checked in `Sipral.open`, which is the one
//! way to get one. Like the Python back end, this prints the raw surface and
//! nothing idiomatic: pointers cross as pointers and lengths as lengths, and
//! `bindings/dart/lib/src/` is written against it by hand.
//!
//! Dart has no way to spell a reserved word as a name, so a name that
//! derives to one -- `SipralToggle::Default` is `default` -- is printed with
//! a `$` after it, which no derived name ever holds.

use std::fmt::Write as _;

use sipral_ffi::abi::{Alias, Code, Enumeration, Function, Record, Shape, Stands, Surface, Value};

use crate::model::{
    Base, Int, Linked, Read, Refused, Role, Type, callback_answer, functions, linked, load_check,
    lower_camel, plain_named, read_all, without_prefix,
};
use crate::names::{Layout, Named, Spelling, audit};

/// Words Dart will not take as a name anywhere, and the members every
/// object has, which a static member of the same name would clash with.
const RESERVED: &[&str] = &[
    "assert",
    "await",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "else",
    "enum",
    "extends",
    "false",
    "final",
    "finally",
    "for",
    "hashCode",
    "if",
    "in",
    "is",
    "new",
    "noSuchMethod",
    "null",
    "rethrow",
    "return",
    "runtimeType",
    "super",
    "switch",
    "this",
    "throw",
    "toString",
    "true",
    "try",
    "var",
    "void",
    "while",
    "with",
    "yield",
];

/// The class the entry points and the constants sit in.
const CONTAINER: &str = "Sipral";

/// The error `Sipral.open` throws.
const LOAD_ERROR: &str = "SipralLoadError";

/// A name as Dart will take it: a reserved word gets a `$` after it.
fn safe(name: &str) -> String {
    if RESERVED.contains(&name) {
        format!("{name}$")
    } else {
        name.to_owned()
    }
}

/// What a member of a record, a parameter or a value is called.
fn member_name(name: &str) -> String {
    safe(&lower_camel(name))
}

/// What a published constant is called inside [`CONTAINER`].
fn constant_name(value: &Value) -> String {
    safe(&lower_camel(
        value.name.strip_prefix("SIPRAL_").unwrap_or(value.name),
    ))
}

/// What an entry point is called inside [`CONTAINER`].
fn entry_name(function: &Function) -> String {
    safe(&without_prefix(function.name))
}

/// The Dart function type a callback's `NativeCallable` is built from.
fn dart_callback(alias: &Alias) -> String {
    format!("{}Dart", alias.name)
}

/// What a name inside a documentation link is called in Dart.
fn spelled(surface: &Surface, path: &str) -> String {
    match linked(surface, path) {
        Some((Linked::Enumeration(name), Some(code))) => format!("{name}.{}", member_name(code)),
        Some((Linked::Enumeration(name) | Linked::Type(name), None)) => name.to_owned(),
        Some((Linked::Type(name), Some(member))) => format!("{name}.{}", member_name(member)),
        None => path.to_owned(),
    }
}

/// Documentation as `///` lines at `indent`.
fn block(out: &mut String, indent: &str, surface: &Surface, doc: &[&str]) {
    for line in plain_named(doc, &|path| spelled(surface, path)) {
        let _ = writeln!(out, "{indent}///{line}");
    }
}

/// The alias, enumeration, record or callback a name refers to.
enum Kind<'a> {
    /// A plain integer under a name of its own.
    Alias(&'a str),
    /// A callback.
    Callback,
    /// An enumeration, which crosses as its width.
    Enumeration(&'a str),
    /// A struct or a union.
    Record,
}

fn kind<'a>(surface: &'a Surface, name: &str) -> Result<Kind<'a>, Refused> {
    if let Some(alias) = surface.aliases.iter().find(|alias| alias.name == name) {
        return Ok(match alias.stands {
            Stands::For(target) => Kind::Alias(target),
            Stands::Callback(_, _) => Kind::Callback,
        });
    }
    if let Some(enumeration) = surface.enumerations.iter().find(|e| e.name == name) {
        return Ok(Kind::Enumeration(enumeration.width));
    }
    if surface.records.iter().any(|record| record.name == name) {
        return Ok(Kind::Record);
    }
    Err(Refused::about(&format!(
        "{name} is named and never declared, so the Dart binding has nothing to spell it as"
    )))
}

/// The `dart:ffi` type of a base with no pointer in front of it, as a type
/// argument or in a native signature.
fn native_base(surface: &Surface, base: &Base) -> Result<String, Refused> {
    Ok(match base {
        Base::Opaque => "ffi.Void".to_owned(),
        Base::Char => "ffi.Char".to_owned(),
        Base::Float(32) => "ffi.Float".to_owned(),
        Base::Float(_) => "ffi.Double".to_owned(),
        Base::Int(int) => native_int(*int).to_owned(),
        Base::Named(name) => match kind(surface, name)? {
            Kind::Alias(_) | Kind::Record => name.clone(),
            Kind::Callback => format!("ffi.NativeFunction<{name}>"),
            Kind::Enumeration(width) => native(surface, &Type::read(width)?)?,
        },
    })
}

fn native_int(int: Int) -> &'static str {
    match (int.bits, int.signed) {
        (0, false) => "ffi.Size",
        (0, true) => "ffi.IntPtr",
        (8, false) => "ffi.Uint8",
        (8, true) => "ffi.Int8",
        (16, false) => "ffi.Uint16",
        (16, true) => "ffi.Int16",
        (32, false) => "ffi.Uint32",
        (32, true) => "ffi.Int32",
        (_, false) => "ffi.Uint64",
        (_, true) => "ffi.Int64",
    }
}

/// The `dart:ffi` type of a whole type in a native signature. A callback
/// taken by value is a pointer to a native function.
fn native(surface: &Surface, ty: &Type) -> Result<String, Refused> {
    let base = native_base(surface, &ty.base)?;
    let callback =
        matches!(&ty.base, Base::Named(name) if matches!(kind(surface, name)?, Kind::Callback));
    Ok(match ty.pointer {
        Some(_) => format!("ffi.Pointer<{base}>"),
        None if callback => format!("ffi.Pointer<{base}>"),
        None => base,
    })
}

/// The Dart type the same thing is on the Dart side of a signature, or in a
/// field: an integer is an `int`, a float a `double`, and a pointer or a
/// record is itself.
fn dart(surface: &Surface, ty: &Type) -> Result<String, Refused> {
    if ty.pointer.is_some() {
        return native(surface, ty);
    }
    Ok(match &ty.base {
        Base::Opaque => "void".to_owned(),
        Base::Char | Base::Int(_) => "int".to_owned(),
        Base::Float(_) => "double".to_owned(),
        Base::Named(name) => match kind(surface, name)? {
            Kind::Alias(target) => dart(surface, &Type::read(target)?)?,
            Kind::Enumeration(_) => "int".to_owned(),
            Kind::Record => name.clone(),
            Kind::Callback => native(surface, ty)?,
        },
    })
}

/// The annotation a field of this type carries, or none for a pointer and
/// a record, whose layout `dart:ffi` reads off the type itself.
fn annotation(surface: &Surface, ty: &Type) -> Result<Option<String>, Refused> {
    if ty.pointer.is_some() {
        return Ok(None);
    }
    Ok(match &ty.base {
        Base::Opaque => {
            return Err(Refused::about(
                "a field of type c_void is not a pointer, and has no layout to annotate",
            ));
        }
        Base::Char | Base::Int(_) | Base::Float(_) => Some(native_base(surface, &ty.base)?),
        Base::Named(name) => match kind(surface, name)? {
            Kind::Alias(target) => annotation(surface, &Type::read(target)?)?,
            Kind::Enumeration(width) => annotation(surface, &Type::read(width)?)?,
            Kind::Record | Kind::Callback => None,
        },
    })
}

/// A parameter list, each parameter typed by `spell` and named as Dart
/// names it.
fn parameters(
    surface: &Surface,
    read: &[Read<'_>],
    spell: fn(&Surface, &Type) -> Result<String, Refused>,
) -> Result<String, Refused> {
    let mut out = Vec::new();
    for parameter in read {
        out.push(format!(
            "{} {}",
            spell(surface, &parameter.ty)?,
            member_name(parameter.member.name)
        ));
    }
    Ok(out.join(", "))
}

/// What a function or a callback answers with, native and Dart: nothing,
/// or a type.
fn returns(surface: &Surface, answer: Option<&Type>) -> Result<(String, String), Refused> {
    match answer {
        None => Ok(("ffi.Void".to_owned(), "void".to_owned())),
        Some(ty) => Ok((native(surface, ty)?, dart(surface, ty)?)),
    }
}

/// A `u64` constant as a Dart literal: past `i64::MAX` the VM only takes
/// it in hexadecimal, as the same 64 bits.
fn literal(value: u64) -> String {
    if i64::try_from(value).is_ok() {
        value.to_string()
    } else {
        format!("0x{value:X}")
    }
}

fn aliases(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    for alias in surface.aliases {
        match alias.stands {
            Stands::For(target) => {
                block(out, "", surface, alias.doc);
                let _ = writeln!(
                    out,
                    "typedef {} = {};\n",
                    alias.name,
                    native(surface, &Type::read(target)?)?
                );
            }
            Stands::Callback(arguments, _) => {
                let read = read_all(alias.name, arguments)?;
                let (native_answer, dart_answer) =
                    returns(surface, callback_answer(alias)?.as_ref())?;
                block(out, "", surface, alias.doc);
                let _ = writeln!(
                    out,
                    "typedef {} = {native_answer} Function({});\n",
                    alias.name,
                    parameters(surface, &read, native)?
                );
                let _ = writeln!(
                    out,
                    "/// The Dart function a `NativeCallable<{}>` is built from.",
                    alias.name
                );
                let _ = writeln!(
                    out,
                    "typedef {} = {dart_answer} Function({});\n",
                    dart_callback(alias),
                    parameters(surface, &read, dart)?
                );
            }
        }
    }
    Ok(())
}

fn enumerations(out: &mut String, surface: &Surface) {
    for enumeration in surface.enumerations {
        block(out, "", surface, enumeration.doc);
        if !enumeration.reserved.is_empty() {
            if !enumeration.doc.is_empty() {
                out.push_str("///\n");
            }
            out.push_str("/// Numbers already spent on features this build does not have:\n");
            for held in enumeration.reserved {
                let _ = writeln!(out, "/// - {}: {}", held.value, held.feature);
            }
        }
        let _ = writeln!(out, "abstract final class {} {{", enumeration.name);
        for (index, code) in enumeration.codes.iter().enumerate() {
            if index > 0 {
                out.push('\n');
            }
            block(out, "  ", surface, code.doc);
            let _ = writeln!(
                out,
                "  static const int {} = {};",
                member_name(code.name),
                code.value
            );
        }
        out.push_str("}\n\n");
    }
}

fn records(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    for record in surface.records {
        let fields = read_all(record.name, record.fields)?;
        if fields.is_empty() {
            return Err(Refused::about(&format!(
                "{} has no members, and dart:ffi lays out no empty struct or union",
                record.name
            )));
        }
        let parent = match record.shape {
            Shape::Struct => "ffi.Struct",
            Shape::Union => "ffi.Union",
        };
        block(out, "", surface, record.doc);
        let _ = writeln!(out, "final class {} extends {parent} {{", record.name);
        for (index, field) in fields.iter().enumerate() {
            if index > 0 {
                out.push('\n');
            }
            block(out, "  ", surface, field.member.doc);
            if let Some(annotation) = annotation(surface, &field.ty).map_err(|why| {
                Refused::about(&format!("{}::{}: {why}", record.name, field.member.name))
            })? {
                let _ = writeln!(out, "  @{annotation}()");
            }
            let _ = writeln!(
                out,
                "  external {} {};",
                dart(surface, &field.ty)?,
                member_name(field.member.name)
            );
        }
        out.push_str("}\n\n");
    }
    Ok(())
}

fn load_error(out: &mut String) {
    let _ = writeln!(
        out,
        "/// Why the library could not be opened, or cannot serve this binding.\n\
         final class {LOAD_ERROR} extends Error {{\n\
         \x20 {LOAD_ERROR}(this.message);\n\
         \n\
         \x20 /// What went wrong, in a sentence.\n\
         \x20 final String message;\n\
         \n\
         \x20 @override\n\
         \x20 String toString() => 'sipral: $message';\n\
         }}\n"
    );
}

/// The status every call answers with when it worked, as Dart spells it.
fn ok_code(surface: &Surface) -> Result<String, Refused> {
    surface
        .enumerations
        .iter()
        .find(|enumeration| enumeration.name == "SipralStatus")
        .and_then(|status| {
            status
                .codes
                .iter()
                .find(|code| code.name == "Ok")
                .map(|code| format!("{}.{}", status.name, member_name(code.name)))
        })
        .ok_or_else(|| {
            Refused::about(
                "the surface declares no SipralStatus::Ok, which the Dart binding compares \
                 the ABI check's answer with at load",
            )
        })
}

fn container(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    let check = load_check(surface, "Dart")?;
    let ok = ok_code(surface)?;
    let check_fn = entry_name(check.function);
    let major = constant_name(check.major);
    let minor = constant_name(check.minor);
    let _ = writeln!(
        out,
        "/// The library, opened and checked, with every entry point it has.\n\
         ///\n\
         /// [open] is the only way to get one: it opens the library and asks\n\
         /// `{check_name}` whether it can serve the ABI this file was printed\n\
         /// from, and throws [{LOAD_ERROR}] naming both versions when it\n\
         /// cannot, rather than letting whichever call first reads a member\n\
         /// that is not there fail instead. Each entry point is looked up the\n\
         /// first time it is read.\n\
         final class {CONTAINER} {{\n\
         \x20 {CONTAINER}._(this.library);\n\
         \n\
         \x20 /// Open the library and check it. [path] names the library file,\n\
         \x20 /// or the directory holding it; without one, `SIPRAL_LIBRARY` does,\n\
         \x20 /// and without that it is looked for by name where the platform\n\
         \x20 /// looks for libraries, or found in the process itself on iOS, where\n\
         \x20 /// it is linked in.\n\
         \x20 static {CONTAINER} open({{String? path}}) {{\n\
         \x20   final sipral = {CONTAINER}._(_openLibrary(path));\n\
         \x20   final status = sipral.{check_fn}({major}, {minor});\n\
         \x20   if (status != {ok}) {{\n\
         \x20     throw {LOAD_ERROR}(\n\
         \x20       'this build of the library does not implement ABI ${major}.${minor}, '\n\
         \x20       'which this binding was generated against; regenerate the binding or '\n\
         \x20       'rebuild the library',\n\
         \x20     );\n\
         \x20   }}\n\
         \x20   return sipral;\n\
         \x20 }}\n\
         \n\
         \x20 /// What the library is called on this platform.\n\
         \x20 static String libraryName() {{\n\
         \x20   if (Platform.isMacOS || Platform.isIOS) return 'libsipral_ffi.dylib';\n\
         \x20   if (Platform.isWindows) return 'sipral_ffi.dll';\n\
         \x20   return 'libsipral_ffi.so';\n\
         \x20 }}\n\
         \n\
         \x20 static ffi.DynamicLibrary _openLibrary(String? path) {{\n\
         \x20   final named = path ?? Platform.environment['SIPRAL_LIBRARY'];\n\
         \x20   try {{\n\
         \x20     if (named != null && named.isNotEmpty) {{\n\
         \x20       final file = FileSystemEntity.isDirectorySync(named)\n\
         \x20           ? '$named${{Platform.pathSeparator}}${{libraryName()}}'\n\
         \x20           : named;\n\
         \x20       return ffi.DynamicLibrary.open(file);\n\
         \x20     }}\n\
         \x20     if (Platform.isIOS) return ffi.DynamicLibrary.process();\n\
         \x20     return ffi.DynamicLibrary.open(libraryName());\n\
         \x20   }} on ArgumentError catch (refused) {{\n\
         \x20     throw {LOAD_ERROR}(\n\
         \x20       'could not open ${{named ?? libraryName()}} (${{refused.message}}); build it '\n\
         \x20       'with `cargo build --release -p sipral-ffi`, or set SIPRAL_LIBRARY to '\n\
         \x20       'its path or its directory',\n\
         \x20     );\n\
         \x20   }}\n\
         \x20 }}\n\
         \n\
         \x20 /// The library every entry point below is looked up in.\n\
         \x20 final ffi.DynamicLibrary library;\n",
        check_name = check.function.name,
    );

    constants(out, surface);
    sizes(out, surface)?;
    entries(out, surface)?;
    out.push_str("}\n");
    Ok(())
}

/// The published constants, inside [`CONTAINER`].
fn constants(out: &mut String, surface: &Surface) {
    for group in surface.constants {
        for value in *group {
            out.push('\n');
            block(out, "  ", surface, value.doc);
            let _ = writeln!(
                out,
                "  static const int {} = {};",
                constant_name(value),
                literal(value.value)
            );
        }
    }
}

/// The layout table, inside [`CONTAINER`].
fn sizes(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    out.push('\n');
    for line in crate::layout::TABLE_DOC {
        let _ = writeln!(out, "  /// {line}");
    }
    out.push_str(
        "  /// Each list is this binding's own length first, then p64, p32a4\n\
         \x20 /// and p32a8.\n\
         \x20 static Map<String, List<int>> recordLayouts() => {\n",
    );
    for lengths in crate::layout::table(surface)? {
        let [p64, p32a4, p32a8] = lengths.sizes;
        let _ = writeln!(
            out,
            "        '{}': [ffi.sizeOf<{}>(), {p64}, {p32a4}, {p32a8}],",
            lengths.record.c_name(),
            lengths.record.name
        );
    }
    out.push_str("      };\n");
    Ok(())
}

/// Every entry point, inside [`CONTAINER`], looked up the first time it is
/// read.
fn entries(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    for (function, read) in functions(surface)? {
        out.push('\n');
        block(out, "  ", surface, function.doc);
        let answer = Type::read(function.returns)
            .map_err(|why| Refused::about(&format!("{} answers with {why}", function.name)))?;
        let (native_answer, dart_answer) = returns(surface, Some(&answer))?;
        let native_parameters = parameters(surface, &read, native)?;
        let dart_parameters = parameters(surface, &read, dart)?;
        let _ = writeln!(
            out,
            "  late final {dart_answer} Function({dart_parameters}) {} = library.lookupFunction<\n\
             \x20     {native_answer} Function({native_parameters}),\n\
             \x20     {dart_answer} Function({dart_parameters})>('{}');",
            entry_name(function),
            function.name
        );
    }
    Ok(())
}

/// Print `bindings/dart/lib/src/sipral_abi.dart`.
pub(crate) fn binding(surface: &Surface) -> Result<String, Refused> {
    audit(surface, &Names)?;
    let mut out = String::new();
    out.push_str(
        "// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial\n\
         // Copyright (c) 2026 Sytek\n\
         //\n\
         // Printed from the declarations in crates/sipral-ffi by tools/abi-gen. Do\n\
         // not edit: `cargo run -p sipral-abi-gen` writes it again, and\n\
         // `scripts/check.sh` fails when what is committed is not what came out.\n\
         //\n\
         // The raw dart:ffi surface over the C ABI: one class per struct and\n\
         // union, laid out as `bindings/c/include/sipral.h` lays it out, the\n\
         // enumerations as integer constants, the callbacks as function types,\n\
         // and every entry point in `Sipral`, looked up in the library\n\
         // `Sipral.open` opened and checked. Names are Dart's: `SipralEvent`\n\
         // for `sipral_event_t`, `bindAddressLen` for `bind_address_len`,\n\
         // `stackCreate` for `sipral_stack_create`; a reserved word has a `$`\n\
         // after it.\n\
         //\n\
         // Nothing here is idiomatic. The stack, the account, the call and the\n\
         // event stream in `bindings/dart/lib/src/` are written against this\n\
         // file by hand, and are what an application reaches for.\n\
         \n\
         // ignore_for_file: constant_identifier_names, non_constant_identifier_names\n\
         \n\
         import 'dart:ffi' as ffi;\n\
         import 'dart:io' show FileSystemEntity, Platform;\n\n",
    );
    aliases(&mut out, surface)?;
    enumerations(&mut out, surface);
    records(&mut out, surface)?;
    load_error(&mut out);
    container(&mut out, surface)?;
    Ok(out)
}

/// What Dart calls what the surface declares.
pub(crate) struct Names;

impl Spelling for Names {
    fn language(&self) -> &'static str {
        "Dart"
    }

    fn reserved(&self) -> &'static [&'static str] {
        RESERVED
    }

    fn layout(&self) -> Layout {
        Layout::Nested
    }

    fn types(&self, surface: &Surface) -> Vec<(String, String)> {
        let mut out = vec![
            (CONTAINER.to_owned(), "this back end".to_owned()),
            (LOAD_ERROR.to_owned(), "this back end".to_owned()),
        ];
        for alias in surface.aliases {
            out.push((alias.name.to_owned(), alias.name.to_owned()));
            if matches!(alias.stands, Stands::Callback(_, _)) {
                out.push((
                    dart_callback(alias),
                    format!("the Dart function type this back end gives {}", alias.name),
                ));
            }
        }
        for enumeration in surface.enumerations {
            out.push((enumeration.name.to_owned(), enumeration.name.to_owned()));
        }
        for record in surface.records {
            out.push((record.name.to_owned(), record.name.to_owned()));
        }
        out
    }

    fn members(&self, record: &Record) -> Result<Vec<(String, String)>, Refused> {
        Ok(record
            .fields
            .iter()
            .map(|field| {
                (
                    member_name(field.name),
                    format!("{}::{}", record.name, field.name),
                )
            })
            .collect())
    }

    fn code(&self, enumeration: &Enumeration, code: &Code) -> String {
        let _ = enumeration;
        member_name(code.name)
    }

    fn constant(&self, value: &Value) -> String {
        constant_name(value)
    }

    fn entry(&self, function: &Function) -> String {
        entry_name(function)
    }

    fn written_by_hand(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("library", "the library this back end holds"),
            ("open", "the load and ABI check this back end writes"),
            ("libraryName", "the library's name this back end writes"),
            ("_openLibrary", "the library search this back end writes"),
            ("recordLayouts", "the layout table this back end writes"),
        ]
    }

    /// The callback's parameters, named in both the native and the Dart
    /// function type.
    fn signature(&self, alias: &Alias, read: &[Read<'_>]) -> Vec<Named> {
        let _ = alias;
        read.iter()
            .map(|parameter| {
                Named::new(
                    "the declaration",
                    member_name(parameter.member.name),
                    parameter.member.name,
                )
            })
            .collect()
    }

    /// The parameters, named in both function types an entry point is
    /// looked up with. The raw binding hands every parameter through as it
    /// came, so the conventions the roles carry write no local here.
    fn inside(
        &self,
        surface: &Surface,
        function: &Function,
        read: &[Read<'_>],
        parts: &[Role<'_>],
    ) -> Result<Vec<Named>, Refused> {
        let _ = (surface, function, parts);
        Ok(read
            .iter()
            .map(|parameter| {
                Named::new(
                    "the declaration",
                    member_name(parameter.member.name),
                    parameter.member.name,
                )
            })
            .collect())
    }
}
