// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The Node.js binding, printed as `bindings/node/src/sipral_abi.ts`.
//!
//! Node reaches the library through koffi, which loads a shared library and
//! calls into it with no compiler at install time: its prebuilt module is the
//! only native part, and it reads C declarations from strings. So, like the
//! Python back end, this one keeps every name exactly as the header spells it
//! -- `sipral_event_t`, `sipral_stack_create`, `SIPRAL_HANDLE_NONE` -- and
//! hands koffi the same declarations the header prints, one call each: a
//! `koffi.alias` per integer alias and per enumeration's width, a
//! `koffi.struct` or `koffi.union` per record, a `koffi.proto` per callback
//! and a function prototype per entry point.
//!
//! Two departures from the header, both about how koffi converts. A pointer
//! member of a record is declared `void *`, whatever it points at: koffi
//! reads a `char *` member as a string up to its first zero, and the ABI's
//! text is a pointer and a length with no zero promised, so every pointer
//! member crosses as an address the hand-written layer reads for exactly the
//! length beside it. And a callback taken by value is a pointer to koffi's
//! prototype, `sipral_log_callback_t *`, which is what koffi spells a
//! function pointer as.
//!
//! On the TypeScript side each enumeration is a frozen object of its codes,
//! named as Rust names them (`SipralStatus.BufferTooSmall`), and each record
//! an interface of its members as koffi decodes them, so the hand-written
//! layer in `bindings/node/src/` is type-checked against the declarations
//! rather than against a copy of them. The load and the ABI check are
//! `Sipral.open`, the only way to get the entry points.

use std::fmt::Write as _;

use sipral_ffi::abi::{Alias, Code, Enumeration, Function, Record, Shape, Stands, Surface, Value};

use crate::c;
use crate::model::{
    Base, Int, Read, Refused, Role, Type, callback_answer, callback_named, functions, load_check,
    read_all,
};
use crate::names::{Layout, Named, Spelling, audit};

/// Words TypeScript will not take as the name of a declaration.
const RESERVED: &[&str] = &[
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "new",
    "null",
    "return",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
    "yield",
    "let",
    "static",
    "implements",
    "interface",
    "package",
    "private",
    "protected",
    "public",
    "await",
];

/// The class the entry points sit in.
const CONTAINER: &str = "Sipral";

/// The error `Sipral.open` throws.
const LOAD_ERROR: &str = "SipralLoadError";

/// The layout table's name.
const LAYOUTS: &str = "RECORD_LAYOUTS";

/// What an address is on the TypeScript side: what koffi hands back for a
/// pointer, and everything it takes for one.
const POINTER: &str = "Pointer";

/// What a 64-bit integer is on the TypeScript side: koffi hands back a
/// `number` while it is exact and a `bigint` past that, and takes either.
const WIDE: &str = "Wide";

/// Documentation as a `/** */` block, every link spelled the C way.
fn block(out: &mut String, indent: &str, surface: &Surface, doc: &[&str]) {
    c::block(out, indent, &c::lines(surface, doc));
}

/// The integer koffi names a width by.
fn koffi_int(int: Int) -> String {
    match int {
        Int { bits: 0, .. } => "size_t".to_owned(),
        Int { bits, signed } => format!("{}int{bits}_t", if signed { "" } else { "u" }),
    }
}

/// What a member is declared as for koffi: as the header spells it, except
/// that a pointer -- a function pointer among them -- is an address.
fn koffi_member(surface: &Surface, ty: &Type) -> String {
    let callback = matches!(&ty.base, Base::Named(name) if callback_named(surface, name).is_some());
    if ty.pointer.is_some() || callback {
        return "void *".to_owned();
    }
    match (&ty.enumeration, &ty.base) {
        (Some(enumeration), _) => c::named(enumeration),
        (None, Base::Int(int)) => koffi_int(*int),
        (None, _) => c::spell(ty),
    }
}

/// What a parameter is declared as in a prototype koffi reads: as the header
/// spells it, a callback as a pointer to its prototype.
fn koffi_parameter(surface: &Surface, ty: &Type) -> String {
    if let (None, Base::Named(name)) = (&ty.pointer, &ty.base)
        && callback_named(surface, name).is_some()
    {
        return format!("{} *", c::named(name));
    }
    c::spell(ty)
}

/// A prototype as koffi reads it.
fn prototype(surface: &Surface, returns: &str, name: &str, read: &[Read<'_>]) -> String {
    let parameters = if read.is_empty() {
        "void".to_owned()
    } else {
        read.iter()
            .map(|parameter| {
                let ty = koffi_parameter(surface, &parameter.ty);
                if ty.ends_with('*') {
                    format!("{ty}{}", parameter.member.name)
                } else {
                    format!("{ty} {}", parameter.member.name)
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let space = if returns.ends_with('*') { "" } else { " " };
    format!("{returns}{space}{name}({parameters})")
}

/// The TypeScript type of a value koffi decodes, or takes, of this type.
fn script(surface: &Surface, ty: &Type) -> Result<String, Refused> {
    if ty.pointer.is_some() {
        return Ok(POINTER.to_owned());
    }
    Ok(match &ty.base {
        Base::Opaque => "void".to_owned(),
        Base::Int(Int { bits: 64, .. }) => WIDE.to_owned(),
        Base::Char | Base::Float(_) | Base::Int(_) => "number".to_owned(),
        Base::Named(name) => {
            if let Some(alias) = surface.aliases.iter().find(|alias| alias.name == name) {
                match alias.stands {
                    Stands::For(target) => script(surface, &Type::read(target)?)?,
                    Stands::Callback(_, _) => POINTER.to_owned(),
                }
            } else if let Some(enumeration) = surface.enumerations.iter().find(|e| e.name == name) {
                script(surface, &Type::read(enumeration.width)?)?
            } else if surface.records.iter().any(|record| record.name == name) {
                name.clone()
            } else {
                return Err(Refused::about(&format!(
                    "{name} is named and never declared, so the Node binding has nothing to \
                     spell it as"
                )));
            }
        }
    })
}

/// A `u64` constant as a TypeScript literal: a `bigint` past what a `number`
/// holds exactly.
fn literal(value: u64) -> String {
    if value <= (1 << 53) {
        value.to_string()
    } else {
        format!("{value}n")
    }
}

/// A record member as an interface and koffi's description name it: in
/// quotes when it is a word TypeScript reserves, which a property may be
/// but only quoted reads the same in every position.
fn property(name: &str) -> String {
    if RESERVED.contains(&name) {
        quoted(name)
    } else {
        name.to_owned()
    }
}

/// A string literal koffi is handed, in single quotes.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn aliases(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    for alias in surface.aliases {
        let Stands::For(target) = alias.stands else {
            continue;
        };
        block(out, "", surface, alias.doc);
        let _ = writeln!(
            out,
            "koffi.alias({}, {});\n",
            quoted(&c::named(alias.name)),
            quoted(&koffi_member(surface, &Type::read(target)?))
        );
    }
    Ok(())
}

fn constants(out: &mut String, surface: &Surface) {
    for group in surface.constants {
        for value in *group {
            block(out, "", surface, value.doc);
            let _ = writeln!(
                out,
                "export const {} = {};\n",
                value.name,
                literal(value.value)
            );
        }
    }
}

fn enumerations(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    for enumeration in surface.enumerations {
        let mut doc = c::lines(surface, enumeration.doc);
        if !enumeration.reserved.is_empty() {
            doc.push(String::new());
            doc.push(" Numbers already spent on features this build does not have:".to_owned());
            for held in enumeration.reserved {
                doc.push(format!(" - {}: {}", held.value, held.feature));
            }
        }
        c::block(out, "", &doc);
        let _ = writeln!(out, "export const {} = Object.freeze({{", enumeration.name);
        for code in enumeration.codes {
            block(out, "  ", surface, code.doc);
            let _ = writeln!(out, "  {}: {},", code.name, code.value);
        }
        out.push_str("} as const);\n");
        let _ = writeln!(
            out,
            "koffi.alias({}, {});\n",
            quoted(&c::named(enumeration.name)),
            quoted(&koffi_member(surface, &Type::read(enumeration.width)?))
        );
    }
    Ok(())
}

fn records(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    for record in surface.records {
        let fields = read_all(record.name, record.fields)?;
        if fields.is_empty() {
            return Err(Refused::about(&format!(
                "{} has no members, and koffi lays out no empty struct or union",
                record.name
            )));
        }
        block(out, "", surface, record.doc);
        let _ = writeln!(out, "export interface {} {{", record.name);
        for field in &fields {
            block(out, "  ", surface, field.member.doc);
            let _ = writeln!(
                out,
                "  {}: {};",
                property(field.member.name),
                script(surface, &field.ty)?
            );
        }
        out.push_str("}\n");
        let shape = match record.shape {
            Shape::Struct => "struct",
            Shape::Union => "union",
        };
        let _ = writeln!(out, "koffi.{shape}({}, {{", quoted(&c::named(record.name)));
        for field in &fields {
            let _ = writeln!(
                out,
                "  {}: {},",
                property(field.member.name),
                quoted(&koffi_member(surface, &field.ty))
            );
        }
        out.push_str("});\n\n");
    }
    Ok(())
}

fn callbacks(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    for alias in surface.aliases {
        let Stands::Callback(arguments, _) = alias.stands else {
            continue;
        };
        let read = read_all(alias.name, arguments)?;
        let returns = match callback_answer(alias)? {
            Some(ty) => c::spell(&ty),
            None => "void".to_owned(),
        };
        block(out, "", surface, alias.doc);
        let _ = writeln!(
            out,
            "export const {} = koffi.proto({});\n",
            c::named(alias.name),
            quoted(&prototype(surface, &returns, &c::named(alias.name), &read))
        );
    }
    Ok(())
}

fn load_error(out: &mut String) {
    let _ = writeln!(
        out,
        "/** Why the library could not be opened, or cannot serve this binding. */\n\
         export class {LOAD_ERROR} extends Error {{\n\
         \x20 constructor(message: string) {{\n\
         \x20   super(`sipral: ${{message}}`);\n\
         \x20   this.name = '{LOAD_ERROR}';\n\
         \x20 }}\n\
         }}\n\
         \n\
         /** What the library is called on this platform. */\n\
         export function libraryName(): string {{\n\
         \x20 if (process.platform === 'darwin') return 'libsipral_ffi.dylib';\n\
         \x20 if (process.platform === 'win32') return 'sipral_ffi.dll';\n\
         \x20 return 'libsipral_ffi.so';\n\
         }}\n\
         \n\
         /**\n\
         \x20* Where the library might be, in the order it is looked for:\n\
         \x20* `path` or `SIPRAL_LIBRARY`, whether either names the file or the\n\
         \x20* directory holding it; then beside this package, for one that\n\
         \x20* bundled the library; then the repository's own `target/release` and\n\
         \x20* `target/debug`, for working against a checkout.\n\
         \x20*/\n\
         export function libraryCandidates(path?: string): string[] {{\n\
         \x20 const name = libraryName();\n\
         \x20 const found: string[] = [];\n\
         \x20 const named = path ?? process.env.SIPRAL_LIBRARY;\n\
         \x20 if (named) {{\n\
         \x20   found.push(existsSync(named) && statSync(named).isDirectory() ? join(named, name) : named);\n\
         \x20 }}\n\
         \x20 const here = dirname(fileURLToPath(import.meta.url));\n\
         \x20 found.push(join(here, '..', name));\n\
         \x20 const repository = join(here, '..', '..', '..');\n\
         \x20 found.push(join(repository, 'target', 'release', name));\n\
         \x20 found.push(join(repository, 'target', 'debug', name));\n\
         \x20 return found;\n\
         }}\n"
    );
}

fn container(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    let check = load_check(surface, "Node")?;
    let listed = functions(surface)?;
    let _ = writeln!(
        out,
        "/**\n\
         \x20* The library, opened and checked, with every entry point it has.\n\
         \x20*\n\
         \x20* {{@link {CONTAINER}.open}} is the only way to get one: it opens the\n\
         \x20* library and asks `{check_name}` whether it can serve the ABI this\n\
         \x20* file was printed from, and throws {{@link {LOAD_ERROR}}} naming both\n\
         \x20* versions when it cannot, rather than letting whichever call first\n\
         \x20* reads a member that is not there fail instead.\n\
         \x20*/\n\
         export class {CONTAINER} {{\n\
         \x20 /** Open the library and check it. */\n\
         \x20 static open(path?: string): {CONTAINER} {{\n\
         \x20   const tried = libraryCandidates(path);\n\
         \x20   const file = tried.find((candidate) => existsSync(candidate));\n\
         \x20   if (file === undefined) {{\n\
         \x20     throw new {LOAD_ERROR}(\n\
         \x20       `could not find ${{libraryName()}}. Tried:\\n${{tried.map((one) => `  ${{one}}`).join('\\n')}}\\n\\n` +\n\
         \x20         'Build it with `cargo build --release -p sipral-ffi`, or set SIPRAL_LIBRARY to its path or its directory.',\n\
         \x20     );\n\
         \x20   }}\n\
         \x20   const sipral = new {CONTAINER}(koffi.load(file), file);\n\
         \x20   const status = sipral.{check_fn}({major}, {minor});\n\
         \x20   if (status !== SipralStatus.Ok) {{\n\
         \x20     throw new {LOAD_ERROR}(\n\
         \x20       `this build of the library does not implement ABI ${{{major}}}.${{{minor}}}, ` +\n\
         \x20         'which this binding was generated against; regenerate the binding or rebuild the library',\n\
         \x20     );\n\
         \x20   }}\n\
         \x20   return sipral;\n\
         \x20 }}\n\
         \n\
         \x20 /** The file the library was loaded from. */\n\
         \x20 readonly path: string;\n",
        check_name = check.function.name,
        check_fn = check.function.name,
        major = check.major.name,
        minor = check.minor.name,
    );
    for (function, read) in &listed {
        out.push('\n');
        block(out, "  ", surface, function.doc);
        let answer = Type::read(function.returns)
            .map_err(|why| Refused::about(&format!("{} answers with {why}", function.name)))?;
        let returns = if answer.pointer.is_some() && answer.base == Base::Char {
            "string".to_owned()
        } else {
            script(surface, &answer)?
        };
        let mut parameters = Vec::new();
        for parameter in read {
            parameters.push(format!(
                "{}: {}",
                parameter.member.name,
                script(surface, &parameter.ty)?
            ));
        }
        let _ = writeln!(
            out,
            "  readonly {}: ({}) => {returns};",
            function.name,
            parameters.join(", ")
        );
    }
    let _ = writeln!(
        out,
        "\n\
         \x20 private constructor(library: ReturnType<typeof koffi.load>, path: string) {{\n\
         \x20   this.path = path;"
    );
    for (function, read) in &listed {
        let answer = c::spell(&Type::read(function.returns)?);
        let _ = writeln!(
            out,
            "    this.{} = library.func({});",
            function.name,
            quoted(&prototype(surface, &answer, function.name, read))
        );
    }
    out.push_str("  }\n}\n");
    Ok(())
}

/// The layout table, for the size test to hold `koffi.sizeof` to.
fn layouts(out: &mut String, surface: &Surface) -> Result<(), Refused> {
    out.push_str("\n/**\n");
    for line in crate::layout::TABLE_DOC {
        let _ = writeln!(out, " * {line}");
    }
    out.push_str(" */\n");
    let _ = writeln!(
        out,
        "export const {LAYOUTS}: Readonly<Record<string, readonly [number, number, number]>> = {{"
    );
    for lengths in crate::layout::table(surface)? {
        let [p64, p32a4, p32a8] = lengths.sizes;
        let _ = writeln!(
            out,
            "  {}: [{p64}, {p32a4}, {p32a8}],",
            lengths.record.c_name()
        );
    }
    out.push_str("};\n");
    Ok(())
}

/// Print `bindings/node/src/sipral_abi.ts`.
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
         // The raw koffi surface over the C ABI: every alias, enumeration width,\n\
         // struct, union and callback declared to koffi under the name\n\
         // `bindings/c/include/sipral.h` gives it, so `docs/08-ffi.md` reads for\n\
         // this module too, and every entry point a member of `Sipral`, loaded\n\
         // from the library `Sipral.open` found and checked. A pointer member of\n\
         // a record is an address here, read for the length beside it.\n\
         //\n\
         // Nothing here is idiomatic. The stack, the account, the call and the\n\
         // media in `bindings/node/src/` are written against this file by hand,\n\
         // and are what an application reaches for.\n\
         \n\
         import { existsSync, statSync } from 'node:fs';\n\
         import { dirname, join } from 'node:path';\n\
         import { fileURLToPath } from 'node:url';\n\
         \n\
         import koffi from 'koffi';\n\
         \n",
    );
    let _ = writeln!(
        out,
        "/** An address as koffi hands one back, or anything it takes for one. */\n\
         export type {POINTER} = bigint | number | Buffer | ArrayBufferView | null;\n\
         \n\
         /** A 64-bit integer: a `number` while it is exact, a `bigint` past that. */\n\
         export type {WIDE} = number | bigint;\n"
    );
    aliases(&mut out, surface)?;
    constants(&mut out, surface);
    enumerations(&mut out, surface)?;
    records(&mut out, surface)?;
    callbacks(&mut out, surface)?;
    load_error(&mut out);
    container(&mut out, surface)?;
    layouts(&mut out, surface)?;
    Ok(out)
}

/// What TypeScript calls what the surface declares.
pub(crate) struct Names;

impl Spelling for Names {
    fn language(&self) -> &'static str {
        "TypeScript"
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
            (LAYOUTS.to_owned(), "this back end".to_owned()),
            (POINTER.to_owned(), "this back end".to_owned()),
            (WIDE.to_owned(), "this back end".to_owned()),
            ("libraryName".to_owned(), "this back end".to_owned()),
            ("libraryCandidates".to_owned(), "this back end".to_owned()),
            (
                "koffi".to_owned(),
                "the module this back end imports".to_owned(),
            ),
        ];
        for alias in surface.aliases {
            if matches!(alias.stands, Stands::Callback(_, _)) {
                out.push((c::named(alias.name), alias.name.to_owned()));
            }
        }
        for enumeration in surface.enumerations {
            out.push((enumeration.name.to_owned(), enumeration.name.to_owned()));
        }
        for record in surface.records {
            out.push((record.name.to_owned(), record.name.to_owned()));
        }
        for group in surface.constants {
            for value in *group {
                out.push((value.name.to_owned(), value.name.to_owned()));
            }
        }
        out
    }

    fn members(&self, record: &Record) -> Result<Vec<(String, String)>, Refused> {
        Ok(record
            .fields
            .iter()
            .map(|field| {
                (
                    property(field.name),
                    format!("{}::{}", record.name, field.name),
                )
            })
            .collect())
    }

    fn code(&self, enumeration: &Enumeration, code: &Code) -> String {
        let _ = enumeration;
        code.name.to_owned()
    }

    /// A constant sits at the top of the module, not in the container, and
    /// is claimed there by [`Names::types`]; inside the container it is the
    /// entry point's name, which the two never share.
    fn constant(&self, value: &Value) -> String {
        format!("{}.{}", CONTAINER, value.name)
    }

    fn entry(&self, function: &Function) -> String {
        function.name.to_owned()
    }

    fn written_by_hand(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("open", "the load and ABI check this back end writes"),
            ("path", "the library path this back end keeps"),
        ]
    }

    /// The callback's parameters, named in the prototype koffi reads.
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

    /// The parameters, named in the prototype and in the member's type. The
    /// raw binding hands every parameter through as it came.
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
                    parameter.member.name.to_owned(),
                    parameter.member.name,
                )
            })
            .collect())
    }
}
