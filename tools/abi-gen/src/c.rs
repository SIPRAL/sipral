// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
    Base, Int, Linked, Read, Refused, Role, Type, Writable, callback_answer, linked, numbers_named,
    plain_named, read_all, screaming, snake,
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
///
/// `pub(crate)` rather than private: the Python back end prints a `cdef` that
/// declares the same types under the same names, and a doc comment that sent
/// a C reader to `sipral_event_t::kind` is the sentence a Python reader wants
/// too, so it reads this rather than carrying a second copy of the same walk.
pub(crate) fn lines(surface: &Surface, doc: &[&str]) -> Vec<String> {
    plain_named(doc, &|path| spelled(surface, path))
}

/// The name a type takes in C.
pub(crate) fn named(name: &str) -> String {
    format!("{}_t", snake(name))
}

/// The C spelling of a type, with the pointer put where C puts it.
pub(crate) fn spell(ty: &Type) -> String {
    let base = match (&ty.enumeration, &ty.base) {
        (Some(enumeration), _) => named(enumeration),
        (None, base) => spell_base(base),
    };
    match ty.pointer {
        None => base,
        Some(Writable::No) => format!("const {base} *"),
        Some(Writable::Yes) => format!("{base} *"),
    }
}

/// What a type is in C once any pointer is off it.
fn spell_base(base: &Base) -> String {
    match base {
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
    }
}

/// `pub(crate)`: printed the same way inside a `/** */` in the header and
/// inside the `cdef` the Python back end builds, since cffi reads the same
/// comment syntax C does.
pub(crate) fn block(out: &mut String, indent: &str, doc: &[String]) {
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

/// `pub(crate)`: a parameter list reads the same in a function prototype and
/// in the `cdef` the Python back end prints, since cffi's grammar for one is
/// C's.
pub(crate) fn parameters(read: &[Read<'_>]) -> String {
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
///
/// `pub(crate)`: a `typedef` for a plain integer is the same declaration in
/// the header and in the Python back end's `cdef`, which shares this rather
/// than printing its own.
pub(crate) fn aliases(out: &mut String, surface: &Surface) -> Result<(), Refused> {
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
///
/// `pub(crate)`: the forward declarations a `cdef` needs are the same ones,
/// for the same reason.
pub(crate) fn forwards(out: &mut String, surface: &Surface) {
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

/// `pub(crate)`: an anonymous `enum` typed to a fixed-width `typedef` is what
/// cffi reads too, so the Python back end prints this rather than a second
/// derivation of it.
pub(crate) fn enumerations(out: &mut String, surface: &Surface) -> Result<(), Refused> {
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

/// `pub(crate)`: a function-pointer `typedef` for a callback is what
/// `ffi.callback` in Python is built against too.
pub(crate) fn callbacks(out: &mut String, surface: &Surface) -> Result<(), Refused> {
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

/// `pub(crate)`: a struct or a union lays out the same way for cffi's ABI
/// mode as for a C compiler, so the Python back end prints this `cdef` rather
/// than a second copy of the member loop.
pub(crate) fn structures(out: &mut String, surface: &Surface) -> Result<(), Refused> {
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
    numbers_named(surface)?;
    let mut out = String::new();
    out.push_str(
        "/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial\n\
         \x20* Copyright (c) 2026 Sytek\n\
         \x20*\n\
         \x20* Printed from the declarations in crates/sipral-ffi by tools/abi-gen.\n\
         \x20* Do not edit: `cargo run -p sipral-abi-gen` writes it again, and\n\
         \x20* `scripts/check.sh` fails when what is committed is not what came out.\n\
         \x20*\n\
         \x20* CONVENTIONS. Every declaration below follows these; a comment that\n\
         \x20* says otherwise is the exception, and says so.\n\
         \x20*\n\
         \x20* Status. Every function returns a sipral_status_t, except the three\n\
         \x20* that return a static name (sipral_status_name, sipral_codec_name,\n\
         \x20* sipral_event_kind_name: NUL-terminated, the library's, valid while it\n\
         \x20* is loaded). sipral_status_t is the one signed type: zero is success,\n\
         \x20* every failure is positive, none is negative, and a newer library may\n\
         \x20* return one an older header has no name for, which is a failure like\n\
         \x20* any other. A failure sets the calling thread's last error\n\
         \x20* (sipral_last_error_message); a success clears it. A panic never\n\
         \x20* crosses: it is SIPRAL_STATUS_PANIC.\n\
         \x20*\n\
         \x20* Enumerations. Each is a typedef of a fixed-width integer and the\n\
         \x20* names as constants, so no compiler picks a width. Every parameter\n\
         \x20* and member that holds one is declared with its typedef, and one\n\
         \x20* declared as a plain integer holds a count, a flag or a number the\n\
         \x20* comment names. Values are only ever added, never renumbered: a\n\
         \x20* number an older header has no name for is read as one the caller\n\
         \x20* does not know. In the enumerations that start at 1 zero names\n\
         \x20* nothing: read it as absent.\n\
         \x20*\n\
         \x20* Structs that carry `size`. Zero the whole struct, padding included,\n\
         \x20* then set `size` to its sizeof, on a struct handed in and on one the\n\
         \x20* library fills alike. A library that knows fewer members reads what\n\
         \x20* it knows and refuses a nonzero byte past it with\n\
         \x20* SIPRAL_STATUS_NOT_SUPPORTED; one that fills fewer writes back the\n\
         \x20* `size` it filled and zeroes the rest. A struct only ever grows by appending members\n\
         \x20* at its end, and no struct here ends in padding on any target, so an\n\
         \x20* appended member never lands inside a length a caller declares. The\n\
         \x20* least a caller may declare is where the oldest version of each\n\
         \x20* struct ended (bindings/c/abi-sizes.txt). sipral_header_t is the one\n\
         \x20* struct without a size: it is the element of an array, and never\n\
         \x20* grows. The event payload union is zeroed whole before the one arm\n\
         \x20* its kind names is written.\n\
         \x20*\n\
         \x20* Text and bytes in. A pointer and a length in bytes, the pointer\n\
         \x20* read for that length during the call and never kept. Text is UTF-8\n\
         \x20* with no NUL expected or read, and at most 65536 bytes. For an\n\
         \x20* optional piece a length of zero is absent, whatever the pointer.\n\
         \x20*\n\
         \x20* Text out. `buffer`, `capacity`, `out_needed`: the text is written\n\
         \x20* with a trailing NUL, and `out_needed`, which may be null, receives\n\
         \x20* the bytes it needs with that NUL counted. Too small a buffer is\n\
         \x20* SIPRAL_STATUS_BUFFER_TOO_SMALL and nothing is written; a null\n\
         \x20* buffer with a capacity of zero asks for the length alone.\n\
         \x20* Bytes out (sipral_account_freeze, sipral_stack_codec_order,\n\
         \x20* sipral_media_playback) are counted without a NUL and say so. A\n\
         \x20* packet struct (sipral_media_packet_t, sipral_transmit_t) brings\n\
         \x20* buffers at least as large as the constant each member's comment\n\
         \x20* names, is refused whole with SIPRAL_STATUS_BUFFER_TOO_SMALL when one\n\
         \x20* is smaller, and comes back with a `len` of zero when nothing was\n\
         \x20* waiting.\n\
         \x20*\n\
         \x20* Handles. 64-bit, zero never valid. A handle that never came from\n\
         \x20* this library, or from another stack, is\n\
         \x20* SIPRAL_STATUS_INVALID_HANDLE; one whose object is gone is\n\
         \x20* SIPRAL_STATUS_STALE_HANDLE. The library hands out no memory for a\n\
         \x20* caller to free.\n\
         \x20*\n\
         \x20* Threads. A stack may be used from any thread, one at a time: a\n\
         \x20* second thread gets SIPRAL_STATUS_BUSY rather than a wait. A call's\n\
         \x20* media is reached through a handle of its own (sipral_call_media) and\n\
         \x20* never waits on the stack; it waits only for a frame another thread\n\
         \x20* is in the middle of on that same call. The sipral_audio_* calls wait\n\
         \x20* for the audio engine, which a platform probe holds for up to\n\
         \x20* sipral_stack_config_t::audio_probe_ms; nothing else waits on them.\n\
         \x20*\n\
         \x20* Callbacks. None may unwind into the library. Each gets back its\n\
         \x20* `user_data` untouched and reads nothing else the caller owns.\n\
         \x20*   event (sipral_stack_config_t::event_callback): on the thread in\n\
         \x20*     sipral_stack_poll, with nothing held; may call anything, this\n\
         \x20*     stack included. user_data lives as long as the stack.\n\
         \x20*   screen (sipral_stack_screen): on the thread feeding the stack\n\
         \x20*     bytes, with the stack's lock held; a call into this stack is\n\
         \x20*     SIPRAL_STATUS_BUSY. user_data lives until the policy is replaced\n\
         \x20*     or removed and no thread is inside the stack.\n\
         \x20*   processor (sipral_media_attach_processor): on the thread in\n\
         \x20*     sipral_media_capture or sipral_media_playback, with that call's\n\
         \x20*     media held; a call on any media handle, or into that call's\n\
         \x20*     stack, is SIPRAL_STATUS_BUSY. user_data lives until\n\
         \x20*     sipral_media_detach_processor returns or the handle is released.\n\
         \x20*   audio transmit (sipral_stack_config_t::audio_transmit_callback):\n\
         \x20*     on the audio engine's own thread, with nothing of the library's\n\
         \x20*     held; sipral_stack_destroy from it is SIPRAL_STATUS_BUSY.\n\
         \x20*     user_data lives as long as the stack.\n\
         \x20*   log (sipral_stack_log): on the thread that just finished a call\n\
         \x20*     into the stack, with nothing held, one line at a time; may call\n\
         \x20*     anything. user_data lives until the log is replaced or turned off\n\
         \x20*     and no thread is inside the stack.\n\
         \x20* Every pointer a callback is handed points into the library's memory\n\
         \x20* and is valid for that one call.\n\
         \x20*/\n\n",
    );
    out.push_str("#ifndef SIPRAL_H\n#define SIPRAL_H\n\n");
    out.push_str("#include <stddef.h>\n#include <stdint.h>\n\n");
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
    no_rust_in(&out)?;
    Ok(out)
}

/// What only a Rust reader can follow, and a line of the header that says it.
///
/// A path into the crate, a macro's name, or a crate below this one names
/// something a C programmer has no way to look up: the documentation was
/// written beside the Rust declaration, and a sentence that sends its reader
/// to a module is one that was never read as C. The generator takes a link's
/// path off and spells a quoted type the C way; what is left is prose to
/// rewrite at the declaration.
fn no_rust_in(header: &str) -> Result<(), Refused> {
    const RUST_ONLY: &[&str] = &["crate::", "entry!", "sipral_ua", "sipral_core", "Self::"];
    for (number, line) in header.lines().enumerate() {
        if let Some(found) = RUST_ONLY.iter().find(|rust| line.contains(*rust)) {
            return Err(Refused::about(&format!(
                "line {} of the header says `{found}`, which names something only the Rust \
                 source has: {}; say it in C terms in the declaration's documentation",
                number + 1,
                line.trim()
            )));
        }
    }
    Ok(())
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
