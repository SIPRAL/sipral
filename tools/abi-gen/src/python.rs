// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The raw cffi layer, printed as `bindings/python/sipral/_sipral_cffi.py`.
//!
//! cffi's ABI mode (`ffi.cdef` plus `ffi.dlopen`) needs no C compiler, and its
//! `cdef` grammar is a restricted C: enough of it to read a struct, a union,
//! an anonymous `enum` typed to a fixed width, a function-pointer `typedef`
//! and a function prototype exactly as [`crate::c`] already prints them for
//! the header. What it will not read is the preprocessor: a macro is either
//! `#define NAME ...` with the value left to introspection -- which ABI mode
//! has no compiler to do -- or `#define NAME NUMBER`, a literal decimal, hex
//! or octal integer and nothing built out of one. So this back end reuses
//! every printer the header does not have to disagree with (aliases,
//! forwards, enumerations, callbacks, structures, a function's parameters,
//! a `/** */` block) and prints only its own two things: the constants,
//! without the cast `crate::c::values` wraps them in, since a cast is an
//! expression and cffi refuses one; and the load-and-check boilerplate around
//! the `cdef`, which is Python and not C at all.
//!
//! What is generated is deliberately the whole of it and no more: `_sipral_cffi`
//! is the seam `sipral.stack`, `sipral.account` and `sipral.call` are written
//! against by hand, the same relationship the Swift and Kotlin back ends have
//! to `SipralAbi.swift` and to the object those Kotlin classes call into.

use std::fmt::Write as _;

use sipral_ffi::abi::Surface;

use crate::c;
use crate::model::{Refused, Type, load_check};
use crate::names::audit;

/// The published constants, as `#define NAME NUMBER`: the one shape cffi's
/// own preprocessor reads without a compiler behind it (verified against
/// cffi 2.0's `cdef()` directly -- it refuses a cast where the header's
/// `values` prints one, and takes a bare literal). The literal is always
/// unsigned and always fits, because [`sipral_ffi::abi::Value::value`] is a
/// `u64` computed by the compiler from the declaration itself.
fn constants(out: &mut String, surface: &Surface) {
    for group in surface.constants {
        for value in *group {
            c::block(out, "", &c::lines(surface, value.doc));
            let _ = writeln!(out, "#define {} {}\n", value.name, value.value);
        }
    }
}

/// The `cdef` text: everything the header prints, minus the include guard and
/// the `extern "C"` wrapper neither means anything to cffi, and with
/// [`constants`] standing in for `crate::c::values`.
fn cdef(surface: &Surface) -> Result<String, Refused> {
    let mut out = String::new();
    c::aliases(&mut out, surface)?;
    constants(&mut out, surface);
    c::forwards(&mut out, surface);
    c::enumerations(&mut out, surface)?;
    c::callbacks(&mut out, surface)?;
    c::structures(&mut out, surface)?;
    for (function, read) in crate::model::functions(surface)? {
        c::block(&mut out, "", &c::lines(surface, function.doc));
        let returns = c::spell(&Type::read(function.returns)?);
        let space = if returns.ends_with('*') { "" } else { " " };
        let _ = writeln!(
            out,
            "{returns}{space}{}({});\n",
            function.name,
            c::parameters(&read)
        );
    }
    // a triple-quoted Python string ends at the first `"""`, and nothing the
    // declarations write puts one there, but the day something does this
    // says which back end broke rather than leaving Python with a `cdef` cut
    // short and no error at all
    if out.contains("\"\"\"") {
        return Err(Refused::about(
            "a declaration's documentation contains `\"\"\"`, which would end the Python \
             module's triple-quoted string early; reword it in crates/sipral-ffi",
        ));
    }
    Ok(out)
}

/// Print `bindings/python/sipral/_sipral_cffi.py`.
pub(crate) fn binding(surface: &Surface) -> Result<String, Refused> {
    audit(surface, &c::Names)?;
    let check = load_check(surface, "Python")?;
    let cdef = cdef(surface)?;
    let mut out = String::new();
    out.push_str(
        "# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial\n\
         # Copyright (c) 2026 Tiberiu Balasea\n\
         #\n\
         # Printed from the declarations in crates/sipral-ffi by tools/abi-gen. Do\n\
         # not edit: `cargo run -p sipral-abi-gen` writes it again, and\n\
         # `scripts/check.sh` fails when what is committed is not what came out.\n\
         #\n\
         # The raw cffi surface over the C ABI, built in cffi's ABI mode so that\n\
         # installing this package needs no C compiler: one `cdef` naming the same\n\
         # types, constants and entry points `bindings/c/include/sipral.h` does,\n\
         # and the `dlopen` that turns it into `lib`. Every name below is spelled\n\
         # exactly as the header spells it, so `docs/08-ffi.md` reads for this\n\
         # module too.\n\
         #\n\
         # Nothing here is idiomatic. `sipral.stack`, `sipral.account` and\n\
         # `sipral.call` are written against `lib` and `ffi` by hand, the way\n\
         # `SipralAbi.swift` is the base the Swift package is written against; an\n\
         # application reaches for those rather than this module.\n\
         \"\"\"The raw cffi surface: `ffi` and `lib`, generated from crates/sipral-ffi.\n\n\
         See sipral.stack, sipral.account and sipral.call for the layer applications\nare meant to use.\n\"\"\"\n\n\
         from __future__ import annotations\n\n\
         import os\n\
         import sys\n\
         from pathlib import Path\n\n\
         from cffi import FFI\n\n\
         CDEF = r\"\"\"\n",
    );
    out.push_str(&cdef);
    out.push_str("\"\"\"\n\n");
    out.push_str(
        "ffi = FFI()\n\
         ffi.cdef(CDEF)\n\n\n\
         def _library_name() -> str:\n\
         \x20\x20\x20\x20\"\"\"What the crate's `cdylib` is called on this platform.\"\"\"\n\
         \x20\x20\x20\x20if sys.platform == \"darwin\":\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return \"libsipral_ffi.dylib\"\n\
         \x20\x20\x20\x20if sys.platform == \"win32\":\n\
         \x20\x20\x20\x20\x20\x20\x20\x20return \"sipral_ffi.dll\"\n\
         \x20\x20\x20\x20return \"libsipral_ffi.so\"\n\n\n\
         def _candidates() -> list[Path]:\n\
         \x20\x20\x20\x20\"\"\"Where the library might be, in the order it is looked for.\n\n\
         \x20\x20\x20\x20`SIPRAL_LIBRARY` first, whether it names the library file itself\n\
         \x20\x20\x20\x20or the directory holding it; then beside this package, for a\n\
         \x20\x20\x20\x20wheel that bundled the library next to the Python; then the\n\
         \x20\x20\x20\x20repository's own `target/release` and `target/debug`, for\n\
         \x20\x20\x20\x20working against a checkout with no install step at all.\n\
         \x20\x20\x20\x20\"\"\"\n\
         \x20\x20\x20\x20name = _library_name()\n\
         \x20\x20\x20\x20found: list[Path] = []\n\
         \x20\x20\x20\x20override = os.environ.get(\"SIPRAL_LIBRARY\")\n\
         \x20\x20\x20\x20if override:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20given = Path(override)\n\
         \x20\x20\x20\x20\x20\x20\x20\x20found.append(given if given.is_file() else given / name)\n\
         \x20\x20\x20\x20package_dir = Path(__file__).resolve().parent\n\
         \x20\x20\x20\x20found.append(package_dir / name)\n\
         \x20\x20\x20\x20repository = package_dir.parents[2] if len(package_dir.parents) > 2 else None\n\
         \x20\x20\x20\x20if repository is not None:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20found.append(repository / \"target\" / \"release\" / name)\n\
         \x20\x20\x20\x20\x20\x20\x20\x20found.append(repository / \"target\" / \"debug\" / name)\n\
         \x20\x20\x20\x20return found\n\n\n\
         def _load():\n\
         \x20\x20\x20\x20tried = _candidates()\n\
         \x20\x20\x20\x20for candidate in tried:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20if candidate.is_file():\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20return ffi.dlopen(str(candidate))\n\
         \x20\x20\x20\x20searched = \"\\n\".join(f\"  {candidate}\" for candidate in tried)\n\
         \x20\x20\x20\x20raise OSError(\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\"sipral: could not find \"\n\
         \x20\x20\x20\x20\x20\x20\x20\x20+ _library_name()\n\
         \x20\x20\x20\x20\x20\x20\x20\x20+ \". Tried:\\n\"\n\
         \x20\x20\x20\x20\x20\x20\x20\x20+ searched\n\
         \x20\x20\x20\x20\x20\x20\x20\x20+ \"\\n\\nBuild it with `cargo build --release -p sipral-ffi`, \"\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\"or set SIPRAL_LIBRARY to its path or its directory.\"\n\
         \x20\x20\x20\x20)\n\n\n\
         lib = _load()\n\n",
    );
    let _ = writeln!(
        out,
        "# Checked once, at import, the way every other binding checks itself at\n\
         # load: {check_fn} is called with the major and minor this file was\n\
         # printed from, so a library that cannot serve them is refused here, in\n\
         # a sentence naming both, rather than in whichever call first reads a\n\
         # member that is not there.\n\
         _abi_status = lib.{check_fn}(lib.{major}, lib.{minor})\n\
         if _abi_status != lib.SIPRAL_STATUS_OK:\n\
         \x20\x20\x20\x20raise OSError(\n\
         \x20\x20\x20\x20\x20\x20\x20\x20f\"sipral: this build of the library does not implement ABI \"\n\
         \x20\x20\x20\x20\x20\x20\x20\x20f\"{{lib.{major}}}.{{lib.{minor}}}, which this binding was \"\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\"generated against; regenerate the binding or rebuild the library\"\n\
         \x20\x20\x20\x20)\n",
        check_fn = check.function.name,
        major = check.major.name,
        minor = check.minor.name,
    );
    Ok(out)
}
