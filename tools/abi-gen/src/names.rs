// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The pass that reads the names back after each back end has derived them.
//!
//! Every back end turns one declaration into a name of its own: `out_state`
//! becomes `state` in C# and in Kotlin, a struct the library fills in becomes
//! a `long[]` beside the three locals the JNI shim needs. Two declarations
//! whose derived names land on the same word produce a file that does not
//! compile, and until 8.1.3 nothing compiled these files, so the first reader
//! would have been a customer. The derivation is therefore read once more
//! before anything is printed: every identifier a back end will emit is
//! claimed in the scope it will sit in, and a second claim on the same word is
//! an error naming both declarations.
//!
//! The reserved words ride along. A language will not take one of its own
//! keywords as a name; three of the four can be made to take one anyway --
//! `@event` in C#, backticks in Swift and in Kotlin -- and the back ends do
//! that where they can. What this reads is the result, the identifier exactly
//! as it will be printed: an escaped keyword is no longer a keyword and
//! passes, an unescaped one is refused with the language and the declaration
//! named. C has no escape of any kind, and the header is the file the other
//! three are written against, so in C it is always an error.
//!
//! The callback is walked with everything else. It is the one signature in
//! the surface that is not an entry point -- `c::callbacks` prints it into
//! the header as a function pointer and `csharp::declarations` into the
//! delegate, each naming its parameters -- and for three releases those were
//! the only names in the surface that nothing read back, because
//! [`Spelling::types`] reports an alias by its type name and says nothing
//! about what it takes. [`Spelling::signature`] is where a back end answers
//! for them now.
//!
//! Every message names the scope, and the scope of anything inside an entry
//! point or inside the callback is the declaration it belongs to. So a
//! refusal says which declaration and which parameter in all four languages,
//! rather than in the one that happened to put the entry point into the
//! name it reported.
//!
//! Nothing here re-derives anything. Each back end answers with the names its
//! own emitting functions produce, from the same helpers, so this pass cannot
//! come to a different answer than the printer it guards.

use std::collections::BTreeMap;

use sipral_ffi::abi::{Alias, Code, Enumeration, Function, Record, Stands, Surface, Value};

use crate::model::{Read, Refused, Role, functions, read_all, roles};

/// How a language arranges what it prints.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layout {
    /// One namespace for the whole file, which is C: a macro, a typedef, an
    /// enumeration constant and a function all collide with one another.
    Flat,
    /// Types above, and the calls and the constants together in one container
    /// below, which is what the other three print.
    Nested,
}

/// One identifier a back end writes inside a declaration -- an entry point,
/// or the callback -- and which of that declaration's scopes it sits in.
///
/// An entry point is not one scope. The Kotlin back end prints three files'
/// worth of it -- the `external fun`, the wrapper above it and the C that
/// implements it -- and a name may repeat across them without anything being
/// wrong.
pub(crate) struct Named {
    /// Which scope inside the declaration: `the declaration`, `the wrapper`,
    /// `the shim`, `the delegate`.
    pub(crate) place: &'static str,
    /// The identifier, exactly as it will be printed.
    pub(crate) emitted: String,
    /// The declaration it came from, for the message when it collides or
    /// when a language will not take it. The entry point is not repeated
    /// here: [`audit`] puts the declaration being printed into the scope, and
    /// every message names the scope.
    pub(crate) from: String,
}

impl Named {
    /// One identifier, where it sits and what it came from.
    pub(crate) fn new(place: &'static str, emitted: String, from: impl Into<String>) -> Self {
        Self {
            place,
            emitted,
            from: from.into(),
        }
    }
}

/// What one language calls the things in the surface, answered by the back
/// end that prints it.
pub(crate) trait Spelling {
    /// What to call this language in a message.
    fn language(&self) -> &'static str;

    /// Words it will not take as a name.
    fn reserved(&self) -> &'static [&'static str];

    /// Whether this language will refuse the identifier, and why.
    ///
    /// `place` is the scope inside an entry point, empty everywhere else; the
    /// Kotlin back end needs it because one of its three scopes is C.
    fn refuses(&self, place: &str, emitted: &str) -> Option<String> {
        let _ = place;
        self.reserved()
            .contains(&emitted)
            .then(|| format!("`{emitted}` is a keyword in {}", self.language()))
    }

    /// Where the names sit.
    fn layout(&self) -> Layout;

    /// Every name this language prints above its container: the types, and
    /// whatever else the back end declares at the top of the file.
    fn types(&self, surface: &Surface) -> Vec<(String, String)>;

    /// Every identifier this language prints inside one record, including any
    /// member the back end adds of its own.
    fn members(&self, record: &Record) -> Result<Vec<(String, String)>, Refused>;

    /// What this language calls one enumeration's value.
    fn code(&self, enumeration: &Enumeration, code: &Code) -> String;

    /// What this language calls one published constant.
    fn constant(&self, value: &Value) -> String;

    /// What this language calls one entry point.
    fn entry(&self, function: &Function) -> String;

    /// The names the back end writes into its container itself, each beside
    /// the declaration it stands for.
    ///
    /// The second half matters: `lastErrorMessage` is written out by hand in
    /// three of the four back ends because the length-then-bytes dance has no
    /// derivation, but it is still `sipral_last_error_message`'s wrapper and
    /// must not be read as a second thing of the same name.
    fn written_by_hand(&self) -> &'static [(&'static str, &'static str)];

    /// Every identifier this language prints inside the one signature that
    /// is not an entry point: the callback the caller hands over.
    ///
    /// C prints it as a function pointer and C# as a delegate, each naming
    /// the parameters in a spelling of its own; Swift and Kotlin import the
    /// C typedef rather than printing one of their own, and answer with
    /// nothing. As everywhere else here, the answer is the identifier
    /// exactly as it will be printed, escape and all.
    fn signature(&self, alias: &Alias, read: &[Read<'_>]) -> Vec<Named>;

    /// Every identifier this language writes inside one entry point.
    fn inside(
        &self,
        surface: &Surface,
        function: &Function,
        read: &[Read<'_>],
        parts: &[Role<'_>],
    ) -> Result<Vec<Named>, Refused>;

    /// Every identifier this language writes inside something of its own,
    /// each with the whole of the scope it sits in.
    ///
    /// Some of what a back end prints is neither an entry point, nor a record
    /// laid out member for member, nor the callback's signature, but is built
    /// out of them: the Kotlin class a struct going in is written as, the
    /// object the listeners are kept in, the C function a callback lands in.
    /// What those hold depends on how the rest of the surface uses a record,
    /// which [`Spelling::members`] is not asked about, so they are answered
    /// here, with the surface. The scope is the back end's to name in full,
    /// because a type it prints of its own sits at the top of the file beside
    /// the ones [`Spelling::types`] reports and has to collide with them. The
    /// default is nothing, which is the answer of every back end that writes
    /// no such thing.
    fn own(&self, surface: &Surface) -> Result<Vec<(String, Named)>, Refused> {
        let _ = surface;
        Ok(Vec::new())
    }
}

/// An escaped keyword is the same name as the unescaped one, so the two have
/// to collide with each other.
fn bare(emitted: &str) -> String {
    emitted.trim_start_matches('@').trim_matches('`').to_owned()
}

/// What has been claimed so far, one map per scope.
struct Pass<'a> {
    how: &'a dyn Spelling,
    taken: BTreeMap<String, BTreeMap<String, String>>,
}

impl<'a> Pass<'a> {
    fn new(how: &'a dyn Spelling) -> Self {
        Self {
            how,
            taken: BTreeMap::new(),
        }
    }

    fn claim(
        &mut self,
        scope: &str,
        place: &str,
        emitted: &str,
        from: &str,
    ) -> Result<(), Refused> {
        if let Some(why) = self.how.refuses(place, emitted) {
            return Err(Refused::about(&format!(
                "{why}, and it is what {from} is printed as in {scope}. Rename the declaration \
                 in crates/sipral-ffi, or give the back end a way to spell it",
            )));
        }
        let language = self.how.language();
        let held = self.taken.entry(scope.to_owned()).or_default();
        match held.get(&bare(emitted)) {
            // one declaration named twice in one scope is one name, not two
            Some(first) if first == from => Ok(()),
            Some(first) => Err(Refused::about(&format!(
                "{first} and {from} are both printed as `{emitted}` in {scope}, which {language} \
                 reads as one name. Rename one of them in crates/sipral-ffi"
            ))),
            None => {
                held.insert(bare(emitted), from.to_owned());
                Ok(())
            }
        }
    }
}

/// Read every name one back end will print, in the scope it will sit in.
///
/// Called by the back end itself before it prints anything, so `--check` and
/// the tests both go through it and a broken file is never written.
pub(crate) fn audit(surface: &Surface, how: &dyn Spelling) -> Result<(), Refused> {
    let mut pass = Pass::new(how);
    let flat = how.layout() == Layout::Flat;
    let top = "the top of the file";
    let container = if flat { top } else { "Sipral" };

    for (emitted, from) in how.types(surface) {
        pass.claim(top, "", &emitted, &from)?;
    }
    for (name, stands_for) in how.written_by_hand() {
        pass.claim(container, "", name, stands_for)?;
    }
    for enumeration in surface.enumerations {
        // C prints the values as constants of the whole header; the other
        // three print them inside the enumeration they belong to
        let scope = if flat {
            top.to_owned()
        } else {
            enumeration.name.to_owned()
        };
        for code in enumeration.codes {
            pass.claim(
                &scope,
                "",
                &how.code(enumeration, code),
                &format!("{}::{}", enumeration.name, code.name),
            )?;
        }
    }
    for record in surface.records {
        for (emitted, from) in how.members(record)? {
            pass.claim(record.name, "", &emitted, &from)?;
        }
    }
    for group in surface.constants {
        for value in *group {
            pass.claim(container, "", &how.constant(value), value.name)?;
        }
    }
    // The one signature in the surface that is not an entry point. It is
    // printed into the header and into the C# delegate, so its parameters are
    // names two of the four languages really emit -- and until this walk
    // existed they were the only names in the surface that nothing read back.
    for alias in surface.aliases {
        let Stands::Callback(arguments) = alias.stands else {
            continue;
        };
        let read = read_all(alias.name, arguments)?;
        for named in how.signature(alias, &read) {
            let scope = format!("{}, {}", alias.name, named.place);
            pass.claim(&scope, named.place, &named.emitted, &named.from)?;
        }
    }
    for (function, read) in functions(surface)? {
        pass.claim(container, "", &how.entry(function), function.name)?;
        let parts = roles(surface, &read);
        for named in how.inside(surface, function, &read, &parts)? {
            let scope = format!("{}, {}", function.name, named.place);
            pass.claim(&scope, named.place, &named.emitted, &named.from)?;
        }
    }
    for (scope, named) in how.own(surface)? {
        pass.claim(&scope, named.place, &named.emitted, &named.from)?;
    }
    Ok(())
}
