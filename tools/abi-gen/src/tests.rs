// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the generator prints, held to what it printed last time.
//!
//! Two kinds of test. The golden ones print a small surface written here --
//! small enough to read in one sitting, and wide enough to reach every shape
//! the real one has -- and compare each back end's output against the file
//! beside this one. A change to an emitter then shows up as a diff in
//! `tools/abi-gen/golden/`, where it can be read, rather than as a diff in
//! `bindings/`, where it is buried in three thousand lines that were not the
//! point.
//!
//! "Wide enough" is measured rather than asserted. A golden test over a
//! surface that misses a shape is a path down which a regression is
//! invisible, and reading the two surfaces side by side is not how anybody
//! would notice: [`the_synthetic_surface_reaches_every_shape`] counts the
//! shapes of both -- the kinds of type, the roles the conventions give a
//! parameter, struct against union, a record with a size member against one
//! without, and the four shapes a documentation link has -- and fails naming
//! each one the synthetic surface does not reach. It found twenty the day it
//! was written.
//!
//! The rest hold the real [`SURFACE`] to the passes: every name it derives is
//! unique in the scope it lands in, and none of them is a word one of the
//! four languages will not take. The day a declaration arrives that breaks
//! either, `cargo test` says so rather than a customer's build.
//!
//! To take a golden file's new contents after a deliberate change:
//! `SIPRAL_WRITE_GOLDEN=1 cargo test -p sipral-abi-gen`, then read the diff.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sipral_ffi::abi::{
    Alias, Code, Enumeration, Function, Held, Member, Record, Shape, Stands, Surface, Value,
};

use crate::model::{
    Base, Int, Refused, Role, Type, Writable, functions, lower_camel, read_all, roles, screaming,
    snake, upper_camel, words,
};
use crate::names::{Spelling, audit};
use crate::{c, csharp, kotlin, swift};

/// Where the golden files live.
fn golden_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("golden")
        .join(name)
}

/// Compare one printed file against the one committed beside this test, and
/// say where they first part company.
fn golden(name: &str, printed: &str) {
    let path = golden_path(name);
    if std::env::var_os("SIPRAL_WRITE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, printed).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|why| {
        panic!(
            "{}: {why}\ntake the new output with: SIPRAL_WRITE_GOLDEN=1 cargo test -p \
             sipral-abi-gen",
            path.display()
        )
    });
    if committed == printed {
        return;
    }
    let mut was = committed.lines();
    let mut now = printed.lines();
    let mut line = 0;
    loop {
        line += 1;
        match (was.next(), now.next()) {
            (Some(left), Some(right)) if left == right => {}
            (left, right) => {
                panic!(
                    "{} line {line}\n  committed: {}\n  printed:   {}\nif the change was meant, \
                     take it with: SIPRAL_WRITE_GOLDEN=1 cargo test -p sipral-abi-gen",
                    path.display(),
                    left.unwrap_or("<end of file>"),
                    right.unwrap_or("<end of file>")
                );
            }
        }
    }
}

/// A member with no documentation, which most of the synthetic ones have.
const fn member(name: &'static str, rust_type: &'static str) -> Member {
    Member {
        name,
        rust_type,
        doc: &[],
    }
}

const STATUS: Enumeration = Enumeration {
    name: "SipralStatus",
    doc: &[" What a call across the boundary answered."],
    width: "i32",
    codes: &[
        Code {
            name: "Ok",
            doc: &[" It worked."],
            value: 0,
        },
        Code {
            name: "InvalidArgument",
            doc: &[" Something handed in was not usable."],
            value: 1,
        },
        Code {
            name: "Panic",
            doc: &[" A panic was caught before it reached C."],
            value: 2,
        },
        Code {
            name: "Default",
            // the case that proves the escapes: a keyword in Swift and in C,
            // printed as a name in all four
            doc: &[" A word three of the four languages will not take plain."],
            value: 3,
        },
    ],
    reserved: &[Held {
        value: 9,
        feature: "video",
    }],
};

const TOGGLE: Enumeration = Enumeration {
    name: "SipralToggle",
    doc: &[" On or off, where C has no bool worth relying on."],
    width: "u32",
    codes: &[
        Code {
            name: "Off",
            doc: &[],
            value: 0,
        },
        Code {
            name: "On",
            doc: &[],
            value: 1,
        },
    ],
    reserved: &[],
};

/// One arm of the payload, and a record with no size member: an event's
/// arms are read through the union and never handed over on their own, so
/// there is nothing to append a member to.
const REGISTRATION: Record = Record {
    name: "SipralRegistrationEvent",
    doc: &[" What a registration event says."],
    shape: Shape::Struct,
    fields: &[
        Member {
            name: "state",
            rust_type: "u32",
            doc: &[" Where it got to."],
        },
        member("status_code", "u32"),
    ],
    size: 8,
};

/// The other arm, which is where a pointer to another record appears.
const MEDIA_EVENT: Record = Record {
    name: "SipralMediaEvent",
    doc: &[
        " What a media event says.",
        "",
        " # Lifetime",
        "",
        " Everything a pointer here names is the library's and lives until",
        " the callback returns.",
    ],
    shape: Shape::Struct,
    fields: &[
        member("codec", "u32"),
        Member {
            name: "reason",
            rust_type: "*const c_char",
            doc: &[" Why, as UTF-8, or null."],
        },
        member("reason_len", "usize"),
        Member {
            name: "statistics",
            rust_type: "*const SipralCounters",
            doc: &[" What the stream has done, or null when there is none."],
        },
    ],
    size: 32,
};

const PAYLOAD: Record = Record {
    name: "SipralEventPayload",
    doc: &[" The one arm [`SipralEvent::kind`] names, and no other."],
    shape: Shape::Union,
    fields: &[
        Member {
            name: "registration",
            rust_type: "SipralRegistrationEvent",
            doc: &[" Read when the kind is a registration one."],
        },
        Member {
            name: "media",
            rust_type: "SipralMediaEvent",
            doc: &[" Read when the kind is a media one."],
        },
    ],
    size: 32,
};

const EVENT: Record = Record {
    name: "SipralEvent",
    doc: &[" One thing that happened, as the callback is handed it."],
    shape: Shape::Struct,
    fields: &[
        member("size", "usize"),
        Member {
            name: "stack",
            rust_type: "SipralHandle",
            doc: &[" Which stack it came from."],
        },
        Member {
            name: "kind",
            rust_type: "u32",
            doc: &[" Which of them, from [`SipralStatus`]."],
        },
        Member {
            name: "message",
            rust_type: "*const u8",
            doc: &[
                " The message behind it, or null. It is the library's, and",
                " it lives as long as [`SipralStatus::Ok`] is being reported",
                " -- see [`sipral_stack_create`] for who owns what.",
            ],
        },
        member("message_len", "usize"),
        Member {
            name: "payload",
            rust_type: "SipralEventPayload",
            doc: &[" The arm the kind names."],
        },
    ],
    size: 64,
};

const CONFIG: Record = Record {
    name: "SipralStackConfig",
    doc: &[
        " What a stack is made with.",
        "",
        " Holds buffers of the caller's and the library only reads it, so it",
        " crosses behind a `const` pointer as a struct going in.",
    ],
    shape: Shape::Struct,
    fields: &[
        member("size", "usize"),
        Member {
            name: "event_callback",
            rust_type: "SipralEventCallback",
            doc: &[" Called for every event, from inside the poll."],
        },
        Member {
            name: "event_user_data",
            rust_type: "*mut c_void",
            doc: &[" Handed back to the callback untouched."],
        },
        Member {
            name: "bind_address",
            rust_type: "*const c_char",
            doc: &[" Where to listen, as UTF-8."],
        },
        member("bind_address_len", "usize"),
        member("echo", "SipralToggle"),
    ],
    size: 48,
};

/// The struct the caller part-fills and the library finishes: it brings the
/// room, the library writes into it and says how much it wrote.
const PACKET: Record = Record {
    name: "SipralMediaPacket",
    doc: &[
        " One datagram, in room the caller brought.",
        "",
        " Holds writable buffers of the caller's, so it crosses behind a",
        " mutable pointer as a struct going both ways.",
    ],
    shape: Shape::Struct,
    fields: &[
        member("size", "usize"),
        Member {
            name: "data",
            rust_type: "*mut u8",
            doc: &[" Where to write the datagram."],
        },
        member("capacity", "usize"),
        member("len", "usize"),
        Member {
            name: "destination",
            rust_type: "*mut c_char",
            doc: &[" Where to write the address it goes to, as UTF-8."],
        },
        member("destination_capacity", "usize"),
        member("destination_len", "usize"),
    ],
    size: 56,
};

const COUNTERS: Record = Record {
    name: "SipralCounters",
    doc: &[" What a stack has done since it was made."],
    shape: Shape::Struct,
    fields: &[
        member("size", "usize"),
        Member {
            name: "requests_sent",
            rust_type: "u64",
            doc: &[" How many went out."],
        },
        Member {
            name: "loss",
            rust_type: "f32",
            doc: &[" The fraction lost, which crosses JNI as its own bits."],
        },
    ],
    size: 24,
};

const FUNCTIONS: &[Function] = &[
    Function {
        name: "sipral_last_error_message",
        doc: &[" The calling thread's last error."],
        parameters: &[
            member("buffer", "*mut c_char"),
            member("capacity", "usize"),
            member("out_needed", "*mut usize"),
        ],
        returns: "SipralStatus",
    },
    Function {
        name: "sipral_status_name",
        doc: &[" The name of one [`SipralStatus`], for a log line."],
        parameters: &[member("code", "i32")],
        // spelled the way a declaration inside a macro reaches stringify!,
        // which is the spelling swift.rs used to miss
        returns: "* const c_char",
    },
    Function {
        name: "sipral_stack_create",
        doc: &[" Make one."],
        parameters: &[
            member("config", "*const SipralStackConfig"),
            member("out_stack", "*mut SipralHandle"),
        ],
        returns: "SipralStatus",
    },
    Function {
        name: "sipral_stack_counters",
        doc: &[" Read [`SipralCounters`] off it."],
        parameters: &[
            member("stack", "SipralHandle"),
            member("out_counters", "*mut SipralCounters"),
        ],
        returns: "SipralStatus",
    },
    Function {
        name: "sipral_stack_send",
        doc: &[" Hand it bytes to send."],
        parameters: &[
            member("stack", "SipralHandle"),
            member("message", "*const u8"),
            member("message_len", "usize"),
        ],
        returns: "SipralStatus",
    },
    Function {
        name: "sipral_stack_describe",
        doc: &[" Hand it text, which crosses as UTF-8 and not as a String."],
        parameters: &[
            member("stack", "SipralHandle"),
            member("note", "*const c_char"),
            member("note_len", "usize"),
        ],
        returns: "SipralStatus",
    },
    Function {
        name: "sipral_stack_name",
        doc: &[" Fill a buffer the caller brings."],
        parameters: &[
            member("stack", "SipralHandle"),
            member("name", "*mut c_char"),
            member("capacity", "usize"),
            member("out_len", "*mut usize"),
        ],
        returns: "SipralStatus",
    },
    Function {
        name: "sipral_stack_codec_order",
        doc: &[" Fill a buffer of numbers the caller brings."],
        parameters: &[
            member("stack", "SipralHandle"),
            member("out_codecs", "*mut u32"),
            member("capacity", "usize"),
            member("out_count", "*mut usize"),
        ],
        returns: "SipralStatus",
    },
    Function {
        name: "sipral_call_playback",
        doc: &[" Fill a buffer of samples the caller brings."],
        parameters: &[
            member("stack", "SipralHandle"),
            member("samples", "*mut i16"),
            member("capacity", "usize"),
            member("out_written", "*mut usize"),
        ],
        returns: "SipralStatus",
    },
    Function {
        name: "sipral_call_capture",
        doc: &[" Hand it samples, and get one datagram back in the struct."],
        parameters: &[
            member("stack", "SipralHandle"),
            member("samples", "*const i16"),
            member("sample_count", "usize"),
            member("packet", "*mut SipralMediaPacket"),
        ],
        returns: "SipralStatus",
    },
    Function {
        name: "sipral_call_media_receive",
        doc: &[
            " Hand it a datagram that arrived, in a buffer it may rewrite in",
            " place, and hear what became of it.",
        ],
        parameters: &[
            member("stack", "SipralHandle"),
            member("data", "*mut u8"),
            member("len", "usize"),
            member("out_arrival", "*mut u32"),
        ],
        returns: "SipralStatus",
    },
    Function {
        name: "sipral_stack_destroy",
        doc: &[" Take it apart."],
        parameters: &[member("stack", "SipralHandle")],
        returns: "SipralStatus",
    },
];

/// A surface small enough to read and wide enough to reach every shape the
/// real one does: a handle, the callback, two enumerations, a union and the
/// records it holds, a record with a size member and records without one,
/// pointers of every width that crosses, constants of three types, and at
/// least one entry point per convention in `docs/08-ffi.md`.
///
/// The second half of that sentence is held by
/// [`the_synthetic_surface_reaches_every_shape`], which counts. Add a shape
/// to `crates/sipral-ffi` that nothing here reaches and that test names it.
const SYNTHETIC: Surface = Surface {
    version: (0, 8, 0),
    aliases: &[
        Alias {
            name: "SipralHandle",
            doc: &[" What names one thing the library holds."],
            stands: Stands::For("u64"),
        },
        Alias {
            name: "SipralEventCallback",
            doc: &[" What the library calls when something happens."],
            stands: Stands::Callback(&[
                member("event", "*const SipralEvent"),
                member("user_data", "*mut c_void"),
            ]),
        },
    ],
    enumerations: &[STATUS, TOGGLE],
    records: &[
        COUNTERS,
        CONFIG,
        PACKET,
        REGISTRATION,
        MEDIA_EVENT,
        PAYLOAD,
        EVENT,
    ],
    constants: &[
        &[Value {
            name: "SIPRAL_HANDLE_NONE",
            doc: &[" The handle that names nothing."],
            rust_type: "SipralHandle",
            value: 0,
        }],
        &[
            Value {
                name: "SIPRAL_FEATURE_OPUS",
                doc: &[" The bit a hardware customer is told to check for."],
                rust_type: "u32",
                value: 64,
            },
            Value {
                name: "SIPRAL_MESSAGE_BYTES",
                doc: &[" The longest message that crosses."],
                rust_type: "usize",
                value: 65_535,
            },
        ],
    ],
    functions: FUNCTIONS,
};

#[test]
fn the_header_is_what_it_was() {
    golden("synthetic.h", &c::header(&SYNTHETIC).unwrap());
}

#[test]
fn the_swift_binding_is_what_it_was() {
    golden("synthetic.swift", &swift::binding(&SYNTHETIC).unwrap());
}

#[test]
fn the_dotnet_binding_is_what_it_was() {
    golden("synthetic.cs", &csharp::binding(&SYNTHETIC).unwrap());
}

#[test]
fn the_kotlin_binding_is_what_it_was() {
    golden("synthetic.kt", &kotlin::binding(&SYNTHETIC).unwrap());
}

#[test]
fn the_jni_shim_is_what_it_was() {
    golden("synthetic_jni.c", &kotlin::shim(&SYNTHETIC).unwrap());
}

/// The smallest surface there is, for a case that wants only one thing in it.
const NOTHING: Surface = Surface {
    version: (0, 0, 0),
    aliases: &[],
    enumerations: &[],
    records: &[],
    constants: &[],
    functions: &[],
};

/// The four back ends, to be asked the same question four times.
fn spellings() -> [&'static dyn Spelling; 4] {
    [&c::Names, &csharp::Names, &kotlin::Names, &swift::Names]
}

/// What a back end said when it refused.
fn refusal(surface: &Surface, how: &dyn Spelling) -> String {
    match audit(surface, how) {
        Ok(()) => panic!("{} took a surface it should have refused", how.language()),
        Err(why) => why.to_string(),
    }
}

#[test]
fn the_real_surface_passes_every_language() {
    for how in spellings() {
        if let Err(why) = audit(&sipral_ffi::abi::SURFACE, how) {
            panic!("{}: {why}", how.language());
        }
    }
}

#[test]
fn the_real_surface_prints_in_every_language() {
    let surface = &sipral_ffi::abi::SURFACE;
    for printed in [
        c::header(surface),
        swift::binding(surface),
        csharp::binding(surface),
        kotlin::binding(surface),
        kotlin::shim(surface),
    ] {
        let printed = printed.unwrap_or_else(|why: Refused| panic!("{why}"));
        assert!(printed.len() > 1_000, "a file with nothing in it");
    }
}

/// Two parameters of one entry point that derive one name.
///
/// This is `sipral_call_consult` as it was until this was written: C# printed
/// two parameters called `call` and would not compile, the JNI shim printed
/// two called `call` and would not compile, and Swift printed `var call`
/// beside the parameter `call` -- which does compile, and passes a zeroed
/// handle where the caller's was meant to go.
const COLLIDING: Surface = Surface {
    functions: &[Function {
        name: "sipral_call_consult",
        doc: &[" Call the transfer target."],
        parameters: &[
            member("call", "SipralHandle"),
            member("out_call", "*mut SipralHandle"),
        ],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

#[test]
fn two_parameters_that_derive_one_name_are_refused() {
    // C prints the names as they were written, so there is nothing to
    // collide; the three that derive names all land on `call`
    assert!(audit(&COLLIDING, &c::Names).is_ok());
    for how in [
        &csharp::Names as &dyn Spelling,
        &kotlin::Names,
        &swift::Names,
    ] {
        let why = refusal(&COLLIDING, how);
        assert!(
            why.contains("call") && why.contains("out_call"),
            "{}: the message names one declaration, not both: {why}",
            how.language()
        );
        assert!(
            why.contains("sipral_call_consult"),
            "{}: the message does not say where: {why}",
            how.language()
        );
    }
}

/// A parameter whose name is one the JNI shim uses for a local of its own.
///
/// This is `sipral_call_reject` as it was: the shim printed
/// `sipral_status_t status = sipral_call_reject(..., (uint32_t)status, ...)`,
/// which reads a variable inside its own initialiser.
const SHADOWED: Surface = Surface {
    functions: &[Function {
        name: "sipral_call_reject",
        doc: &[" Refuse a call that came in."],
        parameters: &[member("call", "SipralHandle"), member("status", "u32")],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

#[test]
fn a_parameter_that_lands_on_a_local_of_the_emitters_is_refused() {
    for how in [&kotlin::Names as &dyn Spelling, &swift::Names] {
        let why = refusal(&SHADOWED, how);
        assert!(
            why.contains("status") && why.contains("sipral_call_reject"),
            "{}: {why}",
            how.language()
        );
    }
    // C and C# write no local of that name, so there is nothing to report
    assert!(audit(&SHADOWED, &c::Names).is_ok());
    assert!(audit(&SHADOWED, &csharp::Names).is_ok());
}

/// A member whose name is a keyword in C, and in nothing else.
const C_KEYWORD: Surface = Surface {
    records: &[Record {
        name: "SipralOdd",
        doc: &[],
        shape: Shape::Struct,
        fields: &[member("size", "usize"), member("switch", "u32")],
        size: 16,
    }],
    ..NOTHING
};

/// A member whose name C reserves to the implementation.
const C_RESERVED: Surface = Surface {
    records: &[Record {
        name: "SipralOdd",
        doc: &[],
        shape: Shape::Struct,
        fields: &[member("size", "usize"), member("_Reserved", "u32")],
        size: 16,
    }],
    ..NOTHING
};

#[test]
fn a_keyword_c_cannot_escape_is_refused() {
    let why = refusal(&C_KEYWORD, &c::Names);
    assert!(
        why.contains("switch") && why.contains("keyword in C"),
        "{why}"
    );
    assert!(why.contains("SipralOdd::switch"), "{why}");
    // the other three spell it without trouble, and say so by not refusing
    assert!(audit(&C_KEYWORD, &csharp::Names).is_ok());
    assert!(audit(&C_KEYWORD, &kotlin::Names).is_ok());
    assert!(audit(&C_KEYWORD, &swift::Names).is_ok());

    let why = refusal(&C_RESERVED, &c::Names);
    assert!(why.contains("implementation"), "{why}");
}

/// A parameter whose name is a keyword in Kotlin and in nothing else, which
/// Kotlin spells in backticks rather than refusing -- but the C shim beside
/// it has no backticks, and prints the name as it is.
const KOTLIN_KEYWORD: Surface = Surface {
    aliases: &[Alias {
        name: "SipralHandle",
        doc: &[],
        stands: Stands::For("u64"),
    }],
    functions: &[Function {
        name: "sipral_stack_hold",
        doc: &[" Hold on to one."],
        parameters: &[member("object", "SipralHandle")],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

#[test]
fn a_keyword_a_language_can_escape_is_escaped() {
    for how in spellings() {
        if let Err(why) = audit(&KOTLIN_KEYWORD, how) {
            panic!("{}: {why}", how.language());
        }
    }
    let printed = kotlin::binding(&KOTLIN_KEYWORD).unwrap();
    assert!(
        printed.contains("fun stackHold(`object`: Long)"),
        "Kotlin did not put the keyword in backticks:\n{printed}"
    );
    // and the C beside it spells the same parameter without them, because C
    // has none and `object` is not a word C reserves
    let shim = kotlin::shim(&KOTLIN_KEYWORD).unwrap();
    assert!(shim.contains("jlong object"), "{shim}");

    // Swift's case, on the real surface: SipralPlayback::Default is `default`
    let printed = swift::binding(&sipral_ffi::abi::SURFACE).unwrap();
    assert!(
        printed.contains("case `default` ="),
        "Swift lost its escape"
    );
    // and C#'s: the callback's `event` parameter
    let printed = csharp::binding(&sipral_ffi::abi::SURFACE).unwrap();
    assert!(printed.contains("IntPtr @event"), "C# lost its escape");
}

/// A parameter named for a word the shim cannot escape, reached through the
/// Kotlin back end: Kotlin would take it, the C beside it would not.
const SHIM_KEYWORD: Surface = Surface {
    aliases: &[Alias {
        name: "SipralHandle",
        doc: &[],
        stands: Stands::For("u64"),
    }],
    functions: &[Function {
        name: "sipral_stack_wait",
        doc: &[" Wait."],
        parameters: &[member("Register", "u64")],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

#[test]
fn a_keyword_only_the_shim_trips_over_is_refused() {
    // `Register` is a name C would take as written, which is why the header
    // is happy with it; Kotlin derives `register`, and the shim prints that
    // into C, where it is a keyword
    assert!(audit(&SHIM_KEYWORD, &c::Names).is_ok());
    let why = refusal(&SHIM_KEYWORD, &kotlin::Names);
    assert!(
        why.contains("register") && why.contains("keyword in C"),
        "{why}"
    );
}

#[test]
fn a_constant_is_readable_in_every_language() {
    assert_eq!(lower_camel("FEATURE_OPUS"), "featureOpus");
    assert_eq!(upper_camel("FEATURE_OPUS"), "FeatureOpus");
    assert_eq!(screaming("FEATURE_OPUS"), "FEATURE_OPUS");
    // the shapes the other derivations still have to produce
    assert_eq!(lower_camel("bind_address_len"), "bindAddressLen");
    assert_eq!(upper_camel("bind_address_len"), "BindAddressLen");
    assert_eq!(lower_camel("InvalidArgument"), "invalidArgument");
    assert_eq!(screaming("InvalidArgument"), "INVALID_ARGUMENT");
    assert_eq!(lower_camel("G711A"), "g711A");

    let surface = &sipral_ffi::abi::SURFACE;
    let swift = swift::binding(surface).unwrap();
    let csharp = csharp::binding(surface).unwrap();
    let kotlin = kotlin::binding(surface).unwrap();
    let header = c::header(surface).unwrap();
    assert!(swift.contains("public static let featureOpus: UInt32 = 64"));
    assert!(csharp.contains("public const uint FeatureOpus = 64;"));
    assert!(kotlin.contains("const val FEATURE_OPUS: Long = 64"));
    assert!(header.contains("#define SIPRAL_FEATURE_OPUS ((uint32_t)64)"));
    // and the spellings nobody could read are gone from all four
    for mangled in [
        "fEATUREOPUS",
        "FEATUREOPUS",
        "fEATURESUBSCRIPTIONS",
        "FEATURESUBSCRIPTIONS",
        "mESSAGEBYTES",
        "MESSAGEBYTES",
    ] {
        for (language, printed) in [
            ("Swift", &swift),
            ("C#", &csharp),
            ("Kotlin", &kotlin),
            ("C", &header),
        ] {
            assert!(
                !printed.contains(mangled),
                "{language} still prints {mangled}"
            );
        }
    }
}

#[test]
fn a_type_spelled_with_a_space_is_the_same_type() {
    // `stringify!` puts its own spaces in when a declaration is written
    // inside a macro, which is how sipral_event_kind_name reaches the
    // generator; swift.rs compared the spelling and printed the wrong shape
    assert_eq!(
        Type::read("* const c_char").unwrap(),
        Type::read("*const c_char").unwrap()
    );
    let printed = swift::binding(&SYNTHETIC).unwrap();
    assert!(
        printed.contains("public static func statusName(code: Int32) -> String? {"),
        "Swift read the spelling rather than the type:\n{printed}"
    );
    let printed = swift::binding(&sipral_ffi::abi::SURFACE).unwrap();
    assert!(
        printed.contains("public static func eventKindName(kind: UInt32) -> String? {"),
        "the one declaration inside a macro is still printed as a status"
    );
}

// ------------------------------------------------------------ what a surface reaches

/// What one type is, in the terms the back ends branch on rather than in the
/// spelling the declaration used.
fn kind_of(surface: &Surface, ty: &Type) -> String {
    let base = match &ty.base {
        Base::Opaque => "c_void".to_owned(),
        Base::Char => "c_char".to_owned(),
        Base::Float(bits) => format!("f{bits}"),
        Base::Int(Int { bits: 0, .. }) => "usize".to_owned(),
        Base::Int(Int { bits, signed }) => {
            format!("{}{bits}", if *signed { "i" } else { "u" })
        }
        Base::Named(name) => named_kind(surface, name),
    };
    match ty.pointer {
        None => base,
        Some(Writable::No) => format!("*const {base}"),
        Some(Writable::Yes) => format!("*mut {base}"),
    }
}

/// Which of the four things a `Sipral…` name can be, since that is what the
/// back ends ask rather than which one it is.
fn named_kind(surface: &Surface, name: &str) -> String {
    if surface.enumerations.iter().any(|e| e.name == name) {
        return "an enumeration".to_owned();
    }
    if let Some(record) = surface.records.iter().find(|r| r.name == name) {
        return if record.is_versioned() {
            "a versioned record".to_owned()
        } else {
            "a plain record".to_owned()
        };
    }
    match surface.aliases.iter().find(|a| a.name == name) {
        Some(Alias {
            stands: Stands::Callback(_),
            ..
        }) => "the callback".to_owned(),
        Some(_) => "an alias for an integer".to_owned(),
        None => format!("{name}, which the surface does not declare"),
    }
}

/// What one parameter's role is called.
fn role_kind(role: &Role<'_>) -> &'static str {
    match role {
        Role::Plain(_) => "a plain value",
        Role::Buffer { .. } => "a buffer going in",
        Role::Fill { .. } => "a buffer being filled",
        Role::Config(_) => "a struct going in",
        Role::Given(_) => "a struct coming back",
        Role::Shared(_) => "a struct going both ways",
        Role::Out(_) => "one value written back",
    }
}

/// Which of the shapes documentation can hold, since each is a branch of its
/// own in the printer that rewrites the links.
fn doc_kinds(surface: &Surface, doc: &[&str], out: &mut BTreeSet<String>) {
    for line in doc {
        if line.starts_with(" # ") {
            out.insert("documentation with a heading in it".to_owned());
        }
        let mut rest = *line;
        while let Some(open) = rest.find("[`") {
            let Some(close) = rest.get(open..).and_then(|tail| tail.find("`]")) else {
                break;
            };
            let Some(inside) = rest.get(open + 2..open + close) else {
                break;
            };
            out.insert(match crate::model::linked(surface, inside) {
                Some((crate::model::Linked::Enumeration(_), Some(_))) => {
                    "a link to one value of an enumeration".to_owned()
                }
                Some((crate::model::Linked::Enumeration(_), None)) => {
                    "a link to an enumeration".to_owned()
                }
                Some((crate::model::Linked::Type(_), Some(_))) => {
                    "a link to one member of a type".to_owned()
                }
                Some((crate::model::Linked::Type(_), None)) => "a link to a type".to_owned(),
                None => "a link to something outside the surface".to_owned(),
            });
            rest = rest.get(open + close + 2..).unwrap_or("");
        }
    }
}

/// Every shape of declaration a surface holds, named the way the emitters
/// branch on them.
///
/// This is the measurement behind [`the_synthetic_surface_reaches_every_shape`]:
/// a golden test over a surface that misses a shape is a path where a
/// regression is invisible, and the only way to know is to count.
fn shapes(surface: &Surface) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for alias in surface.aliases {
        match alias.stands {
            Stands::For(target) => {
                let ty = Type::read(target).expect("an alias this generator can read");
                out.insert(format!("an alias for {}", kind_of(surface, &ty)));
            }
            Stands::Callback(arguments) => {
                out.insert("a callback".to_owned());
                for parameter in read_all(alias.name, arguments).expect("a callback") {
                    out.insert(format!(
                        "a callback parameter that is {}",
                        kind_of(surface, &parameter.ty)
                    ));
                }
            }
        }
        doc_kinds(surface, alias.doc, &mut out);
    }
    for enumeration in surface.enumerations {
        out.insert(format!("an enumeration of width {}", enumeration.width));
        if enumeration.reserved.is_empty() {
            out.insert("an enumeration with every number spent".to_owned());
        } else {
            out.insert("an enumeration with numbers held back".to_owned());
        }
        doc_kinds(surface, enumeration.doc, &mut out);
        for code in enumeration.codes {
            doc_kinds(surface, code.doc, &mut out);
        }
    }
    for record in surface.records {
        out.insert(match record.shape {
            Shape::Struct => "a struct".to_owned(),
            Shape::Union => "a union".to_owned(),
        });
        out.insert(if record.is_versioned() {
            "a record with a size member".to_owned()
        } else {
            "a record without a size member".to_owned()
        });
        doc_kinds(surface, record.doc, &mut out);
        for field in read_all(record.name, record.fields).expect("a record") {
            out.insert(format!("a field that is {}", kind_of(surface, &field.ty)));
            doc_kinds(surface, field.member.doc, &mut out);
        }
    }
    for group in surface.constants {
        for value in *group {
            let ty = Type::read(value.rust_type).expect("a constant this generator can read");
            out.insert(format!("a constant of type {}", kind_of(surface, &ty)));
            doc_kinds(surface, value.doc, &mut out);
        }
    }
    for (function, read) in functions(surface).expect("a surface this generator can read") {
        let returns = Type::read(function.returns).expect("a return this generator can read");
        out.insert(format!(
            "an entry point returning {}",
            kind_of(surface, &returns)
        ));
        if read.is_empty() {
            out.insert("an entry point with no parameters".to_owned());
        }
        doc_kinds(surface, function.doc, &mut out);
        for parameter in &read {
            doc_kinds(surface, parameter.member.doc, &mut out);
        }
        for role in roles(surface, &read) {
            out.insert(format!("a parameter playing {}", role_kind(&role)));
            if let Role::Buffer { data, .. } | Role::Fill { data, .. } = role {
                out.insert(format!(
                    "{} whose element is {}",
                    role_kind(&role),
                    kind_of(surface, &data.ty)
                ));
            }
        }
    }
    out
}

#[test]
fn the_synthetic_surface_reaches_every_shape() {
    let real = shapes(&sipral_ffi::abi::SURFACE);
    let synthetic = shapes(&SYNTHETIC);
    let missing: Vec<&String> = real.difference(&synthetic).collect();
    assert!(
        missing.is_empty(),
        "the golden surface does not reach {} shape(s) the real one has, so a change to the \
         emitter path each of them goes down shows up in bindings/ and nowhere else:\n{}",
        missing.len(),
        missing
            .iter()
            .map(|shape| format!("  {shape}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ------------------------------------------------------------ the callback

/// A callback parameter whose name every one of the four languages reserves.
///
/// The callback is the one signature in the surface that is not an entry
/// point, and until the pass in `names.rs` walked it these were the only
/// names in the surface nothing read back -- while `c::callbacks` printed
/// them straight into the header and `csharp::declarations` into the
/// delegate.
const CALLBACK_KEYWORD: Surface = Surface {
    aliases: &[Alias {
        name: "SipralEventCallback",
        doc: &[" What the library calls when something happens."],
        stands: Stands::Callback(&[
            member("event", "*const c_void"),
            member("class", "*mut c_void"),
        ]),
    }],
    ..NOTHING
};

#[test]
fn a_callback_parameter_a_language_cannot_spell_is_refused() {
    // `class` is a keyword in all four. C is the one with no escape, and the
    // header is read by a C++ compiler as often as by a C one
    let why = refusal(&CALLBACK_KEYWORD, &c::Names);
    assert!(why.contains("`class` is a keyword in C or in C++"), "{why}");
    assert!(
        why.contains("SipralEventCallback"),
        "the message does not say which declaration: {why}"
    );
    assert!(
        why.contains("class"),
        "the message does not say which parameter: {why}"
    );
    // and the generator stops rather than writing the header
    assert!(c::header(&CALLBACK_KEYWORD).is_err());

    // C# escapes it, the way it escapes `event` on the real surface, and
    // says so by printing it rather than refusing
    assert!(audit(&CALLBACK_KEYWORD, &csharp::Names).is_ok());
    let printed = csharp::binding(&CALLBACK_KEYWORD).unwrap();
    assert!(printed.contains("IntPtr @class"), "{printed}");

    // Kotlin and Swift print no signature for the callback at all -- Swift
    // imports the C one and Kotlin never spells it -- so they have nothing
    // to claim and nothing to refuse
    assert!(audit(&CALLBACK_KEYWORD, &kotlin::Names).is_ok());
    assert!(audit(&CALLBACK_KEYWORD, &swift::Names).is_ok());
}

/// Two callback parameters that derive one name.
const CALLBACK_COLLIDING: Surface = Surface {
    aliases: &[Alias {
        name: "SipralEventCallback",
        doc: &[" What the library calls when something happens."],
        stands: Stands::Callback(&[
            member("user_data", "*mut c_void"),
            member("UserData", "*mut c_void"),
        ]),
    }],
    ..NOTHING
};

#[test]
fn two_callback_parameters_that_derive_one_name_are_refused() {
    // C prints the two as they were written, which is two names
    assert!(audit(&CALLBACK_COLLIDING, &c::Names).is_ok());
    let why = refusal(&CALLBACK_COLLIDING, &csharp::Names);
    assert!(
        why.contains("user_data") && why.contains("UserData"),
        "the message names one declaration, not both: {why}"
    );
    assert!(
        why.contains("SipralEventCallback"),
        "the message does not say where: {why}"
    );
}

#[test]
fn a_refusal_says_which_declaration_and_which_parameter() {
    // the reserved-word message used to be built out of `from` alone, and
    // only the C back end put the entry point into `from`; the scope carries
    // it now, so all four say both
    for how in [
        &c::Names as &dyn Spelling,
        &csharp::Names,
        &kotlin::Names,
        &swift::Names,
    ] {
        let why = refusal(&SHIM_KEYWORD_AND_LOCAL, how);
        assert!(
            why.contains("sipral_stack_wait"),
            "{}: the message does not name the declaration: {why}",
            how.language()
        );
        assert!(
            why.contains("switch"),
            "{}: the message does not name the parameter: {why}",
            how.language()
        );
    }
}

/// A parameter named for a word C and C++ will not take, reached through
/// every back end: C prints it into the header, the JNI shim prints it into
/// C, and the two that escape it are asked about the C beside them.
const SHIM_KEYWORD_AND_LOCAL: Surface = Surface {
    aliases: &[Alias {
        name: "SipralHandle",
        doc: &[],
        stands: Stands::For("u64"),
    }],
    functions: &[Function {
        name: "sipral_stack_wait",
        doc: &[" Wait."],
        parameters: &[
            member("switch", "SipralHandle"),
            member("Switch", "SipralHandle"),
        ],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

// ------------------------------------------------------------ the two derivations

/// Every name a surface spells, in the spelling the declaration used.
fn every_spelling(surface: &Surface) -> Vec<&'static str> {
    let mut out = Vec::new();
    for alias in surface.aliases {
        out.push(alias.name);
        if let Stands::Callback(arguments) = alias.stands {
            out.extend(arguments.iter().map(|parameter| parameter.name));
        }
    }
    for enumeration in surface.enumerations {
        out.push(enumeration.name);
        out.extend(enumeration.codes.iter().map(|code| code.name));
    }
    for record in surface.records {
        out.push(record.name);
        out.extend(record.fields.iter().map(|field| field.name));
    }
    for group in surface.constants {
        out.extend(group.iter().map(|value| value.name));
    }
    for function in surface.functions {
        out.push(function.name);
        out.extend(function.parameters.iter().map(|member| member.name));
    }
    out
}

#[test]
fn the_words_a_name_is_made_of_join_back_into_snake() {
    // the property `model::words` is documented against. The boundaries it
    // finds are `snake`'s, letter for letter, so the words joined with `_`
    // and lowered are exactly what `snake` produces -- and a derivation
    // written twice is a derivation that can disagree with itself.
    let held = |name: &str| {
        assert_eq!(
            words(name).join("_").to_ascii_lowercase(),
            snake(name),
            "`{name}` is cut into words one way and into a C name another"
        );
    };
    // every shape a declaration can be written in
    for name in [
        "SipralStackConfig",
        "bind_address_len",
        "FEATURE_OPUS",
        "SIPRAL_FEATURE_OPUS",
        "InvalidArgument",
        "G711A",
        "Ok",
        "sipral_call_send_dtmf",
        "timer_t1_ms",
    ] {
        held(name);
    }
    // and every name the ABI really holds, which is the half that keeps
    // holding as the surface grows
    for name in every_spelling(&sipral_ffi::abi::SURFACE) {
        held(name);
    }

    // The one shape where the two part company, written down rather than
    // left to be discovered: an underscore that borders nothing is a word
    // boundary `snake` keeps and `words` drops. No name in the ABI has one
    // and none can -- C reserves a leading underscore and a doubled one to
    // the implementation, `c::Names::refuses` says so, and the loop above
    // is what proves the surface is clean.
    assert_eq!(snake("_Reserved"), "_reserved");
    assert_eq!(
        words("_Reserved").join("_").to_ascii_lowercase(),
        "reserved"
    );
    let why = refusal(&C_RESERVED, &c::Names);
    assert!(why.contains("implementation"), "{why}");
}
