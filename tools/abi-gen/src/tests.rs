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
    Base, Int, Refused, Role, Type, Writable, functions, listed_in, lower_camel, read_all, roles,
    screaming, snake, upper_camel, words,
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

/// A record with no size member that is not an arm of the payload: an element
/// of an array that crosses behind a pointer, with its length beside it, where
/// a member appended would re-stride every element after the first.
const HEADER: Record = Record {
    name: "SipralHeader",
    doc: &[" One header field: a name and a value."],
    shape: Shape::Struct,
    fields: &[
        member("name", "*const c_char"),
        member("name_len", "usize"),
        member("value", "*const c_char"),
        member("value_len", "usize"),
    ],
    size: 32,
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
        Member {
            name: "headers",
            rust_type: "*const SipralHeader",
            doc: &[" Header fields to send, `headers_len` of them."],
        },
        member("headers_len", "usize"),
    ],
    size: 64,
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
    ABI_CHECK,
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
        name: "sipral_stack_label",
        doc: &[" Hand it header fields, an array of them with its length beside it."],
        parameters: &[
            member("stack", "SipralHandle"),
            member("headers", "*const SipralHeader"),
            member("headers_len", "usize"),
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
        HEADER,
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
        VERSION,
    ],
    functions: FUNCTIONS,
};

/// What a binding checks itself against at load. The back ends that print a
/// load check read it from the surface, so a surface they print declares it
/// the way the real one does.
const ABI_CHECK: Function = Function {
    name: "sipral_abi_check",
    doc: &[" Whether this library can serve a binding generated against `major`.`minor`."],
    parameters: &[member("major", "u32"), member("minor", "u32")],
    returns: "SipralStatus",
};

/// The version a surface is, in the two constants a load check hands over.
const VERSION: &[Value] = &[
    Value {
        name: "SIPRAL_ABI_VERSION_MAJOR",
        doc: &[" Nothing built against another major works against this one."],
        rust_type: "u32",
        value: 0,
    },
    Value {
        name: "SIPRAL_ABI_VERSION_MINOR",
        doc: &[" Raised by anything the header gains."],
        rust_type: "u32",
        value: 8,
    },
];

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

/// The .NET static constructor and the call Swift's documentation gives are
/// read from the declarations, not written into the back end. Written in,
/// they named `AbiCheck`, `AbiVersionMajor` and `AbiVersionMinor` whatever the
/// surface declared, and `golden/synthetic.cs`, printed from a surface that
/// declared none of the three, stopped compiling.
#[test]
fn the_load_check_is_read_from_the_declarations() {
    for (language, printed) in [
        ("C#", csharp::binding(&NOTHING)),
        ("Swift", swift::binding(&NOTHING)),
    ] {
        match printed {
            Ok(text) => {
                panic!("{language} printed a load check for a surface that declares none:\n{text}")
            }
            Err(why) => assert!(
                why.to_string().contains("sipral_abi_check"),
                "{language} refused for another reason: {why}"
            ),
        }
    }

    let printed = csharp::binding(&SYNTHETIC).unwrap();
    assert!(
        printed.contains(
            "    static Sipral()\n    {\n        AbiCheck(AbiVersionMajor, AbiVersionMinor);\n    }\n"
        ),
        "{printed}"
    );
    for declared in [
        "public static void AbiCheck(uint major, uint minor)",
        "public const uint AbiVersionMajor = 0;",
        "public const uint AbiVersionMinor = 8;",
    ] {
        assert!(
            printed.contains(declared),
            "C# calls what it does not declare: {declared}"
        );
    }

    let printed = swift::binding(&SYNTHETIC).unwrap();
    assert!(
        printed.contains(
            "/// try Sipral.abiCheck(major: Sipral.abiVersionMajor, minor: Sipral.abiVersionMinor)\n"
        ),
        "{printed}"
    );
    for declared in [
        "public static func abiCheck(major: UInt32, minor: UInt32) throws {",
        "public static let abiVersionMajor: UInt32 = 0",
        "public static let abiVersionMinor: UInt32 = 8",
    ] {
        assert!(
            printed.contains(declared),
            "Swift documents a call it does not declare: {declared}"
        );
    }
}

/// `sipral_abi_check` with only one parameter, which is not a major and a
/// minor version.
const CHECK_WRONG_ARITY: Function = Function {
    name: "sipral_abi_check",
    doc: &[" Whether this library can serve a binding generated against `major`.`minor`."],
    parameters: &[member("major", "u32")],
    returns: "SipralStatus",
};

/// `sipral_abi_check` with two parameters that are not `u32`.
const CHECK_WRONG_TYPES: Function = Function {
    name: "sipral_abi_check",
    doc: &[" Whether this library can serve a binding generated against `major`.`minor`."],
    parameters: &[member("major", "u64"), member("minor", "u64")],
    returns: "SipralStatus",
};

/// The major version alone, with no minor beside it.
const MAJOR_ONLY: &[Value] = &[Value {
    name: "SIPRAL_ABI_VERSION_MAJOR",
    doc: &[" Nothing built against another major works against this one."],
    rust_type: "u32",
    value: 0,
}];

/// The minor version alone, with no major beside it.
const MINOR_ONLY: &[Value] = &[Value {
    name: "SIPRAL_ABI_VERSION_MINOR",
    doc: &[" Raised by anything the header gains."],
    rust_type: "u32",
    value: 8,
}];

/// Every way a load check can be shaped wrong short of missing
/// `sipral_abi_check` entirely -- which
/// [`the_load_check_is_read_from_the_declarations`] already covers -- is
/// refused by name, not printed as a call to parameters or constants the
/// surface does not declare the way the back end assumes.
#[test]
fn a_load_check_shaped_wrong_is_refused() {
    let wrong_arity = Surface {
        functions: &[CHECK_WRONG_ARITY],
        constants: &[VERSION],
        ..NOTHING
    };
    let wrong_types = Surface {
        functions: &[CHECK_WRONG_TYPES],
        constants: &[VERSION],
        ..NOTHING
    };
    let missing_minor = Surface {
        functions: &[ABI_CHECK],
        constants: &[MAJOR_ONLY],
        ..NOTHING
    };
    let missing_major = Surface {
        functions: &[ABI_CHECK],
        constants: &[MINOR_ONLY],
        ..NOTHING
    };

    for (surface, expect) in [
        (&wrong_arity, "1 parameters"),
        (&wrong_types, "u64 and u64"),
        (&missing_minor, "SIPRAL_ABI_VERSION_MINOR"),
        (&missing_major, "SIPRAL_ABI_VERSION_MAJOR"),
    ] {
        for (language, printed) in [
            ("C#", csharp::binding(surface)),
            ("Swift", swift::binding(surface)),
        ] {
            match printed {
                Ok(text) => panic!(
                    "{language} printed a load check for a surface shaped wrong \
                     ({expect}):\n{text}"
                ),
                Err(why) => assert!(
                    why.to_string().contains(expect),
                    "{language} refused for another reason: {why}"
                ),
            }
        }
    }
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
        Role::Records { .. } => "an array of records going in",
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
            if let Role::Buffer { data, .. }
            | Role::Fill { data, .. }
            | Role::Records { data, .. } = role
            {
                out.insert(format!(
                    "{} whose element is {}",
                    role_kind(&role),
                    kind_of(surface, &data.ty)
                ));
            }
            if let Role::Config(read) = role {
                for listed in listed_in(surface, read, "the golden files").expect("a struct") {
                    out.insert(format!(
                        "a struct going in that holds an array of {}",
                        named_kind(surface, listed.element.record.name)
                    ));
                }
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
    // C# prints this one, so it declares what C# checks the ABI with at load
    constants: &[VERSION],
    functions: &[ABI_CHECK],
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

    // Kotlin spells them too, in the C function the JNI shim prints for the
    // callback to land in -- C, with no escape -- so it refuses the same
    // word for the same reason, naming the same declaration
    let why = refusal(&CALLBACK_KEYWORD, &kotlin::Names);
    assert!(why.contains("`class` is a keyword in C or in C++"), "{why}");
    assert!(why.contains("SipralEventCallback"), "{why}");
    assert!(kotlin::shim(&CALLBACK_KEYWORD).is_err());

    // Swift prints no signature for the callback at all -- it imports the C
    // one -- so it has nothing to claim and nothing to refuse
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

// ------------------------------------------------------------ Kotlin and JNI

#[test]
fn a_struct_going_in_is_a_kotlin_class_the_shim_copies_in() {
    let printed = kotlin::binding(&SYNTHETIC).unwrap();
    // one field per member: the buffer and its length as one, the callback
    // and its user pointer as one listener, and the size member nowhere
    for field in [
        "class SipralStackConfig(",
        "    val eventListener: SipralEventListener? = null,",
        "    val bindAddress: String? = null,",
        "    val echo: Long = 0,",
    ] {
        assert!(printed.contains(field), "no `{field}` in:\n{printed}");
    }
    assert!(
        printed.contains("    fun stackCreate(config: SipralStackConfig): Long {"),
        "{printed}"
    );
    assert!(
        printed.contains(
            "external fun sipral_stack_create(configEventCallback: Long, configBindAddress: \
             ByteArray?, configEcho: Long, configHeadersBytes: ByteArray?, \
             configHeadersLengths: LongArray?, stack: LongArray): Int"
        ),
        "{printed}"
    );

    let shim = kotlin::shim(&SYNTHETIC).unwrap();
    for line in [
        "    sipral_stack_config_t config_value;\n",
        "    memset(&config_value, 0, sizeof config_value);\n",
        "    config_value.size = sizeof config_value;\n",
        "    config_value.bind_address = (const char *)configBindAddress_data;\n",
        "    config_value.bind_address_len = (size_t)configBindAddress_size;\n",
        "    config_value.echo = (sipral_toggle_t)configEcho;\n",
        "sipral_stack_create(&config_value, &stack_value);",
    ] {
        assert!(shim.contains(line), "no `{line}` in:\n{shim}");
    }
    assert!(
        !shim.contains("(const sipral_stack_config_t *)(intptr_t)config"),
        "the struct still crosses as an address:\n{shim}"
    );
}

#[test]
fn the_callback_lands_in_a_kotlin_listener() {
    let printed = kotlin::binding(&SYNTHETIC).unwrap();
    assert!(
        printed.contains(
            "fun interface SipralEventListener {\n    fun onEvent(event: SipralEvent)\n}"
        ),
        "{printed}"
    );
    // the head of the event is handed over, and the union whose arm nothing
    // in the declarations names is not
    assert!(
        printed.contains(
            "    fun deliver(key: Long, size: Long, stack: Long, kind: Long, message: ByteArray?) {"
        ),
        "{printed}"
    );
    // kept by the wrapper, tied to the handle the call made, and let go of
    // where that handle is destroyed
    for line in [
        "        val configEventCallback = SipralEventListeners.register(config.eventListener)\n",
        "        SipralEventListeners.made(configEventCallback, status, stackSlot[0])\n",
        "    fun stackDestroy(stack: Long) {\n        val status = \
         SipralNative.sipral_stack_destroy(stack)\n        SipralEventListeners.gone(stack)\n",
    ] {
        assert!(printed.contains(line), "no `{line}` in:\n{printed}");
    }

    let shim = kotlin::shim(&SYNTHETIC).unwrap();
    assert!(
        shim.contains(
            "(*env)->GetStaticMethodID(env, jni_event_callback_class, \"deliver\", \"(JJJJ[B)V\")"
        ),
        "the descriptor the shim looks deliver up by is not the one Kotlin declares:\n{shim}"
    );
    assert!(
        shim.contains("    config_value.event_callback = configEventCallback != 0 ? jni_event_callback : NULL;\n"),
        "{shim}"
    );
    assert!(
        shim.contains(
            "    config_value.event_user_data = (void *)(intptr_t)configEventCallback;\n"
        ),
        "{shim}"
    );
    let landing = shim
        .split("static void\njni_event_callback(")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .unwrap_or_else(|| panic!("no landing function in:\n{shim}"));
    // attach a thread only when it is not attached, and detach only what was
    // attached here: detaching a thread the JVM made would pull it out from
    // under the Kotlin that called the poll
    assert!(
        landing.contains("if (found == JNI_EDETACHED) {"),
        "{landing}"
    );
    assert_eq!(
        landing.matches("DetachCurrentThread").count(),
        1,
        "{landing}"
    );
    assert!(
        landing.contains(
            "    if (attached) {\n        (*jni_vm)->DetachCurrentThread(jni_vm);\n    }"
        ),
        "{landing}"
    );
    // and the array made for each event is deleted before the next one: a
    // poll delivers all of them inside one native call
    let checked = landing.find("ExceptionCheck").unwrap_or(usize::MAX);
    let deleted = landing
        .find("(*env)->DeleteLocalRef(env, message);")
        .unwrap_or_else(|| panic!("the array made for an event is never deleted:\n{landing}"));
    assert!(
        checked < deleted,
        "a JNI call is made with a Java exception possibly pending:\n{landing}"
    );
}

#[test]
fn a_listener_kept_for_a_call_that_throws_is_let_go_of() {
    // A call can throw rather than answer -- a native library that did not
    // load, one that serves another ABI, an array the JVM could not make --
    // and a listener kept for it would then be kept for ever, with whatever
    // it holds. So it is kept as the last thing before the call, and let go
    // of in a finally around the call, which sees no status when there was
    // none.
    let printed = kotlin::binding(&SYNTHETIC).unwrap();
    let wrapper = printed
        .split("    fun stackCreate(config: SipralStackConfig): Long {\n")
        .nth(1)
        .and_then(|rest| rest.split("\n    }\n").next())
        .unwrap_or_else(|| panic!("no stackCreate in:\n{printed}"));
    let kept = wrapper
        .find("        val configEventCallback = SipralEventListeners.register(config.eventListener)\n")
        .unwrap_or_else(|| panic!("the listener is never kept:\n{wrapper}"));
    let tried = wrapper
        .find("        try {\n            status = SipralNative.sipral_stack_create(")
        .unwrap_or_else(|| panic!("the call that keeps a listener is not tried:\n{wrapper}"));
    let settled = wrapper
        .find(
            "        } finally {\n            \
             SipralEventListeners.made(configEventCallback, status, stackSlot[0])\n        }\n",
        )
        .unwrap_or_else(|| panic!("the listener is not settled in a finally:\n{wrapper}"));
    assert!(kept < tried && tried < settled, "{wrapper}");
    let between = &wrapper[kept..tried];
    assert_eq!(
        between.lines().count(),
        2,
        "something that can throw sits between keeping the listener and trying the call:\n{wrapper}"
    );
    assert!(between.contains("        var status = -1\n"), "{wrapper}");
}

/// The one entry point a binding asks at load, and nothing else.
const ABI_CHECKED: Surface = Surface {
    version: (0, 9, 0),
    enumerations: &[STATUS],
    functions: &[Function {
        name: "sipral_abi_check",
        doc: &[" Whether this library serves a binding of this version."],
        parameters: &[member("major", "u32"), member("minor", "u32")],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

/// The same entry point in a shape the binding cannot ask it with.
const ABI_UNCHECKABLE: Surface = Surface {
    functions: &[Function {
        name: "sipral_abi_check",
        doc: &[],
        parameters: &[
            member("version", "*const u8"),
            member("version_len", "usize"),
        ],
        returns: "SipralStatus",
    }],
    ..ABI_CHECKED
};

#[test]
fn the_kotlin_binding_checks_the_abi_as_it_loads() {
    let printed = kotlin::binding(&ABI_CHECKED).unwrap();
    assert!(
        printed
            .contains("        System.loadLibrary(\"sipral_jni\")\n        agree(0, 9)\n    }\n"),
        "{printed}"
    );
    for line in [
        "        val status = sipral_abi_check(major, minor)\n",
        "            throw SipralException(SipralStatus.of(status), Sipral.lastErrorMessage())\n",
    ] {
        assert!(printed.contains(line), "no `{line}` in:\n{printed}");
    }
    // the binding that ships asks with the version it was printed from
    let real = kotlin::binding(&sipral_ffi::abi::SURFACE).unwrap();
    let (major, minor, _) = sipral_ffi::abi::SURFACE.version;
    assert!(
        real.contains(&format!(
            "        System.loadLibrary(\"sipral_jni\")\n        agree({major}, {minor})\n"
        )),
        "the Kotlin binding no longer checks the ABI as it loads"
    );
    // and a check it could not call is refused rather than left out
    let why = kotlin::binding(&ABI_UNCHECKABLE).unwrap_err().to_string();
    assert!(why.contains("sipral_abi_check"), "{why}");
}

/// A struct going in with a pointer the conventions do not pair with a
/// length.
const UNBUILDABLE: Surface = Surface {
    aliases: &[Alias {
        name: "SipralHandle",
        doc: &[],
        stands: Stands::For("u64"),
    }],
    records: &[Record {
        name: "SipralOddConfig",
        doc: &[],
        shape: Shape::Struct,
        fields: &[
            member("size", "usize"),
            member("blob", "*const u8"),
            member("blob_size", "usize"),
        ],
        size: 24,
    }],
    functions: &[Function {
        name: "sipral_odd_create",
        doc: &[],
        parameters: &[
            member("config", "*const SipralOddConfig"),
            member("out_odd", "*mut SipralHandle"),
        ],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

/// A struct going in that holds a listener, handed to an entry point with
/// nothing to undo what it made.
const UNRELEASED: Surface = Surface {
    aliases: &[
        Alias {
            name: "SipralHandle",
            doc: &[],
            stands: Stands::For("u64"),
        },
        Alias {
            name: "SipralEventCallback",
            doc: &[],
            stands: Stands::Callback(&[
                member("event", "*const SipralEvent"),
                member("user_data", "*mut c_void"),
            ]),
        },
    ],
    records: &[
        Record {
            name: "SipralEvent",
            doc: &[],
            shape: Shape::Struct,
            fields: &[member("size", "usize"), member("stack", "SipralHandle")],
            size: 16,
        },
        Record {
            name: "SipralStackConfig",
            doc: &[],
            shape: Shape::Struct,
            fields: &[
                member("size", "usize"),
                member("event_callback", "SipralEventCallback"),
                member("event_user_data", "*mut c_void"),
            ],
            size: 24,
        },
    ],
    functions: &[Function {
        name: "sipral_stack_create",
        doc: &[],
        parameters: &[
            member("config", "*const SipralStackConfig"),
            member("out_stack", "*mut SipralHandle"),
        ],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

#[test]
fn a_struct_going_in_that_kotlin_cannot_build_is_refused() {
    // a pointer and a `blob_size` is not the buffer convention, and guessing
    // that it is would hand the library a length it never asked for
    let why = refusal(&UNBUILDABLE, &kotlin::Names);
    assert!(
        why.contains("SipralOddConfig::blob") && why.contains("blob_len"),
        "{why}"
    );
    // a listener nothing lets go of is a listener kept for ever
    let why = refusal(&UNRELEASED, &kotlin::Names);
    assert!(
        why.contains("sipral_stack_create") && why.contains("_destroy"),
        "{why}"
    );
    // the other three have no class to build and no listener to keep
    for how in [&c::Names as &dyn Spelling, &csharp::Names, &swift::Names] {
        if let Err(why) = audit(&UNRELEASED, how) {
            panic!("{}: {why}", how.language());
        }
    }
}

/// A struct going in that holds a listener, handed to an entry point that
/// writes back no handle at all: nothing to tie the listener to, and no
/// `_destroy` either. The missing destroyer is the reason named, because it
/// is the more fundamental problem and is checked first.
const ORPHANED: Surface = Surface {
    aliases: &[Alias {
        name: "SipralEventCallback",
        doc: &[],
        stands: Stands::Callback(&[
            member("event", "*const SipralEvent"),
            member("user_data", "*mut c_void"),
        ]),
    }],
    records: &[
        Record {
            name: "SipralEvent",
            doc: &[],
            shape: Shape::Struct,
            fields: &[member("size", "usize")],
            size: 8,
        },
        Record {
            name: "SipralWatchConfig",
            doc: &[],
            shape: Shape::Struct,
            fields: &[
                member("size", "usize"),
                member("event_callback", "SipralEventCallback"),
                member("event_user_data", "*mut c_void"),
            ],
            size: 24,
        },
    ],
    functions: &[Function {
        name: "sipral_watch_arm",
        doc: &[],
        parameters: &[member("config", "*const SipralWatchConfig")],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

#[test]
fn a_listener_with_no_handle_and_no_destroyer_is_refused_for_the_destroyer() {
    // sipral_watch_arm keeps a listener, writes back no handle, and the
    // surface has no sipral_watch_destroy: both are wrong, and the missing
    // destroyer is named rather than the missing handle, because a caller
    // fixes the surface one problem at a time and the destroyer is the one
    // this generator can point at first.
    let why = refusal(&ORPHANED, &kotlin::Names);
    assert!(
        why.contains("sipral_watch_arm") && why.contains("_destroy"),
        "{why}"
    );
    assert!(
        !why.contains("writes back no handle"),
        "the destroyer check did not run first:\n{why}"
    );
}

/// A struct going in with no size member for the shim to set as it copies
/// the class across.
const UNVERSIONED_CONFIG: Surface = Surface {
    records: &[Record {
        name: "SipralPlainConfig",
        doc: &[],
        shape: Shape::Struct,
        fields: &[member("echo", "u32")],
        size: 4,
    }],
    functions: &[Function {
        name: "sipral_plain_create",
        doc: &[],
        parameters: &[member("config", "*const SipralPlainConfig")],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

/// A struct going in that holds nothing but numbers and is versioned: the
/// shape a struct handed back reads, printed as a data class already.
const NUMERIC_CONFIG: Surface = Surface {
    records: &[Record {
        name: "SipralNumericConfig",
        doc: &[],
        shape: Shape::Struct,
        fields: &[member("size", "usize"), member("echo", "u32")],
        size: 16,
    }],
    functions: &[Function {
        name: "sipral_numeric_create",
        doc: &[],
        parameters: &[member("config", "*const SipralNumericConfig")],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

#[test]
fn a_struct_going_in_with_no_shape_of_its_own_is_refused() {
    // no size member for the shim to fill in as it copies the class across
    let why = refusal(&UNVERSIONED_CONFIG, &kotlin::Names);
    assert!(
        why.contains("SipralPlainConfig") && why.contains("no size member"),
        "{why}"
    );
    // all-numeric and versioned is the one shape a struct handed back reads;
    // building it as a class too would print the same record twice
    let why = refusal(&NUMERIC_CONFIG, &kotlin::Names);
    assert!(
        why.contains("SipralNumericConfig") && why.contains("printed twice"),
        "{why}"
    );
}

/// A struct going in that holds a union by value, which a caller has no way
/// to set the live arm of.
const CONFIG_WITH_UNION: Surface = Surface {
    records: &[
        Record {
            name: "SipralArm",
            doc: &[],
            shape: Shape::Union,
            fields: &[member("a", "u32"), member("b", "u32")],
            size: 4,
        },
        Record {
            name: "SipralUnionConfig",
            doc: &[],
            shape: Shape::Struct,
            fields: &[
                member("size", "usize"),
                Member {
                    name: "arm",
                    rust_type: "SipralArm",
                    doc: &[],
                },
            ],
            size: 8,
        },
    ],
    functions: &[Function {
        name: "sipral_union_create",
        doc: &[],
        parameters: &[member("config", "*const SipralUnionConfig")],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

#[test]
fn a_struct_going_in_that_holds_a_union_is_refused() {
    let why = refusal(&CONFIG_WITH_UNION, &kotlin::Names);
    assert!(
        why.contains("SipralUnionConfig::arm")
            && why.contains("is a union inside a struct a caller builds"),
        "{why}"
    );
}

/// A struct going in that holds another struct by value, which the buffer
/// and listener conventions do not cover either.
const CONFIG_WITH_NESTED_STRUCT: Surface = Surface {
    records: &[
        Record {
            name: "SipralNestedStruct",
            doc: &[],
            shape: Shape::Struct,
            fields: &[member("value", "u32")],
            size: 4,
        },
        Record {
            name: "SipralNestedConfig",
            doc: &[],
            shape: Shape::Struct,
            fields: &[
                member("size", "usize"),
                Member {
                    name: "nested",
                    rust_type: "SipralNestedStruct",
                    doc: &[],
                },
            ],
            size: 8,
        },
    ],
    functions: &[Function {
        name: "sipral_nested_create",
        doc: &[],
        parameters: &[member("config", "*const SipralNestedConfig")],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

#[test]
fn a_struct_going_in_that_holds_a_struct_by_value_is_refused() {
    let why = refusal(&CONFIG_WITH_NESTED_STRUCT, &kotlin::Names);
    assert!(
        why.contains("SipralNestedConfig::nested") && why.contains("holds a struct by value"),
        "{why}"
    );
}

/// A struct handed to a listener that itself holds a callback: a listener
/// has nothing to call it with.
const EVENT_WITH_CALLBACK: Surface = Surface {
    aliases: &[
        Alias {
            name: "SipralHandle",
            doc: &[],
            stands: Stands::For("u64"),
        },
        Alias {
            name: "SipralEventCallback",
            doc: &[],
            stands: Stands::Callback(&[
                member("event", "*const SipralEvent"),
                member("user_data", "*mut c_void"),
            ]),
        },
        Alias {
            name: "SipralNestedCallback",
            doc: &[],
            stands: Stands::Callback(&[
                member("event", "*const SipralNestedEvent"),
                member("user_data", "*mut c_void"),
            ]),
        },
    ],
    records: &[
        Record {
            name: "SipralNestedEvent",
            doc: &[],
            shape: Shape::Struct,
            fields: &[member("size", "usize")],
            size: 8,
        },
        Record {
            name: "SipralEvent",
            doc: &[],
            shape: Shape::Struct,
            fields: &[
                member("size", "usize"),
                Member {
                    name: "nested_callback",
                    rust_type: "SipralNestedCallback",
                    doc: &[],
                },
                member("nested_user_data", "*mut c_void"),
            ],
            size: 24,
        },
        Record {
            name: "SipralStackConfig",
            doc: &[],
            shape: Shape::Struct,
            fields: &[
                member("size", "usize"),
                member("event_callback", "SipralEventCallback"),
                member("event_user_data", "*mut c_void"),
            ],
            size: 24,
        },
    ],
    functions: &[
        Function {
            name: "sipral_stack_create",
            doc: &[],
            parameters: &[
                member("config", "*const SipralStackConfig"),
                member("out_stack", "*mut SipralHandle"),
            ],
            returns: "SipralStatus",
        },
        Function {
            name: "sipral_stack_destroy",
            doc: &[],
            parameters: &[member("stack", "SipralHandle")],
            returns: "SipralStatus",
        },
    ],
    ..NOTHING
};

#[test]
fn a_struct_handed_to_a_listener_that_holds_a_callback_is_refused() {
    let why = refusal(&EVENT_WITH_CALLBACK, &kotlin::Names);
    assert!(
        why.contains("SipralEvent::nested_callback")
            && why.contains("is a callback inside a struct the library hands to a listener"),
        "{why}"
    );
}

/// A struct handed to a listener with a member named for the map the
/// listeners are kept in, beside everything else a listener needs.
const SHADOWING: Surface = Surface {
    records: &[
        Record {
            name: "SipralEvent",
            doc: &[],
            shape: Shape::Struct,
            fields: &[member("size", "usize"), member("listening", "u32")],
            size: 16,
        },
        Record {
            name: "SipralStackConfig",
            doc: &[],
            shape: Shape::Struct,
            fields: &[
                member("size", "usize"),
                member("event_callback", "SipralEventCallback"),
                member("event_user_data", "*mut c_void"),
            ],
            size: 24,
        },
    ],
    functions: &[
        Function {
            name: "sipral_stack_create",
            doc: &[],
            parameters: &[
                member("config", "*const SipralStackConfig"),
                member("out_stack", "*mut SipralHandle"),
            ],
            returns: "SipralStatus",
        },
        Function {
            name: "sipral_stack_destroy",
            doc: &[],
            parameters: &[member("stack", "SipralHandle")],
            returns: "SipralStatus",
        },
    ],
    ..UNRELEASED
};

/// A struct handed to a listener that carries a length-prefixed buffer of
/// characters rather than raw bytes: text, not an array.
const EVENT_WITH_TEXT: Surface = Surface {
    records: &[
        Record {
            name: "SipralEvent",
            doc: &[],
            shape: Shape::Struct,
            fields: &[
                member("size", "usize"),
                Member {
                    name: "reason",
                    rust_type: "*const c_char",
                    doc: &[],
                },
                member("reason_len", "usize"),
            ],
            size: 24,
        },
        Record {
            name: "SipralStackConfig",
            doc: &[],
            shape: Shape::Struct,
            fields: &[
                member("size", "usize"),
                member("event_callback", "SipralEventCallback"),
                member("event_user_data", "*mut c_void"),
            ],
            size: 24,
        },
    ],
    functions: &[
        Function {
            name: "sipral_stack_create",
            doc: &[],
            parameters: &[
                member("config", "*const SipralStackConfig"),
                member("out_stack", "*mut SipralHandle"),
            ],
            returns: "SipralStatus",
        },
        Function {
            name: "sipral_stack_destroy",
            doc: &[],
            parameters: &[member("stack", "SipralHandle")],
            returns: "SipralStatus",
        },
    ],
    ..UNRELEASED
};

#[test]
fn a_struct_handed_to_a_listener_with_a_text_buffer_reads_as_a_string() {
    // the buffer convention on a struct going in reads bytes as a String
    // when they point at characters; a struct handed to a listener follows
    // the same rule rather than always handing over an array
    let printed = kotlin::binding(&EVENT_WITH_TEXT).unwrap();
    assert!(printed.contains("val reason: String?"), "{printed}");
    assert!(
        printed.contains("reason?.let { String(it, Charsets.UTF_8) }"),
        "{printed}"
    );
}

#[test]
fn a_member_that_hides_the_listeners_from_deliver_is_refused() {
    // deliver looks the listener up as `listening[key]`, so a member handed
    // over under that name is what the lookup would read, and the Kotlin
    // would not compile
    let why = refusal(&SHADOWING, &kotlin::Names);
    assert!(
        why.contains("SipralEvent::listening") && why.contains("`listening`"),
        "{why}"
    );
}

#[test]
fn a_listener_that_throws_is_not_promised_that_the_poll_goes_on() {
    // What a listener throws goes to the thread's uncaught exception handler,
    // and whether the poll carries on is that handler's to decide: the one
    // Android installs ends the process. The listener's documentation says
    // so rather than promising a poll that carries on regardless.
    let printed = kotlin::binding(&SYNTHETIC).unwrap();
    let about = printed
        .split("fun interface SipralEventListener {")
        .next()
        .and_then(|before| before.rsplit("/**").next())
        .unwrap_or_else(|| panic!("no listener in:\n{printed}"));
    assert!(
        about.contains("Android's default handler does not return"),
        "{about}"
    );
    assert!(
        !about.contains("handler, and the poll carries on.\n"),
        "{about}"
    );
}

// ------------------------------------------------------------ arrays of records going in

/// Header fields handed to an entry point, the way `sipral_call_set_headers`
/// takes them.
const LABEL: Function = Function {
    name: "sipral_stack_label",
    doc: &[],
    parameters: &[
        member("stack", "u64"),
        member("headers", "*const SipralHeader"),
        member("headers_len", "usize"),
    ],
    returns: "SipralStatus",
};

/// The same pointer with a length beside it that is not named for it, which
/// is therefore not its count.
const TAG: Function = Function {
    name: "sipral_stack_tag",
    doc: &[],
    parameters: &[
        member("stack", "u64"),
        member("headers", "*const SipralHeader"),
        member("count", "usize"),
    ],
    returns: "SipralStatus",
};

const RECORDS: Surface = Surface {
    records: &[HEADER],
    functions: &[LABEL, TAG],
    ..NOTHING
};

#[test]
fn an_array_of_records_going_in_is_read_off_the_declarations() {
    let kinds = |surface: &Surface, name: &str| {
        let (_, read) = functions(surface)
            .unwrap()
            .into_iter()
            .find(|(function, _)| function.name == name)
            .unwrap_or_else(|| panic!("no {name}"));
        roles(surface, &read)
            .iter()
            .map(role_kind)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        kinds(&RECORDS, "sipral_stack_label"),
        ["a plain value", "an array of records going in"]
    );
    // a length the pointer is not named in is some other number, and reading
    // it as the count is the mistake the rule is there to rule out
    assert_eq!(
        kinds(&RECORDS, "sipral_stack_tag"),
        ["a plain value", "a struct going in", "a plain value"]
    );

    let surface = &sipral_ffi::abi::SURFACE;
    assert_eq!(
        kinds(surface, "sipral_call_set_headers"),
        [
            "a plain value",
            "a plain value",
            "an array of records going in"
        ]
    );
    // and as two members of every struct going in that carries them
    for (name, record) in [
        ("sipral_call_place", "SipralCallConfig"),
        ("sipral_call_consult", "SipralCallConfig"),
        ("sipral_account_add", "SipralAccountConfig"),
    ] {
        let (_, read) = functions(surface)
            .unwrap()
            .into_iter()
            .find(|(function, _)| function.name == name)
            .unwrap();
        let config = read
            .iter()
            .find(|parameter| parameter.member.name == "config")
            .unwrap();
        let listed = listed_in(surface, config, "the test").unwrap();
        let [one] = listed.as_slice() else {
            panic!("{record} holds {} arrays of records", listed.len());
        };
        assert_eq!(
            (one.data.member.name, one.len.member.name),
            ("headers", "headers_len"),
            "{record}"
        );
        assert_eq!(one.element.record.name, "SipralHeader");
        let texts: Vec<_> = one
            .element
            .texts
            .iter()
            .map(|text| (text.data.member.name, text.len.member.name))
            .collect();
        assert_eq!(texts, [("name", "name_len"), ("value", "value_len")]);
    }
}

#[test]
fn every_binding_hands_over_a_list_with_its_own_count() {
    let surface = &sipral_ffi::abi::SURFACE;

    // Swift: an array of a struct it prints, made into the C array inside
    // the call, with the array's pointer and the array's count, and no length
    // of the caller's anywhere
    let printed = swift::binding(surface).unwrap();
    for line in [
        "    public static func callSetHeaders(stack: SipralHandle, call: SipralHandle, \
         headers: [SipralHeader]) throws {\n        let status =\n            \
         SipralHeader.withUnsafeArray(headers) { p2 in\n                \
         sipral_call_set_headers(stack, call, p2.baseAddress, p2.count)\n",
        "config: sipral_call_config_t, configHeaders: [SipralHeader], nowMs: UInt64) throws \
         -> SipralHandle {\n",
        "SipralHeader.withUnsafeArray(configHeaders) { p2Headers -> sipral_status_t in\n                \
         config.headers = p2Headers.baseAddress\n                \
         config.headers_len = p2Headers.count\n                \
         return sipral_call_place(stack, account, &config, &call, nowMs)\n",
        "config: sipral_account_config_t, configHeaders: [SipralHeader]) throws -> SipralHandle {\n",
    ] {
        assert!(printed.contains(line), "Swift: no `{line}`");
    }
    for stale in ["headersLen", "headers: sipral_header_t"] {
        assert!(!printed.contains(stale), "Swift still prints `{stale}`");
    }

    // C#: an array of tuples, copied into memory the wrapper pins and lets go
    // of as the call returns, and the address and count of that
    let printed = csharp::binding(surface).unwrap();
    for line in [
        "internal static extern SipralStatus sipral_call_set_headers(ulong stack, ulong call, \
         IntPtr headers, nuint headersLen);",
        "    public static void CallSetHeaders(ulong stack, ulong call, (string Name, string \
         Value)[] headers)\n    {\n        using var headersArray = new \
         SipralHeaderArray(headers);\n        Check(NativeMethods.sipral_call_set_headers(stack, \
         call, headersArray.Address, headersArray.Count));\n",
        "in SipralCallConfig config, (string Name, string Value)[]? configHeaders, ulong nowMs)\n",
        "        using var configHeadersArray = new SipralHeaderArray(configHeaders);\n        \
         var configValue = config;\n        configValue.Headers = \
         configHeadersArray.Address;\n        configValue.HeadersLen = \
         configHeadersArray.Count;\n        Check(NativeMethods.sipral_call_place(stack, \
         account, in configValue, out var call, nowMs));\n",
    ] {
        assert!(printed.contains(line), "C#: no `{line}`");
    }
    assert!(
        !printed.contains("in SipralHeader headers"),
        "C# still hands over one record"
    );

    // Kotlin: a list of a class it prints, packed for the shim, and the shim
    // hands the library the array it made and that array's count
    let printed = kotlin::binding(surface).unwrap();
    for line in [
        "    fun callSetHeaders(stack: Long, call: Long, headers: List<SipralHeader>) {\n        \
         val (headersBytes, headersLengths) = SipralHeader.packed(headers)\n        \
         check(SipralNative.sipral_call_set_headers(stack, call, headersBytes, headersLengths))\n",
        "external fun sipral_call_set_headers(stack: Long, call: Long, headersBytes: ByteArray?, \
         headersLengths: LongArray?): Int",
        "    val headers: List<SipralHeader>? = null,\n",
        "        val (configHeadersBytes, configHeadersLengths) = \
         SipralHeader.packed(config.headers)\n",
    ] {
        assert!(printed.contains(line), "Kotlin: no `{line}`");
    }
    let shim = kotlin::shim(surface).unwrap();
    for line in [
        "        status = sipral_call_set_headers((sipral_handle_t)stack, (sipral_handle_t)call, \
         headers_array, headers_count);\n",
        "    config_value.headers = configHeaders_array;\n    config_value.headers_len = \
         configHeaders_count;\n",
    ] {
        assert!(shim.contains(line), "the JNI shim: no `{line}`");
    }
    assert!(
        !shim.contains("(const sipral_header_t *)(intptr_t)"),
        "the shim still hands over an address a Kotlin caller supplied"
    );
}

#[test]
fn the_shim_checks_every_length_before_it_points_into_the_bytes() {
    let shim = kotlin::shim(&SYNTHETIC).unwrap();
    let helper = shim
        .split("static int\njni_header_array(")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .unwrap_or_else(|| panic!("no list helper in:\n{shim}"));
    // one check per piece of text, each against what is left of the bytes
    // and made before the pointer the length goes with
    let check = "if (length < 0 || (uint64_t)length > (uint64_t)((size_t)room - at)) {";
    assert_eq!(helper.matches(check).count(), 2, "{helper}");
    let checked = helper.find(check).unwrap_or(usize::MAX);
    let pointed = helper
        .find("array[index].name = length == 0 ? NULL : (const char *)pinned + at;")
        .unwrap_or_else(|| panic!("{helper}"));
    assert!(checked < pointed, "{helper}");
    // and bytes the lengths leave over are refused too, including bytes with
    // no lengths at all, which would otherwise reach the library as no list
    assert!(
        helper.contains("if (index != count || at != (size_t)room) {"),
        "{helper}"
    );
    let empty = helper
        .find("    if (count == 0) {\n        if (room != 0) {\n            jni_refuse(env, ")
        .unwrap_or_else(|| panic!("no refusal of bytes behind no lengths in:\n{helper}"));
    let allowed = helper
        .find("        return 1;\n    }\n")
        .unwrap_or_else(|| panic!("{helper}"));
    assert!(empty < allowed, "{helper}");
    assert!(
        !helper.contains("if (lengths == NULL) {\n        return 1;"),
        "{helper}"
    );

    // Made after every other fetch, since a list that makes no array leaves an
    // exception pending; the call and every write back only when it made one;
    // and what it pinned let go of whatever happened.
    let create = shim
        .split("Java_org_sipral_SipralNative_sipral_1stack_1create(")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .unwrap_or_else(|| panic!("no sipral_stack_create in:\n{shim}"));
    let at = |what: &str| {
        create
            .find(what)
            .unwrap_or_else(|| panic!("no `{what}` in:\n{create}"))
    };
    let fetched = at("configBindAddress_data = ");
    let made = at("ready = ready && jni_header_array(env, configHeadersBytes, ");
    let called = at("    if (ready) {\n        status = sipral_stack_create(");
    let released = at("    jni_header_release(env, configHeadersBytes, ");
    let written = at("    if (ready) {\n        {\n            jlong slot");
    assert!(
        fetched < made && made < called && called < released && released < written,
        "{create}"
    );
}

/// An element with a size member.
const VERSIONED_ELEMENT: Surface = Surface {
    records: &[Record {
        name: "SipralHeader",
        doc: &[],
        shape: Shape::Struct,
        fields: &[
            member("size", "usize"),
            member("name", "*const c_char"),
            member("name_len", "usize"),
        ],
        size: 24,
    }],
    functions: &[LABEL],
    ..NOTHING
};

/// An element with a member that is not text.
const NUMBER_ELEMENT: Surface = Surface {
    records: &[Record {
        name: "SipralHeader",
        doc: &[],
        shape: Shape::Struct,
        fields: &[
            member("name", "*const c_char"),
            member("name_len", "usize"),
            member("weight", "u32"),
        ],
        size: 24,
    }],
    functions: &[LABEL],
    ..NOTHING
};

/// An element that is a union.
const UNION_ELEMENT: Surface = Surface {
    records: &[Record {
        name: "SipralHeader",
        doc: &[],
        shape: Shape::Union,
        fields: &[member("a", "u32"), member("b", "u32")],
        size: 4,
    }],
    functions: &[LABEL],
    ..NOTHING
};

/// An element of one member.
const SINGLE_ELEMENT: Surface = Surface {
    records: &[Record {
        name: "SipralHeader",
        doc: &[],
        shape: Shape::Struct,
        fields: &[member("name", "*const c_char"), member("name_len", "usize")],
        size: 16,
    }],
    functions: &[LABEL],
    ..NOTHING
};

/// An element with a member C# will not take as the name of a tuple element.
const REST_ELEMENT: Surface = Surface {
    records: &[Record {
        name: "SipralHeader",
        doc: &[],
        shape: Shape::Struct,
        fields: &[
            member("name", "*const c_char"),
            member("name_len", "usize"),
            member("rest", "*const c_char"),
            member("rest_len", "usize"),
        ],
        size: 32,
    }],
    functions: &[LABEL],
    ..NOTHING
};

/// A struct handed to a listener that holds an array of records.
const LISTENER_RECORDS: Surface = Surface {
    records: &[
        HEADER,
        Record {
            name: "SipralEvent",
            doc: &[],
            shape: Shape::Struct,
            fields: &[
                member("size", "usize"),
                member("headers", "*const SipralHeader"),
                member("headers_len", "usize"),
            ],
            size: 24,
        },
        Record {
            name: "SipralStackConfig",
            doc: &[],
            shape: Shape::Struct,
            fields: &[
                member("size", "usize"),
                member("event_callback", "SipralEventCallback"),
                member("event_user_data", "*mut c_void"),
            ],
            size: 24,
        },
    ],
    functions: &[
        Function {
            name: "sipral_stack_create",
            doc: &[],
            parameters: &[
                member("config", "*const SipralStackConfig"),
                member("out_stack", "*mut SipralHandle"),
            ],
            returns: "SipralStatus",
        },
        Function {
            name: "sipral_stack_destroy",
            doc: &[],
            parameters: &[member("stack", "SipralHandle")],
            returns: "SipralStatus",
        },
    ],
    ..UNRELEASED
};

/// An entry point that answers with text and takes an array of records.
const TEXT_WITH_RECORDS: Surface = Surface {
    records: &[HEADER],
    functions: &[Function {
        name: "sipral_stack_label_text",
        doc: &[],
        parameters: &[
            member("headers", "*const SipralHeader"),
            member("headers_len", "usize"),
        ],
        returns: "*const c_char",
    }],
    ..NOTHING
};

#[test]
fn an_element_a_binding_cannot_build_is_refused_by_name() {
    for (surface, expect) in [
        (
            &VERSIONED_ELEMENT,
            "SipralHeader is handed over as the element of an array and carries a size member",
        ),
        (
            &NUMBER_ELEMENT,
            "SipralHeader::weight is not a piece of text",
        ),
        (
            &UNION_ELEMENT,
            "SipralHeader is handed over as the element of an array and is a union",
        ),
    ] {
        // C hands the caller's pointer through and builds nothing
        if let Err(why) = audit(surface, &c::Names) {
            panic!("C: {why}");
        }
        for how in [
            &csharp::Names as &dyn Spelling,
            &kotlin::Names,
            &swift::Names,
        ] {
            let why = refusal(surface, how);
            assert!(
                why.contains(expect) && why.contains(&format!("the {} binding", how.language())),
                "{}: {why}",
                how.language()
            );
        }
    }

    // a tuple has no spelling for one member and no room for some names, and
    // a class or a struct has both
    let why = refusal(&SINGLE_ELEMENT, &csharp::Names);
    assert!(
        why.contains("SipralHeader") && why.contains("no tuple of one"),
        "{why}"
    );
    let why = refusal(&REST_ELEMENT, &csharp::Names);
    assert!(
        why.contains("SipralHeader::rest") && why.contains("`Rest`"),
        "{why}"
    );
    for surface in [&SINGLE_ELEMENT, &REST_ELEMENT] {
        for how in [&kotlin::Names as &dyn Spelling, &swift::Names] {
            if let Err(why) = audit(surface, how) {
                panic!("{}: {why}", how.language());
            }
        }
    }

    // Kotlin builds lists and reads none back out of what a listener is
    // handed, and prints a call that answers with text with nothing before it
    let why = refusal(&LISTENER_RECORDS, &kotlin::Names);
    assert!(
        why.contains("SipralEvent::headers") && why.contains("hands to a listener"),
        "{why}"
    );
    let why = refusal(&TEXT_WITH_RECORDS, &kotlin::Names);
    assert!(
        why.contains("sipral_stack_label_text") && why.contains("answers with text"),
        "{why}"
    );
}

/// Header fields behind a pointer the library may write through, with the
/// `_len` named for them: an array written back, which no back end builds.
const FILLED_RECORDS: Surface = Surface {
    records: &[HEADER],
    functions: &[Function {
        name: "sipral_stack_fill",
        doc: &[],
        parameters: &[
            member("stack", "u64"),
            member("headers", "*mut SipralHeader"),
            member("headers_len", "usize"),
        ],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

/// Versioned records behind a pointer the library may write through, with the
/// `_len` named for them: an array written back of a struct that does carry
/// its size.
const FILLED_VERSIONED: Surface = Surface {
    records: &[Record {
        name: "SipralTally",
        doc: &[],
        shape: Shape::Struct,
        fields: &[member("size", "usize"), member("sent", "u64")],
        size: 16,
    }],
    functions: &[Function {
        name: "sipral_stack_tallies",
        doc: &[],
        parameters: &[
            member("stack", "u64"),
            member("tallies", "*mut SipralTally"),
            member("tallies_len", "usize"),
        ],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

/// Header fields with a length beside them that is not named for them.
const COUNTED_RECORDS: Surface = Surface {
    records: &[HEADER],
    functions: &[TAG],
    ..NOTHING
};

#[test]
fn a_record_behind_a_pointer_with_a_length_no_binding_reads_is_refused() {
    // None of these is an array of records going in, and none is one struct
    // either: two are arrays the library writes back, the third points at a
    // record with no size member, which only an array is made of. Printed as
    // one struct, the wrapper hands C the address of a single element and a
    // length the caller chose, and C reads past the element.
    for (surface, parameter, record, why_not) in [
        (
            &FILLED_RECORDS,
            "sipral_stack_fill::headers",
            "SipralHeader",
            "an array the library writes back",
        ),
        (
            &FILLED_VERSIONED,
            "sipral_stack_tallies::tallies",
            "SipralTally",
            "an array the library writes back",
        ),
        (
            &COUNTED_RECORDS,
            "sipral_stack_tag::headers",
            "SipralHeader",
            "has no size member",
        ),
    ] {
        // C hands the caller's pointer and length through as they are
        if let Err(why) = audit(surface, &c::Names) {
            panic!("C: {why}");
        }
        let mut refusing: Vec<&dyn Spelling> = vec![&csharp::Names, &swift::Names];
        // Kotlin refuses a record with no size behind a const pointer before
        // it reaches an entry point, for the class it would have to build
        if why_not != "has no size member" {
            refusing.push(&kotlin::Names);
        }
        for how in refusing {
            let why = refusal(surface, how);
            assert!(
                why.contains(parameter)
                    && why.contains(record)
                    && why.contains(why_not)
                    && why.contains(&format!("the {} binding", how.language())),
                "{}: {why}",
                how.language()
            );
        }
        let why = refusal(surface, &kotlin::Names);
        assert!(why.contains(record), "Kotlin: {why}");
    }
}

/// An entry point that answers with text and takes a struct holding a list.
const TEXT_WITH_LISTED_CONFIG: Surface = Surface {
    records: &[
        HEADER,
        Record {
            name: "SipralCallConfig",
            doc: &[],
            shape: Shape::Struct,
            fields: &[
                member("size", "usize"),
                member("headers", "*const SipralHeader"),
                member("headers_len", "usize"),
            ],
            size: 24,
        },
    ],
    functions: &[Function {
        name: "sipral_call_label_text",
        doc: &[],
        parameters: &[member("config", "*const SipralCallConfig")],
        returns: "*const c_char",
    }],
    ..NOTHING
};

#[test]
fn a_call_that_answers_with_text_and_takes_a_list_is_refused_in_every_binding() {
    // a call that answers with text is printed with its parameters handed
    // through as they came, so a list would cross as whatever the caller
    // supplied beside it
    for (surface, function) in [
        (&TEXT_WITH_RECORDS, "sipral_stack_label_text"),
        (&TEXT_WITH_LISTED_CONFIG, "sipral_call_label_text"),
    ] {
        for how in [
            &csharp::Names as &dyn Spelling,
            &kotlin::Names,
            &swift::Names,
        ] {
            let why = refusal(surface, how);
            assert!(
                why.contains(function) && why.contains("answers with text"),
                "{}: {why}",
                how.language()
            );
        }
    }
}

/// A struct going in that carries its own size, immediately followed by a
/// plain length with nothing to do with it.
const SIZED_THING: Record = Record {
    name: "SipralThing",
    doc: &[],
    shape: Shape::Struct,
    fields: &[
        member("size", "usize"),
        member("label", "*const c_char"),
        member("label_len", "usize"),
        member("value", "u32"),
    ],
    size: 24,
};

/// A versioned struct going in beside a length that is some other number:
/// `counts_records` never reads this pointer as an array, since the pointee
/// carries a size member, and [`unprintable`](crate::model::unprintable) has
/// to let it through rather than refuse it the way it refuses the same shape
/// over a record with no size member.
const SIZED_BESIDE_A_LENGTH: Surface = Surface {
    records: &[SIZED_THING],
    functions: &[Function {
        name: "sipral_stack_configure",
        doc: &[],
        parameters: &[
            member("stack", "u64"),
            member("thing", "*const SipralThing"),
            member("extra", "usize"),
        ],
        returns: "SipralStatus",
    }],
    ..NOTHING
};

#[test]
fn a_versioned_struct_going_in_beside_an_unrelated_length_is_not_refused() {
    for how in [
        &csharp::Names as &dyn Spelling,
        &kotlin::Names,
        &swift::Names,
    ] {
        if let Err(why) = audit(&SIZED_BESIDE_A_LENGTH, how) {
            panic!("{}: {why}", how.language());
        }
    }
}

/// A record that has nothing to do with header fields, but is named the way
/// C# names the class a list of `SipralHeader` is pinned in.
const HEADER_ARRAY_COLLISION: Surface = Surface {
    records: &[
        HEADER,
        Record {
            name: "SipralHeaderArray",
            doc: &[],
            shape: Shape::Struct,
            fields: &[member("flag", "u32")],
            size: 4,
        },
    ],
    functions: &[LABEL],
    ..NOTHING
};

#[test]
fn a_list_class_named_for_an_unrelated_declaration_is_refused() {
    // `list_classes` names the class C# pins a list of `SipralHeader` in
    // `SipralHeaderArray` without asking the declarations first, and nothing
    // stops a later declaration from taking that name for something else;
    // the audit is what has to notice the two are printed as one.
    let why = refusal(&HEADER_ARRAY_COLLISION, &csharp::Names);
    assert!(
        why.contains("SipralHeaderArray") && why.contains("SipralHeader"),
        "{why}"
    );
}

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
