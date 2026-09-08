// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! STUN: the codec, the two message-integrity mechanisms, the fingerprint and
//! a binding client.
//!
//! Written from RFC 8489, which obsoletes RFC 5389; the pieces RFC 5389 had
//! and RFC 8489 kept are what a server that never moved will speak, and
//! nothing here needs the newer attributes to be present. The ICE attributes
//! come from RFC 8445 §16.1, and they are in the codec rather than in an ICE
//! module because they are ordinary attributes that this crate's later layers
//! read and write.
//!
//! What is deliberately absent is NAT type classification. RFC 5389 removed it
//! when it obsoleted RFC 3489, because real NATs do not fall into the classic
//! types and the algorithm gave wrong answers on the devices that were
//! actually deployed.

pub(crate) mod address;
mod attribute;
pub(crate) mod binding;
mod builder;
mod message;

pub use attribute::{AttributeType, ErrorCode, PasswordAlgorithm, UnknownRequired, error_code};
pub use binding::{
    BindingClient, BindingConfig, DEFAULT_RC, DEFAULT_RM, DEFAULT_RTO, Failure,
    LongTermCredentials, Password, Progress,
};
pub use builder::{BuildError, MessageBuilder};
pub use message::{
    Attribute, Attributes, Class, FINGERPRINT_XOR, HEADER_LEN, Integrity, MAGIC_COOKIE, Message,
    Method, OfferedAlgorithms, ParseError, TransactionId,
};
