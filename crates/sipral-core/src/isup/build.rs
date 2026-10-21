// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Writing an ISUP message (Q.763 §1.4 to §1.8, §2.3), for the seven types
//! [`super::parse`] reads into parts.

use super::{
    BackwardCall, CallEvent, Cause, ForwardCall, GenericNumber, IsupError, MessageType,
    NatureOfConnection, Number, Redirection, code,
};

/// An ISUP message being written: its mandatory parts, then its optional
/// parameters in the order given.
///
/// A parameter that cannot be written is remembered and returned by
/// [`IsupBuilder::build`], so the calls chain.
#[derive(Clone, Debug)]
pub struct IsupBuilder {
    kind: MessageType,
    fixed: Vec<u8>,
    variable: Option<Vec<u8>>,
    optional: Vec<(u8, Vec<u8>)>,
    failed: Option<IsupError>,
}

impl IsupBuilder {
    /// A message of this type, with nothing in it yet.
    #[must_use]
    pub const fn new(kind: MessageType) -> Self {
        Self {
            kind,
            fixed: Vec::new(),
            variable: None,
            optional: Vec::new(),
            failed: None,
        }
    }

    /// An IAM: its mandatory fixed part and its called party number.
    #[must_use]
    pub fn initial_address(
        nature: NatureOfConnection,
        forward: ForwardCall,
        category: u8,
        medium: u8,
        called: &Number,
    ) -> Self {
        let [first, second] = forward.to_bytes();
        Self::new(MessageType::InitialAddress)
            .fixed(&[nature.to_byte(), first, second, category, medium])
            .written(called.to_called_party(), Self::variable)
    }

    /// An ACM with these backward call indicators.
    #[must_use]
    pub fn address_complete(backward: BackwardCall) -> Self {
        Self::new(MessageType::AddressComplete).fixed(&backward.to_bytes())
    }

    /// A CPG reporting this event.
    #[must_use]
    pub fn call_progress(event: CallEvent) -> Self {
        Self::new(MessageType::CallProgress).fixed(&[event.to_byte()])
    }

    /// An ANM.
    #[must_use]
    pub const fn answer() -> Self {
        Self::new(MessageType::Answer)
    }

    /// A CON with these backward call indicators.
    #[must_use]
    pub fn connect(backward: BackwardCall) -> Self {
        Self::new(MessageType::Connect).fixed(&backward.to_bytes())
    }

    /// A REL for this cause.
    #[must_use]
    pub fn release(cause: Cause) -> Self {
        Self::new(MessageType::Release).variable(&cause.to_bytes())
    }

    /// An RLC.
    #[must_use]
    pub const fn release_complete() -> Self {
        Self::new(MessageType::ReleaseComplete)
    }

    /// The mandatory fixed part, octets as they go.
    #[must_use]
    pub fn fixed(mut self, octets: &[u8]) -> Self {
        self.fixed = octets.to_vec();
        self
    }

    /// The content of the one mandatory variable parameter.
    #[must_use]
    pub fn variable(mut self, content: &[u8]) -> Self {
        self.variable = Some(content.to_vec());
        self
    }

    /// One optional parameter: its name code and its content.
    #[must_use]
    pub fn optional(mut self, name: u8, content: &[u8]) -> Self {
        self.optional.push((name, content.to_vec()));
        self
    }

    /// The calling party number.
    #[must_use]
    pub fn calling_party(self, number: &Number) -> Self {
        self.written(number.to_calling_party(), |this, content| {
            this.optional(code::CALLING_PARTY_NUMBER, content)
        })
    }

    /// The original called number.
    #[must_use]
    pub fn original_called(self, number: &Number) -> Self {
        self.written(number.to_redirecting(), |this, content| {
            this.optional(code::ORIGINAL_CALLED_NUMBER, content)
        })
    }

    /// The redirecting number.
    #[must_use]
    pub fn redirecting(self, number: &Number) -> Self {
        self.written(number.to_redirecting(), |this, content| {
            this.optional(code::REDIRECTING_NUMBER, content)
        })
    }

    /// The connected number.
    #[must_use]
    pub fn connected(self, number: &Number) -> Self {
        self.written(number.to_connected(), |this, content| {
            this.optional(code::CONNECTED_NUMBER, content)
        })
    }

    /// The redirection information.
    #[must_use]
    pub fn redirection(self, redirection: Redirection) -> Self {
        self.optional(code::REDIRECTION_INFORMATION, &redirection.to_bytes())
    }

    /// One generic number; call again for another.
    #[must_use]
    pub fn generic_number(self, number: &GenericNumber) -> Self {
        self.written(number.to_bytes(), |this, content| {
            this.optional(code::GENERIC_NUMBER, content)
        })
    }

    /// Cause indicators as an optional parameter (an ACM's, a CPG's, an
    /// RLC's).
    #[must_use]
    pub fn cause(self, cause: Cause) -> Self {
        self.optional(code::CAUSE, &cause.to_bytes())
    }

    /// Backward call indicators as an optional parameter (an ANM's, a
    /// CPG's).
    #[must_use]
    pub fn backward_call(self, backward: BackwardCall) -> Self {
        self.optional(code::BACKWARD_CALL, &backward.to_bytes())
    }

    fn written(
        mut self,
        content: Result<Vec<u8>, IsupError>,
        put: impl FnOnce(Self, &[u8]) -> Self,
    ) -> Self {
        match content {
            Ok(content) => put(self, &content),
            Err(error) => {
                self.failed.get_or_insert(error);
                self
            }
        }
    }

    /// The message, from its message type code on.
    ///
    /// # Errors
    /// [`IsupError::Unwritable`] for a parameter that could not be written,
    /// a type other than the seven, a mandatory part that is not the one
    /// the type has, a parameter longer than 255 octets, or an optional
    /// parameter named zero.
    pub fn build(&self) -> Result<Vec<u8>, IsupError> {
        if let Some(failed) = &self.failed {
            return Err(failed.clone());
        }
        let layout = self.kind.layout().ok_or(IsupError::Unwritable(
            "a message type whose parts this builder does not know",
        ))?;
        if self.fixed.len() != layout.fixed {
            return Err(IsupError::Unwritable(
                "a mandatory fixed part of another length than the type's",
            ));
        }
        if usize::from(self.variable.is_some()) != layout.variable {
            return Err(IsupError::Unwritable(
                "a mandatory variable part the type does not have, or without the one it has",
            ));
        }
        let length = |content: &[u8]| {
            u8::try_from(content.len())
                .map_err(|_| IsupError::Unwritable("a parameter longer than 255 octets"))
        };
        let mut out = Vec::with_capacity(16);
        out.push(self.kind.code());
        out.extend_from_slice(&self.fixed);
        let variable = match &self.variable {
            Some(content) => Some((length(content)?, content)),
            None => None,
        };
        // the pointers: to the variable parameter, two octets on (itself and
        // the optional part's pointer), then to the optional part
        let optional_pointer = match variable {
            Some((size, _)) => {
                out.push(2);
                2 + u16::from(size)
            }
            None => 1,
        };
        if self.optional.is_empty() {
            out.push(0);
        } else {
            out.push(u8::try_from(optional_pointer).map_err(|_| {
                IsupError::Unwritable("a mandatory variable part too long to point past")
            })?);
        }
        if let Some((size, content)) = variable {
            out.push(size);
            out.extend_from_slice(content);
        }
        if !self.optional.is_empty() {
            for (name, content) in &self.optional {
                if *name == code::END_OF_OPTIONAL {
                    return Err(IsupError::Unwritable("an optional parameter named zero"));
                }
                out.push(*name);
                out.push(length(content)?);
                out.extend_from_slice(content);
            }
            out.push(code::END_OF_OPTIONAL);
        }
        Ok(out)
    }
}
