// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg_attr(not(test), no_std)]
#![warn(
    missing_debug_implementations,
    missing_docs,
    non_ascii_idents,
    trivial_casts,
    unused,
    unused_qualifications,
    clippy::expect_used,
    clippy::unwrap_used
)]
#![deny(unsafe_code)]

//! A Trussed API extension for authentication and a backend that implements it.
//!
//! This crate contains an API extension for [Trussed][], [`AuthExtension`][].  The extension
//! currently provides basic PIN handling with retry counters.  Applications can access it using
//! the [`AuthClient`][] trait.
//!
//! This crate also contains [`AuthBackend`][], an implementation of the auth extension that stores
//! PINs in the filesystem.
//!
//! # Examples
//!
//! ```
//! use trussed::{Bytes, syscall};
//! use trussed_auth::{AuthClient, PinId};
//!
//! #[repr(u8)]
//! enum Pin {
//!     User = 0,
//! }
//!
//! impl From<Pin> for PinId {
//!     fn from(pin: Pin) -> Self {
//!         (pin as u8).into()
//!     }
//! }
//!
//! fn authenticate_user<C: AuthClient>(client: &mut C, pin: Option<&[u8]>) -> bool {
//!     if !syscall!(client.has_pin(Pin::User)).has_pin {
//!         // no PIN set
//!         return true;
//!     }
//!     let Some(pin) = pin else {
//!         // PIN is set but not provided
//!         return false;
//!     };
//!     let Ok(pin) = Bytes::from_slice(pin) else {
//!         // provided PIN is too long
//!         return false;
//!     };
//!     // check PIN
//!     syscall!(client.check_pin(Pin::User, pin)).success
//! }
//! ```
//!
//! [Trussed]: https://docs.rs/trussed

mod backend;
mod extension;

use core::str::FromStr;

use serde::{Deserialize, Serialize};
use trussed::{
    config::MAX_SHORT_DATA_LENGTH,
    types::{Bytes, PathBuf},
};

pub use backend::{AuthBackend, AuthContext, MAX_HW_KEY_LEN};
pub use extension::{
    reply, request, AuthClient, AuthExtension, AuthReply, AuthRequest, AuthResult,
};

/// The maximum length of a PIN.
pub const MAX_PIN_LENGTH: usize = MAX_SHORT_DATA_LENGTH;

/// A PIN.
pub type Pin = Bytes<MAX_PIN_LENGTH>;

const BACKEND_DIR: &str = "backend-auth";

/// The ID of a PIN within the namespace of a client.
///
/// It is recommended that applications use an enum that implements `Into<PinId>`.
///
/// # Examples
///
/// ```
/// use trussed_auth::PinId;
///
/// #[repr(u8)]
/// enum Pin {
///     User = 0,
///     Admin = 1,
///     ResetCode = 2,
/// }
///
/// impl From<Pin> for PinId {
///     fn from(pin: Pin) -> Self {
///         (pin as u8).into()
///     }
/// }
/// ```
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize,
)]
pub struct PinId(u8);

/// Error obtained when trying to parse a [`PinId`][] either through [`PinId::from_path`][] or through the [`FromStr`](core::str::FromStr) implementation.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize,
)]
pub struct PinIdFromStrError;

impl PinId {
    /// Get the path to the PIN id.
    ///
    /// Path are of the form `pin.XX` where `xx` is the hexadecimal representation of the PIN number.
    pub fn path(&self) -> PathBuf {
        let mut path = [0; 6];
        path[0..4].copy_from_slice(b"pin.");
        path[4..].copy_from_slice(&self.hex());

        PathBuf::from(&path)
    }

    /// Get the hex representation of the PIN id
    pub fn hex(&self) -> [u8; 2] {
        const CHARS: &[u8; 16] = b"0123456789abcdef";
        [
            CHARS[usize::from(self.0 >> 4)],
            CHARS[usize::from(self.0 & 0xf)],
        ]
    }

    /// Parse a PinId path
    pub fn from_path(path: &str) -> Result<Self, PinIdFromStrError> {
        let path = path.strip_prefix("pin.").ok_or(PinIdFromStrError)?;
        if path.len() != 2 {
            return Err(PinIdFromStrError);
        }

        let id = u8::from_str_radix(&*path, 16).map_err(|_| PinIdFromStrError)?;
        Ok(PinId(id))
    }
}

impl From<u8> for PinId {
    fn from(id: u8) -> Self {
        Self(id)
    }
}

impl From<PinId> for u8 {
    fn from(id: PinId) -> Self {
        id.0
    }
}

impl FromStr for PinId {
    type Err = PinIdFromStrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_path(s)
    }
}

#[cfg(test)]
mod tests {
    use super::PinId;
    use trussed::types::PathBuf;

    #[test]
    fn pin_id_path() {
        for i in 0..u8::MAX {
            assert_eq!(Ok(PinId(i)), PinId::from_path(PinId(i).path().as_ref()));
            let actual = PinId(i).path();
            let expected = PathBuf::from(format!("pin.{i:02x}").as_str());
            println!("id: {i}, actual: {actual}, expected: {expected}");
            assert_eq!(actual, expected);
        }
    }
}
