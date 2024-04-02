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

//! A Trussed API extension for authentication.
//!
//! This crate contains an API extension for [Trussed][], [`AuthExtension`][].  The extension
//! currently provides basic PIN handling with retry counters.  Applications can access it using
//! the [`AuthClient`][] trait.
//!
//! # Examples
//!
//! ```
//! use heapless_bytes::Bytes;
//! use trussed_auth::{AuthClient, PinId};
//! use trussed_core::syscall;
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

#[allow(missing_docs)]
pub mod reply;
#[allow(missing_docs)]
pub mod request;

use core::str::FromStr;

use serde::{Deserialize, Serialize};
use trussed_core::{
    config::MAX_SHORT_DATA_LENGTH,
    serde_extensions::{Extension, ExtensionClient, ExtensionResult},
    types::{Bytes, KeyId, Message, PathBuf},
};

/// The maximum length of a PIN.
pub const MAX_PIN_LENGTH: usize = MAX_SHORT_DATA_LENGTH;

/// A PIN.
pub type Pin = Bytes<MAX_PIN_LENGTH>;

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

/// Error obtained when trying to parse a [`PinId`][] either through [`PinId::from_path`][] or through the [`FromStr`][] implementation.
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

        // path has only ASCII characters and is not too long
        #[allow(clippy::unwrap_used)]
        PathBuf::try_from(&path).ok().unwrap()
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

        let id = u8::from_str_radix(path, 16).map_err(|_| PinIdFromStrError)?;
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

/// A result returned by [`AuthClient`][].
pub type AuthResult<'a, R, C> = ExtensionResult<'a, AuthExtension, R, C>;

/// An extension that provides basic PIN handling.
///
/// See [`AuthClient`][] for the requests provided by the extension.
#[derive(Debug, Default)]
pub struct AuthExtension;

impl Extension for AuthExtension {
    type Request = AuthRequest;
    type Reply = AuthReply;
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum AuthRequest {
    HasPin(request::HasPin),
    CheckPin(request::CheckPin),
    GetPinKey(request::GetPinKey),
    GetApplicationKey(request::GetApplicationKey),
    SetPin(request::SetPin),
    SetPinWithKey(request::SetPinWithKey),
    ChangePin(request::ChangePin),
    DeletePin(request::DeletePin),
    DeleteAllPins(request::DeleteAllPins),
    PinRetries(request::PinRetries),
    ResetAppKeys(request::ResetAppKeys),
    ResetAuthData(request::ResetAuthData),
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum AuthReply {
    HasPin(reply::HasPin),
    CheckPin(reply::CheckPin),
    GetPinKey(reply::GetPinKey),
    GetApplicationKey(reply::GetApplicationKey),
    SetPin(reply::SetPin),
    SetPinWithKey(reply::SetPinWithKey),
    ChangePin(reply::ChangePin),
    DeletePin(reply::DeletePin),
    DeleteAllPins(reply::DeleteAllPins),
    PinRetries(reply::PinRetries),
    ResetAppKeys(reply::ResetAppKeys),
    ResetAuthData(reply::ResetAuthData),
}

/// Provides access to the [`AuthExtension`][].
///
/// The extension manages PINs identified by a [`PinId`][] within the namespace of this client.
/// PINs can have a retry counter.  If a retry counter is configured when setting a PIN, it is
/// decremented on every failed authentication attempt.  If the counter reaches zero, all further
/// authentication attempts fail until the PIN is reset.
///
/// The extension does not enforce any constraints on the PINs (except for the maximum length, see
/// [`MAX_PIN_LENGTH`][]).  Even empty PINs can be used.  Also, there is no authentication required
/// to set, reset or delete a PIN.  It is up to the application to enforce any policies and
/// constraints.
///
/// [`MAX_PIN_LENGTH`]: `crate::MAX_PIN_LENGTH`
pub trait AuthClient: ExtensionClient<AuthExtension> {
    /// Returns true if the PIN is set.
    fn has_pin<I: Into<PinId>>(&mut self, id: I) -> AuthResult<'_, reply::HasPin, Self> {
        self.extension(request::HasPin { id: id.into() })
    }

    /// Returns true if the provided PIN is correct and not blocked.
    ///
    /// If the PIN is not correct and a retry counter is configured, the counter is decremented.
    /// Once it reaches zero, authentication attempts for that PIN fail.  If the PIN with the given
    /// ID is not set, an error is returned.
    fn check_pin<I>(&mut self, id: I, pin: Pin) -> AuthResult<'_, reply::CheckPin, Self>
    where
        I: Into<PinId>,
    {
        self.extension(request::CheckPin { id: id.into(), pin })
    }

    /// Returns a keyid if the provided PIN is correct and not blocked.
    ///
    /// The pin must have been created with `derive_key` set to true.
    /// If the PIN is not correct and a retry counter is configured, the counter is decremented.
    /// Once it reaches zero, authentication attempts for that PIN fail.  If the PIN with the given
    /// ID is not set, an error is returned.
    fn get_pin_key<I>(&mut self, id: I, pin: Pin) -> AuthResult<'_, reply::GetPinKey, Self>
    where
        I: Into<PinId>,
    {
        self.extension(request::GetPinKey { id: id.into(), pin })
    }

    /// Sets the given PIN and resets its retry counter.
    ///
    /// If the retry counter is `None`, the number of retries is not limited and the PIN will never
    /// be blocked.
    fn set_pin<I: Into<PinId>>(
        &mut self,
        id: I,
        pin: Pin,
        retries: Option<u8>,
        derive_key: bool,
    ) -> AuthResult<'_, reply::SetPin, Self> {
        self.extension(request::SetPin {
            id: id.into(),
            pin,
            retries,
            derive_key,
        })
    }

    /// Set a pin, resetting its retry counter and setting the key to be wrapped
    ///
    /// Similar to [`set_pin`](AuthClient::set_pin), but allows the key that the pin will unwrap to be configured.
    /// Currently only symmetric 256 bit keys are accepted. This method should be used only with keys that were obtained through [`get_pin_key`](AuthClient::get_pin_key)
    /// This allows for example backing up the key for a pin, to be able to restore it from another source.
    fn set_pin_with_key<I: Into<PinId>>(
        &mut self,
        id: I,
        pin: Pin,
        retries: Option<u8>,
        key: KeyId,
    ) -> AuthResult<'_, reply::SetPinWithKey, Self> {
        self.extension(request::SetPinWithKey {
            id: id.into(),
            pin,
            retries,
            key,
        })
    }

    /// Change the given PIN and resets its retry counter.
    ///
    /// The key obtained by [`get_pin_key`](AuthClient::get_pin_key) will stay the same
    fn change_pin<I: Into<PinId>>(
        &mut self,
        id: I,
        old_pin: Pin,
        new_pin: Pin,
    ) -> AuthResult<'_, reply::ChangePin, Self> {
        self.extension(request::ChangePin {
            id: id.into(),
            old_pin,
            new_pin,
        })
    }

    /// Deletes the given PIN (if it exists).
    fn delete_pin<I: Into<PinId>>(&mut self, id: I) -> AuthResult<'_, reply::DeletePin, Self> {
        self.extension(request::DeletePin { id: id.into() })
    }

    /// Deletes all PINs for this client.
    fn delete_all_pins(&mut self) -> AuthResult<'_, reply::DeleteAllPins, Self> {
        self.extension(request::DeleteAllPins)
    }

    /// Returns the remaining retries for the given PIN.
    fn pin_retries<I: Into<PinId>>(&mut self, id: I) -> AuthResult<'_, reply::PinRetries, Self> {
        self.extension(request::PinRetries { id: id.into() })
    }

    /// Returns a keyid that is persistent given the "info" parameter
    fn get_application_key(
        &mut self,
        info: Message,
    ) -> AuthResult<'_, reply::GetApplicationKey, Self> {
        self.extension(request::GetApplicationKey { info })
    }

    /// Delete all application keys
    fn reset_app_keys(&mut self) -> AuthResult<'_, reply::ResetAppKeys, Self> {
        self.extension(request::ResetAppKeys {})
    }

    /// Combines [`reset_app_keys`][AuthClient::reset_app_keys] and [`delete_all_pins`](AuthClient::delete_all_pins)
    fn reset_auth_data(&mut self) -> AuthResult<'_, reply::ResetAuthData, Self> {
        self.extension(request::ResetAuthData {})
    }
}

impl<C: ExtensionClient<AuthExtension>> AuthClient for C {}

#[cfg(test)]
mod tests {
    use super::PinId;
    use trussed_core::types::PathBuf;

    #[test]
    fn pin_id_path() {
        for i in 0..=u8::MAX {
            assert_eq!(Ok(PinId(i)), PinId::from_path(PinId(i).path().as_ref()));
            let actual = PinId(i).path();
            #[allow(clippy::unwrap_used)]
            let expected = PathBuf::try_from(format!("pin.{i:02x}").as_str()).unwrap();
            println!("id: {i}, actual: {actual}, expected: {expected}");
            assert_eq!(actual, expected);
        }
    }
}
