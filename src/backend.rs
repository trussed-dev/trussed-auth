// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

mod data;

use trussed::{
    backend::Backend,
    error::Result,
    platform::Platform,
    serde_extensions::ExtensionImpl,
    service::ServiceResources,
    store::filestore::Filestore,
    types::{CoreContext, Location, PathBuf},
};

use crate::{
    extension::{reply, AuthExtension, AuthReply, AuthRequest},
    PIN_PATH,
};
use data::PinData;

/// A basic implementation of the [`AuthExtension`][].
///
/// This implementation stores PINs together with their retry counters on the filesystem.  PINs are
/// hashed with SHA-256 using a salt that is generated per PIN.
#[derive(Clone, Debug)]
pub struct AuthBackend {
    location: Location,
}

impl AuthBackend {
    /// Creates a new `AuthBackend` using the given storage location for the PINs.
    pub fn new(location: Location) -> Self {
        Self { location }
    }
}

impl<P: Platform> Backend<P> for AuthBackend {
    type Context = ();
}

impl<P: Platform> ExtensionImpl<AuthExtension, P> for AuthBackend {
    fn extension_request(
        &mut self,
        core_ctx: &mut CoreContext,
        _ctx: &mut (),
        request: &AuthRequest,
        resources: &mut ServiceResources<P>,
    ) -> Result<AuthReply> {
        let fs = &mut resources.filestore(core_ctx);
        match request {
            AuthRequest::HasPin(request) => {
                let has_pin = fs.exists(&request.id.path(), self.location);
                Ok(reply::HasPin { has_pin }.into())
            }
            AuthRequest::CheckPin(request) => {
                let success = PinData::load(fs, self.location, request.id)?.write(
                    fs,
                    self.location,
                    |data| data.check_pin(&request.pin),
                )?;
                Ok(reply::CheckPin { success }.into())
            }
            AuthRequest::SetPin(request) => {
                let mut rng = resources.rng().map_err(|_| Error::RngFailed)?;
                PinData::new(request.id, &request.pin, request.retries, &mut rng)
                    .save(fs, self.location)?;
                Ok(reply::SetPin.into())
            }
            AuthRequest::DeletePin(request) => {
                let path = request.id.path();
                if fs.exists(&path, self.location) {
                    fs.remove_file(&request.id.path(), self.location)
                        .map_err(|_| Error::WriteFailed)?;
                }
                Ok(reply::DeletePin.into())
            }
            AuthRequest::DeleteAllPins(_) => {
                fs.remove_dir_all(&PathBuf::from(PIN_PATH), self.location)
                    .map_err(|_| Error::WriteFailed)?;
                Ok(reply::DeleteAllPins.into())
            }
            AuthRequest::PinRetries(request) => {
                let retries = PinData::load(fs, self.location, request.id)?.retries_left();
                Ok(reply::PinRetries { retries }.into())
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Error {
    NotFound,
    RngFailed,
    ReadFailed,
    WriteFailed,
    DeserializationFailed,
    SerializationFailed,
}

impl From<Error> for trussed::error::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::NotFound => Self::NoSuchKey,
            Error::RngFailed => Self::EntropyMalfunction,
            Error::ReadFailed => Self::FilesystemReadFailure,
            Error::WriteFailed => Self::FilesystemWriteFailure,
            Error::DeserializationFailed => Self::ImplementationError,
            Error::SerializationFailed => Self::ImplementationError,
        }
    }
}
