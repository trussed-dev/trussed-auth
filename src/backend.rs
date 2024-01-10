// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

mod data;

use core::fmt;

use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use salty::agreement::SecretKey;
use sha2::Sha256;
use trussed::{
    backend::Backend,
    error::Result,
    key::{Kind, Secrecy},
    platform::Platform,
    serde_extensions::ExtensionImpl,
    service::{Keystore, ServiceResources},
    store::filestore::Filestore,
    types::{CoreContext, Location, PathBuf},
    Bytes,
};

use crate::{
    backend::data::{expand_app_key, get_app_salt},
    extension::{reply, AuthExtension, AuthReply, AuthRequest},
    BACKEND_DIR,
};
use data::{DeriveKey, PinData, Salt, CHACHA_KEY_LEN, SALT_LEN};

use self::data::{delete_app_salt, ChachaKey, DecryptedKey};

/// max accepted length for the hardware initial key material
pub const MAX_HW_KEY_LEN: usize = 64;

#[derive(Clone)]
enum HardwareKey {
    None,
    /// Means that the hardware key was not obtainable and that operations depending on it should fail
    Missing,
    Raw(Bytes<MAX_HW_KEY_LEN>),
    Extracted(Hkdf<Sha256>),
}

impl fmt::Debug for HardwareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.debug_tuple("None").finish(),
            Self::Missing => f.debug_tuple("Missing").finish(),
            Self::Raw(_) => f.debug_tuple("Raw").field(&"[redacted]").finish(),
            Self::Extracted(_) => f.debug_tuple("Raw").field(&"[redacted]").finish(),
        }
    }
}

/// A basic implementation of the [`AuthExtension`][].
///
/// This implementation stores PINs together with their retry counters on the filesystem.  PINs are
/// hashed with SHA-256 using a salt that is generated per PIN.
///
/// # Filesystem Layout
///
/// ```text
/// backend-auth/
///     dat/
///        salt            global salt for key derivation
/// <client>/
///     backend-auth/
///         dat/
///             pin.<id>        PIN data, can be deleted with DeletePin or DeleteAllPins
/// ```
///
/// The storage location can be set when creating the backend, see [`AuthBackend::new`][] and
/// [`AuthBackend::with_hw_key`][].
#[derive(Clone, Debug)]
pub struct AuthBackend {
    location: Location,
    hw_key: HardwareKey,
}

impl AuthBackend {
    /// Creates a new `AuthBackend` using the given storage location for the PINs.
    pub fn new(location: Location) -> Self {
        Self {
            location,
            hw_key: HardwareKey::None,
        }
    }

    /// Creates a new `AuthBackend` with a given key.
    ///
    /// This key is used to strengthen key generation from the pins
    pub fn with_hw_key(location: Location, hw_key: Bytes<MAX_HW_KEY_LEN>) -> Self {
        Self {
            location,
            hw_key: HardwareKey::Raw(hw_key),
        }
    }

    /// Creates a new `AuthBackend` with a missing hw key
    ///
    /// Contrary to [`new`](Self::new) which uses a default `&[]` key, this will make operations depending on the hardware key to fail:
    /// - [`set_pin`](crate::AuthClient::set_pin) with `derive_key = true`
    /// - All operations on a pin that was created with `derive_key = true`
    pub fn with_missing_hw_key(location: Location) -> Self {
        Self {
            location,
            hw_key: HardwareKey::Missing,
        }
    }

    fn get_global_salt<R: CryptoRng + RngCore>(
        &self,
        global_fs: &mut impl Filestore,
        rng: &mut R,
    ) -> Result<Salt, Error> {
        let path = PathBuf::from("salt");
        global_fs
            .read(&path, self.location)
            .or_else(|_| {
                if global_fs.exists(&path, self.location) {
                    return Err(Error::ReadFailed);
                }

                let mut salt = Bytes::<SALT_LEN>::default();
                salt.resize_to_capacity();
                rng.fill_bytes(&mut salt);
                global_fs
                    .write(&path, self.location, &salt)
                    .or(Err(Error::WriteFailed))
                    .and(Ok(salt))
            })
            .and_then(|b| (**b).try_into().or(Err(Error::ReadFailed)))
    }

    fn extract<R: CryptoRng + RngCore>(
        &mut self,
        global_fs: &mut impl Filestore,
        ikm: Option<Bytes<MAX_HW_KEY_LEN>>,
        rng: &mut R,
    ) -> Result<&Hkdf<Sha256>, Error> {
        let ikm: &[u8] = ikm.as_deref().map(|i| &**i).unwrap_or(&[]);
        let salt = self.get_global_salt(global_fs, rng)?;
        let kdf = Hkdf::new(Some(&*salt), ikm);
        self.hw_key = HardwareKey::Extracted(kdf);
        match &self.hw_key {
            HardwareKey::Extracted(kdf) => Ok(kdf),
            // hw_key was just set to Extracted
            _ => unreachable!(),
        }
    }

    fn expand(kdf: &Hkdf<Sha256>, client_id: &PathBuf) -> ChachaKey {
        let mut out = ChachaKey::default();
        #[allow(clippy::expect_used)]
        kdf.expand(client_id.as_ref().as_bytes(), &mut *out)
            .expect("Out data is always valid");
        out
    }

    fn generate_app_key<R: CryptoRng + RngCore>(
        &mut self,
        client_id: PathBuf,
        global_fs: &mut impl Filestore,
        rng: &mut R,
    ) -> Result<ChachaKey, Error> {
        Ok(match &self.hw_key {
            HardwareKey::Extracted(okm) => Self::expand(okm, &client_id),
            HardwareKey::Missing => return Err(Error::MissingHwKey),
            HardwareKey::Raw(hw_k) => {
                let kdf = self.extract(global_fs, Some(hw_k.clone()), rng)?;
                Self::expand(kdf, &client_id)
            }
            HardwareKey::None => {
                let kdf = self.extract(global_fs, None, rng)?;
                Self::expand(kdf, &client_id)
            }
        })
    }

    fn get_app_key<R: CryptoRng + RngCore>(
        &mut self,
        client_id: PathBuf,
        global_fs: &mut impl Filestore,
        ctx: &mut AuthContext,
        rng: &mut R,
    ) -> Result<ChachaKey, Error> {
        if let Some(app_key) = ctx.application_key {
            return Ok(app_key);
        }

        let app_key = self.generate_app_key(client_id, global_fs, rng)?;
        ctx.application_key = Some(app_key);
        Ok(app_key)
    }
}

/// Per-client context for [`AuthBackend`][]
#[derive(Default, Debug)]
pub struct AuthContext {
    application_key: Option<ChachaKey>,
}

impl Backend for AuthBackend {
    type Context = AuthContext;
}

impl ExtensionImpl<AuthExtension> for AuthBackend {
    fn extension_request<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        ctx: &mut AuthContext,
        request: &AuthRequest,
        resources: &mut ServiceResources<P>,
    ) -> Result<AuthReply> {
        // FIXME: Have a real implementation from trussed
        let mut backend_path = core_ctx.path.clone();
        backend_path.push(&PathBuf::from(BACKEND_DIR));
        let fs = &mut resources.filestore(backend_path);
        let global_fs = &mut resources.filestore(PathBuf::from(BACKEND_DIR));
        let rng = &mut resources.rng()?;
        let client_id = core_ctx.path.clone();
        let keystore = &mut resources.keystore(core_ctx.path.clone())?;
        match request {
            AuthRequest::HasPin(request) => {
                let has_pin = fs.exists(&request.id.path(), self.location);
                Ok(reply::HasPin { has_pin }.into())
            }
            AuthRequest::CheckPin(request) => {
                let success = PinData::load(fs, self.location, request.id)?.write(
                    fs,
                    self.location,
                    |data| {
                        data.check_pin(&request.pin, || {
                            self.get_app_key(client_id, global_fs, ctx, rng)
                        })
                    },
                )??;
                Ok(reply::CheckPin { success }.into())
            }
            AuthRequest::GetPinKey(request) => {
                let application_key =
                    self.get_app_key(core_ctx.path.clone(), global_fs, ctx, rng)?;
                let verification = PinData::load(fs, self.location, request.id)?.write(
                    fs,
                    self.location,
                    |data| data.get_pin_key(&request.pin, &application_key),
                )??;
                if let Some(k) = verification {
                    let key_id = keystore.store_key(
                        Location::Volatile,
                        Secrecy::Secret,
                        k.kind(),
                        &k.data(),
                    )?;
                    Ok(reply::GetPinKey {
                        result: Some(key_id),
                    }
                    .into())
                } else {
                    Ok(reply::GetPinKey { result: None }.into())
                }
            }
            AuthRequest::ChangePin(request) => {
                let success = PinData::load(fs, self.location, request.id)?.write(
                    fs,
                    self.location,
                    |data| {
                        data.change_pin(
                            &request.old_pin,
                            &request.new_pin,
                            move |rng| self.get_app_key(client_id, global_fs, ctx, rng),
                            rng,
                        )
                    },
                )??;
                Ok(reply::ChangePin { success }.into())
            }
            AuthRequest::SetPin(request) => {
                let key_derivation = match request.derive_key {
                    Some(key_type) => Some(DeriveKey {
                        application_key: self.get_app_key(client_id, global_fs, ctx, rng)?,
                        key_type,
                    }),
                    None => None,
                };
                PinData::new(
                    request.id,
                    &request.pin,
                    request.retries,
                    rng,
                    key_derivation,
                )
                .save(fs, self.location)?;
                Ok(reply::SetPin.into())
            }
            AuthRequest::SetPinWithKey(request) => {
                let app_key = self.get_app_key(client_id, global_fs, ctx, rng)?;
                let key_material = keystore.load_key(Secrecy::Secret, None, &request.key)?;
                let material_32: [u8; 32] = (&*key_material.material)
                    .try_into()
                    .map_err(|_| Error::ReadFailed)?;
                let key_to_wrap = match key_material.kind {
                    Kind::Symmetric(32) => DecryptedKey::Chacha20Poly1305(material_32.into()),
                    Kind::X255 => DecryptedKey::X25519(SecretKey::from_seed(&material_32)),
                    _ => return Err(Error::NotFound)?,
                };
                PinData::reset_with_key(
                    request.id,
                    &request.pin,
                    request.retries,
                    rng,
                    &app_key,
                    key_to_wrap,
                )
                .save(fs, self.location)?;
                Ok(reply::SetPinWithKey.into())
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
                fs.remove_dir_all_where(&PathBuf::new(), self.location, |entry| {
                    entry.file_name().as_ref().starts_with("pin.")
                })
                .map_err(|_| Error::WriteFailed)?;
                Ok(reply::DeleteAllPins.into())
            }
            AuthRequest::ResetAppKeys(_) => {
                delete_app_salt(fs, self.location)?;
                Ok(reply::ResetAppKeys {}.into())
            }
            AuthRequest::ResetAuthData(_) => {
                fs.remove_dir_all(&PathBuf::new(), self.location)
                    .map_err(|_| Error::WriteFailed)?;
                Ok(reply::ResetAuthData.into())
            }
            AuthRequest::PinRetries(request) => {
                let retries = PinData::load(fs, self.location, request.id)?.retries_left();
                Ok(reply::PinRetries { retries }.into())
            }
            AuthRequest::GetApplicationKey(request) => {
                let salt = get_app_salt(fs, rng, self.location)?;
                let key = expand_app_key(
                    &salt,
                    &self.get_app_key(client_id, global_fs, ctx, rng)?,
                    &request.info,
                );
                let key_id = keystore.store_key(
                    Location::Volatile,
                    Secrecy::Secret,
                    Kind::Symmetric(CHACHA_KEY_LEN),
                    &*key,
                )?;
                Ok(reply::GetApplicationKey { key: key_id }.into())
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Error {
    NotFound,
    MissingHwKey,
    ReadFailed,
    WriteFailed,
    DeserializationFailed,
    SerializationFailed,
    BadPinType,
}

impl From<Error> for trussed::error::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::NotFound => Self::NoSuchKey,
            Error::MissingHwKey => Self::GeneralError,
            Error::ReadFailed => Self::FilesystemReadFailure,
            Error::WriteFailed => Self::FilesystemWriteFailure,
            Error::DeserializationFailed => Self::ImplementationError,
            Error::SerializationFailed => Self::ImplementationError,
            Error::BadPinType => Self::MechanismInvalid,
        }
    }
}
