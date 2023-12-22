// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use core::ops::Deref;

use chacha20poly1305::ChaCha8Poly1305;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use trussed::{
    platform::{CryptoRng, RngCore},
    store::filestore::Filestore,
    types::{Location, PathBuf},
    Bytes,
};

use super::Error;
use crate::{request::DerivedKeyMechanism, Pin, PinId, MAX_PIN_LENGTH};

pub(crate) const SIZE: usize = 256;
pub(crate) const CHACHA_TAG_LEN: usize = 16;
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const HASH_LEN: usize = 32;
pub(crate) const CHACHA_KEY_LEN: usize = 32;
pub(crate) const X25519_KEY_LEN: usize = 32;
const ENCODED_X25519_KEY_LEN: usize = X25519_KEY_LEN + 1;

pub(crate) type Salt = ByteArray<SALT_LEN>;
pub(crate) type Hash = ByteArray<HASH_LEN>;
pub(crate) type ChaChaTag = ByteArray<CHACHA_TAG_LEN>;
pub(crate) type ChachaKey = ByteArray<CHACHA_KEY_LEN>;
pub(crate) type X25519Key = [u8; X25519_KEY_LEN];

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Key {
    Chacha20Poly1305(ChachaKey),
    X25519(X25519Key),
}

impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Key::Chacha20Poly1305(k) => serializer.serialize_bytes(&**k),
            Key::X25519(k) => {
                let mut encoded = [0; ENCODED_X25519_KEY_LEN];
                encoded[0..X25519_KEY_LEN].copy_from_slice(&*k);
                serializer.serialize_bytes(&encoded)
            }
        }
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Visitor;

        struct KeyVisitor;
        impl<'de> Visitor<'de> for KeyVisitor {
            type Value = Key;
            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("A byte array of length 32 or 33")
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match v.len() {
                    CHACHA_KEY_LEN => Ok(Key::Chacha20Poly1305(ByteArray::new(
                        v.try_into().expect("Len was just checked"),
                    ))),
                    ENCODED_X25519_KEY_LEN if v[X25519_KEY_LEN] == 0 => Ok(Key::X25519(
                        v[..X25519_KEY_LEN]
                            .try_into()
                            .expect("Len was just checked"),
                    )),
                    _ => Err(E::invalid_length(v.len(), &self)),
                }
            }
        }

        deserializer.deserialize_bytes(KeyVisitor)
    }
}

/// Represent a key wrapped by the pin.
/// The key derivation process is as follow (pseudocode):
///
/// ```rust,compile_fail
/// // length depends on hardware
/// let device_ikm: [u8] = values_from_hardware();
///
/// // generated on first power-up, stays constant for the lifetime of the device
/// let device_salt: [u8;32] = csprng();
///
/// // The salt is useful for the security proof of HKDF
/// let device_prk = hkdf_extract(salt: device_salt, ikm: device_ikm);
///
/// fn get_app_key(app_id) {
///     // Domain separation between the apps
///     // This means the `app_key` can also be used for purposes other than Pin key derivation.
///     return hkdf_expand(prk: device_prk, info: app_id, output_len: 32);
/// }
///
/// fn register_pin(app_id, pin_id, pin) {
///     let app_key = get_app_key(app_id);
///     let salt = csprng();
///     let key_to_be_wrapped = csprng();
///
///     // Get a pseudo-random key from the pin and the salt
///     //
///     // This is fine because app_key is uniform, therefore pin_key is too
///     // because HMAC is a PRF
///     //
///     // We can't use PBKDF or argon2 here because of limited hardware.
///     // Ideally such a step would be done on the host
///     //
///     // `pin_kek` is never stored
///     let pin_kek = HMAC(key: app_key, pin_id || len(pin) || pin || salt);
///
///     // On pin creation or change, the key is wrapped and stored on a persistent filesystem
///     // The constant nonce is acceptable and won't lead to nonce reuse because the `pin_kek` is only used to encrypt this data once
///     //
///     // Any change of pin changes also changes the salt
///     // which means that it is not possible to get the `pin_kek` twice
///     let wrapped_key = aead_encrypt(key: pin_kek, data: key_to_be_wrapped, nonce: [0;12]);
///
///     // wrapped_key is represented by the WrappedKeyData struct
///
///     to_presistent_storage(salt, wrapped_key);
/// }
///
/// fn get_pin_key(app_id, pin_id, pin) {
///     let app_key = get_app_key(app_id);
///     let (salt, wrapped_key) = from_persistent_storage();
///
///     // re-derive the pin kek
///     let pin_kek = HMAC(key: app_key, pin_id || len(pin) || pin || salt);
///
///     // Unwrap the key
///     let unwrapped_key = aead_decrypt(key: pin_kek, data: wrapped_key , nonce: [0;12])
///     return unwrapped_key;
/// }
///
///
/// fn change_pin(app_id, pin_id, old_pin, new_pin) {
///     let app_key = get_app_key(app_id);
///     let key_to_be_wrapped = get_pin_key(app_id, pin_id, pin);
///
///     // The procedure is the same as for `register_pin` but it reuses the `key_to_be_wrapped` instead of generating it
///
///     // Generate a new salt for the new pin
///     let salt = csprng();
///
///     let pin_kek = HMAC(key: app_key, pin_id || len(new_pin) || new_pin || salt);
///
///     let wrapped_key = aead_encrypt(key: pin_kek, data: key_to_be_wrapped, nonce: [0;12]);
///
///     to_presistent_storage(salt, wrapped_key);
/// }
/// ```
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Serialize)]
struct WrappedKeyData {
    wrapped_key: Key,
    tag: ChaChaTag,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Serialize)]
enum KeyOrHash {
    Key(WrappedKeyData),
    Hash(Hash),
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct PinData {
    #[serde(skip)]
    id: PinId,
    retries: Option<Retries>,
    salt: Salt,
    data: KeyOrHash,
}

/// Information required to derive a key
pub(crate) struct DeriveKey {
    pub(crate) application_key: ChachaKey,
    pub(crate) key_type: DerivedKeyMechanism,
}

impl PinData {
    /// An application_key of `None` means that the pin should only be salted/hashed
    /// `Some` means that it should instead be used to wrap a 32 bytes encryption key
    pub fn new<R>(
        id: PinId,
        pin: &Pin,
        retries: Option<u8>,
        rng: &mut R,
        derive_parameter: Option<DeriveKey>,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut salt = Salt::default();
        rng.fill_bytes(salt.as_mut());
        let data = match derive_parameter {
            None => KeyOrHash::Hash(hash(id, pin, &salt)),
            Some(DeriveKey {
                application_key,
                key_type: DerivedKeyMechanism::Chacha8Poly1305,
            }) => {
                let mut key = ChachaKey::default();
                rng.fill_bytes(&mut *key);
                let tag = encrypt_pin_data(id, pin, &salt, &application_key, &mut *key, None);

                KeyOrHash::Key(WrappedKeyData {
                    wrapped_key: Key::Chacha20Poly1305(key),
                    tag: tag.into(),
                })
            }
            Some(DeriveKey {
                application_key,
                key_type: DerivedKeyMechanism::X25519,
            }) => {
                use salty::agreement::SecretKey;
                let mut seed: [u8; 32] = Default::default();
                rng.fill_bytes(&mut seed);
                let key = SecretKey::from_seed(&seed);

                let mut key_bytes = key.to_bytes();

                // X25519 keys have a dedicated AAD to avoid key confusion
                let tag = encrypt_pin_data(
                    id,
                    pin,
                    &salt,
                    &application_key,
                    &mut key_bytes,
                    Some([0x00]),
                );

                KeyOrHash::Key(WrappedKeyData {
                    wrapped_key: Key::X25519(key_bytes),
                    tag: tag.into(),
                })
            }
        };
        Self {
            id,
            retries: retries.map(From::from),
            salt,
            data,
        }
    }

    pub fn reset_with_key<R>(
        id: PinId,
        pin: &Pin,
        retries: Option<u8>,
        rng: &mut R,
        application_key: &ChachaKey,
        mut key_to_wrap: ChachaKey,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        use chacha20poly1305::{AeadInPlace, KeyInit};
        let mut salt = Salt::default();
        rng.fill_bytes(salt.as_mut());
        let pin_key = derive_key(id, pin, &salt, application_key);
        let aead = ChaCha8Poly1305::new((&*pin_key).into());
        let nonce = Default::default();
        #[allow(clippy::expect_used)]
        let tag: [u8; CHACHA_TAG_LEN] = aead
            .encrypt_in_place_detached(&nonce, &[u8::from(id)], &mut *key_to_wrap)
            .expect("Wrapping the key should always work, length are acceptable")
            .into();
        Self {
            id,
            retries: retries.map(From::from),
            salt,
            data: KeyOrHash::Key(WrappedKeyData {
                wrapped_key: Key::Chacha20Poly1305(key_to_wrap),
                tag: tag.into(),
            }),
        }
    }

    pub fn load<S: Filestore>(fs: &mut S, location: Location, id: PinId) -> Result<Self, Error> {
        let path = id.path();
        if !fs.exists(&path, location) {
            return Err(Error::NotFound);
        }
        let data = fs
            .read::<SIZE>(&path, location)
            .map_err(|_| Error::ReadFailed)?;
        let mut data: Self =
            trussed::cbor_deserialize(&data).map_err(|_| Error::DeserializationFailed)?;
        data.id = id;
        Ok(data)
    }

    pub fn save<S: Filestore>(&self, fs: &mut S, location: Location) -> Result<(), Error> {
        let data = trussed::cbor_serialize_bytes::<_, SIZE>(self)
            .map_err(|_| Error::SerializationFailed)?;
        fs.write(&self.id.path(), location, &data)
            .map_err(|_| Error::WriteFailed)
    }

    pub fn retries_left(&self) -> Option<u8> {
        self.retries.map(|retries| retries.left)
    }

    pub fn is_blocked(&self) -> bool {
        if let Some(retries) = self.retries {
            retries.left == 0
        } else {
            false
        }
    }

    pub fn write<S, F, R>(&mut self, fs: &mut S, location: Location, f: F) -> Result<R, Error>
    where
        S: Filestore,
        F: FnOnce(&mut PinDataMut<'_>) -> R,
    {
        let mut data = PinDataMut::new(self);
        let result = f(&mut data);
        if data.modified {
            self.save(fs, location)?;
        }
        Ok(result)
    }
}

pub(crate) struct PinDataMut<'a> {
    data: &'a mut PinData,
    modified: bool,
}

enum CheckResult {
    Validated,
    Derived { k: ChachaKey, app_key: ChachaKey },
    Failed,
}

impl CheckResult {
    fn is_success(&self) -> bool {
        matches!(self, CheckResult::Validated | CheckResult::Derived { .. })
    }
}

impl<'a> PinDataMut<'a> {
    fn new(data: &'a mut PinData) -> Self {
        Self {
            data,
            modified: false,
        }
    }

    fn check_or_unwrap(
        &mut self,
        pin: &Pin,
        application_key: impl FnOnce() -> Result<ChachaKey, Error>,
    ) -> Result<CheckResult, Error> {
        if self.is_blocked() {
            return Ok(CheckResult::Failed);
        }
        let res = match self.data.data {
            KeyOrHash::Hash(h) => {
                if hash(self.id, pin, &self.salt).ct_eq(&*h).into() {
                    CheckResult::Validated
                } else {
                    CheckResult::Failed
                }
            }
            KeyOrHash::Key(WrappedKeyData {
                wrapped_key: Key::Chacha20Poly1305(wrapped_key),
                tag,
            }) => {
                let app_key = application_key()?;
                if let Some(k) = self.unwrap_key(pin, &app_key, wrapped_key, &tag) {
                    CheckResult::Derived { k, app_key }
                } else {
                    CheckResult::Failed
                }
            }
            KeyOrHash::Key(WrappedKeyData {
                wrapped_key: Key::X25519(_x25519),
                tag,
            }) => {
                let _ = tag;
                todo!()
            }
        };
        if let Some(retries) = &mut self.data.retries {
            if res.is_success() {
                if retries.reset() {
                    self.modified = true;
                }
            } else {
                retries.decrement();
                self.modified = true;
            }
        }
        Ok(res)
    }

    pub fn check_pin(
        &mut self,
        pin: &Pin,
        application_key: impl FnOnce() -> Result<ChachaKey, Error>,
    ) -> Result<bool, Error> {
        self.check_or_unwrap(pin, application_key)
            .map(|res| res.is_success())
    }

    #[must_use]
    fn unwrap_key(
        &self,
        pin: &Pin,
        application_key: &ChachaKey,
        mut wrapped_key: ChachaKey,
        tag: &ChaChaTag,
    ) -> Option<ChachaKey> {
        use chacha20poly1305::{AeadInPlace, KeyInit};

        let pin_key = derive_key(self.id, pin, &self.salt, application_key);
        let aead = ChaCha8Poly1305::new((&*pin_key).into());
        // The pin key is only ever used to once to wrap a key. Nonce reuse is not a concern
        // Because the salt is also used in the key derivation process, PIN reuse across PINs will still lead to different keys
        let nonce = Default::default();
        aead.decrypt_in_place_detached(
            &nonce,
            &[u8::from(self.data.id)],
            &mut *wrapped_key,
            (&**tag).into(),
        )
        .ok()
        .and(Some(wrapped_key))
    }

    pub fn get_pin_key(
        &mut self,
        pin: &Pin,
        application_key: &ChachaKey,
    ) -> Result<Option<ChachaKey>, Error> {
        match self.check_or_unwrap(pin, || Ok(*application_key))? {
            CheckResult::Validated => Err(Error::BadPinType),
            CheckResult::Derived { k, .. } => Ok(Some(k)),
            CheckResult::Failed => Ok(None),
        }
    }

    fn new_normal_pin<R: CryptoRng + RngCore>(
        &mut self,
        new: &Pin,
        rng: &mut R,
    ) -> Result<(), Error> {
        *self.data = PinData::new(
            self.data.id,
            new,
            self.data.retries.map(|r| r.max),
            rng,
            None,
        );
        Ok(())
    }

    fn new_wrapping_pin<R: CryptoRng + RngCore>(
        &mut self,
        new: &Pin,
        mut old_key: ChachaKey,
        application_key: &ChachaKey,
        rng: &mut R,
    ) {
        use chacha20poly1305::{AeadInPlace, KeyInit};
        let mut salt = Salt::default();
        rng.fill_bytes(&mut *salt);

        let pin_key = derive_key(self.id, new, &salt, application_key);

        let aead = ChaCha8Poly1305::new((&*pin_key).into());
        // The pin key is only ever used to once to wrap a key. Nonce reuse is not a concern
        // Because the salt is also used in the key derivation process, PIN reuse across PINs will still lead to different keys
        let nonce = Default::default();

        #[allow(clippy::expect_used)]
        let tag: [u8; CHACHA_TAG_LEN] = aead
            .encrypt_in_place_detached(&nonce, &[u8::from(self.id)], &mut *old_key)
            .expect("Wrapping the key should always work, length are acceptable")
            .into();

        *self.data = PinData {
            id: self.id,
            retries: self.retries,
            salt,
            data: KeyOrHash::Key(WrappedKeyData {
                wrapped_key: Key::Chacha20Poly1305(old_key),
                tag: tag.into(),
            }),
        };
    }

    pub fn change_pin<R: CryptoRng + RngCore>(
        &mut self,
        old_pin: &Pin,
        new_pin: &Pin,
        application_key: impl FnOnce(&mut R) -> Result<ChachaKey, Error>,
        rng: &mut R,
    ) -> Result<bool, Error> {
        match self.check_or_unwrap(old_pin, || application_key(rng))? {
            CheckResult::Validated => {
                self.new_normal_pin(new_pin, rng)?;
                self.modified = true;
                Ok(true)
            }
            CheckResult::Derived { k, app_key } => {
                self.new_wrapping_pin(new_pin, k, &app_key, rng);
                self.modified = true;
                Ok(true)
            }
            CheckResult::Failed => Ok(false),
        }
    }
}

impl Deref for PinDataMut<'_> {
    type Target = PinData;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct Retries {
    max: u8,
    left: u8,
}

impl Retries {
    fn decrement(&mut self) {
        self.left = self.left.saturating_sub(1);
    }

    fn reset(&mut self) -> bool {
        if self.left == self.max {
            false
        } else {
            self.left = self.max;
            true
        }
    }
}

impl From<u8> for Retries {
    fn from(retries: u8) -> Self {
        Self {
            max: retries,
            left: retries,
        }
    }
}

fn hash(id: PinId, pin: &Pin, salt: &Salt) -> Hash {
    let mut digest = Sha256::new();
    digest.update([u8::from(id)]);
    digest.update([pin_len(pin)]);
    digest.update(pin);
    digest.update(salt);
    Hash::new(digest.finalize().into())
}

fn derive_key(id: PinId, pin: &Pin, salt: &Salt, application_key: &[u8; 32]) -> Hash {
    #[allow(clippy::expect_used)]
    let mut hmac = Hmac::<Sha256>::new_from_slice(application_key)
        .expect("Slice will always be of acceptable size");
    hmac.update(&[u8::from(id)]);
    hmac.update(&[pin_len(pin)]);
    hmac.update(pin);
    hmac.update(&**salt);
    let tmp: [_; HASH_LEN] = hmac.finalize().into_bytes().into();
    tmp.into()
}

fn encrypt_pin_data(
    id: PinId,
    pin: &Pin,
    salt: &Salt,
    application_key: &[u8; 32],
    data: &mut [u8],
    aad: Option<[u8; 1]>,
) -> [u8; CHACHA_TAG_LEN] {
    use chacha20poly1305::{AeadInPlace, KeyInit};
    let pin_key = derive_key(id, pin, &salt, application_key);
    let aead = ChaCha8Poly1305::new((&*pin_key).into());
    // The pin key is only ever used to once to wrap a key. Nonce reuse is not a concern
    // Because the salt is also used in the key derivation process, PIN reuse across PINs will still lead to different keys
    let nonce = Default::default();

    let sup_1;
    let sup_2;

    let aad: &[u8] = match aad {
        Some([aad_byte]) => {
            sup_1 = [u8::from(id), aad_byte];
            &sup_1
        }
        None => {
            sup_2 = [u8::from(id)];
            &sup_2
        }
    };
    #[allow(clippy::expect_used)]
    let tag: [u8; CHACHA_TAG_LEN] = aead
        .encrypt_in_place_detached(&nonce, aad, &mut *data)
        .expect("Wrapping the key should always work, length are acceptable")
        .into();
    tag
}

fn pin_len(pin: &Pin) -> u8 {
    const _: () = assert!(MAX_PIN_LENGTH <= u8::MAX as usize);
    pin.len() as u8
}

fn app_salt_path() -> PathBuf {
    const SALT_PATH: &str = "application_salt";

    PathBuf::from(SALT_PATH)
}

pub(crate) fn get_app_salt<S: Filestore, R: CryptoRng + RngCore>(
    fs: &mut S,
    rng: &mut R,
    location: Location,
) -> Result<Salt, Error> {
    if !fs.exists(&app_salt_path(), location) {
        create_app_salt(fs, rng, location)
    } else {
        load_app_salt(fs, location)
    }
}

pub(crate) fn delete_app_salt<S: Filestore>(
    fs: &mut S,
    location: Location,
) -> Result<(), trussed::Error> {
    if fs.exists(&app_salt_path(), location) {
        fs.remove_file(&app_salt_path(), location)
    } else {
        Ok(())
    }
}

fn create_app_salt<S: Filestore, R: CryptoRng + RngCore>(
    fs: &mut S,
    rng: &mut R,
    location: Location,
) -> Result<Salt, Error> {
    let mut salt = Salt::default();
    rng.fill_bytes(&mut *salt);
    fs.write(&app_salt_path(), location, &*salt)
        .map_err(|_| Error::WriteFailed)?;
    Ok(salt)
}

fn load_app_salt<S: Filestore>(fs: &mut S, location: Location) -> Result<Salt, Error> {
    fs.read(&app_salt_path(), location)
        .map_err(|_| Error::ReadFailed)
        .and_then(|b: Bytes<SALT_LEN>| (**b).try_into().map_err(|_| Error::ReadFailed))
}

pub fn expand_app_key(salt: &Salt, application_key: &ChachaKey, info: &[u8]) -> ChachaKey {
    #[allow(clippy::expect_used)]
    let mut hmac = Hmac::<Sha256>::new_from_slice(&**application_key)
        .expect("Slice will always be of acceptable size");
    hmac.update(&**salt);
    hmac.update(&(info.len() as u64).to_be_bytes());
    hmac.update(info);
    let tmp: [_; HASH_LEN] = hmac.finalize().into_bytes().into();
    tmp.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_data_size() {
        let data = PinData {
            id: PinId::from(u8::MAX),
            retries: Some(Retries {
                max: u8::MAX,
                left: u8::MAX,
            }),
            salt: [u8::MAX; SALT_LEN].into(),
            data: KeyOrHash::Hash([u8::MAX; HASH_LEN].into()),
        };
        let serialized = trussed::cbor_serialize_bytes::<_, 1024>(&data).unwrap();
        assert!(serialized.len() <= SIZE);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_salt_size() {
        // We allow one byte overhead for byte array serialization
        let salt = Salt::from([u8::MAX; SALT_LEN]);
        let serialized = trussed::cbor_serialize_bytes::<_, 1024>(&salt).unwrap();
        assert!(serialized.len() <= SALT_LEN + 1, "{}", serialized.len());
    }

    #[test]
    fn data_serialization() {
        use serde_test::{assert_tokens, Token};

        let data = PinData {
            id: PinId::from(0),
            retries: Some(Retries { max: 3, left: 1 }),
            salt: [0xFE; SALT_LEN].into(),
            data: KeyOrHash::Hash([0xFD; HASH_LEN].into()),
        };

        assert_tokens(
            &data,
            &[
                Token::Struct {
                    name: "PinData",
                    // Id is skipped
                    len: 3,
                },
                Token::Str("retries"),
                Token::Some,
                Token::Struct {
                    name: "Retries",
                    len: 2,
                },
                Token::Str("max"),
                Token::U8(3),
                Token::Str("left"),
                Token::U8(1),
                Token::StructEnd,
                Token::Str("salt"),
                Token::Bytes(&[0xFE; SALT_LEN]),
                Token::Str("data"),
                Token::Enum { name: "KeyOrHash" },
                Token::Str("Hash"),
                Token::Bytes(&[0xFD; HASH_LEN]),
                Token::StructEnd,
            ],
        );

        let data = PinData {
            id: PinId::from(0),
            retries: None,
            salt: [0xFE; SALT_LEN].into(),
            data: KeyOrHash::Key(WrappedKeyData {
                wrapped_key: Key::Chacha20Poly1305([0xFC; CHACHA_KEY_LEN].into()),
                tag: [0xFB; CHACHA_TAG_LEN].into(),
            }),
        };

        assert_tokens(
            &data,
            &[
                Token::Struct {
                    name: "PinData",
                    // Id is skipped
                    len: 3,
                },
                Token::Str("retries"),
                Token::None,
                Token::Str("salt"),
                Token::Bytes(&[0xFE; SALT_LEN]),
                Token::Str("data"),
                Token::Enum { name: "KeyOrHash" },
                Token::Str("Key"),
                Token::Struct {
                    name: "WrappedKeyData",
                    len: 2,
                },
                Token::Str("wrapped_key"),
                Token::Bytes(&[0xFC; CHACHA_KEY_LEN]),
                Token::Str("tag"),
                Token::Bytes(&[0xFB; CHACHA_TAG_LEN]),
                Token::StructEnd,
                Token::StructEnd,
            ],
        );
    }
}
