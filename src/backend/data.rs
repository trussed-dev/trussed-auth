// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use core::ops::Deref;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use trussed::{
    platform::{CryptoRng, RngCore},
    store::filestore::Filestore,
    types::Location,
};

use super::Error;
use crate::{Pin, PinId, MAX_PIN_LENGTH};

const SIZE: usize = 256;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;

type Salt = [u8; SALT_LEN];
type Hash = [u8; HASH_LEN];

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct PinData {
    #[serde(skip)]
    id: PinId,
    retries: Option<Retries>,
    salt: Salt,
    hash: Hash,
}

impl PinData {
    pub fn new<R>(id: PinId, pin: &Pin, retries: Option<u8>, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut salt = Salt::default();
        rng.fill_bytes(&mut salt);
        let hash = hash(id, pin, &salt);
        Self {
            id,
            retries: retries.map(From::from),
            salt,
            hash,
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
        F: Fn(&mut PinDataMut<'_>) -> R,
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

impl<'a> PinDataMut<'a> {
    fn new(data: &'a mut PinData) -> Self {
        Self {
            data,
            modified: false,
        }
    }

    pub fn check_pin(&mut self, pin: &Pin) -> bool {
        if self.is_blocked() {
            return false;
        }
        let success = hash(self.id, pin, &self.salt).ct_eq(&self.hash).into();
        if let Some(retries) = &mut self.data.retries {
            if success {
                if retries.reset() {
                    self.modified = true;
                }
            } else {
                retries.decrement();
                self.modified = true;
            }
        }
        success
    }
}

impl Deref for PinDataMut<'_> {
    type Target = PinData;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

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
    digest.finalize().into()
}

fn pin_len(pin: &Pin) -> u8 {
    const _: () = assert!(MAX_PIN_LENGTH <= u8::MAX as usize);
    pin.len() as u8
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
            salt: [u8::MAX; SALT_LEN],
            hash: [u8::MAX; HASH_LEN],
        };
        let serialized = trussed::cbor_serialize_bytes::<_, 1024>(&data).unwrap();
        assert!(serialized.len() <= SIZE);
    }
}
