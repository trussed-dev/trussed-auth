// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use serde::{Deserialize, Serialize};
use trussed::types::{KeyId, Message};

use super::AuthRequest;
use crate::{Pin, PinId};

#[derive(Debug, Deserialize, Serialize)]
pub struct HasPin {
    pub id: PinId,
}

impl From<HasPin> for AuthRequest {
    fn from(request: HasPin) -> Self {
        Self::HasPin(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CheckPin {
    pub id: PinId,
    pub pin: Pin,
}

impl From<CheckPin> for AuthRequest {
    fn from(request: CheckPin) -> Self {
        Self::CheckPin(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetPinKey {
    pub id: PinId,
    pub pin: Pin,
}

impl From<GetPinKey> for AuthRequest {
    fn from(request: GetPinKey) -> Self {
        Self::GetPinKey(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetApplicationKey {
    pub info: Message,
}

impl From<GetApplicationKey> for AuthRequest {
    fn from(request: GetApplicationKey) -> Self {
        Self::GetApplicationKey(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SetPin {
    pub id: PinId,
    pub pin: Pin,
    pub retries: Option<u8>,
    /// If true, the PIN can be used to wrap/unwrap a PIN key
    pub derive_key: bool,
}

impl From<SetPin> for AuthRequest {
    fn from(request: SetPin) -> Self {
        Self::SetPin(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SetPinWithKey {
    pub id: PinId,
    pub pin: Pin,
    pub retries: Option<u8>,
    /// This key will be wrapped. It can be obtained again via a `GetPinKey` request
    pub key: KeyId,
}

impl From<SetPinWithKey> for AuthRequest {
    fn from(request: SetPinWithKey) -> Self {
        Self::SetPinWithKey(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChangePin {
    pub id: PinId,
    pub old_pin: Pin,
    pub new_pin: Pin,
}

impl From<ChangePin> for AuthRequest {
    fn from(request: ChangePin) -> Self {
        Self::ChangePin(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeletePin {
    pub id: PinId,
}

impl From<DeletePin> for AuthRequest {
    fn from(request: DeletePin) -> Self {
        Self::DeletePin(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteAllPins;

impl From<DeleteAllPins> for AuthRequest {
    fn from(request: DeleteAllPins) -> Self {
        Self::DeleteAllPins(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PinRetries {
    pub id: PinId,
}

impl From<PinRetries> for AuthRequest {
    fn from(request: PinRetries) -> Self {
        Self::PinRetries(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResetAppKeys;

impl From<ResetAppKeys> for AuthRequest {
    fn from(request: ResetAppKeys) -> Self {
        Self::ResetAppKeys(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResetAuthData;

impl From<ResetAuthData> for AuthRequest {
    fn from(request: ResetAuthData) -> Self {
        Self::ResetAuthData(request)
    }
}
