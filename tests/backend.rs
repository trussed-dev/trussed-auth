// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

mod dispatch {
    use trussed::{
        api::{reply, request, Reply, Request},
        backend::{Backend as _, BackendId},
        error::Error,
        platform::Platform,
        serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl as _},
        service::ServiceResources,
        types::{Bytes, Context, Location},
    };
    use trussed_auth::{AuthBackend, AuthContext, AuthExtension, MAX_HW_KEY_LEN};

    pub const BACKENDS: &[BackendId<Backend>] =
        &[BackendId::Custom(Backend::Auth), BackendId::Core];

    pub enum Backend {
        Auth,
    }

    pub enum Extension {
        Auth,
    }

    impl From<Extension> for u8 {
        fn from(extension: Extension) -> Self {
            match extension {
                Extension::Auth => 0,
            }
        }
    }

    impl TryFrom<u8> for Extension {
        type Error = Error;

        fn try_from(id: u8) -> Result<Self, Self::Error> {
            match id {
                0 => Ok(Extension::Auth),
                _ => Err(Error::InternalError),
            }
        }
    }

    pub struct Dispatch {
        auth: AuthBackend,
    }

    #[derive(Default)]
    pub struct DispatchContext {
        auth: AuthContext,
    }

    impl Dispatch {
        pub fn new() -> Self {
            Self {
                auth: AuthBackend::new(Location::Internal),
            }
        }

        pub fn with_hw_key(hw_key: Bytes<MAX_HW_KEY_LEN>) -> Self {
            Self {
                auth: AuthBackend::with_hw_key(Location::Internal, hw_key),
            }
        }
        pub fn with_missing_hw_key() -> Self {
            Self {
                auth: AuthBackend::with_missing_hw_key(Location::Internal),
            }
        }
    }

    impl ExtensionDispatch for Dispatch {
        type BackendId = Backend;
        type Context = DispatchContext;
        type ExtensionId = Extension;

        fn core_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            ctx: &mut Context<Self::Context>,
            request: &Request,
            resources: &mut ServiceResources<P>,
        ) -> Result<Reply, Error> {
            match backend {
                Backend::Auth => {
                    self.auth
                        .request(&mut ctx.core, &mut ctx.backends.auth, request, resources)
                }
            }
        }

        fn extension_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            extension: &Self::ExtensionId,
            ctx: &mut Context<Self::Context>,
            request: &request::SerdeExtension,
            resources: &mut ServiceResources<P>,
        ) -> Result<reply::SerdeExtension, Error> {
            match backend {
                Backend::Auth => match extension {
                    Extension::Auth => self.auth.extension_request_serialized(
                        &mut ctx.core,
                        &mut ctx.backends.auth,
                        request,
                        resources,
                    ),
                },
            }
        }
    }

    impl ExtensionId<AuthExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Auth;
    }
}

use rand_core::{OsRng, RngCore as _};
use trussed::{
    backend::BackendId,
    client::{ClientImplementation, HmacSha256},
    service::Service,
    syscall, try_syscall,
    types::Bytes,
    virt::{self, Ram},
};
use trussed_auth::{AuthClient as _, PinId, MAX_HW_KEY_LEN};

use dispatch::{Backend, Dispatch, BACKENDS};

type Platform = virt::Platform<Ram>;
type Client = ClientImplementation<Service<Platform, Dispatch>, Dispatch>;

enum Pin {
    User,
    Admin,
    Custom,
}

impl From<Pin> for u8 {
    fn from(pin: Pin) -> Self {
        match pin {
            Pin::User => 0,
            Pin::Admin => 1,
            Pin::Custom => 2,
        }
    }
}

impl From<Pin> for PinId {
    fn from(pin: Pin) -> Self {
        Self::from(u8::from(pin))
    }
}

fn run<F: FnOnce(&mut Client)>(backends: &'static [BackendId<Backend>], f: F) {
    virt::with_platform(Ram::default(), |platform| {
        platform.run_client_with_backends("test", Dispatch::new(), backends, |mut client| {
            f(&mut client)
        })
    })
}

fn run_with_hw_key<F: FnOnce(&mut Client)>(
    backends: &'static [BackendId<Backend>],
    hw_key: Bytes<{ MAX_HW_KEY_LEN }>,
    f: F,
) {
    virt::with_platform(Ram::default(), |platform| {
        platform.run_client_with_backends(
            "test",
            Dispatch::with_hw_key(hw_key),
            backends,
            |mut client| f(&mut client),
        )
    })
}

fn run_with_missing_hw_key<F: FnOnce(&mut Client)>(backends: &'static [BackendId<Backend>], f: F) {
    virt::with_platform(Ram::default(), |platform| {
        platform.run_client_with_backends(
            "test",
            Dispatch::with_missing_hw_key(),
            backends,
            |mut client| f(&mut client),
        )
    })
}

fn random_pin() -> trussed_auth::Pin {
    let mut pin = Bytes::new();
    pin.resize_to_capacity();
    OsRng.fill_bytes(&mut pin);
    pin
}

#[test]
fn basic() {
    run(BACKENDS, |client| {
        let pin1 = Bytes::from_slice(b"12345678").unwrap();
        let pin2 = Bytes::from_slice(b"123456").unwrap();

        let reply = syscall!(client.has_pin(Pin::User));
        assert!(!reply.has_pin);

        syscall!(client.set_pin(Pin::User, pin1.clone(), None, false));

        let reply = syscall!(client.has_pin(Pin::User));
        assert!(reply.has_pin);
        let reply = syscall!(client.has_pin(Pin::Admin));
        assert!(!reply.has_pin);

        let reply = syscall!(client.pin_retries(Pin::User));
        assert_eq!(reply.retries, None);

        let reply = syscall!(client.check_pin(Pin::User, pin1.clone()));
        assert!(reply.success);

        let reply = syscall!(client.pin_retries(Pin::User));
        assert_eq!(reply.retries, None);

        let reply = syscall!(client.check_pin(Pin::User, pin2));
        assert!(!reply.success);

        let result = try_syscall!(client.check_pin(Pin::Admin, pin1.clone()));
        assert!(result.is_err());

        let reply = syscall!(client.pin_retries(Pin::User));
        assert_eq!(reply.retries, None);

        syscall!(client.delete_pin(Pin::User));

        let result = try_syscall!(client.check_pin(Pin::User, pin1));
        assert!(result.is_err());

        let result = try_syscall!(client.pin_retries(Pin::User));
        assert!(result.is_err());
    })
}

#[test]
fn basic_wrapped() {
    run(BACKENDS, |client| {
        let pin1 = Bytes::from_slice(b"12345678").unwrap();
        let pin2 = Bytes::from_slice(b"123456").unwrap();

        let reply = syscall!(client.has_pin(Pin::User));
        assert!(!reply.has_pin);

        syscall!(client.set_pin(Pin::User, pin1.clone(), None, true));

        let reply = syscall!(client.has_pin(Pin::User));
        assert!(reply.has_pin);
        let reply = syscall!(client.has_pin(Pin::Admin));
        assert!(!reply.has_pin);

        let reply = syscall!(client.pin_retries(Pin::User));
        assert_eq!(reply.retries, None);

        let reply = syscall!(client.check_pin(Pin::User, pin1.clone()));
        assert!(reply.success);

        let reply = syscall!(client.pin_retries(Pin::User));
        assert_eq!(reply.retries, None);

        let reply = syscall!(client.check_pin(Pin::User, pin2));
        assert!(!reply.success);

        let result = try_syscall!(client.check_pin(Pin::Admin, pin1.clone()));
        assert!(result.is_err());

        let reply = syscall!(client.pin_retries(Pin::User));
        assert_eq!(reply.retries, None);

        syscall!(client.delete_pin(Pin::User));

        let result = try_syscall!(client.check_pin(Pin::User, pin1));
        assert!(result.is_err());

        let result = try_syscall!(client.pin_retries(Pin::User));
        assert!(result.is_err());
    })
}

#[test]
fn hw_key_wrapped() {
    run_with_hw_key(
        BACKENDS,
        Bytes::from_slice(b"Some HW ikm").unwrap(),
        |client| {
            let pin1 = Bytes::from_slice(b"12345678").unwrap();
            let pin2 = Bytes::from_slice(b"123456").unwrap();

            let reply = syscall!(client.has_pin(Pin::User));
            assert!(!reply.has_pin);

            syscall!(client.set_pin(Pin::User, pin1.clone(), None, true));

            let reply = syscall!(client.has_pin(Pin::User));
            assert!(reply.has_pin);
            let reply = syscall!(client.has_pin(Pin::Admin));
            assert!(!reply.has_pin);

            let reply = syscall!(client.pin_retries(Pin::User));
            assert_eq!(reply.retries, None);

            let reply = syscall!(client.check_pin(Pin::User, pin1.clone()));
            assert!(reply.success);

            let reply = syscall!(client.pin_retries(Pin::User));
            assert_eq!(reply.retries, None);

            let reply = syscall!(client.check_pin(Pin::User, pin2));
            assert!(!reply.success);

            let result = try_syscall!(client.check_pin(Pin::Admin, pin1.clone()));
            assert!(result.is_err());

            let reply = syscall!(client.pin_retries(Pin::User));
            assert_eq!(reply.retries, None);

            syscall!(client.delete_pin(Pin::User));

            let result = try_syscall!(client.check_pin(Pin::User, pin1));
            assert!(result.is_err());

            let result = try_syscall!(client.pin_retries(Pin::User));
            assert!(result.is_err());
        },
    )
}

#[test]
fn missing_hw_key() {
    run_with_missing_hw_key(BACKENDS, |client| {
        let pin1 = Bytes::from_slice(b"12345678").unwrap();
        let pin2 = Bytes::from_slice(b"123456").unwrap();

        let reply = syscall!(client.has_pin(Pin::User));
        assert!(!reply.has_pin);

        assert!(try_syscall!(client.set_pin(Pin::User, pin1.clone(), None, true)).is_err());

        let reply = syscall!(client.has_pin(Pin::User));
        assert!(!reply.has_pin);

        syscall!(client.set_pin(Pin::User, pin1.clone(), None, false));

        let reply = syscall!(client.has_pin(Pin::User));
        assert!(reply.has_pin);
        let reply = syscall!(client.has_pin(Pin::Admin));
        assert!(!reply.has_pin);

        let reply = syscall!(client.pin_retries(Pin::User));
        assert_eq!(reply.retries, None);

        let reply = syscall!(client.check_pin(Pin::User, pin1.clone()));
        assert!(reply.success);

        let reply = syscall!(client.pin_retries(Pin::User));
        assert_eq!(reply.retries, None);

        let reply = syscall!(client.check_pin(Pin::User, pin2));
        assert!(!reply.success);

        let result = try_syscall!(client.check_pin(Pin::Admin, pin1.clone()));
        assert!(result.is_err());

        let reply = syscall!(client.pin_retries(Pin::User));
        assert_eq!(reply.retries, None);

        syscall!(client.delete_pin(Pin::User));

        let result = try_syscall!(client.check_pin(Pin::User, pin1));
        assert!(result.is_err());

        let result = try_syscall!(client.pin_retries(Pin::User));
        assert!(result.is_err());
    })
}

#[test]
fn pin_key() {
    run_with_hw_key(
        BACKENDS,
        Bytes::from_slice(b"Some HW ikm").unwrap(),
        |client| {
            let pin1 = Bytes::from_slice(b"12345678").unwrap();
            let pin2 = Bytes::from_slice(b"123456").unwrap();

            syscall!(client.set_pin(Pin::User, pin1.clone(), Some(3), true));
            assert!(syscall!(client.get_pin_key(Pin::User, pin2.clone()))
                .result
                .is_none());
            assert_eq!(syscall!(client.pin_retries(Pin::User)).retries, Some(2));
            assert!(!syscall!(client.check_pin(Pin::User, pin2.clone())).success);
            assert_eq!(syscall!(client.pin_retries(Pin::User)).retries, Some(1));
            assert!(syscall!(client.check_pin(Pin::User, pin1.clone())).success);
            let key = syscall!(client.get_pin_key(Pin::User, pin1.clone()))
                .result
                .unwrap();
            assert_eq!(syscall!(client.pin_retries(Pin::User)).retries, Some(3));
            let mac = syscall!(client.sign_hmacsha256(key, b"Some data")).signature;
            let key2 = syscall!(client.get_pin_key(Pin::User, pin1.clone()))
                .result
                .unwrap();
            let mac2 = syscall!(client.sign_hmacsha256(key2, b"Some data")).signature;
            assert_eq!(mac, mac2);

            assert!(syscall!(client.change_pin(Pin::User, pin1.clone(), pin2.clone())).success);

            let key3 = syscall!(client.get_pin_key(Pin::User, pin2.clone()))
                .result
                .unwrap();
            let mac3 = syscall!(client.sign_hmacsha256(key3, b"Some data")).signature;
            assert_eq!(mac, mac3);

            assert!(!syscall!(client.check_pin(Pin::User, pin1.clone())).success);
            assert!(!syscall!(client.check_pin(Pin::User, pin1.clone())).success);
            assert!(!syscall!(client.check_pin(Pin::User, pin1)).success);
            assert!(!syscall!(client.check_pin(Pin::User, pin2.clone())).success);
            assert!(syscall!(client.get_pin_key(Pin::User, pin2))
                .result
                .is_none());
            assert_eq!(syscall!(client.pin_retries(Pin::User)).retries, Some(0));
        },
    )
}

#[test]
fn blocked_pin() {
    run(BACKENDS, |client| {
        let pin1 = Bytes::from_slice(b"12345678").unwrap();
        let pin2 = Bytes::from_slice(b"123456").unwrap();

        syscall!(client.set_pin(Pin::User, pin1.clone(), Some(3), false));

        let reply = syscall!(client.check_pin(Pin::User, pin1.clone()));
        assert!(reply.success);

        for _ in 0..10 {
            let reply = syscall!(client.check_pin(Pin::User, pin2.clone()));
            assert!(!reply.success);
        }

        let reply = syscall!(client.check_pin(Pin::User, pin1));
        assert!(!reply.success);
    })
}

#[test]
fn set_blocked_pin() {
    run(BACKENDS, |client| {
        let pin1 = Bytes::from_slice(b"12345678").unwrap();
        let pin2 = Bytes::from_slice(b"123456").unwrap();

        syscall!(client.set_pin(Pin::User, pin1.clone(), Some(1), false));
        let reply = syscall!(client.check_pin(Pin::User, pin1.clone()));
        assert!(reply.success);
        let reply = syscall!(client.check_pin(Pin::User, pin2.clone()));
        assert!(!reply.success);
        let reply = syscall!(client.check_pin(Pin::User, pin1));
        assert!(!reply.success);

        syscall!(client.set_pin(Pin::User, pin2.clone(), Some(1), false));
        let reply = syscall!(client.check_pin(Pin::User, pin2));
        assert!(reply.success);
    })
}

#[test]
fn empty_pin() {
    run(BACKENDS, |client| {
        let pin1 = Bytes::new();
        let pin2 = Bytes::from_slice(b"123456").unwrap();

        syscall!(client.set_pin(Pin::User, pin1.clone(), None, false));
        let reply = syscall!(client.has_pin(Pin::User));
        assert!(reply.has_pin);
        let reply = syscall!(client.check_pin(Pin::User, pin1.clone()));
        assert!(reply.success);
        let reply = syscall!(client.check_pin(Pin::User, pin2));
        assert!(!reply.success);
        let reply = syscall!(client.check_pin(Pin::User, pin1));
        assert!(reply.success);
    })
}

#[test]
fn max_pin_length() {
    run(BACKENDS, |client| {
        let pin1 = random_pin();
        let pin2 = loop {
            let pin = random_pin();
            if pin1 != pin {
                break pin;
            }
        };

        syscall!(client.set_pin(Pin::User, pin1.clone(), None, false));
        let reply = syscall!(client.check_pin(Pin::User, pin1));
        assert!(reply.success);
        let reply = syscall!(client.check_pin(Pin::User, pin2));
        assert!(!reply.success);
    })
}

#[test]
fn pin_retries() {
    run(BACKENDS, |client| {
        let pin1 = Bytes::from_slice(b"12345678").unwrap();
        let pin2 = Bytes::from_slice(b"123456").unwrap();
        let pin3 = Bytes::from_slice(b"654321").unwrap();

        syscall!(client.set_pin(Pin::User, pin1.clone(), Some(3), false));
        syscall!(client.set_pin(Pin::Admin, pin2.clone(), Some(5), false));
        syscall!(client.set_pin(Pin::Custom, pin3.clone(), None, false));

        let reply = syscall!(client.pin_retries(Pin::User));
        assert_eq!(reply.retries, Some(3));
        let reply = syscall!(client.pin_retries(Pin::Admin));
        assert_eq!(reply.retries, Some(5));
        let reply = syscall!(client.pin_retries(Pin::Custom));
        assert_eq!(reply.retries, None);

        for i in 0..2 {
            let reply = syscall!(client.check_pin(Pin::User, pin2.clone()));
            assert!(!reply.success);
            let reply = syscall!(client.check_pin(Pin::Admin, pin3.clone()));
            assert!(!reply.success);
            let reply = syscall!(client.check_pin(Pin::Custom, pin1.clone()));
            assert!(!reply.success);

            let reply = syscall!(client.pin_retries(Pin::User));
            assert_eq!(reply.retries, Some(3 - i - 1));
            let reply = syscall!(client.pin_retries(Pin::Admin));
            assert_eq!(reply.retries, Some(5 - i - 1));
            let reply = syscall!(client.pin_retries(Pin::Custom));
            assert_eq!(reply.retries, None);
        }

        let reply = syscall!(client.check_pin(Pin::User, pin1));
        assert!(reply.success);
        let reply = syscall!(client.check_pin(Pin::Admin, pin2));
        assert!(reply.success);
        let reply = syscall!(client.check_pin(Pin::Custom, pin3));
        assert!(reply.success);

        let reply = syscall!(client.pin_retries(Pin::User));
        assert_eq!(reply.retries, Some(3));
        let reply = syscall!(client.pin_retries(Pin::Admin));
        assert_eq!(reply.retries, Some(5));
        let reply = syscall!(client.pin_retries(Pin::Custom));
        assert_eq!(reply.retries, None);
    })
}

#[test]
fn delete_pin() {
    run(BACKENDS, |client| {
        let pin = Bytes::from_slice(b"123456").unwrap();

        syscall!(client.set_pin(Pin::User, pin.clone(), None, false));
        let reply = syscall!(client.has_pin(Pin::User));
        assert!(reply.has_pin);

        syscall!(client.delete_pin(Pin::User));
        let reply = syscall!(client.has_pin(Pin::User));
        assert!(!reply.has_pin);

        let result = try_syscall!(client.check_pin(Pin::User, pin));
        assert!(result.is_err());

        syscall!(client.delete_pin(Pin::User));
    })
}

#[test]
fn delete_all_pins() {
    run(BACKENDS, |client| {
        let pin1 = Bytes::from_slice(b"123456").unwrap();
        let pin2 = Bytes::from_slice(b"12345678").unwrap();

        syscall!(client.set_pin(Pin::User, pin1.clone(), None, false));
        syscall!(client.set_pin(Pin::Admin, pin2.clone(), None, false));

        let reply = syscall!(client.has_pin(Pin::User));
        assert!(reply.has_pin);
        let reply = syscall!(client.has_pin(Pin::Admin));
        assert!(reply.has_pin);

        syscall!(client.delete_all_pins());

        let reply = syscall!(client.has_pin(Pin::User));
        assert!(!reply.has_pin);
        let reply = syscall!(client.has_pin(Pin::Admin));
        assert!(!reply.has_pin);

        let result = try_syscall!(client.check_pin(Pin::User, pin1));
        assert!(result.is_err());
        let result = try_syscall!(client.check_pin(Pin::Admin, pin2));
        assert!(result.is_err());
    })
}
