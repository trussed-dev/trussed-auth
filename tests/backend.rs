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
    client::{ClientImplementation, FilesystemClient, HmacSha256},
    service::Service,
    syscall, try_syscall,
    types::{Bytes, Location, Message, PathBuf},
    virt::{self, Ram},
};
use trussed_auth::{request::DerivedKeyMechanism, AuthClient as _, PinId, MAX_HW_KEY_LEN};

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

        syscall!(client.set_pin(Pin::User, pin1.clone(), None, None));

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

        syscall!(client.set_pin(
            Pin::User,
            pin1.clone(),
            None,
            Some(DerivedKeyMechanism::Chacha8Poly1305)
        ));

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

            syscall!(client.set_pin(
                Pin::User,
                pin1.clone(),
                None,
                Some(DerivedKeyMechanism::Chacha8Poly1305)
            ));

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

        assert!(try_syscall!(client.set_pin(
            Pin::User,
            pin1.clone(),
            None,
            Some(DerivedKeyMechanism::Chacha8Poly1305)
        ))
        .is_err());

        let reply = syscall!(client.has_pin(Pin::User));
        assert!(!reply.has_pin);

        syscall!(client.set_pin(Pin::User, pin1.clone(), None, None));

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

            syscall!(client.set_pin(
                Pin::User,
                pin1.clone(),
                Some(3),
                Some(DerivedKeyMechanism::Chacha8Poly1305)
            ));
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
fn reset_pin_key() {
    run_with_hw_key(
        BACKENDS,
        Bytes::from_slice(b"Some HW ikm").unwrap(),
        |client| {
            let pin1 = Bytes::from_slice(b"12345678").unwrap();
            let pin2 = Bytes::from_slice(b"123456").unwrap();
            let pin3 = Bytes::from_slice(b"1234567890").unwrap();

            syscall!(client.set_pin(
                Pin::User,
                pin1.clone(),
                Some(3),
                Some(DerivedKeyMechanism::Chacha8Poly1305)
            ));
            assert!(syscall!(client.get_pin_key(Pin::User, pin2.clone()))
                .result
                .is_none());
            assert_eq!(syscall!(client.pin_retries(Pin::User)).retries, Some(2));
            assert!(!syscall!(client.check_pin(Pin::User, pin2.clone())).success);
            assert_eq!(syscall!(client.pin_retries(Pin::User)).retries, Some(1));
            assert!(syscall!(client.check_pin(Pin::User, pin1.clone())).success);
            let key = syscall!(client.get_pin_key(Pin::User, pin1))
                .result
                .unwrap();
            assert_eq!(syscall!(client.pin_retries(Pin::User)).retries, Some(3));
            let mac = syscall!(client.sign_hmacsha256(key, b"Some data")).signature;

            syscall!(client.set_pin_with_key(Pin::User, pin3.clone(), Some(3), key));

            let key2 = syscall!(client.get_pin_key(Pin::User, pin3.clone()))
                .result
                .unwrap();
            let mac2 = syscall!(client.sign_hmacsha256(key2, b"Some data")).signature;
            assert_eq!(mac, mac2);

            assert!(syscall!(client.change_pin(Pin::User, pin3.clone(), pin2.clone())).success);

            let key3 = syscall!(client.get_pin_key(Pin::User, pin2.clone()))
                .result
                .unwrap();
            let mac3 = syscall!(client.sign_hmacsha256(key3, b"Some data")).signature;
            assert_eq!(mac, mac3);

            assert!(!syscall!(client.check_pin(Pin::User, pin3.clone())).success);
            assert!(!syscall!(client.check_pin(Pin::User, pin3.clone())).success);
            assert!(!syscall!(client.check_pin(Pin::User, pin3)).success);
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

        syscall!(client.set_pin(
            Pin::User,
            pin1.clone(),
            Some(3),
            Some(DerivedKeyMechanism::Chacha8Poly1305)
        ));

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

        syscall!(client.set_pin(Pin::User, pin1.clone(), Some(1), None));
        let reply = syscall!(client.check_pin(Pin::User, pin1.clone()));
        assert!(reply.success);
        let reply = syscall!(client.check_pin(Pin::User, pin2.clone()));
        assert!(!reply.success);
        let reply = syscall!(client.check_pin(Pin::User, pin1));
        assert!(!reply.success);

        syscall!(client.set_pin(Pin::User, pin2.clone(), Some(1), None));
        let reply = syscall!(client.check_pin(Pin::User, pin2));
        assert!(reply.success);
    })
}

#[test]
fn empty_pin() {
    run(BACKENDS, |client| {
        let pin1 = Bytes::new();
        let pin2 = Bytes::from_slice(b"123456").unwrap();

        syscall!(client.set_pin(Pin::User, pin1.clone(), None, None));
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

        syscall!(client.set_pin(Pin::User, pin1.clone(), None, None));
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

        syscall!(client.set_pin(Pin::User, pin1.clone(), Some(3), None));
        syscall!(client.set_pin(Pin::Admin, pin2.clone(), Some(5), None));
        syscall!(client.set_pin(Pin::Custom, pin3.clone(), None, None));

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

        syscall!(client.set_pin(Pin::User, pin.clone(), None, None));
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

        syscall!(client.set_pin(Pin::User, pin1.clone(), None, None));
        syscall!(client.set_pin(Pin::Admin, pin2.clone(), None, None));

        let reply = syscall!(client.has_pin(Pin::User));
        assert!(reply.has_pin);
        let reply = syscall!(client.has_pin(Pin::Admin));
        assert!(reply.has_pin);
        assert!(try_syscall!(
            client.read_file(Location::Internal, PathBuf::from("/backend-auth/pin.00"))
        )
        .is_err());

        syscall!(client.reset_app_keys());
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

#[test]
fn reset_application_key() {
    run(BACKENDS, |client| {
        let info1 = Message::from_slice(b"test1").unwrap();
        let info2 = Message::from_slice(b"test2").unwrap();
        let app_key1 = syscall!(client.get_application_key(info1.clone())).key;
        let app_key2 = syscall!(client.get_application_key(info2)).key;
        let mac1 = syscall!(client.sign_hmacsha256(app_key1, b"Some data")).signature;
        let mac2 = syscall!(client.sign_hmacsha256(app_key2, b"Some data")).signature;
        // Different info leads to different keys
        assert_ne!(mac1, mac2);

        let app_key1_again = syscall!(client.get_application_key(info1.clone())).key;
        let mac1_again = syscall!(client.sign_hmacsha256(app_key1_again, b"Some data")).signature;
        // Same info leads to same key
        assert_eq!(mac1, mac1_again);

        syscall!(client.delete_all_pins());

        let app_key1_after_delete = syscall!(client.get_application_key(info1.clone())).key;
        let mac1_after_delete =
            syscall!(client.sign_hmacsha256(app_key1_after_delete, b"Some data")).signature;
        // Same info leads to same key
        assert_eq!(mac1, mac1_after_delete);

        syscall!(client.reset_app_keys());

        // After deletion same info leads to different keys
        let app_key1_after_delete = syscall!(client.get_application_key(info1)).key;
        let mac1_after_delete =
            syscall!(client.sign_hmacsha256(app_key1_after_delete, b"Some data")).signature;
        assert_ne!(mac1, mac1_after_delete);
    })
}

#[test]
fn reset_auth_data() {
    run(BACKENDS, |client| {
        /* ------- APP KEYS ------- */
        let info1 = Message::from_slice(b"test1").unwrap();
        let info2 = Message::from_slice(b"test2").unwrap();
        let app_key1 = syscall!(client.get_application_key(info1.clone())).key;
        let app_key2 = syscall!(client.get_application_key(info2)).key;
        let mac1 = syscall!(client.sign_hmacsha256(app_key1, b"Some data")).signature;
        let mac2 = syscall!(client.sign_hmacsha256(app_key2, b"Some data")).signature;
        // Different info leads to different keys
        assert_ne!(mac1, mac2);

        let app_key1_again = syscall!(client.get_application_key(info1.clone())).key;
        let mac1_again = syscall!(client.sign_hmacsha256(app_key1_again, b"Some data")).signature;
        // Same info leads to same key
        assert_eq!(mac1, mac1_again);

        /* ------- PINS  ------- */
        let pin1 = Bytes::from_slice(b"123456").unwrap();
        let pin2 = Bytes::from_slice(b"12345678").unwrap();

        syscall!(client.set_pin(Pin::User, pin1.clone(), None, None));
        syscall!(client.set_pin(Pin::Admin, pin2.clone(), None, None));

        let reply = syscall!(client.has_pin(Pin::User));
        assert!(reply.has_pin);
        let reply = syscall!(client.has_pin(Pin::Admin));
        assert!(reply.has_pin);
        assert!(try_syscall!(
            client.read_file(Location::Internal, PathBuf::from("/backend-auth/pin.00"))
        )
        .is_err());

        syscall!(client.reset_auth_data());

        /* ------- APP KEYS ------- */
        // After deletion same info leads to different keys
        let app_key1_after_delete = syscall!(client.get_application_key(info1)).key;
        let mac1_after_delete =
            syscall!(client.sign_hmacsha256(app_key1_after_delete, b"Some data")).signature;
        assert_ne!(mac1, mac1_after_delete);

        /* ------- PINS  ------- */
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
