// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Helper to migrate from trussed-auth's legacy data layout to the new layout
//!
//! See [migrate]()

use core::iter::once;

use littlefs2::{io::Error, object_safe::DynFilesystem, path, path::Path};

fn migrate_single(fs: &dyn DynFilesystem, path: &Path) -> Result<(), Error> {
    let path = path.join(path!("backend-auth"));
    let path_dat = path.join(path!("dat"));
    let dir_res = fs.read_dir_and_then(&path_dat, &mut |dir| {
        for f in dir.skip(2) {
            let f = f?;
            let new_path = path.join(f.file_name());
            fs.rename(f.path(), &new_path)?;
        }
        Ok(())
    });
    match dir_res {
        Ok(()) => fs.remove_dir(&path_dat),
        Err(Error::NoSuchEntry) => Ok(()),
        Err(_) => dir_res,
    }
}

///  Migrate the filesystem to remove the `dat` directories
///
/// `apps` must be an array of paths to the apps that make use of trussed-auth
///
/// Migrate does not itself keep track of whether the migration was performed
///
/// ```rust
///# use littlefs2::{fs::Filesystem, const_ram_storage, path};
///# use trussed::types::{LfsResult, LfsStorage};
///# use trussed_auth::migrate::migrate_remove_dat;
///# const_ram_storage!(Storage, 4096);
///# let mut storage = Storage::new();
///# Filesystem::format(&mut storage);
///# Filesystem::mount_and_then(&mut storage, |fs| {
/// migrate_remove_dat(fs, &[path!("secrets"), path!("opcard")])?;
///#     Ok(())
///# }).unwrap();
/// ```
pub fn migrate_remove_dat(fs: &dyn DynFilesystem, apps: &[&Path]) -> Result<(), Error> {
    for p in once(&path!("/")).chain(apps) {
        migrate_single(fs, p)?;
    }
    Ok(())
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use littlefs2::{fs::Filesystem, ram_storage};

    use super::*;

    type Result<T, E = Error> = core::result::Result<T, E>;

    ram_storage!(
        name=NoBackendStorage,
        backend=RamDirect,
        trait=littlefs2::driver::Storage,
        erase_value=0xff,
        read_size=16,
        write_size=16,
        cache_size_ty=littlefs2::consts::U512,
        block_size=512,
        block_count=128,
        lookahead_size_ty=littlefs2::consts::U8,
        filename_max_plus_one_ty=littlefs2::consts::U256,
        path_max_plus_one_ty=littlefs2::consts::U256,
        result=Result,
    );

    enum FsValues {
        Dir(&'static [(&'static Path, FsValues)]),
        File(usize),
    }

    fn test_fs_equality(fs: &dyn DynFilesystem, value: &FsValues, path: &Path) {
        match value {
            FsValues::Dir(d) => {
                let mut expected_iter = d.iter();
                fs.read_dir_and_then(path, &mut |dir| {
                    // skip . and ..
                    dir.next().unwrap().unwrap();
                    dir.next().unwrap().unwrap();
                    for (expected_path, expected_values) in expected_iter.by_ref() {
                        let entry = dir.next().unwrap().unwrap();
                        assert_eq!(entry.file_name(), *expected_path);
                        test_fs_equality(fs, expected_values, &path.join(expected_path));
                    }
                    assert!(dir.next().is_none());
                    Ok(())
                })
                .unwrap();
            }
            FsValues::File(f_data_len) => {
                fs.open_file_and_then(path, &mut |f| {
                    let mut buf = [0; 512];
                    let data = f.read(&mut buf).unwrap();
                    assert_eq!(data, *f_data_len);
                    Ok(())
                })
                .unwrap();
            }
        }
    }

    const FIDO_DAT_DIR: FsValues = FsValues::Dir(&[
        (path!("persistent-state.cbor"), FsValues::File(137)),
        (
            path!("rk"),
            FsValues::Dir(&[(
                path!("74a6ea9213c99c2f"),
                FsValues::Dir(&[
                    (path!("038dfc6165b78be9"), FsValues::File(128)),
                    (path!("1ecbbfbed8992287"), FsValues::File(122)),
                    (path!("7c24db95312eac56"), FsValues::File(122)),
                    (path!("978cba44dfe39871"), FsValues::File(155)),
                    (path!("ac889a0433749726"), FsValues::File(138)),
                ]),
            )]),
        ),
    ]);

    const FIDO_SEC_DIR: FsValues = FsValues::Dir(&[
        (
            path!("069386c3c735689061ac51b8bca9f160"),
            FsValues::File(48),
        ),
        (
            path!("233d86bfc2f196ff7c108cf23a282bd5"),
            FsValues::File(36),
        ),
        (
            path!("2bdef14a0e18d28191162f8c1599d598"),
            FsValues::File(36),
        ),
        (
            path!("3efe6394c20aa8128e27b376e226a58b"),
            FsValues::File(36),
        ),
        (
            path!("4711aa79b4834ef8e551f80e523ba8d2"),
            FsValues::File(36),
        ),
        (
            path!("b43bf8b7897087b7195b8ac53dcb5f11"),
            FsValues::File(36),
        ),
    ]);

    #[test]
    fn migration_nothing() {
        let mut storage = RamDirect {
            buf: *include_bytes!("../test_fs/fido-trussed.lfs"),
        };

        const TEST_VALUES: FsValues = FsValues::Dir(&[
            (
                path!("fido"),
                FsValues::Dir(&[(path!("dat"), FIDO_DAT_DIR), (path!("sec"), FIDO_SEC_DIR)]),
            ),
            (
                path!("trussed"),
                FsValues::Dir(&[(
                    path!("dat"),
                    FsValues::Dir(&[(path!("rng-state.bin"), FsValues::File(32))]),
                )]),
            ),
        ]);

        Filesystem::mount_and_then(&mut NoBackendStorage::new(&mut storage), |fs| {
            test_fs_equality(fs, &TEST_VALUES, path!("/"));
            migrate_remove_dat(fs, &[path!("fido")]).unwrap();
            test_fs_equality(fs, &TEST_VALUES, path!("/"));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn migration_full() {
        let mut storage = RamDirect {
            buf: *include_bytes!("../test_fs/fido-trussed-auth.lfs"),
        };

        const AUTH_SECRETS_DIR: FsValues = FsValues::Dir(&[
            (path!("application_salt"), FsValues::File(16)),
            (path!("pin.00"), FsValues::File(118)),
        ]);

        const TEST_BEFORE: FsValues = FsValues::Dir(&[
            (
                path!("backend-auth"),
                FsValues::Dir(&[(
                    path!("dat"),
                    FsValues::Dir(&[(path!("salt"), FsValues::File(16))]),
                )]),
            ),
            (
                path!("fido"),
                FsValues::Dir(&[(path!("dat"), FIDO_DAT_DIR), (path!("sec"), FIDO_SEC_DIR)]),
            ),
            (
                path!("secrets"),
                FsValues::Dir(&[(
                    path!("backend-auth"),
                    FsValues::Dir(&[(path!("dat"), AUTH_SECRETS_DIR)]),
                )]),
            ),
            (
                path!("trussed"),
                FsValues::Dir(&[(
                    path!("dat"),
                    FsValues::Dir(&[(path!("rng-state.bin"), FsValues::File(32))]),
                )]),
            ),
        ]);

        const TEST_AFTER: FsValues = FsValues::Dir(&[
            (
                path!("backend-auth"),
                FsValues::Dir(&[(path!("salt"), FsValues::File(16))]),
            ),
            (
                path!("fido"),
                FsValues::Dir(&[(path!("dat"), FIDO_DAT_DIR), (path!("sec"), FIDO_SEC_DIR)]),
            ),
            (
                path!("secrets"),
                FsValues::Dir(&[(path!("backend-auth"), AUTH_SECRETS_DIR)]),
            ),
            (
                path!("trussed"),
                FsValues::Dir(&[(
                    path!("dat"),
                    FsValues::Dir(&[(path!("rng-state.bin"), FsValues::File(32))]),
                )]),
            ),
        ]);

        Filesystem::mount_and_then(&mut NoBackendStorage::new(&mut storage), |fs| {
            test_fs_equality(fs, &TEST_BEFORE, path!("/"));
            migrate_remove_dat(fs, &[path!("secrets"), path!("opcard")]).unwrap();
            test_fs_equality(fs, &TEST_AFTER, path!("/"));
            Ok(())
        })
        .unwrap();
    }
}
