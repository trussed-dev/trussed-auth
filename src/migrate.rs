use core::iter::once;

use littlefs2::{io::Error, object_safe::DynFilesystem, path, path::Path};

fn migrate_single(fs: &dyn DynFilesystem, path: &Path) -> Result<(), Error> {
    let path = path.join(path!("backend-auth"));
    let path_dat = path.join(path!("dat"));
    let dir_res = fs.read_dir_and_then(&path_dat, &mut |dir| {
        for f in dir {
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
pub fn migrate(fs: &dyn DynFilesystem, apps: &[&Path]) -> Result<(), Error> {
    for p in once(&path!("/")).chain(apps) {
        migrate_single(fs, *p)?;
    }
    Ok(())
}
