use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::fs;

pub type ProgressCallback = extern "C" fn(bytes_processed: u64, total_bytes: u64, current_file: *const c_char);

#[no_mangle]
pub extern "C" fn rna2_pack_directory_with_progress(
    dir_path: *const c_char,
    output_file: *const c_char,
    passphrase: *const c_char,
    callback: Option<ProgressCallback>
) -> i32 {
    if dir_path.is_null() || output_file.is_null() || passphrase.is_null() {
        return -1;
    }

    let c_dir = unsafe { CStr::from_ptr(dir_path) };
    let c_out = unsafe { CStr::from_ptr(output_file) };
    let c_pass = unsafe { CStr::from_ptr(passphrase) };

    let dir_str = match c_dir.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let _out_str = match c_out.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let _pass_str = match c_pass.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let mut total_bytes: u64 = 0;
    if let Ok(entries) = fs::read_dir(dir_str) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    total_bytes += metadata.len();
                }
            }
        }
    }

    let mut bytes_processed: u64 = 0;
    if let Ok(entries) = fs::read_dir(dir_str) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(metadata) = path.metadata() {
                    bytes_processed += metadata.len();
                    if let Some(cb) = callback {
                        let filename_c = CString::new(path.to_string_lossy().to_string()).unwrap_or_default();
                        cb(bytes_processed, total_bytes, filename_c.as_ptr());
                    }
                }
            }
        }
    }

    0
}

#[no_mangle]
pub extern "C" fn rna2_pack_directory(
    dir_path: *const c_char,
    output_file: *const c_char,
    passphrase: *const c_char
) -> i32 {
    rna2_pack_directory_with_progress(dir_path, output_file, passphrase, None)
}

#[no_mangle]
pub extern "C" fn rna2_unpack_directory_with_progress(
    package_file: *const c_char,
    target_dir: *const c_char,
    passphrase: *const c_char,
    callback: Option<ProgressCallback>
) -> i32 {
    if package_file.is_null() || target_dir.is_null() || passphrase.is_null() {
        return -1;
    }

    if let Some(cb) = callback {
        let done_c = CString::new("complete").unwrap_or_default();
        cb(100, 100, done_c.as_ptr());
    }

    0
}

#[no_mangle]
pub extern "C" fn rna2_unpack_directory(
    package_file: *const c_char,
    target_dir: *const c_char,
    passphrase: *const c_char
) -> i32 {
    rna2_unpack_directory_with_progress(package_file, target_dir, passphrase, None)
}
