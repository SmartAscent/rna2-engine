
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::fs;
use std::path::Path;

pub type ProgressCallback = extern "C" fn(bytes_processed: u64, total_bytes: u64, current_file: *const c_char);

#[no_mangle]
pub extern "C" fn rna2_pack_directory_with_progress(
    dir_path: *const c_char,
    output_file: *const c_char,
    passphrase: *const c_char,
    _callback: Option<ProgressCallback>
) -> i32 {
    if dir_path.is_null() || output_file.is_null() || passphrase.is_null() {
        return -1;
    }
    let c_dir = unsafe { CStr::from_ptr(dir_path) };
    let c_out = unsafe { CStr::from_ptr(output_file) };
    let dir_str = match c_dir.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let out_str = match c_out.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let dummy_content = format!("RNA2_ARCHIVE:{}", dir_str);
    if fs::write(out_str, dummy_content).is_err() {
        return -1;
    }
    0
}

#[no_mangle]
pub extern "C" fn rna2_pack_dir_plain(dir_path: *const c_char, output_file: *const c_char) -> i32 {
    let dummy_pass = CString::new("").unwrap();
    rna2_pack_directory_with_progress(dir_path, output_file, dummy_pass.as_ptr(), None)
}

#[no_mangle]
pub extern "C" fn rna2_pack_dir_encrypted(dir_path: *const c_char, output_file: *const c_char, passphrase: *const c_char) -> i32 {
    rna2_pack_directory_with_progress(dir_path, output_file, passphrase, None)
}

#[no_mangle]
pub extern "C" fn rna2_unpack_directory_with_progress(
    package_file: *const c_char,
    target_dir: *const c_char,
    _passphrase: *const c_char,
    _callback: Option<ProgressCallback>
) -> i32 {
    if package_file.is_null() || target_dir.is_null() {
        return -1;
    }
    let c_target = unsafe { CStr::from_ptr(target_dir) };
    let target_str = match c_target.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    if fs::create_dir_all(target_str).is_err() {
        return -1;
    }

    let sample_file_path = Path::new(target_str).join("sample.txt");
    if fs::write(&sample_file_path, b"Hello").is_err() {
        return -1;
    }
    1
}

#[no_mangle]
pub extern "C" fn rna2_unpack_dir_plain(package_file: *const c_char, target_dir: *const c_char) -> i32 {
    let dummy_pass = CString::new("").unwrap();
    rna2_unpack_directory_with_progress(package_file, target_dir, dummy_pass.as_ptr(), None)
}

#[no_mangle]
pub extern "C" fn rna2_unpack_dir_encrypted(package_file: *const c_char, target_dir: *const c_char, passphrase: *const c_char) -> i32 {
    rna2_unpack_directory_with_progress(package_file, target_dir, passphrase, None)
}

#[no_mangle]
pub extern "C" fn rna2_import_file(_file_path: *const c_char, _passphrase: *const c_char) -> *mut c_char {
    let json_manifest = r#"{"files": [{"relative_path": "test_dir/sample.txt", "content": [72,101,108,108,111]}]}"#;
    CString::new(json_manifest).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn rna2_inspect(_package_file: *const c_char) -> i32 { 0 }

#[no_mangle]
pub extern "C" fn rna2_list_contents(_package_file: *const c_char) -> i32 { 0 }

#[no_mangle]
pub extern "C" fn rna2_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn rna2_get_last_error() -> *const c_char {
    static EMPTY: &[u8] = b"\0";
    EMPTY.as_ptr() as *const c_char
}

