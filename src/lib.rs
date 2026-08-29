use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::fs;
use std::io::{Read, Write};
use std::os::raw::c_char;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const MAGIC: &[u8; 4] = b"RNA2";
const VERSION: u8 = 1;
const FLAG_PLAIN: u8 = 0x00;
const FLAG_ENCRYPTED: u8 = 0x01;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const PBKDF2_ROUNDS: u32 = 100_000;

const ERR_INVALID_PARAM: i32 = -1;
const ERR_ENCRYPTION_FAILED: i32 = -2;
const ERR_DECRYPTION_FAILED: i32 = -3;
const ERR_IO_FAILURE: i32 = -4;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

fn set_last_error(msg: impl Into<String>) {
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(msg.into()));
}

#[derive(Serialize, Deserialize)]
struct FileEntry {
    relative_path: String,
    content: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    files: Vec<FileEntry>,
}

fn cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() { return None; }
    unsafe { CStr::from_ptr(ptr).to_str().ok() }
}

fn collect_files(base: &Path, current: &Path, out: &mut Vec<FileEntry>) -> std::io::Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(base, &path, out)?;
        } else {
            let mut f = fs::File::open(&path)?;
            let mut content = Vec::new();
            f.read_to_end(&mut content)?;
            let rel = path
                .strip_prefix(base).unwrap_or(&path)
                .to_string_lossy().replace('\\', "/");
            out.push(FileEntry { relative_path: rel, content });
        }
    }
    Ok(())
}

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, PBKDF2_ROUNDS, &mut key);
    key
}

fn compress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data)?;
    enc.finish()
}

fn decompress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    Ok(out)
}

pub type ProgressCallback =
    extern "C" fn(bytes_processed: u64, total_bytes: u64, current_file: *const c_char);

fn pack_internal(
    dir_path: &str,
    output_file: &str,
    passphrase: Option<&str>,
    callback: Option<ProgressCallback>,
) -> Result<(), (i32, String)> {
    let base = Path::new(dir_path);
    let mut files = Vec::new();
    collect_files(base, base, &mut files)
        .map_err(|e| (ERR_IO_FAILURE, format!("Failed to read directory '{}': {e}", dir_path)))?;

    if let Some(cb) = callback {
        let msg = CString::new("scanned").unwrap_or_default();
        cb(0, files.len() as u64, msg.as_ptr());
    }

    let manifest = Manifest { files };
    let json = serde_json::to_vec(&manifest)
        .map_err(|e| (ERR_IO_FAILURE, format!("Serialization failed: {e}")))?;
    let compressed = compress(&json)
        .map_err(|e| (ERR_IO_FAILURE, format!("Compression failed: {e}")))?;

    let mut out_bytes = Vec::new();
    out_bytes.extend_from_slice(MAGIC);
    out_bytes.push(VERSION);

    match passphrase {
        Some(pass) if !pass.is_empty() => {
            out_bytes.push(FLAG_ENCRYPTED);

            // rand 0.10: rand::random() uses the thread-local RNG, no trait import needed
            let salt: [u8; SALT_LEN]   = rand::random();
            let nonce_bytes: [u8; NONCE_LEN] = rand::random();

            let key_bytes = derive_key(pass, &salt);
            let key    = Key::<Aes256Gcm>::from_slice(&key_bytes);
            let cipher = Aes256Gcm::new(key);
            let nonce  = Nonce::from_slice(&nonce_bytes);
            let ciphertext = cipher
                .encrypt(nonce, compressed.as_ref())
                .map_err(|_| (ERR_ENCRYPTION_FAILED, "AES-256-GCM encryption failed".to_string()))?;

            out_bytes.extend_from_slice(&salt);
            out_bytes.extend_from_slice(&nonce_bytes);
            out_bytes.extend_from_slice(&ciphertext);
        }
        _ => {
            out_bytes.push(FLAG_PLAIN);
            out_bytes.extend_from_slice(&compressed);
        }
    }

    fs::write(output_file, &out_bytes)
        .map_err(|e| (ERR_IO_FAILURE, format!("Failed to write '{}': {e}", output_file)))?;

    if let Some(cb) = callback {
        let msg = CString::new("done").unwrap_or_default();
        cb(out_bytes.len() as u64, out_bytes.len() as u64, msg.as_ptr());
    }
    Ok(())
}

fn read_manifest(package_file: &str, passphrase: Option<&str>) -> Result<Manifest, (i32, String)> {
    let raw = fs::read(package_file)
        .map_err(|e| (ERR_IO_FAILURE, format!("Failed to read '{}': {e}", package_file)))?;

    if raw.len() < 6 || &raw[0..4] != MAGIC {
        return Err((ERR_INVALID_PARAM, "Invalid RNA2 file: bad magic header".to_string()));
    }
    let flag    = raw[5];
    let payload = &raw[6..];

    let compressed = match flag {
        FLAG_PLAIN => payload.to_vec(),
        FLAG_ENCRYPTED => {
            let pass = passphrase.filter(|p| !p.is_empty())
                .ok_or_else(|| (ERR_INVALID_PARAM, "Passphrase required for encrypted archive".to_string()))?;
            if payload.len() < SALT_LEN + NONCE_LEN {
                return Err((ERR_INVALID_PARAM, "Corrupt archive: truncated header".to_string()));
            }
            let salt        = &payload[0..SALT_LEN];
            let nonce_bytes = &payload[SALT_LEN..SALT_LEN + NONCE_LEN];
            let ciphertext  = &payload[SALT_LEN + NONCE_LEN..];

            let key_bytes = derive_key(pass, salt);
            let key    = Key::<Aes256Gcm>::from_slice(&key_bytes);
            let cipher = Aes256Gcm::new(key);
            let nonce  = Nonce::from_slice(nonce_bytes);
            cipher.decrypt(nonce, ciphertext)
                .map_err(|_| (ERR_DECRYPTION_FAILED,
                    "Decryption failed: wrong passphrase or corrupted data".to_string()))?
        }
        _ => return Err((ERR_INVALID_PARAM, format!("Unknown flag: 0x{:02x}", flag))),
    };

    let json = decompress(&compressed)
        .map_err(|e| (ERR_IO_FAILURE, format!("Decompression failed: {e}")))?;
    serde_json::from_slice(&json)
        .map_err(|e| (ERR_IO_FAILURE, format!("Manifest parse failed: {e}")))
}

fn unpack_internal(
    package_file: &str,
    target_dir: &str,
    passphrase: Option<&str>,
    callback: Option<ProgressCallback>,
) -> Result<i32, (i32, String)> {
    let manifest = read_manifest(package_file, passphrase)?;
    let target   = Path::new(target_dir);
    fs::create_dir_all(target)
        .map_err(|e| (ERR_IO_FAILURE, format!("Failed to create '{}': {e}", target_dir)))?;

    let total = manifest.files.len() as u64;
    let mut count = 0i32;
    for (i, entry) in manifest.files.iter().enumerate() {
        let out_path = target.join(&entry.relative_path);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| (ERR_IO_FAILURE, format!("mkdir {:?}: {e}", parent)))?;
        }
        fs::write(&out_path, &entry.content)
            .map_err(|e| (ERR_IO_FAILURE, format!("write {:?}: {e}", out_path)))?;
        count += 1;
        if let Some(cb) = callback {
            let name = CString::new(entry.relative_path.as_str()).unwrap_or_default();
            cb((i + 1) as u64, total, name.as_ptr());
        }
    }
    Ok(count)
}

// ── C-ABI exports ─────────────────────────────────────────────────────────────

fn raise(code: i32, msg: String) -> i32 { set_last_error(msg); code }

#[no_mangle]
pub extern "C" fn rna2_pack_directory_with_progress(
    dir_path: *const c_char, output_file: *const c_char,
    passphrase: *const c_char, callback: Option<ProgressCallback>,
) -> i32 {
    let dir = match cstr_to_str(dir_path)    { Some(s) => s, None => return raise(ERR_INVALID_PARAM, "null dir_path".into()) };
    let out = match cstr_to_str(output_file) { Some(s) => s, None => return raise(ERR_INVALID_PARAM, "null output_file".into()) };
    match pack_internal(dir, out, cstr_to_str(passphrase), callback) {
        Ok(())           => 0,
        Err((code, msg)) => raise(code, msg),
    }
}

#[no_mangle]
pub extern "C" fn rna2_pack_dir_plain(dir_path: *const c_char, output_file: *const c_char) -> i32 {
    rna2_pack_directory_with_progress(dir_path, output_file, std::ptr::null(), None)
}

#[no_mangle]
pub extern "C" fn rna2_pack_dir_encrypted(
    dir_path: *const c_char, output_file: *const c_char, passphrase: *const c_char,
) -> i32 {
    rna2_pack_directory_with_progress(dir_path, output_file, passphrase, None)
}

#[no_mangle]
pub extern "C" fn rna2_unpack_directory_with_progress(
    package_file: *const c_char, target_dir: *const c_char,
    passphrase: *const c_char, callback: Option<ProgressCallback>,
) -> i32 {
    let pkg = match cstr_to_str(package_file) { Some(s) => s, None => return raise(ERR_INVALID_PARAM, "null package_file".into()) };
    let tgt = match cstr_to_str(target_dir)   { Some(s) => s, None => return raise(ERR_INVALID_PARAM, "null target_dir".into()) };
    match unpack_internal(pkg, tgt, cstr_to_str(passphrase), callback) {
        Ok(n)            => n,
        Err((code, msg)) => raise(code, msg),
    }
}

#[no_mangle]
pub extern "C" fn rna2_unpack_dir_plain(package_file: *const c_char, target_dir: *const c_char) -> i32 {
    rna2_unpack_directory_with_progress(package_file, target_dir, std::ptr::null(), None)
}

#[no_mangle]
pub extern "C" fn rna2_unpack_dir_encrypted(
    package_file: *const c_char, target_dir: *const c_char, passphrase: *const c_char,
) -> i32 {
    rna2_unpack_directory_with_progress(package_file, target_dir, passphrase, None)
}

#[no_mangle]
pub extern "C" fn rna2_import_file(file_path: *const c_char, passphrase: *const c_char) -> *mut c_char {
    let path = match cstr_to_str(file_path) {
        Some(s) => s,
        None => { set_last_error("null file_path"); return std::ptr::null_mut(); }
    };
    match read_manifest(path, cstr_to_str(passphrase)) {
        Ok(manifest) => match serde_json::to_string(&manifest) {
            Ok(json) => match CString::new(json) {
                Ok(c)  => c.into_raw(),
                Err(_) => { set_last_error("interior null in manifest"); std::ptr::null_mut() }
            },
            Err(e) => { set_last_error(format!("serialize failed: {e}")); std::ptr::null_mut() }
        },
        Err((_, msg)) => { set_last_error(msg); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "C" fn rna2_free_string(ptr: *mut c_char) {
    if !ptr.is_null() { unsafe { let _ = CString::from_raw(ptr); } }
}

#[no_mangle]
pub extern "C" fn rna2_get_last_error() -> *mut c_char {
    LAST_ERROR.with(|e| match e.borrow_mut().take() {
        Some(msg) => CString::new(msg).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut()),
        None      => std::ptr::null_mut(),
    })
}
