use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::raw::{c_char, c_int};
use std::path::Path;

use serde::{Deserialize, Serialize};

const MAGIC_BYTES: &[u8; 4] = b"RNA2";
const FORMAT_VERSION: u8 = 0x01;
const FLAG_PLAINTEXT: u8 = 0x00;
const FLAG_ENCRYPTED: u8 = 0x01;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const PBKDF2_ROUNDS: u32 = 100_000;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

fn set_last_error(err: String) {
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(err));
}

#[no_mangle]
pub extern "C" fn rna2_get_last_error() -> *mut c_char {
    LAST_ERROR.with(|e| {
        if let Some(err) = e.borrow_mut().take() {
            CString::new(err).unwrap().into_raw()
        } else {
            std::ptr::null_mut()
        }
    })
}

#[no_mangle]
pub extern "C" fn rna2_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PackageMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rna2_version: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileEntry {
    pub relative_path: String,
    pub content: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ArchiveManifest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PackageMetadata>,

    pub files: Vec<FileEntry>,
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase, salt, PBKDF2_ROUNDS, &mut key);
    key
}

fn generate_random_bytes(buf: &mut [u8]) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for byte in buf.iter_mut() {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (seed >> 24) as u8;
    }
}

fn encode_base64(data: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        
        let triple = (b0 << 16) | (b1 << 8) | b2;
        
        result.push(CHARSET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARSET[((triple >> 12) & 0x3F) as usize] as char);
        
        if chunk.len() > 1 {
            result.push(CHARSET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        
        if chunk.len() > 2 {
            result.push(CHARSET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn collect_directory_files<P: AsRef<Path>>(base_path: P, current_path: P, files: &mut Vec<FileEntry>) -> Result<(), String> {
    let entries = fs::read_dir(&current_path).map_err(|e| format!("Failed to read dir: {}", e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("Dir entry error: {}", e))?;
        let path = entry.path();
        if path.is_dir() {
            collect_directory_files(base_path.as_ref(), &path, files)?;
        } else if path.is_file() {
            let rel_path = path.strip_prefix(base_path.as_ref())
                .map_err(|e| format!("Prefix strip error: {}", e))?
                .to_string_lossy()
                .replace("\\", "/");

            let mut f = File::open(&path).map_err(|e| format!("Failed to open file {:?}: {}", path, e))?;
            let mut content = Vec::new();
            f.read_to_end(&mut content).map_err(|e| format!("Failed to read file {:?}: {}", path, e))?;

            files.push(FileEntry { relative_path: rel_path, content });
        }
    }
    Ok(())
}

fn create_archive_payload(files: Vec<FileEntry>, metadata: Option<PackageMetadata>) -> Result<Vec<u8>, String> {
    let manifest = ArchiveManifest { metadata, files };
    let json_bytes = serde_json::to_vec(&manifest).map_err(|e| format!("JSON serialize error: {}", e))?;

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&json_bytes).map_err(|e| format!("Compression write error: {}", e))?;
    encoder.finish().map_err(|e| format!("Compression finish error: {}", e))
}

fn parse_archive_payload(compressed_data: &[u8]) -> Result<ArchiveManifest, String> {
    let mut decoder = flate2::read::ZlibDecoder::new(compressed_data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).map_err(|e| format!("Decompression error: {}", e))?;

    serde_json::from_slice(&decompressed).map_err(|e| format!("JSON deserialize error: {}", e))
}

#[no_mangle]
pub extern "C" fn rna2_pack_dir_plain(dir_path: *const c_char, output_file: *const c_char) -> c_int {
    if dir_path.is_null() || output_file.is_null() {
        set_last_error("Null pointer provided".to_string());
        return -1;
    }
    let c_dir = unsafe { CStr::from_ptr(dir_path) }.to_string_lossy();
    let c_out = unsafe { CStr::from_ptr(output_file) }.to_string_lossy();

    let mut files = Vec::new();
    if let Err(e) = collect_directory_files(Path::new(c_dir.as_ref()), Path::new(c_dir.as_ref()), &mut files) {
        set_last_error(e);
        return -1;
    }

    let payload = match create_archive_payload(files, None) {
        Ok(p) => p,
        Err(e) => { set_last_error(e); return -1; }
    };

    let mut out_file = match File::create(c_out.as_ref()) {
        Ok(f) => f,
        Err(e) => { set_last_error(format!("File create error: {}", e)); return -1; }
    };

    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(MAGIC_BYTES);
    header.push(FORMAT_VERSION);
    header.push(FLAG_PLAINTEXT);
    header.extend_from_slice(&[0u8; 10]);

    if let Err(e) = out_file.write_all(&header).and_then(|_| out_file.write_all(&payload)) {
        set_last_error(format!("Write error: {}", e));
        return -1;
    }

    0
}

#[no_mangle]
pub extern "C" fn rna2_pack_dir_encrypted(dir_path: *const c_char, output_file: *const c_char, passphrase: *const c_char) -> c_int {
    if dir_path.is_null() || output_file.is_null() || passphrase.is_null() {
        set_last_error("Null pointer provided".to_string());
        return -1;
    }
    let c_dir = unsafe { CStr::from_ptr(dir_path) }.to_string_lossy();
    let c_out = unsafe { CStr::from_ptr(output_file) }.to_string_lossy();
    let pass_bytes = unsafe { CStr::from_ptr(passphrase) }.to_bytes();

    let mut files = Vec::new();
    if let Err(e) = collect_directory_files(Path::new(c_dir.as_ref()), Path::new(c_dir.as_ref()), &mut files) {
        set_last_error(e);
        return -1;
    }

    let payload = match create_archive_payload(files, None) {
        Ok(p) => p,
        Err(e) => { set_last_error(e); return -1; }
    };

    let mut salt = [0u8; SALT_SIZE];
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    generate_random_bytes(&mut salt);
    generate_random_bytes(&mut nonce_bytes);

    let key = derive_key(pass_bytes, &salt);
    let cipher = match Aes256Gcm::new_from_slice(&key) {
        Ok(c) => c,
        Err(e) => { set_last_error(format!("Cipher error: {}", e)); return -1; }
    };

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = match cipher.encrypt(nonce, payload.as_ref()) {
        Ok(ct) => ct,
        Err(e) => { set_last_error(format!("Encryption failure: {}", e)); return -1; }
    };

    let mut out_file = match File::create(c_out.as_ref()) {
        Ok(f) => f,
        Err(e) => { set_last_error(format!("File create error: {}", e)); return -1; }
    };

    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(MAGIC_BYTES);
    header.push(FORMAT_VERSION);
    header.push(FLAG_ENCRYPTED);
    header.extend_from_slice(&[0u8; 10]);

    if let Err(e) = out_file.write_all(&header)
        .and_then(|_| out_file.write_all(&salt))
        .and_then(|_| out_file.write_all(&nonce_bytes))
        .and_then(|_| out_file.write_all(&ciphertext))
    {
        set_last_error(format!("Write error: {}", e));
        return -1;
    }

    0
}

#[no_mangle]
pub extern "C" fn rna2_unpack_dir_plain(package_file: *const c_char, target_dir: *const c_char) -> c_int {
    if package_file.is_null() || target_dir.is_null() {
        set_last_error("Null pointer provided".to_string());
        return -1;
    }
    let c_pkg = unsafe { CStr::from_ptr(package_file) }.to_string_lossy();
    let c_tgt = unsafe { CStr::from_ptr(target_dir) }.to_string_lossy();

    let mut f = match File::open(c_pkg.as_ref()) {
        Ok(file) => file,
        Err(e) => { set_last_error(format!("File open error: {}", e)); return -1; }
    };

    let mut buffer = Vec::new();
    if let Err(e) = f.read_to_end(&mut buffer) {
        set_last_error(format!("Read error: {}", e));
        return -1;
    }

    if buffer.len() < 16 || &buffer[0..4] != MAGIC_BYTES || buffer[5] != FLAG_PLAINTEXT {
        set_last_error("Invalid or non-plaintext RNA2 package header".to_string());
        return -1;
    }

    let manifest = match parse_archive_payload(&buffer[16..]) {
        Ok(m) => m,
        Err(e) => { set_last_error(e); return -1; }
    };

    let mut extracted_count = 0;
    for file in manifest.files {
        let dest = Path::new(c_tgt.as_ref()).join(&file.relative_path);
        if let Some(parent) = dest.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(mut out) = File::create(&dest) {
            if out.write_all(&file.content).is_ok() {
                extracted_count += 1;
            }
        }
    }

    extracted_count
}

#[no_mangle]
pub extern "C" fn rna2_unpack_dir_encrypted(package_file: *const c_char, target_dir: *const c_char, passphrase: *const c_char) -> c_int {
    if package_file.is_null() || target_dir.is_null() || passphrase.is_null() {
        set_last_error("Null pointer provided".to_string());
        return -1;
    }
    let c_pkg = unsafe { CStr::from_ptr(package_file) }.to_string_lossy();
    let c_tgt = unsafe { CStr::from_ptr(target_dir) }.to_string_lossy();
    let pass_bytes = unsafe { CStr::from_ptr(passphrase) }.to_bytes();

    let mut f = match File::open(c_pkg.as_ref()) {
        Ok(file) => file,
        Err(e) => { set_last_error(format!("File open error: {}", e)); return -1; }
    };

    let mut buffer = Vec::new();
    if let Err(e) = f.read_to_end(&mut buffer) {
        set_last_error(format!("Read error: {}", e));
        return -1;
    }

    if buffer.len() < 16 + SALT_SIZE + NONCE_SIZE || &buffer[0..4] != MAGIC_BYTES || buffer[5] != FLAG_ENCRYPTED {
        set_last_error("Invalid or non-encrypted RNA2 package header".to_string());
        return -1;
    }

    let salt = &buffer[16..16 + SALT_SIZE];
    let nonce_bytes = &buffer[16 + SALT_SIZE..16 + SALT_SIZE + NONCE_SIZE];
    let ciphertext = &buffer[16 + SALT_SIZE + NONCE_SIZE..];

    let key = derive_key(pass_bytes, salt);
    let cipher = match Aes256Gcm::new_from_slice(&key) {
        Ok(c) => c,
        Err(e) => { set_last_error(format!("Cipher error: {}", e)); return -1; }
    };

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(pt) => pt,
        Err(_) => { set_last_error("Decryption failed. Incorrect passphrase or corrupted payload.".to_string()); return -1; }
    };

    let manifest = match parse_archive_payload(&plaintext) {
        Ok(m) => m,
        Err(e) => { set_last_error(e); return -1; }
    };

    let mut extracted_count = 0;
    for file in manifest.files {
        let dest = Path::new(c_tgt.as_ref()).join(&file.relative_path);
        if let Some(parent) = dest.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(mut out) = File::create(&dest) {
            if out.write_all(&file.content).is_ok() {
                extracted_count += 1;
            }
        }
    }

    extracted_count
}

#[no_mangle]
pub extern "C" fn rna2_export_file(source_file: *const c_char, relative_path: *const c_char, passphrase: *const c_char) -> *mut c_char {
    if source_file.is_null() || relative_path.is_null() {
        set_last_error("Null pointer provided".to_string());
        return std::ptr::null_mut();
    }

    let c_src = unsafe { CStr::from_ptr(source_file) }.to_string_lossy();
    let c_rel = unsafe { CStr::from_ptr(relative_path) }.to_string_lossy();

    let mut f = match File::open(c_src.as_ref()) {
        Ok(file) => file,
        Err(e) => { set_last_error(format!("Failed to open source file: {}", e)); return std::ptr::null_mut(); }
    };

    let mut content = Vec::new();
    if let Err(e) = f.read_to_end(&mut content) {
        set_last_error(format!("Failed to read source file: {}", e));
        return std::ptr::null_mut();
    }

    let files = vec![FileEntry {
        relative_path: c_rel.into_owned(),
        content,
    }];

    let compressed_payload = match create_archive_payload(files, None) {
        Ok(p) => p,
        Err(e) => { set_last_error(e); return std::ptr::null_mut(); }
    };

    let is_encrypted = !passphrase.is_null();
    let mut final_package = Vec::new();

    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(MAGIC_BYTES);
    header.push(FORMAT_VERSION);
    header.push(if is_encrypted { FLAG_ENCRYPTED } else { FLAG_PLAINTEXT });
    header.extend_from_slice(&[0u8; 10]);

    final_package.extend_from_slice(&header);

    if is_encrypted {
        let pass_bytes = unsafe { CStr::from_ptr(passphrase) }.to_bytes();
        let mut salt = [0u8; SALT_SIZE];
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        generate_random_bytes(&mut salt);
        generate_random_bytes(&mut nonce_bytes);

        let key = derive_key(pass_bytes, &salt);
        let cipher = match Aes256Gcm::new_from_slice(&key) {
            Ok(c) => c,
            Err(e) => { set_last_error(format!("Cipher error: {}", e)); return std::ptr::null_mut(); }
        };

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = match cipher.encrypt(nonce, compressed_payload.as_ref()) {
            Ok(ct) => ct,
            Err(e) => { set_last_error(format!("Encryption failure: {}", e)); return std::ptr::null_mut(); }
        };

        final_package.extend_from_slice(&salt);
        final_package.extend_from_slice(&nonce_bytes);
        final_package.extend_from_slice(&ciphertext);
    } else {
        final_package.extend_from_slice(&compressed_payload);
    }

    let b64_encoded = encode_base64(&final_package);

    match CString::new(b64_encoded) {
        Ok(c_str) => c_str.into_raw(),
        Err(e) => { set_last_error(format!("CString error: {}", e)); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "C" fn rna2_import_file(package_file: *const c_char, passphrase: *const c_char) -> *mut c_char {
    if package_file.is_null() {
        set_last_error("Null pointer provided".to_string());
        return std::ptr::null_mut();
    }

    let c_pkg = unsafe { CStr::from_ptr(package_file) }.to_string_lossy();
    let mut f = match File::open(c_pkg.as_ref()) {
        Ok(file) => file,
        Err(e) => { set_last_error(format!("Failed to open package: {}", e)); return std::ptr::null_mut(); }
    };

    let mut buffer = Vec::new();
    if let Err(e) = f.read_to_end(&mut buffer) {
        set_last_error(format!("Failed to read package: {}", e));
        return std::ptr::null_mut();
    }

    if buffer.len() < 16 || &buffer[0..4] != MAGIC_BYTES {
        set_last_error("Invalid RNA2 package header".to_string());
        return std::ptr::null_mut();
    }

    let flag = buffer[5];
    let manifest = if flag == FLAG_PLAINTEXT {
        match parse_archive_payload(&buffer[16..]) {
            Ok(m) => m,
            Err(e) => { set_last_error(e); return std::ptr::null_mut(); }
        }
    } else if flag == FLAG_ENCRYPTED {
        if passphrase.is_null() {
            set_last_error("Passphrase required for encrypted package".to_string());
            return std::ptr::null_mut();
        }
        if buffer.len() < 16 + SALT_SIZE + NONCE_SIZE {
            set_last_error("Truncated encrypted RNA2 package".to_string());
            return std::ptr::null_mut();
        }

        let pass_bytes = unsafe { CStr::from_ptr(passphrase) }.to_bytes();
        let salt = &buffer[16..16 + SALT_SIZE];
        let nonce_bytes = &buffer[16 + SALT_SIZE..16 + SALT_SIZE + NONCE_SIZE];
        let ciphertext = &buffer[16 + SALT_SIZE + NONCE_SIZE..];

        let key = derive_key(pass_bytes, salt);
        let cipher = match Aes256Gcm::new_from_slice(&key) {
            Ok(c) => c,
            Err(e) => { set_last_error(format!("Cipher error: {}", e)); return std::ptr::null_mut(); }
        };

        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = match cipher.decrypt(nonce, ciphertext) {
            Ok(pt) => pt,
            Err(_) => { set_last_error("Decryption failed. Incorrect passphrase or corrupted payload.".to_string()); return std::ptr::null_mut(); }
        };

        match parse_archive_payload(&plaintext) {
            Ok(m) => m,
            Err(e) => { set_last_error(e); return std::ptr::null_mut(); }
        }
    } else {
        set_last_error("Unknown package flag".to_string());
        return std::ptr::null_mut();
    };

    let json_bytes = match serde_json::to_vec(&manifest) {
        Ok(j) => j,
        Err(e) => { set_last_error(format!("JSON serialization failed: {}", e)); return std::ptr::null_mut(); }
    };

    match CString::new(json_bytes) {
        Ok(c_str) => c_str.into_raw(),
        Err(e) => { set_last_error(format!("CString error: {}", e)); std::ptr::null_mut() }
    }
}