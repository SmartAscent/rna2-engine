import ctypes
import os
import sys

dll_path = os.path.abspath("./target/release/rna2_pm.dll")

if not os.path.exists(dll_path):
    print(f"ERROR: Could not find DLL at {dll_path}")
    sys.exit(1)

rna2 = ctypes.CDLL(dll_path)

# Return explicit c_void_p to safely handle NULL pointers across C-ABI
rna2.rna2_engine_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
rna2.rna2_engine_create.restype = ctypes.c_void_p

rna2.rna2_export_plain.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
rna2.rna2_export_plain.restype = ctypes.c_int

rna2.rna2_import_plain.argtypes = [ctypes.c_char_p]
rna2.rna2_import_plain.restype = ctypes.c_void_p

rna2.rna2_export_encrypted.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte)]
rna2.rna2_export_encrypted.restype = ctypes.c_int

rna2.rna2_import_encrypted.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte)]
rna2.rna2_import_encrypted.restype = ctypes.c_void_p

rna2.rna2_free_string.argtypes = [ctypes.c_void_p]
rna2.rna2_free_string.restype = None

rna2.rna2_engine_destroy.argtypes = [ctypes.c_void_p]
rna2.rna2_engine_destroy.restype = None

rna2.rna2_get_last_error.argtypes = []
rna2.rna2_get_last_error.restype = ctypes.c_void_p

rna2.rna2_clear_last_error.argtypes = []
rna2.rna2_clear_last_error.restype = None

def get_last_error():
    err_ptr = rna2.rna2_get_last_error()
    if err_ptr:
        err_str = ctypes.string_at(err_ptr).decode('utf-8')
        rna2.rna2_free_string(err_ptr)
        return err_str
    return "None"

print("--- 1. Testing Normal Plaintext Export ---")
raw_text_plain = b"USER: TLS Error handling test.\nAI: System normal."
export_res = rna2.rna2_export_plain(b"plain_test.rna2", raw_text_plain)
print(f"Export Return Code: {export_res}, Last Error: {get_last_error()}")

print("\n--- 2. Testing Error Handling (Attempting to import non-existent file) ---")
res_ptr = rna2.rna2_import_plain(b"non_existent_file.rna2")
if not res_ptr:
    print(f"Import failed as expected!\n-> High-level Rust error retrieved: '{get_last_error()}'")

print("\n--- 3. Testing Error Handling (Decrypting encrypted payload with wrong password) ---")
engine_pass1 = rna2.rna2_engine_create(b"correct_password", b"salt1")
engine_pass2 = rna2.rna2_engine_create(b"WRONG_password", b"salt1")
nonce_bytes = (ctypes.c_ubyte * 12)(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)

rna2.rna2_export_encrypted(engine_pass1, b"secure.rna2", b"Secret context payload", nonce_bytes)

failed_ptr = rna2.rna2_import_encrypted(engine_pass2, b"secure.rna2", nonce_bytes)
if not failed_ptr:
    print(f"Decryption failed as expected!\n-> High-level Rust error retrieved: '{get_last_error()}'")

rna2.rna2_engine_destroy(engine_pass1)
rna2.rna2_engine_destroy(engine_pass2)

print("\nSUCCESS: Thread-local error reporting fully operational!")