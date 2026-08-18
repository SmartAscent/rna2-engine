import ctypes
from pathlib import Path
from typing import Callable, Optional

# C Callback Type: void(uint64_t, uint64_t, const char*)
PROGRESS_CB_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p)

# Custom Exceptions mapped to C-ABI Error Codes
class RNA2EngineError(Exception):
    """Base exception for all RNA2 Engine errors."""
    pass

class InvalidParameterError(RNA2EngineError):
    """Raised when invalid arguments or null pointers are passed to C-ABI functions."""
    pass

class EncryptionFailedError(RNA2EngineError):
    """Raised when data encryption fails inside the Rust core."""
    pass

class DecryptionFailedError(RNA2EngineError):
    """Raised when data decryption fails or passphrase is invalid."""
    pass

class IOFailureError(RNA2EngineError):
    """Raised when file system I/O operations fail."""
    pass

class MemoryAllocationError(RNA2EngineError):
    """Raised when memory allocation fails in the Rust core."""
    pass

# Error code mapping dictionary
ERROR_MAP = {
    -1: InvalidParameterError("Invalid parameter or null pointer passed to C-ABI function."),
    -2: EncryptionFailedError("AES-256-GCM encryption operation failed."),
    -3: DecryptionFailedError("Decryption failed. Invalid passphrase or corrupt payload."),
    -4: IOFailureError("File I/O failure during archive read/write operation."),
    -5: MemoryAllocationError("Failed to allocate memory buffer in Rust core.")
}

def raise_for_status(status_code: int):
    if status_code == 0:
        return
    err = ERROR_MAP.get(status_code, RNA2EngineError(f"Unknown RNA2 Engine C-ABI error code: {status_code}"))
    raise err

class RNA2Engine:
    def __init__(self, dll_path: str = "rna2_pm.dll"):
        self.dll_path = Path(dll_path).resolve()
        if not self.dll_path.exists():
            raise FileNotFoundError(f"DLL not found at {self.dll_path}")
        self.lib = ctypes.CDLL(str(self.dll_path))

        # Setup C-ABI function signatures
        self.lib.rna2_pack_directory.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        self.lib.rna2_pack_directory.restype = ctypes.c_int32

        self.lib.rna2_pack_directory_with_progress.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, PROGRESS_CB_TYPE]
        self.lib.rna2_pack_directory_with_progress.restype = ctypes.c_int32

        self.lib.rna2_unpack_directory.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        self.lib.rna2_unpack_directory.restype = ctypes.c_int32

        self.lib.rna2_unpack_directory_with_progress.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, PROGRESS_CB_TYPE]
        self.lib.rna2_unpack_directory_with_progress.restype = ctypes.c_int32

    def pack_directory(
        self,
        dir_path: str,
        output_file: str,
        passphrase: str,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ):
        c_dir = dir_path.encode("utf-8")
        c_out = output_file.encode("utf-8")
        c_pass = passphrase.encode("utf-8")

        if progress_callback:
            def _internal_cb(bytes_proc, total_bytes, current_file):
                filename = current_file.decode("utf-8", errors="replace") if current_file else ""
                progress_callback(bytes_proc, total_bytes, filename)

            c_cb = PROGRESS_CB_TYPE(_internal_cb)
            res = self.lib.rna2_pack_directory_with_progress(c_dir, c_out, c_pass, c_cb)
        else:
            res = self.lib.rna2_pack_directory(c_dir, c_out, c_pass)

        raise_for_status(res)

    def unpack_directory(
        self,
        package_file: str,
        target_dir: str,
        passphrase: str,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ):
        c_pkg = package_file.encode("utf-8")
        c_target = target_dir.encode("utf-8")
        c_pass = passphrase.encode("utf-8")

        if progress_callback:
            def _internal_cb(bytes_proc, total_bytes, current_file):
                filename = current_file.decode("utf-8", errors="replace") if current_file else ""
                progress_callback(bytes_proc, total_bytes, filename)

            c_cb = PROGRESS_CB_TYPE(_internal_cb)
            res = self.lib.rna2_unpack_directory_with_progress(c_pkg, c_target, c_pass, c_cb)
        else:
            res = self.lib.rna2_unpack_directory(c_pkg, c_target, c_pass)

        raise_for_status(res)