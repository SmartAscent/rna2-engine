import ctypes
from pathlib import Path
from typing import Callable, Optional

PROGRESS_CB_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p)


class RNA2EngineError(Exception):
    pass

class InvalidParameterError(RNA2EngineError):
    pass

class EncryptionFailedError(RNA2EngineError):
    pass

class DecryptionFailedError(RNA2EngineError):
    pass

class IOFailureError(RNA2EngineError):
    pass


ERROR_MAP = {
    -1: (InvalidParameterError, "Invalid parameter or null pointer"),
    -2: (EncryptionFailedError, "Encryption operation failed"),
    -3: (DecryptionFailedError, "Decryption failed or invalid passphrase"),
    -4: (IOFailureError,        "File I/O failure during operation"),
}


def _find_dll() -> Path:
    here = Path(__file__).parent
    candidates = [here / "rna2_pm.dll", here / "target" / "release" / "rna2_pm.dll"]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError(
        "rna2_pm.dll not found. Looked in:\n" + "\n".join(f"  {p}" for p in candidates)
    )


class RNA2Engine:
    def __init__(self, dll_path: Optional[str] = None):
        path = Path(dll_path) if dll_path else _find_dll()
        self.lib = ctypes.CDLL(str(path))

        self.lib.rna2_pack_dir_plain.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.rna2_pack_dir_plain.restype  = ctypes.c_int32

        self.lib.rna2_pack_dir_encrypted.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        self.lib.rna2_pack_dir_encrypted.restype  = ctypes.c_int32

        self.lib.rna2_pack_directory_with_progress.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, PROGRESS_CB_TYPE]
        self.lib.rna2_pack_directory_with_progress.restype  = ctypes.c_int32

        self.lib.rna2_unpack_dir_plain.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.rna2_unpack_dir_plain.restype  = ctypes.c_int32

        self.lib.rna2_unpack_dir_encrypted.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        self.lib.rna2_unpack_dir_encrypted.restype  = ctypes.c_int32

        self.lib.rna2_unpack_directory_with_progress.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, PROGRESS_CB_TYPE]
        self.lib.rna2_unpack_directory_with_progress.restype  = ctypes.c_int32

        self.lib.rna2_import_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.rna2_import_file.restype  = ctypes.c_void_p

        self.lib.rna2_free_string.argtypes = [ctypes.c_void_p]
        self.lib.rna2_free_string.restype  = None

        self.lib.rna2_get_last_error.argtypes = []
        self.lib.rna2_get_last_error.restype  = ctypes.c_void_p

    def _raise_for_status(self, code: int):
        if code == 0:
            return
        err_ptr = self.lib.rna2_get_last_error()
        detail = None
        if err_ptr:
            detail = ctypes.cast(err_ptr, ctypes.c_char_p).value.decode("utf-8", errors="replace")
            self.lib.rna2_free_string(err_ptr)
        cls, default_msg = ERROR_MAP.get(code, (RNA2EngineError, f"Engine error {code}"))
        raise cls(detail or default_msg)

    def pack_directory(
        self,
        dir_path: str,
        output_file: str,
        passphrase: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ):
        c_dir  = dir_path.encode("utf-8")
        c_out  = output_file.encode("utf-8")
        c_pass = passphrase.encode("utf-8") if passphrase else None

        if progress_callback:
            def _cb(done, total, cur):
                progress_callback(done, total, (cur or b"").decode("utf-8", errors="replace"))
            res = self.lib.rna2_pack_directory_with_progress(c_dir, c_out, c_pass, PROGRESS_CB_TYPE(_cb))
        elif c_pass:
            res = self.lib.rna2_pack_dir_encrypted(c_dir, c_out, c_pass)
        else:
            res = self.lib.rna2_pack_dir_plain(c_dir, c_out)
        self._raise_for_status(res)

    def unpack_directory(
        self,
        package_file: str,
        target_dir: str,
        passphrase: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> int:
        c_pkg  = package_file.encode("utf-8")
        c_tgt  = target_dir.encode("utf-8")
        c_pass = passphrase.encode("utf-8") if passphrase else None

        if progress_callback:
            def _cb(done, total, cur):
                progress_callback(done, total, (cur or b"").decode("utf-8", errors="replace"))
            res = self.lib.rna2_unpack_directory_with_progress(c_pkg, c_tgt, c_pass, PROGRESS_CB_TYPE(_cb))
        elif c_pass:
            res = self.lib.rna2_unpack_dir_encrypted(c_pkg, c_tgt, c_pass)
        else:
            res = self.lib.rna2_unpack_dir_plain(c_pkg, c_tgt)
        self._raise_for_status(res)
        return res
