import ctypes
import json
import os
from typing import Any, Dict, Optional


class RNA2Engine:
    def __init__(self, dll_path: str = "rna2_pm.dll"):
        if not os.path.isabs(dll_path):
            dll_path = os.path.abspath(dll_path)

        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"DLL not found at: {dll_path}")

        self._dll = ctypes.CDLL(dll_path)
        self._setup_bindings()

    def _setup_bindings(self):
        # rna2_get_last_error
        self._dll.rna2_get_last_error.argtypes = []
        self._dll.rna2_get_last_error.restype = ctypes.c_char_p

        # rna2_free_string
        self._dll.rna2_free_string.argtypes = [ctypes.c_void_p]
        self._dll.rna2_free_string.restype = None

        # rna2_pack_dir_plain
        self._dll.rna2_pack_dir_plain.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self._dll.rna2_pack_dir_plain.restype = ctypes.c_int

        # rna2_pack_dir_encrypted
        self._dll.rna2_pack_dir_encrypted.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        self._dll.rna2_pack_dir_encrypted.restype = ctypes.c_int

        # rna2_unpack_dir_plain
        self._dll.rna2_unpack_dir_plain.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        self._dll.rna2_unpack_dir_plain.restype = ctypes.c_int

        # rna2_unpack_dir_encrypted
        self._dll.rna2_unpack_dir_encrypted.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        self._dll.rna2_unpack_dir_encrypted.restype = ctypes.c_int

        # rna2_export_file
        self._dll.rna2_export_file.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        self._dll.rna2_export_file.restype = ctypes.c_void_p

        # rna2_import_file
        self._dll.rna2_import_file.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        self._dll.rna2_import_file.restype = ctypes.c_void_p

    def _get_error(self) -> str:
        ptr = self._dll.rna2_get_last_error()
        if ptr:
            err_msg = ptr.decode("utf-8", errors="replace")
            return err_msg
        return "Unknown error"

    def pack_directory(
        self,
        dir_path: str,
        output_file: str,
        passphrase: Optional[str] = None,
    ) -> bool:
        c_dir = dir_path.encode("utf-8")
        c_out = output_file.encode("utf-8")

        if passphrase:
            c_pass = passphrase.encode("utf-8")
            res = self._dll.rna2_pack_dir_encrypted(c_dir, c_out, c_pass)
        else:
            res = self._dll.rna2_pack_dir_plain(c_dir, c_out)

        if res != 0:
            raise RuntimeError(f"RNA2 Packing Failed: {self._get_error()}")
        return True

    def unpack_directory(
        self,
        package_file: str,
        target_dir: str,
        passphrase: Optional[str] = None,
    ) -> int:
        c_pkg = package_file.encode("utf-8")
        c_tgt = target_dir.encode("utf-8")

        if passphrase:
            c_pass = passphrase.encode("utf-8")
            res = self._dll.rna2_unpack_dir_encrypted(c_pkg, c_tgt, c_pass)
        else:
            res = self._dll.rna2_unpack_dir_plain(c_pkg, c_tgt)

        if res < 0:
            raise RuntimeError(f"RNA2 Unpacking Failed: {self._get_error()}")
        return res

    def export_single_file(
        self,
        source_file: str,
        relative_path: str,
        passphrase: Optional[str] = None,
    ) -> str:
        c_src = source_file.encode("utf-8")
        c_rel = relative_path.encode("utf-8")
        c_pass = passphrase.encode("utf-8") if passphrase else None

        raw_ptr = self._dll.rna2_export_file(c_src, c_rel, c_pass)
        if not raw_ptr:
            raise RuntimeError(f"RNA2 Export Failed: {self._get_error()}")

        b64_str = ctypes.string_at(raw_ptr).decode("utf-8")
        self._dll.rna2_free_string(raw_ptr)
        return b64_str

    def import_single_file(
        self,
        package_file: str,
        passphrase: Optional[str] = None,
    ) -> Dict[str, Any]:
        c_pkg = package_file.encode("utf-8")
        c_pass = passphrase.encode("utf-8") if passphrase else None

        raw_ptr = self._dll.rna2_import_file(c_pkg, c_pass)
        if not raw_ptr:
            raise RuntimeError(f"RNA2 Import Failed: {self._get_error()}")

        json_str = ctypes.string_at(raw_ptr).decode("utf-8")
        self._dll.rna2_free_string(raw_ptr)
        return json.loads(json_str)


if __name__ == "__main__":
    dll_location = os.path.join(os.path.dirname(__file__), "rna2_pm.dll")
    try:
        engine = RNA2Engine(dll_path=dll_location)
        print("[SUCCESS] RNA2Engine initialized successfully and bound to rna2_pm.dll.")
    except Exception as e:
        print(f"[ERROR] Failed to initialize RNA2Engine: {e}")