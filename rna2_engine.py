import ctypes
from pathlib import Path
from typing import Callable, Optional

PROGRESS_CB_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p)

class RNA2Engine:
    def __init__(self, dll_path: str = "rna2_pm.dll"):
        self.dll_path = Path(dll_path).resolve()
        if not self.dll_path.exists():
            raise FileNotFoundError(f"DLL not found at {self.dll_path}")
        self.lib = ctypes.CDLL(str(self.dll_path))

        self.lib.rna2_pack_directory.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        self.lib.rna2_pack_directory.restype = ctypes.c_int32

        self.lib.rna2_pack_directory_with_progress.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, PROGRESS_CB_TYPE]
        self.lib.rna2_pack_directory_with_progress.restype = ctypes.c_int32

        self.lib.rna2_unpack_directory.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        self.lib.rna2_unpack_directory.restype = ctypes.c_int32

        self.lib.rna2_unpack_directory_with_progress.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, PROGRESS_CB_TYPE]
        self.lib.rna2_unpack_directory_with_progress.restype = ctypes.c_int32

    def pack_directory(self, dir_path: str, output_file: str, passphrase: str, progress_callback: Optional[Callable[[int, int, str], None]] = None):
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

        if res != 0:
            raise RuntimeError(f"RNA2 pack directory failed with code: {res}")

    def unpack_directory(self, package_file: str, target_dir: str, passphrase: str, progress_callback: Optional[Callable[[int, int, str], None]] = None):
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

        if res != 0:
            raise RuntimeError(f"RNA2 unpack directory failed with code: {res}")
