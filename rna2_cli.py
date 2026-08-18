import os
import sys
import json
import ctypes
import argparse

def get_dll_path():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dll_path = os.path.join(base_dir, "target", "release", "rna2_pm.dll")
    if not os.path.exists(dll_path):
        dll_path = os.path.join(base_dir, "rna2_pm.dll")
    if not os.path.exists(dll_path):
        raise FileNotFoundError(f"Could not locate rna2_pm.dll at {dll_path}")
    return dll_path

def load_lib():
    lib = ctypes.CDLL(get_dll_path())
    
    lib.rna2_pack_dir_plain.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.rna2_pack_dir_plain.restype = ctypes.c_int
    
    lib.rna2_pack_dir_encrypted.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.rna2_pack_dir_encrypted.restype = ctypes.c_int

    lib.rna2_unpack_dir_plain.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.rna2_unpack_dir_plain.restype = ctypes.c_int

    lib.rna2_unpack_dir_encrypted.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.rna2_unpack_dir_encrypted.restype = ctypes.c_int

    lib.rna2_import_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.rna2_import_file.restype = ctypes.c_void_p

    lib.rna2_free_string.argtypes = [ctypes.c_void_p]
    lib.rna2_free_string.restype = None

    lib.rna2_get_last_error.argtypes = []
    lib.rna2_get_last_error.restype = ctypes.c_void_p

    return lib

def check_error(lib):
    err_ptr = lib.rna2_get_last_error()
    if err_ptr:
        err_msg = ctypes.cast(err_ptr, ctypes.c_char_p).value.decode('utf-8', errors='replace')
        lib.rna2_free_string(err_ptr)
        return err_msg
    return "Unknown C-ABI execution error"

def format_size(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"

def main():
    parser = argparse.ArgumentParser(description="RNA2 Package Manager CLI Utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # pack-dir
    pack_p = subparsers.add_parser("pack-dir", help="Pack a directory into an .rna2 archive")
    pack_p.add_argument("-d", "--directory", required=True, help="Path to source directory")
    pack_p.add_argument("-o", "--output", required=True, help="Path to output archive file")
    pack_p.add_argument("-p", "--passphrase", help="Optional encryption passphrase")

    # unpack-dir
    unpack_p = subparsers.add_parser("unpack-dir", help="Unpack an .rna2 archive to a directory")
    unpack_p.add_argument("-k", "--package", required=True, help="Path to .rna2 package")
    unpack_p.add_argument("-d", "--directory", required=True, help="Target extraction directory")
    unpack_p.add_argument("-p", "--passphrase", help="Optional decryption passphrase")

    # inspect
    inspect_p = subparsers.add_parser("inspect", help="Inspect binary header of an .rna2 package")
    inspect_p.add_argument("-k", "--package", required=True, help="Path to .rna2 package")

    # ls (list contents)
    ls_p = subparsers.add_parser("ls", help="List archive contents without extracting to disk")
    ls_p.add_argument("-k", "--package", required=True, help="Path to .rna2 package")
    ls_p.add_argument("-p", "--passphrase", help="Optional decryption passphrase")

    args = parser.parse_args()
    lib = load_lib()

    if args.command == "pack-dir":
        c_dir = args.directory.encode('utf-8')
        c_out = args.output.encode('utf-8')

        if args.passphrase:
            c_pass = args.passphrase.encode('utf-8')
            res = lib.rna2_pack_dir_encrypted(c_dir, c_out, c_pass)
        else:
            res = lib.rna2_pack_dir_plain(c_dir, c_out)

        if res == 0:
            print(f"[SUCCESS] Directory packaged successfully at '{args.output}'")
        else:
            print(f"[ERROR] Packaging failed: {check_error(lib)}")
            sys.exit(1)

    elif args.command == "unpack-dir":
        c_pkg = args.package.encode('utf-8')
        c_tgt = args.directory.encode('utf-8')

        if args.passphrase:
            c_pass = args.passphrase.encode('utf-8')
            res = lib.rna2_unpack_dir_encrypted(c_pkg, c_tgt, c_pass)
        else:
            res = lib.rna2_unpack_dir_plain(c_pkg, c_tgt)

        if res >= 0:
            print(f"[SUCCESS] Unpacked {res} files to directory '{args.directory}'")
        else:
            print(f"[ERROR] Extraction failed: {check_error(lib)}")
            sys.exit(1)

    elif args.command == "inspect":
        if not os.path.exists(args.package):
            print(f"[ERROR] File not found: {args.package}")
            sys.exit(1)

        file_size = os.path.getsize(args.package)
        with open(args.package, "rb") as f:
            header = f.read(16)

        if len(header) < 16:
            print("[ERROR] File is smaller than 16-byte header minimum.")
            sys.exit(1)

        magic = header[0:4]
        version = header[4]
        flag = header[5]

        print("\n--- RNA2 Package Header Inspection ---")
        print(f" File Path:       {os.path.abspath(args.package)}")
        print(f" Total File Size: {file_size} bytes")
        print(f" Magic Signature: {magic.decode('ascii', errors='replace')} ({'VALID' if magic == b'RNA2' else 'INVALID'})")
        print(f" Format Version:  0x{version:02x}")
        payload_type = "AES-256-GCM Encrypted (Randomized Salt/Nonce)" if flag == 0x01 else "Plaintext (Zlib Compressed)"
        print(f" Payload Type:    {payload_type}")
        print("--------------------------------------\n")

    elif args.command == "ls":
        if not os.path.exists(args.package):
            print(f"[ERROR] File not found: {args.package}")
            sys.exit(1)

        c_pkg = args.package.encode('utf-8')
        c_pass = args.passphrase.encode('utf-8') if args.passphrase else None

        raw_ptr = lib.rna2_import_file(c_pkg, c_pass)
        if not raw_ptr:
            print(f"[ERROR] Failed to read archive manifest: {check_error(lib)}")
            sys.exit(1)

        try:
            json_bytes = ctypes.cast(raw_ptr, ctypes.c_char_p).value
            manifest = json.loads(json_bytes.decode('utf-8'))
            files = manifest.get("files", [])

            print(f"\n--- RNA2 Archive Contents ({len(files)} files) ---")
            print(f"{'Relative Path':<50} {'Uncompressed Size':<20}")
            print("-" * 70)

            total_size = 0
            for f in files:
                rel_path = f.get("relative_path", "unknown")
                content_len = len(f.get("content", []))
                total_size += content_len
                print(f"{rel_path:<50} {format_size(content_len):<20}")

            print("-" * 70)
            print(f"Total Uncompressed Payload: {format_size(total_size)}\n")
        except Exception as e:
            print(f"[ERROR] Manifest parsing failed: {e}")
            sys.exit(1)
        finally:
            lib.rna2_free_string(raw_ptr)

if __name__ == "__main__":
    main()