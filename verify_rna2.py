import os
import shutil
import tempfile
from rna2_engine import RNA2Engine


def run_verification():
    print("=" * 60)
    print("        RNA2 ENGINE LOCAL VERIFICATION SUITE")
    print("=" * 60)

    # 1. Initialize Engine
    dll_path = os.path.join(os.path.dirname(__file__), "rna2_pm.dll")
    print(f"[1/5] Initializing RNA2Engine using DLL at:\n      {dll_path}")
    
    try:
        engine = RNA2Engine(dll_path=dll_path)
        print("      [PASS] C-ABI bindings loaded successfully.\n")
    except Exception as e:
        print(f"      [FAIL] Failed to load C-ABI DLL: {e}\n")
        return

    # 2. Setup Temporary Test Sandbox
    temp_dir = tempfile.mkdtemp(prefix="rna2_verify_")
    src_dir = os.path.join(temp_dir, "source_data")
    plain_out_dir = os.path.join(temp_dir, "unpacked_plain")
    enc_out_dir = os.path.join(temp_dir, "unpacked_encrypted")
    
    plain_archive = os.path.join(temp_dir, "test_plain.rna2")
    enc_archive = os.path.join(temp_dir, "test_encrypted.rna2")

    os.makedirs(src_dir, exist_ok=True)

    # Create dummy payload files
    test_file_path = os.path.join(src_dir, "hello.txt")
    payload_text = "RNA2 Engine Core Functional Verification Payload 2026"
    with open(test_file_path, "w", encoding="utf-8") as f:
        f.write(payload_text)

    sub_dir = os.path.join(src_dir, "subfolder")
    os.makedirs(sub_dir, exist_ok=True)
    with open(os.path.join(sub_dir, "nested.json"), "w", encoding="utf-8") as f:
        f.write('{"status": "valid", "engine": "rna2"}')

    print(f"[2/5] Created sandbox environment in:\n      {temp_dir}\n")

    try:
        # 3. Test Plain Packing & Unpacking
        print("[3/5] Testing Unencrypted Packing & Unpacking...")
        engine.pack_directory(dir_path=src_dir, output_file=plain_archive)
        print(f"      - Packed directory -> {os.path.basename(plain_archive)}")

        count = engine.unpack_directory(package_file=plain_archive, target_dir=plain_out_dir)
        print(f"      - Unpacked {count} items -> {os.path.basename(plain_out_dir)}")

        # Validate content integrity
        unpacked_file = os.path.join(plain_out_dir, "hello.txt")
        with open(unpacked_file, "r", encoding="utf-8") as f:
            read_back = f.read()

        if read_back == payload_text:
            print("      [PASS] Plain archive integrity verified.\n")
        else:
            print("      [FAIL] Plain archive content mismatch.\n")

        # 4. Test AES-GCM Encrypted Packing & Unpacking
        print("[4/5] Testing AES-256-GCM Encrypted Packing & Unpacking...")
        passphrase = "SecureTestPassword123!"

        engine.pack_directory(
            dir_path=src_dir,
            output_file=enc_archive,
            passphrase=passphrase
        )
        print(f"      - Encrypted & packed -> {os.path.basename(enc_archive)}")

        count_enc = engine.unpack_directory(
            package_file=enc_archive,
            target_dir=enc_out_dir,
            passphrase=passphrase
        )
        print(f"      - Decrypted & unpacked {count_enc} items -> {os.path.basename(enc_out_dir)}")

        unpacked_enc_file = os.path.join(enc_out_dir, "hello.txt")
        with open(unpacked_enc_file, "r", encoding="utf-8") as f:
            read_back_enc = f.read()

        if read_back_enc == payload_text:
            print("      [PASS] Encrypted archive integrity verified.\n")
        else:
            print("      [FAIL] Encrypted archive content mismatch.\n")

        # 5. Test Error Handling (Invalid Passphrase)
        print("[5/5] Testing Error Handling (Bad Passphrase)...")
        bad_out_dir = os.path.join(temp_dir, "unpacked_bad")

        try:
            engine.unpack_directory(
                package_file=enc_archive,
                target_dir=bad_out_dir,
                passphrase="WRONG_PASSWORD"
            )
            print("      [FAIL] Unpacking succeeded with wrong password when it should have failed.\n")
        except RuntimeError as err:
            print(f"      [PASS] Caught expected error: {err}\n")

    finally:
        # Cleanup Sandbox
        shutil.rmtree(temp_dir, ignore_errors=True)
        print("=" * 60)
        print("            VERIFICATION COMPLETE & CLEANED UP")
        print("=" * 60)


if __name__ == "__main__":
    run_verification()