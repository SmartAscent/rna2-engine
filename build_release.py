import os
import shutil
import zipfile
from pathlib import Path

def package_release():
    release_dir = Path("release")
    dist_dir = release_dir / "rna2_pm_dist"
    zip_output = release_dir / "rna2_pm_release.zip"

    # Core required files
    required_artifacts = [
        Path("rna2_pm.dll"),
        Path("rna2_engine.py"),
        Path("README.md"),
        Path("LICENSE.md")
    ]

    # Optional files (e.g. MSVC import lib)
    optional_artifacts = [
        Path("rna2_pm.lib")
    ]

    print("[1/4] Checking required release artifacts...")
    missing = [str(art) for art in required_artifacts if not art.exists()]
    if missing:
        print(f"[ERROR] Missing required artifacts: {", ".join(missing)}")
        return

    # Prepare directories
    if release_dir.exists():
        shutil.rmtree(release_dir)
    dist_dir.mkdir(parents=True, exist_ok=True)

    print("[2/4] Copying release artifacts into distribution staging area...")
    for art in required_artifacts:
        target = dist_dir / art.name
        shutil.copy2(art, target)
        print(f"  -> Staged: {art.name}")

    for art in optional_artifacts:
        if art.exists():
            shutil.copy2(art, dist_dir / art.name)
            print(f"  -> Staged (Optional): {art.name}")

    print("[3/4] Generating release ZIP archive...")
    with zipfile.ZipFile(zip_output, "w", zipfile.ZIP_DEFLATED) as zipf:
        for file in dist_dir.iterdir():
            zipf.write(file, arcname=file.name)
            print(f"  -> Compressed: {file.name}")

    print(f"[4/4] SUCCESS: Release package created successfully at {zip_output.resolve()}")

if __name__ == "__main__":
    package_release()
