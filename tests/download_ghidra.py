"""Fetch the pinned Ghidra distribution for CI builds."""
from pathlib import Path
import hashlib
import os
import urllib.request
import zipfile

ROOT = Path(os.environ["RUNNER_TEMP"]) / "ghidra with spaces"
NAME = "ghidra_12.1.4_PUBLIC_20260921.zip"
URL = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/" + NAME
EXPECTED = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
ROOT.mkdir(parents=True, exist_ok=True)
archive = ROOT / NAME
with urllib.request.urlopen(URL, timeout=120) as response, archive.open("wb") as output:
    while chunk := response.read(1024 * 1024):
        output.write(chunk)
digest = hashlib.sha256()
with archive.open("rb") as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest() != EXPECTED:
    raise RuntimeError("Ghidra download checksum mismatch")
with zipfile.ZipFile(archive) as bundle:
    bundle.extractall(ROOT)
    if os.name != "nt":
        for entry in bundle.infolist():
            mode = (entry.external_attr >> 16) & 0o777
            if mode:
                (ROOT / entry.filename).chmod(mode)
installation = ROOT / "ghidra_12.1.4_PUBLIC"
if not (installation / "support" / "buildExtension.gradle").is_file():
    raise RuntimeError("Ghidra distribution is incomplete")
with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as output:
    output.write(f"GHIDRA_INSTALL_DIR={installation}\n")
print("Ghidra 12.1.4 download verified.")
