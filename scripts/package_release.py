#!/usr/bin/env python3
"""Package the locked Linux release with dependency notices and measured ABI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

TARGET = "x86_64-unknown-linux-gnu"
TOOLCHAIN = "1.92.0"
ROOT = Path(__file__).resolve().parents[1]


def output(*command):
    return subprocess.check_output(command, cwd=ROOT, text=True,
                                   env={**os.environ, "LC_ALL": "C"})


def dependency_ids(metadata):
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    root = metadata["resolve"]["root"]
    pending, visited = [root], set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        for dependency in nodes[current]["deps"]:
            if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])
    return visited - {root}


def copy_notices(directory, metadata):
    inventory = []
    dependencies = dependency_ids(metadata)
    for package in sorted(metadata["packages"], key=lambda item: (item["name"], item["version"])):
        if package["id"] not in dependencies:
            continue
        source = Path(package["manifest_path"]).parent
        destination = directory / f'{package["name"]}-{package["version"]}'
        destination.mkdir()
        candidates = {path for path in source.iterdir()
                      if path.is_file() and path.name.lower().startswith(
                          ("license", "copying", "notice", "copyright"))}
        if package.get("license_file"):
            candidates.add(source / package["license_file"])
        if not candidates:
            raise RuntimeError(f'no license text found for {package["name"]}')
        for path in sorted(candidates):
            shutil.copyfile(path, destination / path.name)
        inventory.append({
            "name": package["name"], "version": package["version"],
            "license": package.get("license"),
            "files": sorted(path.name for path in candidates),
        })
    rust_docs = Path(output("rustc", f"+{TOOLCHAIN}", "--print", "sysroot").strip()) / "share/doc/rust"
    rust = directory / f"rust-standard-library-{TOOLCHAIN}"
    rust.mkdir()
    shutil.copyfile(rust_docs / "COPYRIGHT-library.html", rust / "COPYRIGHT-library.html")
    shutil.copytree(rust_docs / "licenses", rust / "licenses")
    (directory / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    (directory / "README.md").write_text(
        "# Third-party notices\n\n"
        "These are the license and notice files distributed with the locked Cargo "
        "dependencies used by the Linux build, including build dependencies. "
        "Alternative-license texts are preserved together; additional notices such "
        "as Unicode-3.0 are included. The Rust standard-library notice also covers "
        "its upstream components and other supported platforms. No third-party "
        "source is vendored in this package.\n"
    )
    return inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/lnfs-lite")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    version = package["version"]
    if args.tag != f"v{version}":
        raise RuntimeError("tag and Cargo version differ")
    locked = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
    assert [item["version"] for item in locked if item["name"] == package["name"]] == [version]
    binary = args.binary.resolve()
    assert binary.is_file() and os.access(binary, os.X_OK), "executable release binary required"
    header = output("readelf", "-h", str(binary))
    assert "Advanced Micro Devices X86-64" in header and "ELF64" in header, header
    versions = output("readelf", "--version-info", str(binary))
    glibc = sorted({tuple(map(int, value.split(".")))
                    for value in re.findall(r"GLIBC_(\d+\.\d+(?:\.\d+)?)", versions)})
    assert glibc and glibc[-1] <= (2, 39), f"binary exceeds documented glibc 2.39 baseline: {glibc}"
    needed = re.findall(r"Shared library: \[(.*?)\]", output("readelf", "-d", str(binary)))
    assert "libc.so.6" in needed, needed
    assert output(str(binary), "--version").strip() == f"lnfs-lite-rs {version}"
    assert "--backend" in output(str(binary), "--help")
    metadata = json.loads(output("cargo", f"+{TOOLCHAIN}", "metadata", "--locked",
                                 "--format-version", "1", "--filter-platform", TARGET))
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / f"lnfs-lite-{args.tag}-{TARGET}.tar.gz"
    if archive.exists() or (args.output / "SHA256SUMS").exists():
        raise FileExistsError("refusing to overwrite existing release assets")
    with tempfile.TemporaryDirectory(prefix="lnfs-package-") as temporary:
        staging = Path(temporary)
        for name in ("LICENSE", "README.md"):
            shutil.copyfile(ROOT / name, staging / name)
        shutil.copy2(binary, staging / "lnfs-lite")
        (staging / "docs").mkdir()
        shutil.copyfile(ROOT / "docs/lnfs-lite-design.md", staging / "docs/lnfs-lite-design.md")
        notices = staging / "THIRD_PARTY_LICENSES"
        notices.mkdir()
        inventory = copy_notices(notices, metadata)
        source_files = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", *sorted((ROOT / "src").glob("*.rs"))]
        info = {
            "version": version, "tag": args.tag, "target": TARGET,
            "rust": output("rustc", f"+{TOOLCHAIN}", "--version").strip(),
            "github_commit": os.environ.get("GITHUB_SHA"),
            "maximum_required_glibc": ".".join(map(str, glibc[-1])),
            "documented_glibc_baseline": "2.39", "dynamic_libraries": needed,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in source_files},
            "cargo_dependency_notice_count": len(inventory),
        }
        (staging / "BUILD_INFO.json").write_text(json.dumps(info, indent=2) + "\n")
        with tarfile.open(archive, "w:gz") as bundle:
            for path in sorted(staging.iterdir()):
                bundle.add(path, arcname=path.name)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (args.output / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n")
    print(json.dumps({"archive": str(archive), "sha256": digest, "build": info}, indent=2))


if __name__ == "__main__":
    main()
