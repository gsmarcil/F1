#!/usr/bin/env python3
"""Build the release bundles into an output folder. Runs on any system with Python 3.9 or newer.

    python3 packaging/build-release.py dist --agents <folder> [--all]

  garrett-linux-x86_64.tar.gz     for Linux without apt, 64-bit Intel/AMD: unpack, sudo sh garrett/install.sh
  garrett-linux-aarch64.tar.gz    the same for 64-bit ARM
  garrett-linux-armv7.tar.gz      the same for 32-bit ARM (ARMv7 with hardware floating point: small boards and devices)
  garrett-macos.tar.gz            for macOS (Apple silicon and Intel): unpack, double-click "Install garrett.command"
  garrett-windows.zip             for Windows: unpack, double-click "Install garrett.cmd"
  garrett-service.tar.gz          the Sentinel service for your own Linux machine (packaging/service.sh installs it)
  garrett-service-windows.zip     the same for Windows (packaging/service.ps1 installs it)
  SHA256SUMS              what the one-line installers check a download against

The agent is one program file for each system. They are built and tested on hosted machines by
.github/workflows/release.yml; --agents names the folder they were downloaded to:

  garrett-linux-x86_64  garrett-linux-aarch64  garrett-linux-armv7  garrett-macos  garrett-windows.exe

A bundle is built for each agent that is there; --all fails unless all five are (a release uses it).

SHA256SUMS lists every file already in the output folder, so the Debian packages (packaging/build-deb.sh) and
anything else that belongs to the release go there first. packaging/assemble-release.sh does all of it in order.
The archives are reproducible: fixed times, fixed owners, sorted names.
"""
import gzip
import hashlib
import io
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WHEN = 1793491200  # 2026-11-01, the same in every build


def unix(path):
    return (ROOT / path).read_bytes().replace(b"\r\n", b"\n")


def windows(path):
    return unix(path).replace(b"\n", b"\r\n")


def tarball(target, files, folder="garrett"):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data, mode in sorted(files):
            info = tarfile.TarInfo(folder + "/" + name)
            info.size, info.mode, info.mtime, info.uid, info.gid, info.uname, info.gname = len(data), mode, WHEN, 0, 0, "root", "root"
            archive.addfile(info, io.BytesIO(data))
    with open(target, "wb") as handle, gzip.GzipFile(fileobj=handle, mode="wb", mtime=WHEN, filename="") as packed:
        packed.write(raw.getvalue())


def sums(out):
    names = sorted(path.name for path in out.iterdir() if path.is_file() and path.name != "SHA256SUMS" and not path.name.startswith("."))
    (out / "SHA256SUMS").write_bytes("".join("%s  %s\n" % (hashlib.sha256((out / name).read_bytes()).hexdigest(), name) for name in names).encode())


def main(arguments):
    out = Path(arguments[0] if arguments and not arguments[0].startswith("--") else "dist").resolve()
    out.mkdir(parents=True, exist_ok=True)
    if "--sums-only" in arguments:
        sums(out)
        return 0
    if "--agents" not in arguments:
        raise SystemExit("Give --agents <folder with the built agents>.")
    agents = Path(arguments[arguments.index("--agents") + 1]).resolve()
    names = ("garrett-linux-x86_64", "garrett-linux-aarch64", "garrett-linux-armv7", "garrett-macos", "garrett-windows.exe")
    built = {name: (agents / name).read_bytes() for name in names if (agents / name).is_file()}
    if "--all" in arguments and len(built) != len(names):
        raise SystemExit("Not every agent is in %s: missing %s" % (agents, ", ".join(name for name in names if name not in built)))
    notices = [("LICENSE", unix("LICENSE"), 0o644), ("NOTICES.md", unix("rust/NOTICES.md"), 0o644)]
    launcher = ("garrett", unix("packaging/garrett"), 0o755)
    for processor in (item for item in ("x86_64", "aarch64", "armv7") if "garrett-linux-" + item in built):
        tarball(out / ("garrett-linux-%s.tar.gz" % processor), notices + [("garrett-agent", built["garrett-linux-" + processor], 0o755), launcher, ("unblock", unix("packaging/unblock"), 0o755),
                ("garrett.service", unix("debian/garrett.service"), 0o644), ("garrett.openrc", unix("packaging/linux/garrett.openrc"), 0o755),
                ("install.sh", unix("packaging/linux/install.sh"), 0o755)])
    if "garrett-macos" in built:
        tarball(out / "garrett-macos.tar.gz", notices + [("garrett-agent", built["garrett-macos"], 0o755), launcher, ("install.sh", unix("packaging/macos/install.sh"), 0o755),
                ("Install garrett.command", unix("packaging/macos/Install garrett.command"), 0o755)])
    with zipfile.ZipFile(out / "garrett-windows.zip" if "garrett-windows.exe" in built else io.BytesIO(), "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        def add(name, data):
            info = zipfile.ZipInfo("garrett/" + name, (2026, 11, 1, 0, 0, 0))
            info.compress_type, info.external_attr = zipfile.ZIP_DEFLATED, 0o644 << 16
            archive.writestr(info, data)
        add("Install garrett.cmd", windows("packaging/windows/Install garrett.cmd"))
        add("Uninstall garrett.cmd", windows("packaging/windows/Uninstall garrett.cmd"))
        add("deploy/install-windows.ps1", windows("deploy/install-windows.ps1"))
        add("deploy/uninstall-windows.ps1", windows("deploy/uninstall-windows.ps1"))
        add("garrett.exe", built.get("garrett-windows.exe", b""))
        add("LICENSE", windows("LICENSE"))
        add("NOTICES.md", windows("rust/NOTICES.md"))
    service = [(name, unix("server/" + name), 0o644) for name in ("serve.mjs", "sqlite.mjs", "ask.mjs", "schema.sql")]
    service += [("src/" + path.name, unix("server/src/" + path.name), 0o644) for path in sorted((ROOT / "server" / "src").glob("*.mjs"))]
    tarball(out / "garrett-service.tar.gz", service + [("LICENSE", unix("LICENSE"), 0o644), ("install.sh", unix("packaging/service/install.sh"), 0o755),
            ("garrett-service", unix("packaging/service/garrett-service"), 0o755), ("garrett-service.service", unix("packaging/service/garrett-service.service"), 0o644)], "garrett-service")
    with zipfile.ZipFile(out / "garrett-service-windows.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in [(name, data) for name, data, _ in service] + [("LICENSE", windows("LICENSE")), ("garrett-service.ps1", windows("packaging/service/garrett-service.ps1"))]:
            info = zipfile.ZipInfo("garrett-service/" + name, (2026, 11, 1, 0, 0, 0))
            info.compress_type, info.external_attr = zipfile.ZIP_DEFLATED, 0o644 << 16
            archive.writestr(info, data)
    sums(out)
    for path in sorted(out.iterdir()):
        if path.is_file() and not path.name.startswith("."):
            print("%10d  %s" % (path.stat().st_size, path.name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
