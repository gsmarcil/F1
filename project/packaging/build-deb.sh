#!/bin/sh
# Build the garrett Debian package for one kind of processor from this repository and an agent built beforehand.
#   sh packaging/build-deb.sh <output directory> <amd64|arm64> <the garrett program file for that processor>
#   ->  garrett_<version>_<amd64|arm64>.deb
# Needs a Debian or Ubuntu machine with:  sudo apt install build-essential debhelper
# The program file comes from the release workflow (.github/workflows/release.yml), which builds and tests
# it on hosted machines. This script only packs it, from a clean copy, and leaves this checkout untouched.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ $# -eq 3 ] || { echo "Usage: $0 <output directory> <amd64|arm64> <garrett program file>" >&2; exit 1; }
OUT=$1; ARCH=$2; AGENT=$3
case "$ARCH" in amd64|arm64) ;; *) echo "The processor is amd64 or arm64." >&2; exit 1 ;; esac
[ -f "$AGENT" ] || { echo "No such file: $AGENT" >&2; exit 1; }
command -v dpkg-buildpackage >/dev/null || { echo "dpkg-buildpackage is required: sudo apt install build-essential debhelper" >&2; exit 1; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/garrett/prebuilt" "$WORK/garrett/rust"
cp -r "$HERE/packaging" "$HERE/debian" "$HERE/LICENSE" "$WORK/garrett/"
cp "$HERE/rust/NOTICES.md" "$WORK/garrett/rust/"
# Files checked out on Windows may carry CRLF line endings and no execute bits; a package must have neither problem.
find "$WORK/garrett" -type f -exec sed -i 's/\r$//' {} + -exec chmod 0644 {} +
cp "$AGENT" "$WORK/garrett/prebuilt/garrett-agent"
chmod 0755 "$WORK/garrett/debian/rules" "$WORK/garrett/packaging/garrett" "$WORK/garrett/packaging/unblock" "$WORK/garrett/prebuilt/garrett-agent"
# -d: the only build dependency is debhelper itself. -a: the package is for $ARCH whatever machine packs it.
(cd "$WORK/garrett" && dpkg-buildpackage -us -uc -b -d -a"$ARCH" >"$WORK/build.log" 2>&1) || { tail -30 "$WORK/build.log" >&2; exit 1; }
mkdir -p "$OUT"
cp "$WORK"/garrett_*_"$ARCH".deb "$OUT/"
ls "$OUT"/garrett_*_"$ARCH".deb
