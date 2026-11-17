#!/bin/sh
# Pack a garrett release from the program files the release workflow built. Unsigned: sign-release.sh does that.
#
#   sh packaging/assemble-release.sh <folder the built program files were downloaded to> <output folder>
#
#   <output>/dist   for the GitHub release: Debian packages, bundles, program files, SHA256SUMS
#   <output>/site   for the project's site: apt repository, installers, update list, manual, the same downloads
#
# Needs a Debian or Ubuntu machine with: build-essential debhelper apt-utils mandoc python3
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ $# -eq 2 ] || { echo "Usage: $0 <built program files> <output folder>" >&2; exit 1; }
BUILT=$(CDPATH= cd -- "$1" && pwd); OUT=$2
rm -rf "$OUT"; mkdir -p "$OUT/agents" "$OUT/dist" "$OUT/site"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$HERE/rust/Cargo.toml" | head -1)
head -1 "$HERE/debian/changelog" | grep -q "($VERSION)" || { echo "debian/changelog does not start with version $VERSION." >&2; exit 1; }
NAMES="garrett-linux-x86_64 garrett-linux-aarch64 garrett-linux-armv7 garrett-macos garrett-windows.exe"
for name in $NAMES; do
  # A download from the workflow puts each file in a folder of its own name.
  if [ -f "$BUILT/$name/$name" ]; then cp "$BUILT/$name/$name" "$OUT/agents/$name"; else cp "$BUILT/$name" "$OUT/agents/$name"; fi
done
sh "$HERE/packaging/build-deb.sh" "$OUT/dist" amd64 "$OUT/agents/garrett-linux-x86_64"
sh "$HERE/packaging/build-deb.sh" "$OUT/dist" arm64 "$OUT/agents/garrett-linux-aarch64"
sh "$HERE/packaging/make-apt-repo.sh" "$OUT/dist" "$OUT/site"
# The program files by themselves: what an installed agent downloads when it updates itself.
for name in $NAMES; do cp "$OUT/agents/$name" "$OUT/dist/$name"; done
sed 's/\r$//' "$HERE/deploy/kubernetes-daemonset.yaml" > "$OUT/dist/kubernetes-daemonset.yaml"
python3 -B "$HERE/packaging/build-release.py" "$OUT/dist" --agents "$OUT/agents" --all
# The update list: the version, then the SHA-256 of each program file. An agent installs nothing this list
# does not name, and nothing at all unless the list carries the project's signature.
{ echo "garrett $VERSION"; for name in $NAMES; do grep "  $name\$" "$OUT/dist/SHA256SUMS"; done; } > "$OUT/site/update.txt"
[ "$(wc -l < "$OUT/site/update.txt")" = 6 ] || { echo "The update list is incomplete." >&2; exit 1; }
for name in $NAMES garrett-linux-x86_64.tar.gz garrett-linux-aarch64.tar.gz garrett-linux-armv7.tar.gz garrett-macos.tar.gz garrett-windows.zip garrett-service.tar.gz garrett-service-windows.zip SHA256SUMS; do cp "$OUT/dist/$name" "$OUT/site/$name"; done
for name in install.sh install.ps1 service.sh service.ps1; do sed 's/\r$//' "$HERE/packaging/$name" > "$OUT/site/$name"; done
# The site's front page, and the manual as a page.
sed "s/@VERSION@/$VERSION/g" "$HERE/packaging/site/index.html" > "$OUT/site/index.html"
{ sed -n '1,/@MANUAL@/p' "$HERE/packaging/site/manual.html" | sed '$d'; mandoc -T html -O fragment "$HERE/debian/garrett.8"; sed -n '/@MANUAL@/,$p' "$HERE/packaging/site/manual.html" | sed '1d'; } > "$OUT/site/manual.html"
: > "$OUT/site/.nojekyll"
rm -rf "$OUT/agents"
echo "garrett $VERSION, unsigned:"; (cd "$OUT" && find dist site -type f | sort)
