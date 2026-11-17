#!/bin/sh
# Turn this Linux machine into your own Sentinel service, in one line. Free: it runs on your machine, nothing is
# sent anywhere else, and there is no account.
#
#   curl -fsSL https://gary23w.github.io/sentinels/service.sh | sudo sh
#
# It prints the command that joins your other machines (Linux, macOS, Windows) to it.
# Options:  --port <number, default 8443>  --address <name or address other machines reach this one by>
# Remove it again:  curl -fsSL .../service.sh | sudo sh -s -- --remove
#
# It downloads garrett-service.tar.gz, checks it against the published SHA-256, and runs its installer.
set -eu
BASE=${GARRETT_BASE:-https://gary23w.github.io/sentinels}
[ "$(id -u)" = 0 ] || { echo "Run this as root (put sudo before sh)." >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo "This installer covers Linux. On Windows use service.ps1; elsewhere see serve.mjs in the repository." >&2; exit 1; }
fetch() { if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"; else wget -q "$1" -O "$2"; fi; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fetch "$BASE/garrett-service.tar.gz" "$WORK/garrett-service.tar.gz"
fetch "$BASE/SHA256SUMS" "$WORK/SHA256SUMS"
WANT=$(grep " garrett-service.tar.gz\$" "$WORK/SHA256SUMS" | cut -d' ' -f1)
HAVE=$(sha256sum "$WORK/garrett-service.tar.gz" | cut -d' ' -f1)
[ -n "$WANT" ] && [ "$WANT" = "$HAVE" ] || { echo "The download does not match its published checksum. Nothing was installed." >&2; exit 1; }
tar -xzf "$WORK/garrett-service.tar.gz" -C "$WORK"
GARRETT_BASE=$BASE sh "$WORK/garrett-service/install.sh" "$@"
