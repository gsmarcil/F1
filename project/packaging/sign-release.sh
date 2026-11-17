#!/bin/sh
# Sign a garrett release that assemble-release.sh packed. Run it where the signing keys are kept; they never
# leave that machine, and only their public halves are written into the release.
#
#   GNUPGHOME=<keyring with the package signing key>  GARRETT_UPDATE_KEY=<Ed25519 private key, PEM> \
#     sh packaging/sign-release.sh <release folder>
#
# Two keys sign two things:
#   the package signing key (OpenPGP)   the apt repository, and SHA256SUMS
#   the update key (Ed25519)            update.txt, the list an installed agent checks before it updates itself;
#                                       its public half is compiled into the agent (rust/src/update.rs)
# Needs gpg and OpenSSL 3.
set -eu
[ $# -eq 1 ] || { echo "Usage: $0 <release folder>" >&2; exit 1; }
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
REL=$(CDPATH= cd -- "$1" && pwd)
: "${GNUPGHOME:?Set GNUPGHOME to the keyring that holds the package signing key}"
: "${GARRETT_UPDATE_KEY:?Set GARRETT_UPDATE_KEY to the update key file}"
export GNUPGHOME
KEY=$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')
[ -n "$KEY" ] || { echo "No signing key in $GNUPGHOME." >&2; exit 1; }
cd "$REL/site"
gpg --batch --yes --default-key "$KEY" --armor --detach-sign -o dists/stable/Release.gpg dists/stable/Release
gpg --batch --yes --default-key "$KEY" --clearsign -o dists/stable/InRelease dists/stable/Release
gpg --batch --yes --export "$KEY" > garrett.gpg
gpg --batch --yes --armor --export "$KEY" > garrett.asc
gpg --verify dists/stable/Release.gpg dists/stable/Release 2>/dev/null
cd "$REL/dist"
sha256sum -c SHA256SUMS >/dev/null
gpg --batch --yes --default-key "$KEY" --armor --detach-sign -o SHA256SUMS.asc SHA256SUMS
gpg --verify SHA256SUMS.asc SHA256SUMS 2>/dev/null
cp SHA256SUMS.asc "$REL/site/SHA256SUMS.asc"
cp "$REL/site/garrett.asc" "$REL/dist/garrett.asc"
gpgconf --kill all 2>/dev/null || true
# The update list. The signature is written as hex, one line.
cd "$REL/site"
openssl pkeyutl -sign -inkey "$GARRETT_UPDATE_KEY" -rawin -in update.txt -out update.txt.bin
od -An -tx1 update.txt.bin | tr -d ' \n' > update.txt.sig
rm update.txt.bin
# It must check out against the key the agents carry, or no agent would ever update.
CARRIED=$(sed -n 's/^const KEY: &str = "\([0-9a-f]*\)";/\1/p' "$HERE/rust/src/update.rs")
MINE=$(openssl pkey -in "$GARRETT_UPDATE_KEY" -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n')
[ -n "$CARRIED" ] && [ "$CARRIED" = "$MINE" ] || { echo "This update key is not the one compiled into the agent." >&2; rm -f update.txt.sig; exit 1; }
echo "Signed with package key $KEY and update key $MINE:"
head -1 update.txt
