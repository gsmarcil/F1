#!/bin/sh
# For the update checks in verify.yml only: build this commit twice (as it is, and with the version 9.9.9), both
# trusting a signing key made here and now, and serve what a site would offer on 127.0.0.1:8766.
#
#   sh .github/update-site.sh <work folder> <published file name for this system> <openssl 3 command>
#
#   <work>/old, old.version      the agent as it is (old.exe on Windows)
#   site/good                    the later version, properly listed and signed
#   site/unsigned                the same list with no signature
#   site/stranger                the same list signed with a key the agent does not know
#   site/swapped                 a properly signed list, but the program file offered is a different one
set -eu
WORK=$1; NAME=$2; SSL=$3
EXT=""; case "$NAME" in *.exe) EXT=.exe ;; esac
mkdir -p "$WORK/site/good" "$WORK/site/unsigned" "$WORK/site/stranger" "$WORK/site/swapped"
"$SSL" genpkey -algorithm ed25519 -out "$WORK/key.pem"
"$SSL" genpkey -algorithm ed25519 -out "$WORK/stranger.pem"
GARRETT_TEST_UPDATE_KEY=$("$SSL" pkey -in "$WORK/key.pem" -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n')
export GARRETT_TEST_UPDATE_KEY
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' rust/Cargo.toml | head -1)
echo "$VERSION" > "$WORK/old.version"
(cd rust && cargo build --locked && cp "target/debug/garrett$EXT" "$WORK/old$EXT")
cp rust/Cargo.toml "$WORK/Cargo.toml.kept"; cp rust/Cargo.lock "$WORK/Cargo.lock.kept"
sed -i.bak "s/^version = \"$VERSION\"/version = \"9.9.9\"/" rust/Cargo.toml
(cd rust && cargo build && cp "target/debug/garrett$EXT" "$WORK/new$EXT")
cp "$WORK/Cargo.toml.kept" rust/Cargo.toml; cp "$WORK/Cargo.lock.kept" rust/Cargo.lock; rm -f rust/Cargo.toml.bak
test "$("$WORK/old$EXT" version)" = "garrett $VERSION"
test "$("$WORK/new$EXT" version)" = "garrett 9.9.9"
sum() { if command -v sha256sum >/dev/null 2>&1; then sha256sum < "$1" | cut -d' ' -f1; else shasum -a 256 < "$1" | cut -d' ' -f1; fi; }
sign() { "$SSL" pkeyutl -sign -inkey "$1" -rawin -in "$2" -out "$2.bin" && od -An -tx1 "$2.bin" | tr -d ' \n' > "$2.sig" && rm "$2.bin"; }
for site in good unsigned stranger swapped; do
  cp "$WORK/new$EXT" "$WORK/site/$site/$NAME"
  printf 'garrett 9.9.9\n%s  %s\n' "$(sum "$WORK/new$EXT")" "$NAME" > "$WORK/site/$site/update.txt"
done
sign "$WORK/key.pem" "$WORK/site/good/update.txt"
: > "$WORK/site/unsigned/update.txt.sig"
sign "$WORK/stranger.pem" "$WORK/site/stranger/update.txt"
sign "$WORK/key.pem" "$WORK/site/swapped/update.txt"
cp "$WORK/old$EXT" "$WORK/site/swapped/$NAME"
PY=python3; command -v python3 >/dev/null 2>&1 || PY=python
(cd "$WORK/site" && nohup "$PY" -m http.server 8766 --bind 127.0.0.1 >/dev/null 2>&1 &)
sleep 2
echo "serving: $(ls "$WORK/site")"
