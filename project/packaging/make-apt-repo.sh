#!/bin/sh
# Turn a folder of garrett .deb files into an apt repository you can host on any static web server.
#   sh packaging/make-apt-repo.sh <folder with .deb files> <repository folder> [gpg key id]
# With a key id the repository is signed (Release.gpg and InRelease) and machines can verify it:
#   curl -fsSL https://your-host/garrett.gpg | sudo tee /usr/share/keyrings/garrett.gpg >/dev/null
#   echo "deb [signed-by=/usr/share/keyrings/garrett.gpg] https://your-host stable main" | sudo tee /etc/apt/sources.list.d/garrett.list
#   sudo apt update && sudo apt install garrett
# Without a key the repository is unsigned and only suitable for testing with [trusted=yes].
set -eu
[ $# -ge 2 ] || { echo "Usage: $0 <folder with .deb files> <repository folder> [gpg key id]" >&2; exit 1; }
DEBS=$1; REPO=$2; KEY=${3:-}
command -v apt-ftparchive >/dev/null || { echo "apt-ftparchive (package apt-utils) is required." >&2; exit 1; }
mkdir -p "$REPO/pool/main"
cp "$DEBS"/garrett_*.deb "$REPO/pool/main/"
cd "$REPO"
for arch in all amd64 arm64; do
  mkdir -p "dists/stable/main/binary-$arch"
  # Each list names the packages for that processor, and the ones (from before version 1) that run on any.
  apt-ftparchive --arch "$arch" packages pool/main > "dists/stable/main/binary-$arch/Packages"
  gzip -9 -k -f "dists/stable/main/binary-$arch/Packages"
done
apt-ftparchive -o APT::FTPArchive::Release::Origin=garrett -o APT::FTPArchive::Release::Label=garrett \
  -o APT::FTPArchive::Release::Suite=stable -o APT::FTPArchive::Release::Codename=stable \
  -o APT::FTPArchive::Release::Components=main -o "APT::FTPArchive::Release::Architectures=all amd64 arm64" \
  release dists/stable > Release.new
mv Release.new dists/stable/Release
if [ -n "$KEY" ]; then
  gpg --batch --yes --default-key "$KEY" --armor --detach-sign -o dists/stable/Release.gpg dists/stable/Release
  gpg --batch --yes --default-key "$KEY" --clearsign -o dists/stable/InRelease dists/stable/Release
  gpg --batch --yes --export "$KEY" > garrett.gpg
  echo "Signed apt repository in $REPO (public key: garrett.gpg)"
else
  echo "Unsigned apt repository in $REPO (testing only)"
fi
