#!/bin/sh
# Publish a signed garrett release: the site first (the apt repository, the installers, the update list), then the
# GitHub release. Run it from a checkout of this repository, with git and gh signed in.
#
#   sh packaging/publish-release.sh <release folder>
#
# The site is the gh-pages branch. Each release is one ordinary commit on top of it. Installed agents find the
# new version through the site's update list within a few hours and install it by themselves.
set -eu
[ $# -eq 1 ] || { echo "Usage: $0 <release folder>" >&2; exit 1; }
REL=$(CDPATH= cd -- "$1" && pwd)
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(sed -n '1s/^garrett //p' "$REL/site/update.txt")
for need in site/update.txt.sig site/dists/stable/InRelease site/garrett.gpg dist/SHA256SUMS.asc; do
  [ -s "$REL/$need" ] || { echo "$need is missing: sign the release first (packaging/sign-release.sh)." >&2; exit 1; }
done
ORIGIN=$(git -C "$HERE" remote get-url origin)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
if git ls-remote --exit-code --heads "$ORIGIN" gh-pages >/dev/null 2>&1; then
  git clone --quiet --depth 1 --branch gh-pages "$ORIGIN" "$WORK/site"
else
  git init --quiet "$WORK/site" && git -C "$WORK/site" checkout --quiet --orphan gh-pages && git -C "$WORK/site" remote add origin "$ORIGIN"
fi
cd "$WORK/site"
git config user.name "$(git -C "$HERE" config user.name)"; git config user.email "$(git -C "$HERE" config user.email)"
# Earlier packages stay in the pool; everything else is replaced by this release.
find . -mindepth 1 -maxdepth 1 ! -name .git ! -name pool -exec rm -rf {} +
cp -R "$REL/site/." .
git add -A
git commit --quiet -m "garrett $VERSION"
git push --quiet origin gh-pages
echo "The site carries garrett $VERSION."
cd "$HERE"
NOTES="$REL/notes.md"
[ -s "$NOTES" ] || sed -n '/^garrett ('"$VERSION"')/,/^ -- /p' debian/changelog | sed '1d;$d' | sed 's/^  //' > "$NOTES"
gh release create "v$VERSION" --title "garrett $VERSION" --notes-file "$NOTES" "$REL"/dist/*
echo "Released: v$VERSION"
