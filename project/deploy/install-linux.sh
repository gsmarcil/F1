#!/bin/sh
# Install garrett from this checkout as a systemd service (the same layout the package and the bundles use).
# Build the agent first:  (cd rust && cargo build --release --locked)
#   sudo deploy/install-linux.sh                                             protect this machine by itself
#   sudo SENTINEL_ENROLL_KEY=<key> deploy/install-linux.sh https://your-service [kill|decide|pause|report]
# The mode defaults to kill: a hostile program and everything it started is ended at once.
# Remove it again with:  sudo sh packaging/linux/install.sh --remove
set -eu
[ "$(id -u)" = 0 ] || { echo "Run as root." >&2; exit 1; }
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SERVER=${1:-}; MODE=${2:-}
if [ -n "$SERVER" ]; then
  : "${SENTINEL_ENROLL_KEY:?Set SENTINEL_ENROLL_KEY}"
  install -d -m 0755 /etc/garrett
  umask 077
  printf 'SERVER=%s\nENROLL_KEY=%s\n' "$SERVER" "$SENTINEL_ENROLL_KEY" > /etc/garrett/garrett.conf
  [ -z "$MODE" ] || printf 'MODE=%s\n' "$MODE" >> /etc/garrett/garrett.conf
  chmod 0600 /etc/garrett/garrett.conf
fi
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
[ -x "$HERE/rust/target/release/garrett" ] || { echo "Build the agent first: (cd rust && cargo build --release --locked)" >&2; exit 1; }
cp "$HERE/rust/target/release/garrett" "$WORK/garrett-agent"
cp "$HERE/packaging/garrett" "$HERE/packaging/unblock" "$HERE/debian/garrett.service" "$HERE/packaging/linux/install.sh" "$WORK/"
sh "$WORK/install.sh"
