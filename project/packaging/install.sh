#!/bin/sh
# Install garrett on this machine. It works out what kind of machine this is and sets itself up.
#
#   curl -fsSL https://gary23w.github.io/sentinels/install.sh | sudo sh
#
# That alone protects the machine: garrett watches it and ends what is hostile. To join a fleet as well:
#
#   curl -fsSL https://gary23w.github.io/sentinels/install.sh | sudo sh -s -- --server https://your-service --key <enrolment key>
#
# Options:  --server <address>  --key <enrolment key>  --mode kill|decide|pause|report  --label <name>
#
#   Debian, Ubuntu and relatives   adds the signed apt repository and installs the package (64-bit Intel/AMD and ARM)
#   other Linux                    installs the same files from the release bundle, after checking its SHA-256: with
#                                  systemd or OpenRC it runs as a service; 32-bit ARM boards and devices included
#   macOS                          installs a LaunchDaemon from the release bundle, after checking its SHA-256
#
# Once installed, garrett keeps itself current: it installs each new version by itself, after checking that the
# project signed it. Turn that off with UPDATE=off in its configuration file.
set -eu
BASE=${GARRETT_BASE:-https://gary23w.github.io/sentinels}
SERVER=""; KEY=""; MODE=""; LABEL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER=$2; shift 2 ;;
    --key) KEY=$2; shift 2 ;;
    --mode) MODE=$2; shift 2 ;;
    --label) LABEL=$2; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "Run this as root (put sudo before sh)." >&2; exit 1; }
if [ -n "$SERVER" ] && [ -z "$KEY" ] || [ -z "$SERVER" ] && [ -n "$KEY" ]; then echo "Give --server and --key together, or neither." >&2; exit 1; fi
fetch() { if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"; else wget -q "$1" -O "$2"; fi; }
SYSTEM=$(uname -s)
CONF=/etc/garrett/garrett.conf
[ "$SYSTEM" = Darwin ] && CONF=/usr/local/etc/garrett.conf

# The configuration goes down first, so the service finds it the moment it starts.
if [ -n "$SERVER$MODE$LABEL" ]; then
  mkdir -p "$(dirname "$CONF")"
  # Only root may read the enrolment key. The file is made empty and closed to others before anything is written
  # to it; the umask is left alone, because apt must be able to read the files this installer adds next.
  : > "$CONF"
  chmod 0600 "$CONF"
  [ -z "$SERVER" ] || printf 'SERVER=%s\nENROLL_KEY=%s\n' "$SERVER" "$KEY" >> "$CONF"
  [ -z "$MODE" ] || printf 'MODE=%s\n' "$MODE" >> "$CONF"
  [ -z "$LABEL" ] || printf 'LABEL=%s\n' "$LABEL" >> "$CONF"
  chmod 0600 "$CONF"
fi

bundle() {
  # $1 = bundle name. Downloads it, checks it against the published SHA-256, unpacks it, runs its installer.
  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT
  fetch "$BASE/$1" "$WORK/$1"
  fetch "$BASE/SHA256SUMS" "$WORK/SHA256SUMS"
  WANT=$(grep " $1\$" "$WORK/SHA256SUMS" | cut -d' ' -f1)
  if command -v sha256sum >/dev/null 2>&1; then HAVE=$(sha256sum "$WORK/$1" | cut -d' ' -f1); else HAVE=$(shasum -a 256 "$WORK/$1" | cut -d' ' -f1); fi
  [ -n "$WANT" ] && [ "$WANT" = "$HAVE" ] || { echo "The download does not match its published checksum. Nothing was installed." >&2; exit 1; }
  tar -xzf "$WORK/$1" -C "$WORK"
  sh "$WORK/garrett/install.sh"
}

# The apt repository carries packages for 64-bit Intel/AMD and 64-bit ARM. Anything else takes the bundle.
PACKAGED=no
if [ "$SYSTEM" = Linux ] && command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
  case "$(dpkg --print-architecture 2>/dev/null)" in amd64|arm64) PACKAGED=yes ;; esac
fi
if [ "$PACKAGED" = yes ]; then
  mkdir -p /usr/share/keyrings
  fetch "$BASE/garrett.gpg" /usr/share/keyrings/garrett.gpg
  echo "deb [signed-by=/usr/share/keyrings/garrett.gpg] $BASE stable main" > /etc/apt/sources.list.d/garrett.list
  chmod 0644 /usr/share/keyrings/garrett.gpg /etc/apt/sources.list.d/garrett.list
  apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/garrett.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y garrett
elif [ "$SYSTEM" = Linux ]; then
  case "$(uname -m)" in
    x86_64|amd64) bundle garrett-linux-x86_64.tar.gz ;;
    aarch64|arm64) bundle garrett-linux-aarch64.tar.gz ;;
    armv7l|armv8l) bundle garrett-linux-armv7.tar.gz ;;
    *) echo "garrett is built for 64-bit Intel/AMD, 64-bit ARM and 32-bit ARMv7 machines. This one is $(uname -m)." >&2; exit 1 ;;
  esac
elif [ "$SYSTEM" = Darwin ]; then
  bundle garrett-macos.tar.gz
else
  echo "This installer covers Linux and macOS. For Windows, download garrett-windows.zip from the releases page." >&2
  exit 1
fi
if [ -n "$SERVER" ]; then echo "garrett is installed and is enrolling with $SERVER."; else echo "garrett is installed and protecting this machine. See what it finds: garrett cases"; fi
