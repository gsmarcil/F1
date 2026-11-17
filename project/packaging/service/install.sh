#!/bin/sh
# Turn this Linux machine into your own Sentinel service, from this folder.
#   sudo sh install.sh [--port 8443] [--address <name or address other machines reach this one by>]
#   sudo sh install.sh --remove
#
# It installs the service under /usr/lib/garrett-service, makes its keys and its own HTTPS certificate, runs it as
# the unprivileged user garrett-service, and prints the command that joins other machines to it.
# Running it again upgrades the program and keeps the keys, the certificate and the database.
set -eu
[ "$(id -u)" = 0 ] || { echo "Run this as root." >&2; exit 1; }
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LIB=/usr/lib/garrett-service; ETC=/etc/garrett-service; DATA=/var/lib/garrett-service; UNIT=/etc/systemd/system/garrett-service.service
NODE_VERSION=v24.22.3
NODE_SUM_x64=061ec3e3062115705b56b51fa9cc330ab50d34b6969387d4e4b1a50c6809acc2
NODE_SUM_arm64=261af2af250dfd7e9f25cf151d1b2713a0adf8f10a9ad116c4947f68627affe8
PORT=""; ADDRESS=""; REMOVE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT=$2; shift 2 ;;
    --address) ADDRESS=$2; shift 2 ;;
    --remove) REMOVE=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done
if [ -n "$REMOVE" ]; then
  systemctl disable --now garrett-service.service >/dev/null 2>&1 || true
  rm -rf "$LIB" "$ETC" "$DATA" "$UNIT" /usr/bin/garrett-service
  systemctl daemon-reload 2>/dev/null || true
  userdel garrett-service >/dev/null 2>&1 || true
  echo "The Sentinel service, its keys and its database were removed. Machines that reported to it protect themselves alone until they are enrolled somewhere else."
  exit 0
fi
[ -d /run/systemd/system ] || { echo "This installer needs systemd. On other systems run:  node serve.mjs <configuration file>  from your own supervisor (see serve.mjs)." >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl is required. Install it with your package manager and run this again." >&2; exit 1; }
case "$PORT" in *[!0-9]*) echo "The port must be a number." >&2; exit 1 ;; esac
command -v curl >/dev/null 2>&1 || { echo "curl is required. Install it with your package manager and run this again." >&2; exit 1; }
fetch() { curl -fsSL "$1" -o "$2"; }

install -d -m 0755 "$LIB" "$LIB/src"
install -m 0644 "$HERE/serve.mjs" "$HERE/sqlite.mjs" "$HERE/schema.sql" "$HERE/LICENSE" "$LIB/"
install -m 0644 "$HERE"/src/*.mjs "$LIB/src/"
install -m 0755 "$HERE/garrett-service" /usr/bin/garrett-service

# Node.js: the one already here if it is new enough, otherwise the official build from nodejs.org, checked against
# the SHA-256 this installer was published with.
NODE=""
if command -v node >/dev/null 2>&1 && node -e "require('node:sqlite'); process.exit(Number(process.versions.node.split('.')[0]) >= 22 ? 0 : 1)" >/dev/null 2>&1; then NODE=$(command -v node); fi
if [ -z "$NODE" ] && [ -x "$LIB/node" ] && [ "$("$LIB/node" --version 2>/dev/null)" = "$NODE_VERSION" ]; then NODE=$LIB/node; fi
if [ -z "$NODE" ]; then
  case "$(uname -m)" in
    x86_64|amd64) ARCH=x64; WANT=$NODE_SUM_x64 ;;
    aarch64|arm64) ARCH=arm64; WANT=$NODE_SUM_arm64 ;;
    *) echo "No Node.js 22.13 or newer was found, and there is no official build to fetch for $(uname -m). Install Node.js and run this again." >&2; exit 1 ;;
  esac
  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT
  NAME=node-$NODE_VERSION-linux-$ARCH
  echo "Fetching Node.js $NODE_VERSION from nodejs.org ..."
  fetch "https://nodejs.org/dist/$NODE_VERSION/$NAME.tar.gz" "$WORK/node.tar.gz"
  HAVE=$(sha256sum "$WORK/node.tar.gz" | cut -d' ' -f1)
  [ "$WANT" = "$HAVE" ] || { echo "The Node.js download does not match its published checksum. Nothing was started." >&2; exit 1; }
  tar -xzf "$WORK/node.tar.gz" -C "$WORK" "$NAME/bin/node"
  install -m 0755 "$WORK/$NAME/bin/node" "$LIB/node"
  NODE=$LIB/node
fi

id garrett-service >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin garrett-service
install -d -m 0750 -o root -g garrett-service "$ETC"
install -d -m 0700 -o garrett-service -g garrett-service "$DATA"
if [ ! -s "$ETC/service.conf" ]; then
  [ -n "$ADDRESS" ] || ADDRESS=$(hostname -I 2>/dev/null | cut -d' ' -f1)
  [ -n "$ADDRESS" ] || ADDRESS=$(hostname)
  umask 027
  {
    echo "# The Sentinel service on this machine. Restart after a change:  systemctl restart garrett-service"
    echo "PORT=${PORT:-8443}"
    echo "ADDRESS=$ADDRESS"
    echo "DATABASE=$DATA/sentinel.db"
    echo "TLS_CERT=$ETC/tls.crt"
    echo "TLS_KEY=$ETC/tls.key"
    echo "# Lets a machine enrol. garrett-service join prints the command that carries it."
    echo "ENROLL_KEY=$(openssl rand -hex 32)"
    echo "# Lets you read cases and decide. Keep it to yourself."
    echo "ADMIN_TOKEN=$(openssl rand -hex 32)"
    echo "# Encrypts case evidence in the database. Lose it and stored evidence cannot be read."
    echo "DATA_KEY=$(openssl rand -hex 32)"
    echo "# What machines do about a hostile program: kill (the default), pause or report. See the README for the rest."
    echo "RESPONSE_MODE="
  } > "$ETC/service.conf"
else
  # An upgrade keeps everything; only what was asked for on the command line changes.
  [ -z "$PORT" ] || sed -i "s/^PORT=.*/PORT=$PORT/" "$ETC/service.conf"
  [ -z "$ADDRESS" ] || sed -i "s/^ADDRESS=.*/ADDRESS=$ADDRESS/" "$ETC/service.conf"
fi
ADDRESS=$(sed -n 's/^ADDRESS=//p' "$ETC/service.conf" | tail -n 1)
if [ ! -s "$ETC/tls.crt" ] || [ ! -s "$ETC/tls.key" ]; then
  # The service's own certificate. Machines are given its SHA-256 with the join command and accept no other.
  case "$ADDRESS" in *[!0-9.]*|"") SAN="DNS:$ADDRESS" ;; *) SAN="IP:$ADDRESS" ;; esac
  umask 027
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 -subj "/CN=garrett-service" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,$SAN" -keyout "$ETC/tls.key" -out "$ETC/tls.crt" >/dev/null 2>&1
fi
chown root:garrett-service "$ETC/service.conf" "$ETC/tls.crt" "$ETC/tls.key"
chmod 0640 "$ETC/service.conf" "$ETC/tls.key"; chmod 0644 "$ETC/tls.crt"

sed "s#@NODE@#$NODE#" "$HERE/garrett-service.service" > "$UNIT"
chmod 0644 "$UNIT"
systemctl daemon-reload
systemctl enable garrett-service.service >/dev/null 2>&1 || true
systemctl restart garrett-service.service
i=0
until garrett-service ready >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -lt 30 ] || { echo "The service did not start. See:  journalctl -u garrett-service -n 30" >&2; exit 1; }
  sleep 1
done
echo
echo "Your Sentinel service is running on this machine."
echo
garrett-service join
