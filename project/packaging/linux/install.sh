#!/bin/sh
# Install garrett from this folder on a Linux machine that has no apt package for it: Fedora, RHEL, SUSE, Arch,
# Alpine, and small boards and devices. It runs as a service where the machine has systemd or OpenRC.
#   sudo sh install.sh          remove it again with:  sudo sh install.sh --remove
set -eu
[ "$(id -u)" = 0 ] || { echo "Run this as root." >&2; exit 1; }
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "${1:-}" = --remove ]; then
  if [ -d /run/systemd/system ]; then systemctl disable --now garrett.service >/dev/null 2>&1 || true; fi
  if [ -x /etc/init.d/garrett ] && command -v rc-service >/dev/null 2>&1; then rc-service garrett stop >/dev/null 2>&1 || true; rc-update del garrett default >/dev/null 2>&1 || true; fi
  /usr/lib/garrett/unblock 2>/dev/null || true
  rm -rf /usr/lib/garrett /usr/bin/garrett /etc/systemd/system/garrett.service /etc/init.d/garrett /var/lib/garrett /etc/garrett
  if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
  echo "garrett was removed."
  exit 0
fi
# Without ss garrett still ends hostile programs as they start; it cannot see who a program talks to.
command -v ss >/dev/null 2>&1 || echo "Note: the ss command (package iproute2) is not on this machine. garrett will watch program starts, but not connections." >&2
install -d -m 0755 /usr/lib/garrett
install -m 0755 "$HERE/garrett-agent" /usr/lib/garrett/garrett-agent
install -m 0755 "$HERE/unblock" /usr/lib/garrett/unblock
install -m 0755 "$HERE/garrett" /usr/bin/garrett
if [ -d /run/systemd/system ]; then
  install -m 0644 "$HERE/garrett.service" /etc/systemd/system/garrett.service
  systemctl daemon-reload
  systemctl enable garrett.service >/dev/null 2>&1 || true
  systemctl restart garrett.service
  echo "garrett is running. Check: systemctl status garrett"
elif command -v rc-update >/dev/null 2>&1 && [ -d /etc/init.d ]; then
  install -m 0755 "$HERE/garrett.openrc" /etc/init.d/garrett
  rc-update add garrett default >/dev/null 2>&1 || true
  rc-service garrett stop >/dev/null 2>&1 || true
  rc-service garrett start
  echo "garrett is running. Check: rc-service garrett status"
else
  echo "garrett is installed. This machine has neither systemd nor OpenRC: start it from your own supervisor with:  garrett auto && garrett run"
fi
