#!/bin/sh
# Double-click this file. It asks for your password once and installs garrett on this Mac.
cd "$(dirname "$0")" || exit 1
echo "Installing garrett. macOS will ask for your password."
sudo sh ./install.sh
echo
echo "You can close this window."
