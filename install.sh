#!/usr/bin/env bash
# install.sh -- sets up KaliFuzz on Kali / Debian-based systems.
set -e

echo "[*] Installing python3-tk (needed for the GUI)..."
sudo apt-get update -qq
sudo apt-get install -y python3-tk python3-pip

echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt

chmod +x kalifuzz_cli.py kalifuzz_gui.py

echo "[+] Done."
echo "    CLI : python3 kalifuzz_cli.py -u http://target -w wordlists/common.txt -x php,html -t 50 -r"
echo "    GUI : python3 kalifuzz_gui.py"
