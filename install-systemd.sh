#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/guardd"
DATA_DIR="${INSTALL_DIR}/data"
SYSTEMD_DIR="/etc/systemd/system"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script with sudo or as root."
  exit 1
fi

echo "[*] Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  python3 \
  python3-venv \
  python3-pip \
  build-essential \
  clang \
  llvm \
  libbpf-dev \
  libelf-dev \
  bpftool \
  pkg-config \
  sqlite3 \
  rsync

echo "[*] Creating install directory..."
mkdir -p "${INSTALL_DIR}"
mkdir -p "${DATA_DIR}"

echo "[*] Copying project to ${INSTALL_DIR}..."
rsync -a --delete \
  --exclude '.git' \
  --exclude '.venv' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '*.pyo' \
  --exclude 'data/*.db' \
  --exclude 'data/*.bundle' \
  "${SRC_DIR}/" "${INSTALL_DIR}/"

echo "[*] Setting ownership..."
chown -R root:root "${INSTALL_DIR}"

echo "[*] Creating Python virtual environment..."
rm -rf "${INSTALL_DIR}/.venv"
python3 -m venv "${INSTALL_DIR}/.venv"

echo "[*] Installing Python package..."
"${INSTALL_DIR}/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
"${INSTALL_DIR}/.venv/bin/python" -m pip install -e "${INSTALL_DIR}"

echo "[*] Building eBPF components..."
pushd "${INSTALL_DIR}/ebpf" >/dev/null
PATH="${PATH}:/usr/sbin:/sbin" make clean || true
PATH="${PATH}:/usr/sbin:/sbin" make
popd >/dev/null

echo "[*] Installing systemd unit file..."
install -m 0644 "${INSTALL_DIR}/systemd/guardd.service" "${SYSTEMD_DIR}/guardd.service"

echo "[*] Removing legacy training units if present..."
systemctl disable --now guardd-train.timer 2>/dev/null || true
systemctl disable --now guardd-train.service 2>/dev/null || true
rm -f "${SYSTEMD_DIR}/guardd-train.timer"
rm -f "${SYSTEMD_DIR}/guardd-train.service"

echo "[*] Reloading systemd..."
systemctl daemon-reload

echo "[*] Enabling service (not starting)..."
systemctl enable guardd.service

echo
echo "[+] Installation complete."
echo
echo "[+] Next steps:"
echo "    sudo systemctl start guardd.service"
echo
echo "[+] Debug:"
echo "    systemctl status guardd.service"
echo "    journalctl -u guardd.service -f"
