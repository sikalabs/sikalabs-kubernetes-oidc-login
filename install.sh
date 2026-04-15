#!/bin/sh
set -e

REPO="sikalabs/sikalabs-kubernetes-oidc-login"
BINARY="sikalabs-kubernetes-oidc-login"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  linux) OS="linux" ;;
  darwin) OS="darwin" ;;
  *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# Get latest release tag from GitHub API
LATEST_TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' \
  | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"

if [ -z "$LATEST_TAG" ]; then
  echo "Failed to determine latest release" >&2
  exit 1
fi

TARBALL="${BINARY}_${LATEST_TAG}_${OS}_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${TARBALL}"

echo "Installing ${BINARY} ${LATEST_TAG} (${OS}/${ARCH}) to ${INSTALL_DIR}..."

curl -fsSL "$DOWNLOAD_URL" -o "/tmp/${TARBALL}"
tar -xzf "/tmp/${TARBALL}" -C /tmp "${BINARY}"
rm "/tmp/${TARBALL}"
mv "/tmp/${BINARY}" "${INSTALL_DIR}/${BINARY}"
chmod +x "${INSTALL_DIR}/${BINARY}"

echo "Installed: $(${INSTALL_DIR}/${BINARY} version)"
