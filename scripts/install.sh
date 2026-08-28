#!/bin/sh

set -eu

REPOSITORY="julienmarie/envctl"
VERSION="${ENVCTL_VERSION:-latest}"
INSTALL_DIR="${ENVCTL_INSTALL_DIR:-$HOME/.local/bin}"

usage() {
    cat <<'EOF'
Install envctl from a GitHub Release.

Usage:
  install.sh [--version VERSION] [--dir DIRECTORY]

Options:
  --version VERSION   Release to install, such as v0.1.0 (default: latest)
  --dir DIRECTORY     Installation directory (default: ~/.local/bin)
  -h, --help          Show this help

Environment variables:
  ENVCTL_VERSION       Same as --version
  ENVCTL_INSTALL_DIR   Same as --dir
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || { echo "error: --version requires a value" >&2; exit 2; }
            VERSION="$2"
            shift 2
            ;;
        --dir)
            [ "$#" -ge 2 ] || { echo "error: --dir requires a value" >&2; exit 2; }
            INSTALL_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

command -v curl >/dev/null 2>&1 || {
    echo "error: curl is required" >&2
    exit 1
}

case "$(uname -s)" in
    Darwin) os="macos" ;;
    Linux) os="linux" ;;
    *)
        echo "error: unsupported operating system: $(uname -s)" >&2
        exit 1
        ;;
esac

case "$(uname -m)" in
    arm64|aarch64) arch="arm64" ;;
    x86_64|amd64) arch="x86_64" ;;
    *)
        echo "error: unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

if [ "$VERSION" = "latest" ]; then
    latest_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPOSITORY}/releases/latest")"
    VERSION="$(basename "$latest_url")"
fi

case "$VERSION" in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    [0-9]*.[0-9]*.[0-9]*) VERSION="v${VERSION}" ;;
    *)
        echo "error: invalid release version: $VERSION" >&2
        exit 1
        ;;
esac

plain_version="${VERSION#v}"
package="envctl-${plain_version}-${os}-${arch}"
archive="${package}.tar.gz"
base_url="https://github.com/${REPOSITORY}/releases/download/${VERSION}"
temp_dir="$(mktemp -d)"

cleanup() {
    rm -rf "$temp_dir"
}
trap cleanup EXIT HUP INT TERM

echo "Downloading envctl ${VERSION} for ${os}-${arch}..."
curl -fL "${base_url}/${archive}" -o "${temp_dir}/${archive}"
curl -fL "${base_url}/${archive}.sha256" -o "${temp_dir}/${archive}.sha256"

(
    cd "$temp_dir"
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c "${archive}.sha256"
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c "${archive}.sha256"
    else
        echo "error: shasum or sha256sum is required" >&2
        exit 1
    fi
    tar -xzf "$archive"
)

mkdir -p "$INSTALL_DIR"
install -m 0755 "${temp_dir}/${package}/envctl" "${INSTALL_DIR}/envctl"

echo "Installed envctl to ${INSTALL_DIR}/envctl"
case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *) echo "Add ${INSTALL_DIR} to PATH before running envctl." ;;
esac
