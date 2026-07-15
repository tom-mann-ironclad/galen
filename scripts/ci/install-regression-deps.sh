#!/usr/bin/env bash
set -euo pipefail

if [[ ! -r /etc/os-release ]]; then
    echo "Unable to identify distro: /etc/os-release is missing" >&2
    exit 1
fi

# shellcheck source=/dev/null
source /etc/os-release

case "${ID}" in
    debian | ubuntu)
        apt-get update
        apt-get install -y --no-install-recommends \
            bash \
            ca-certificates \
            curl \
            gcc \
            gzip \
            libc6-dev \
            make \
            pkg-config \
            tar \
            zip
        ;;
    fedora)
        dnf install -y \
            bash \
            ca-certificates \
            curl \
            gcc \
            gzip \
            make \
            pkgconf-pkg-config \
            tar \
            zip
        ;;
    arch)
        pacman -Syu --noconfirm
        pacman -S --noconfirm \
            bash \
            ca-certificates \
            curl \
            gcc \
            gzip \
            make \
            pkgconf \
            tar \
            zip
        ;;
    *)
        echo "Unsupported regression distro: ${ID}" >&2
        exit 1
        ;;
esac
