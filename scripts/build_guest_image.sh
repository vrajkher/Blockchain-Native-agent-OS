#!/usr/bin/env bash
# Build the Firecracker guest image for BlockSwarm secure mode.
#
#   sudo scripts/build_guest_image.sh [OUT_DIR]     (default /var/lib/blockswarm)
#
# Produces OUT_DIR/vmlinux and OUT_DIR/guest-rootfs.ext4:
#   * kernel and base Ubuntu 24.04 userland from Firecracker's CI artifacts
#     (pinned versions, SHA-256 checked)
#   * /opt/blockswarm: the blockswarm package + cryptography wheels (Python 3.12)
#   * /sbin/blockswarm-init: mounts /proc,/sys,/dev and tmpfs, runs the guest
#     agent over vsock (CID 2 = host), powers off when it exits
# The rootfs is attached read-only; the guest has no network device.
set -euo pipefail

OUT=${1:-/var/lib/blockswarm}
CACHE=${BLOCKSWARM_CACHE:-$HOME/.cache/blockswarm}
REPO=$(cd "$(dirname "$0")/.." && pwd)
FC_CI=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/x86_64
KERNEL=vmlinux-6.1.128
KERNEL_SHA256=${KERNEL_SHA256:-27a8310b9a727517e9eb02044524b6ceb77de5728e3491b6974d5c846227ecc8}
SQUASHFS=ubuntu-24.04.squashfs
SQUASHFS_SHA256=${SQUASHFS_SHA256:-88821a26b5a38c92b84a064d452167d7f80f9e17cf4441d1ebbae7569e340aee}

mkdir -p "$OUT" "$CACHE"
fetch() {  # url file sha256
  if [ ! -f "$CACHE/$2" ]; then curl -fsSL -o "$CACHE/$2.part" "$1" && mv "$CACHE/$2.part" "$CACHE/$2"; fi
  echo "$3  $CACHE/$2" | sha256sum -c --quiet - || { echo "checksum mismatch: $2" >&2; exit 1; }
}
fetch "$FC_CI/$KERNEL" "$KERNEL" "$KERNEL_SHA256"
fetch "$FC_CI/$SQUASHFS" "$SQUASHFS" "$SQUASHFS_SHA256"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/root"
if command -v unsquashfs >/dev/null; then
  unsquashfs -q -d "$ROOT" "$CACHE/$SQUASHFS"
else
  python3 "$REPO/scripts/unsquash.py" "$CACHE/$SQUASHFS" "$ROOT"
fi

# Guest software: the package (no tests, no caches) and its one native dependency.
mkdir -p "$ROOT/opt/blockswarm"
cp -r "$REPO/blockswarm" "$ROOT/opt/blockswarm/"
find "$ROOT/opt/blockswarm" -name __pycache__ -prune -exec rm -rf {} +
python3 -m pip install --quiet --no-compile --target "$ROOT/opt/blockswarm" \
  --platform manylinux2014_x86_64 --python-version 3.12 --implementation cp \
  --only-binary=:all: "cryptography>=42"

cat > "$ROOT/sbin/blockswarm-init" <<'INIT'
#!/bin/sh
# PID 1 inside the microVM. No network, read-only root, tmpfs scratch only.
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
mount -t tmpfs -o size=16m,mode=1777 tmpfs /tmp
port=5000
for arg in $(cat /proc/cmdline); do case "$arg" in bs_port=*) port=${arg#bs_port=};; esac; done
cd /opt/blockswarm
PYTHONPATH=/opt/blockswarm PYTHONDONTWRITEBYTECODE=1 \
  setpriv --reuid=65534 --regid=65534 --clear-groups \
  python3 -s -m blockswarm.guest.agent --vsock "2:$port"
echo o > /proc/sysrq-trigger 2>/dev/null   # power off; Firecracker exits (reboot=k)
reboot -f
INIT
chmod 0755 "$ROOT/sbin/blockswarm-init"

SIZE_MB=$(( $(du -sm "$ROOT" | cut -f1) + 64 ))
rm -f "$OUT/guest-rootfs.ext4"
mkfs.ext4 -q -F -L bsroot -d "$ROOT" "$OUT/guest-rootfs.ext4" "${SIZE_MB}M"
cp "$CACHE/$KERNEL" "$OUT/vmlinux"
chmod 0444 "$OUT/vmlinux" "$OUT/guest-rootfs.ext4"
echo "kernel: $OUT/vmlinux"
echo "rootfs: $OUT/guest-rootfs.ext4 (${SIZE_MB} MiB)"
