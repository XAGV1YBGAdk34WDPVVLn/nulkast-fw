#!/usr/bin/env bash
set -euo pipefail

KERNEL=$(ls /boot/vmlinuz-* | head -n1)
KVM_ARGS=""
if [[ -e /dev/kvm ]]; then
    KVM_ARGS="-enable-kvm -cpu host"
    echo "=== Launching Stock Debian 6.x VM under Hardware KVM (/dev/kvm) ==="
else
    KVM_ARGS="-cpu max"
    echo "=== Launching Stock Debian 6.x VM under QEMU TCG (no /dev/kvm) ==="
fi

OUT=$(mktemp)
timeout 45 qemu-system-x86_64 \
    ${KVM_ARGS} \
    -m 512M \
    -nographic \
    -no-reboot \
    -kernel "${KERNEL}" \
    -initrd /opt/initramfs.cpio.gz \
    -append "console=ttyS0 quiet panic=1 rdinit=/init" \
    | tee "${OUT}"

if grep -q "VM_SQM_ALL_PASSED" "${OUT}"; then
    echo "=== STOCK DEBIAN 6.x QEMU/KVM CAKE SQM VERIFICATION PASSED ==="
    rm -f "${OUT}"
    exit 0
else
    echo "=== STOCK DEBIAN 6.x QEMU/KVM CAKE SQM VERIFICATION FAILED ==="
    rm -f "${OUT}"
    exit 1
fi
