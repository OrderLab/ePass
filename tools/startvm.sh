#!/bin/bash

KERNEL_PATH=/home/linsy/Projects/ebpf/ePass-kernel

DRIVE_PATH=/home/linsy/Projects/ebpf/vm/vm/ebpf.qcow2

# First enable bridge virbr0

qemu-system-x86_64 -enable-kvm -drive file=${DRIVE_PATH},format=qcow2 -kernel ${KERNEL_PATH}/arch/x86_64/boot/bzImage -append "root=/dev/sda1" --nographic -netdev bridge,id=net0,br=virbr0 -device virtio-net-pci,netdev=net0 -cpu host -smp $(nproc) -m 8G &

#qemu-system-x86_64 -enable-kvm -drive file=${DRIVE_PATH},format=qcow2 -kernel ${KERNEL_PATH}/arch/x86_64/boot/bzImage -append "root=/dev/sda1 console=ttyS0" --nographic -netdev bridge,id=net0,br=virbr0 -device virtio-net-pci,netdev=net0 -cpu host -smp $(nproc) -m 8G
