#!/bin/bash

GIT_REPO=$(git rev-parse --show-toplevel)

KERNEL_PATH=$GIT_REPO/ePass-kernel

DRIVE_PATH=$GIT_REPO/test/vm/disk.qcow2

screen -S epass -dm bash -c "qemu-system-x86_64 -enable-kvm -drive file=${DRIVE_PATH},format=qcow2 -kernel ${KERNEL_PATH}/arch/x86_64/boot/bzImage -append 'root=/dev/sda1' --nographic -net nic -net user,hostfwd=tcp::2222-:22 -cpu host -smp 16 -m 8G"

# To start with default kernel, run:

# qemu-system-x86_64 -enable-kvm -drive file=${DRIVE_PATH},format=qcow2 --nographic -net nic -net user,hostfwd=tcp::2222-:22 -cpu host -smp 16 -m 8G
