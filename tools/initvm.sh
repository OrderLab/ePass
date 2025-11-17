#!/bin/bash

VMSSHPORT=2222

GIT_REPO=$(git rev-parse --show-toplevel)

DRIVE_PATH=$GIT_REPO/test/vm/disk.qcow2

qemu-system-x86_64 -enable-kvm -drive file=${DRIVE_PATH},format=qcow2 --nographic -net nic -net user,hostfwd=tcp::2222-:22 -cpu host -smp 16 -m 8G &

sleep 10
ssh -p $VMSSHPORT root@localhost -C "apt-get install -y cloud-guest-utils"
ssh -p $VMSSHPORT root@localhost -C "growpart /dev/sda 1"
ssh -p $VMSSHPORT root@localhost -C "resize2fs /dev/sda1"

scp -P $VMSSHPORT ~/.ssh/* root@localhost:~/.ssh/
