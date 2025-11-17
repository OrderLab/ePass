#!/bin/bash

GIT_REPO=$(git rev-parse --show-toplevel)

mkdir -p $GIT_REPO/test/vm
cd $GIT_REPO/test/vm

wget https://cdimage.debian.org/images/cloud/trixie/latest/debian-13-nocloud-amd64.qcow2 -O disk.qcow2

qemu-img resize disk.qcow2 +20G

# Run inside VM:
# apt update; apt-get install -y openssh-server; echo 'PermitEmptyPasswords yes' >> /etc/ssh/sshd_config; echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config; systemctl restart sshd
