# These examples are from this repo: 
## https://github.com/ganjiaravind/ebpf/tree/main

### ebpf

#Required packages

RHEL/centos/fedora

yum install clang

yum install llvm

ubuntu

apt-get install clang

apt-get install llvm

#compilation:-

clang -I /root/kernel/include/ -I /root/kernel/tools/lib/ -O2 -emit-llvm -c <source file> -o - | llc -march=bpf -filetype=obj -o <output in .o>

# -I is used for header location, so provide headers available in kernel source repo

#To load object file into kernel memory

tc filter add dev eth0  ingress bpf direct-action obj <object file.o> sec <RX section needs to load from source>

#To List object file is successfully loaded

tc filter show dev eth0 ingress

#To list debug logs

tc exec bpf dbg

#To list maps

bpftool -f map show

#To update maps

bpftool map update id <map id> key hex <key value in bytes> value hex <values in bytes>

example :-

bpftool map update id 1 key hex 00 00 00 00 value hex 10 00 00 00

#To dump maps content

bpftool map dump id <map id>

#to figureout global ebpf fs mount

tree /sys/fs/bpf/
