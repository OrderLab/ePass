#!/usr/bin/env bash
# M8 acceptance, run as root in the VM (kernel with CONFIG_BPF_EPASS,
# bpftool from third-party/ePass-bpftool, i.e. built on ePass-libbpf).
#
#   acceptance.sh <objects...>  >  results.csv
#
# Every object is loaded (bpftool prog loadall) four ways:
#   base    no ePass
#   user    ePass in userspace, in libbpf (LIBBPF_ENABLE_EPASS=1)
#   kernel  ePass in the kernel, requested by libbpf (LIBBPF_EPASS_KERNEL=1)
#   always  ePass in the kernel for every program (policy mode=always),
#           with an unmodified load (no flag, no options)
# and every loaded program is measured: xlated and JIT-ed
# bytes. The acceptance criterion is that the set of objects the
# verifier accepts is the same in all four modes.
set -u

BPFTOOL=${BPFTOOL:-bpftool}
POLICY=/proc/sys/kernel/bpf_epass_policy
PIN=/sys/fs/bpf/epass_acc
[ -w $POLICY ] || { echo "no $POLICY: this kernel has no ePass (CONFIG_BPF_EPASS)" >&2; exit 1; }
saved_policy=$(cat $POLICY)

measure() {	# mode obj -> "ok;progs;xlated;jited" or "fail;0;0;0"
	local mode=$1 obj=$2 env=() rc
	rm -rf $PIN
	case $mode in
	user) env=(LIBBPF_ENABLE_EPASS=1) ;;
	kernel) env=(LIBBPF_ENABLE_EPASS=1 LIBBPF_EPASS_KERNEL=1) ;;
	esac
	if [ "$mode" = always ] && ! echo "mode=always" > $POLICY; then
		echo "cannot set the policy" >&2
		exit 1
	fi
	env "${env[@]}" timeout 20 $BPFTOOL prog loadall "$obj" $PIN >/dev/null 2>&1
	rc=$?
	[ "$mode" = always ] && echo "mode=optin" > $POLICY
	if [ $rc -ne 0 ]; then
		rm -rf $PIN
		echo "fail;0;0;0"
		return
	fi
	local n=0 x=0 v=0 p info
	for p in $PIN/*; do
		info=$($BPFTOOL prog show pinned "$p" --json 2>/dev/null) || continue
		n=$((n + 1))
		x=$((x + $(echo "$info" | sed -n 's/.*"bytes_xlated":\([0-9]*\).*/\1/p' | grep . || echo 0)))
		v=$((v + $(echo "$info" | sed -n 's/.*"bytes_jited":\([0-9]*\).*/\1/p' | grep . || echo 0)))
	done
	rm -rf $PIN
	echo "ok;$n;$x;$v"
}

echo "mode=optin" > $POLICY
echo "object,base,base_progs,base_xlated,base_jited,user,user_xlated,user_jited,kernel,kernel_xlated,kernel_jited,always,always_xlated,always_jited"
for obj in "$@"; do
	row=$(basename "$obj")
	for mode in base user kernel always; do
		IFS=';' read -r ok n x v <<<"$(measure $mode "$obj")"
		if [ $mode = base ]; then
			row="$row,$ok,$n,$x,$v"
		else
			row="$row,$ok,$x,$v"
		fi
	done
	echo "$row"
done
echo "$saved_policy" > $POLICY
