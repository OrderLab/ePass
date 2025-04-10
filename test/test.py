#!/usr/bin/env python3

"""
ePass Compiler Testing Suite
"""

import glob, os

CORRECT_PROGS = [
    "output/progs_map1.o",
    "output/trace_output.bpf.o",
    "output/evaluation_counter_loopnested.o",
    "output/evaluation_counter_loop2.o",
    "output/progs_test_asm.o",
    "output/evaluation_counter_loopwithif.o",
    "output/progs_libbpf_profile.bpf.o",
    "output/evaluation_msan_msan1.o",
    "output/tcp_bufs_kern.o",
    "output/tracex3.bpf.o",
    "output/test_map_in_map.bpf.o",
    "output/ibumad_kern.o",
    "output/progs_empty.o",
    "output/sock_flags.bpf.o",
    "output/progs_tengjiang_syscount.o",
    "output/tracex4.bpf.o",
    "output/map_perf_test.bpf.o",
    "output/tracex5.bpf.o",
    "output/trace_event_kern.o",
    "output/tracex2.bpf.o",
    "output/progs_libbpf_uprobe.bpf.o",
    "output/evaluation_msan_msan3.o",
    "output/tcp_rwnd_kern.o",
    "output/tcp_clamp_kern.o",
    "output/progs_libbpf_minimal_ns.bpf.o",
    "output/tcp_iw_kern.o",
    "output/progs_loop3.o",
    "output/test_current_task_under_cgroup.bpf.o",
    "output/tcp_tos_reflect_kern.o",
    "output/spintest.bpf.o",
    "output/evaluation_masking_masksimple.o",
    "output/progs_simple2.o",
    "output/evaluation_counter_loop1med.o",
    "output/progs_libbpf_bootstrap.bpf.o",
    "output/evaluation_div_by_zero_div_by_zero.o",
    "output/progs_simple1.o",
    "output/syscall_tp_kern.o",
    "output/progs_libbpf_sockfilter.bpf.o",
    "output/test_probe_write_user.bpf.o",
    "output/evaluation_masking_map_val_accepted.o",
    "output/sampleip_kern.o",
    "output/progs_fn_nonrejected_uninit_var_access.o",
    "output/progs_mem2.o",
    "output/progs_compact_opt.o",
    "output/progs_str.o",
    "output/tcp_basertt_kern.o",
    "output/tcp_cong_kern.o",
    "output/progs_libbpf_ksyscall.bpf.o",
    "output/progs_tengjiang_xdp.o",
    "output/tcp_synrto_kern.o",
    "output/evaluation_masking_map_val_rejected.o",
    "output/tracex7.bpf.o",
    "output/progs_libbpf_minimal.bpf.o",
    "output/xdp_tx_iptunnel_kern.o",
    "output/progs_loop2.o",
    "output/progs_ringbuf.o",
    "output/evaluation_div_by_zero_div_by_zero2.o",
    "output/evaluation_counter_complex2.o",
    "output/test_overhead_tp.bpf.o",
    "output/progs_fn_oob.o",
    "output/task_fd_query_kern.o",
    "output/progs_alu64.o",
    "output/progs_tengjiang_simple_trace.o",
    "output/evaluation_counter_loop1sim.o",
    "output/progs_libbpf_kprobe.bpf.o",
    "output/lathist_kern.o",
    "output/test_overhead_raw_tp.bpf.o",
    "output/progs_libbpf_minimal_legacy.bpf.o",
    "output/evaluation_msan_msan2.o",
    "output/evaluation_counter_loop4.o"
]

ALL_PROGS = [
    "output/progs_map1.o",
    "output/trace_output.bpf.o",
    "output/evaluation_counter_loopnested.o",
    "output/evaluation_counter_loop2.o",
    "output/progs_test_asm.o",
    "output/evaluation_counter_loopwithif.o",
    "output/progs_libbpf_profile.bpf.o",
    "output/evaluation_msan_msan1.o",
    "output/tcp_bufs_kern.o",
    "output/tracex3.bpf.o",
    "output/test_map_in_map.bpf.o",
    "output/ibumad_kern.o",
    "output/progs_empty.o",
    "output/sock_flags.bpf.o",
    "output/progs_tengjiang_syscount.o",
    "output/tracex4.bpf.o",
    "output/map_perf_test.bpf.o",
    "output/cpustat_kern.o",
    "output/hbm_out_kern.o",
    "output/tracex5.bpf.o",
    "output/trace_event_kern.o",
    "output/tracex2.bpf.o",
    "output/progs_libbpf_uprobe.bpf.o",
    "output/evaluation_msan_msan3.o",
    "output/tcp_rwnd_kern.o",
    "output/tcp_clamp_kern.o",
    "output/progs_libbpf_minimal_ns.bpf.o",
    "output/tcp_iw_kern.o",
    "output/progs_loop3.o",
    "output/test_current_task_under_cgroup.bpf.o",
    "output/tcp_tos_reflect_kern.o",
    "output/spintest.bpf.o",
    "output/progs_tengjiang_access_control.o",
    "output/evaluation_masking_masksimple.o",
    "output/progs_simple2.o",
    "output/hbm_edt_kern.o",
    "output/evaluation_counter_loop1med.o",
    "output/progs_libbpf_bootstrap.bpf.o",
    "output/evaluation_div_by_zero_div_by_zero.o",
    "output/evaluation_counter_loop1.o",
    "output/progs_simple1.o",
    "output/syscall_tp_kern.o",
    "output/progs_libbpf_sockfilter.bpf.o",
    "output/test_probe_write_user.bpf.o",
    "output/evaluation_masking_map_val_accepted.o",
    "output/sampleip_kern.o",
    "output/progs_libbpf_task_iter.bpf.o",
    "output/progs_fn_nonrejected_uninit_var_access.o",
    "output/progs_libbpf_fentry.bpf.o",
    "output/progs_mem2.o",
    "output/progs_compact_opt.o",
    "output/progs_Thejokr_ebpf-playground_probe.o",
    "output/progs_str.o",
    "output/tcp_basertt_kern.o",
    "output/sockex3_kern.o",
    "output/evaluation_counter_loop3.o",
    "output/progs_libbpf_lsm.bpf.o",
    "output/tcp_cong_kern.o",
    "output/progs_libbpf_ksyscall.bpf.o",
    "output/progs_tengjiang_xdp.o",
    "output/tcp_synrto_kern.o",
    "output/evaluation_masking_map_val_rejected.o",
    "output/tracex7.bpf.o",
    "output/progs_libbpf_minimal.bpf.o",
    "output/xdp_tx_iptunnel_kern.o",
    "output/progs_loop2.o",
    "output/progs_ringbuf.o",
    "output/evaluation_div_by_zero_div_by_zero2.o",
    "output/evaluation_counter_complex2.o",
    "output/test_overhead_tp.bpf.o",
    "output/progs_fn_oob.o",
    "output/task_fd_query_kern.o",
    "output/progs_alu64.o",
    "output/progs_tengjiang_simple_trace.o",
    "output/evaluation_counter_loop1sim.o",
    "output/progs_libbpf_kprobe.bpf.o",
    "output/lathist_kern.o",
    "output/test_overhead_raw_tp.bpf.o",
    "output/progs_libbpf_minimal_legacy.bpf.o",
    "output/evaluation_msan_msan2.o",
    "output/evaluation_counter_loop4.o"
]


def all_objects():
    # Get all .o file paths in the output directory
    o_files = glob.glob(os.path.join("output", "*.o"))
    o_files.remove("output/evaluation_compile_speed_speed_100.o")
    o_files.remove("output/evaluation_compile_speed_speed_50.o")
    o_files.remove("output/evaluation_compile_speed_speed_20.o")
    return o_files


def init():
    print("init...")
    os.system("sudo /sbin/sysctl -w kernel.bpf_stats_enabled=1")


def is_correct(prog: str):
    return os.system(f"timeout 2 sudo epass read {prog} --direct-load")


def is_correct_epass(prog: str):
    return os.system(f"timeout 2 sudo epass read {prog}")


def is_correct_epass_v2(prog: str):
    return os.system(f"timeout 2 sudo epass read {prog} --gopt cgv2")


def find_correct_progs():
    correct_set = []
    for o in all_objects():
        if is_correct(o) == 0:
            correct_set.append(o)
            print(o)
    print("--- SUMMARY ---")
    print(correct_set)


def test_correct_progs():
    failed_progs = []
    for o in ALL_PROGS:
        if is_correct_epass(o) == 0:
            print(f"\x1b[32m {o} Passed\x1b[0m")
        else:
            failed_progs.append(o)
            print(f"\x1b[31m {o} Failed\x1b[0m")
    print("--- SUMMARY ---")
    print(failed_progs)

def test_correct_progs_v2():
    failed_progs = []
    for o in CORRECT_PROGS:
        if is_correct_epass_v2(o) == 0:
            print(f"\x1b[32m {o} Passed\x1b[0m")
        else:
            failed_progs.append(o)
            print(f"\x1b[31m {o} Failed\x1b[0m")
    print("--- SUMMARY ---")
    print(failed_progs)


if __name__ == "__main__":
    init()
    # find_correct_progs()
    test_correct_progs()
