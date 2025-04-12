#!/usr/bin/env python3

"""
Run the program w/ and w/o ePass

Evaluate the time it costs
"""

import os
import subprocess
import re
import matplotlib.pyplot as plt
import matplotlib
import numpy as np
from pathlib import Path
import env
import time
import glob
import matplotlib.ticker as mticker

EXPERIMENT_TIMES = env.EXPERIMENT_TIMES
CARD = env.CARD

compile_prog_tests = [
    "output/evaluation_compile_speed_speed_20.o",
    "output/evaluation_compile_speed_speed_30.o",
    "output/evaluation_compile_speed_speed_50.o",
    "output/evaluation_compile_speed_speed_70.o",
    "output/evaluation_compile_speed_speed_100.o",
    "output/evaluation_compile_speed_speed_120.o",
    "output/progs_latency.o",
    "output/progs_map1.o",
    "output/trace_output.bpf.o",
    "output/evaluation_counter_loop2.o",
    "output/progs_test_asm.o",
    "output/progs_libbpf_profile.bpf.o",
    "output/cache.o",
    "output/evaluation_msan_msan1.o",
    "output/tracex3.bpf.o",
    "output/test_map_in_map.bpf.o",
    "output/ibumad_kern.o",
    "output/progs_empty.o",
    "output/sock_flags.bpf.o",
    "output/progs_tengjiang_syscount.o",
    "output/tracex4.bpf.o",
    "output/progs_filter.o",
    "output/progs_mask.o",
    "output/tracex5.bpf.o",
    "output/test_cgrp2_tc.bpf.o",
    "output/xdp_adjust_tail_kern.o",
    "output/trace_event_kern.o",
    "output/evaluation_counter_complex.o",
    "output/tracex2.bpf.o",
    "output/progs_libbpf_uprobe.bpf.o",
    "output/evaluation_msan_msan3.o",
    "output/tcp_rwnd_kern.o",
    "output/progs_libbpf_minimal_ns.bpf.o",
    "output/syscalle.o",
    "output/progs_loop3.o",
    "output/tcp_tos_reflect_kern.o",
    "output/spintest.bpf.o",
    "output/progs_simple2.o",
    "output/syscall.o",
    "output/evaluation_counter_loop1med.o",
    "output/evaluation_div_by_zero_div_by_zero.o",
    "output/evaluation_counter_loop1.o",
    "output/progs_simple1.o",
    "output/syscall_tp_kern.o",
    "output/progs_hashmap.o",
    "output/progs_libbpf_sockfilter.bpf.o",
    "output/test_probe_write_user.bpf.o",
    "output/sampleip_kern.o",
    "output/progs_fn_nonrejected_uninit_var_access.o",
    "output/progs_libbpf_fentry.bpf.o",
    "output/syscall2.o",
    "output/evaluation_masking_mask.o",
    "output/progs_mem2.o",
    "output/progs_compact_opt.o",
    "output/parse_simple.o",
    "output/progs_str.o",
    "output/progs_loop1.o",
    "output/tcp_basertt_kern.o",
    "output/evaluation_counter_loop3.o",
    "output/progs_libbpf_lsm.bpf.o",
    "output/xdp2skb_meta_kern.o",
    "output/progs_tengjiang_xdp.o",
    "output/tcp_synrto_kern.o",
    "output/swf.o",
    "output/progs_mem1.o",
    "output/tracex7.bpf.o",
    "output/progs_libbpf_minimal.bpf.o",
    "output/read.o",
    "output/progs_loop2.o",
    "output/progs_ringbuf.o",
    "output/evaluation_counter_complex2.o",
    "output/pf.o",
    "output/test_overhead_tp.bpf.o",
    "output/progs_fn_oob.o",
    "output/task_fd_query_kern.o",
    "output/progs_alu64.o",
    "output/evaluation_counter_loop1sim.o",
    "output/progs_libbpf_kprobe.bpf.o",
    "output/progs_counter.o",
    "output/lathist_kern.o",
    "output/test_overhead_raw_tp.bpf.o",
    "output/progs_libbpf_minimal_legacy.bpf.o",
    "output/read2.o",
    "output/evaluation_msan_msan2.o",
    "output/evaluation_counter_loop4.o",

]

prog_tests = [
    "output/progs_latency.o",
    "output/progs_map1.o",
    "output/trace_output.bpf.o",
    "output/evaluation_counter_loop2.o",
    "output/progs_test_asm.o",
    "output/progs_libbpf_profile.bpf.o",
    "output/cache.o",
    "output/evaluation_msan_msan1.o",
    "output/tracex3.bpf.o",
    "output/test_map_in_map.bpf.o",
    "output/ibumad_kern.o",
    "output/progs_empty.o",
    "output/sock_flags.bpf.o",
    "output/progs_tengjiang_syscount.o",
    "output/tracex4.bpf.o",
    "output/progs_filter.o",
    "output/progs_mask.o",
    "output/tracex5.bpf.o",
    "output/test_cgrp2_tc.bpf.o",
    "output/xdp_adjust_tail_kern.o",
    "output/trace_event_kern.o",
    # "output/evaluation_counter_complex.o",
    "output/tracex2.bpf.o",
    "output/progs_libbpf_uprobe.bpf.o",
    "output/evaluation_msan_msan3.o",
    "output/tcp_rwnd_kern.o",
    "output/progs_libbpf_minimal_ns.bpf.o",
    "output/syscalle.o",
    "output/progs_loop3.o",
    "output/tcp_tos_reflect_kern.o",
    "output/spintest.bpf.o",
    "output/progs_tengjiang_access_control.o",
    "output/progs_simple2.o",
    "output/syscall.o",
    "output/evaluation_counter_loop1med.o",
    "output/progs_libbpf_bootstrap.bpf.o",
    "output/evaluation_div_by_zero_div_by_zero.o",
    # "output/evaluation_counter_loop1.o",
    "output/progs_simple1.o",
    "output/syscall_tp_kern.o",
    "output/progs_hashmap.o",
    "output/progs_libbpf_sockfilter.bpf.o",
    "output/test_probe_write_user.bpf.o",
    "output/sampleip_kern.o",
    "output/progs_fn_nonrejected_uninit_var_access.o",
    "output/progs_libbpf_fentry.bpf.o",
    "output/syscall2.o",
    "output/evaluation_masking_mask.o",
    "output/progs_mem2.o",
    "output/progs_compact_opt.o",
    "output/parse_simple.o",
    "output/progs_str.o",
    "output/progs_loop1.o",
    "output/tcp_basertt_kern.o",
    "output/evaluation_counter_loop3.o",
    "output/progs_libbpf_lsm.bpf.o",
    "output/xdp2skb_meta_kern.o",
    "output/progs_tengjiang_xdp.o",
    "output/tcp_synrto_kern.o",
    "output/swf.o",
    "output/progs_mem1.o",
    "output/tracex7.bpf.o",
    "output/progs_libbpf_minimal.bpf.o",
    "output/read.o",
    "output/progs_loop2.o",
    "output/progs_ringbuf.o",
    "output/evaluation_counter_complex2.o",
    "output/pf.o",
    "output/test_overhead_tp.bpf.o",
    "output/progs_fn_oob.o",
    "output/task_fd_query_kern.o",
    "output/progs_alu64.o",
    "output/progs_tengjiang_simple_trace.o",
    "output/evaluation_counter_loop1sim.o",
    "output/progs_libbpf_kprobe.bpf.o",
    "output/progs_counter.o",
    "output/lathist_kern.o",
    "output/test_overhead_raw_tp.bpf.o",
    "output/progs_libbpf_minimal_legacy.bpf.o",
    "output/read2.o",
    "output/evaluation_msan_msan2.o",
    "output/evaluation_counter_loop4.o",
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
    os.system("./gen_tests.sh")
    os.system("make all -j$(nproc)")
    os.mkdir("evalout")


def measure_cmd_time_avg(cmd: str):
    times = []
    cmds = cmd.split(" ")

    for _ in range(EXPERIMENT_TIMES):
        process = subprocess.Popen(
            ["./time"] + cmds, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, _ = process.communicate()
        rec = re.compile(r"Real Time: (.*?) nanoseconds")
        times.append(int(rec.findall(out.decode())[0]))

    return sum(times) / len(times) / 1000000


def measure_epass_insns(prog, gopt="", popt=""):
    if prog[-3:] == "txt":
        mode = "readlog"
    else:
        mode = "read"
    process = subprocess.Popen(
        [
            "epass",
            "-m",
            mode,
            "-p",
            prog,
            "--gopt",
            gopt,
            "--popt",
            popt,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, _ = process.communicate()
    rec = re.compile(r"program size: (.*?)->(.*?)\s")
    try:
        (c1, c2) = rec.findall(out.decode())[0]
        return (int(c1), int(c2))
    except:
        return 0, 0


def measure_epass_time_avg(prog, gopt="", popt=""):
    tot_times = []
    lift_times = []
    run_times = []
    compile_times = []

    for _ in range(EXPERIMENT_TIMES):
        process = subprocess.Popen(
            [
                "epass",
                "-m",
                "read",
                "-p",
                prog,
                "--gopt",
                gopt,
                "--popt",
                popt,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out, _ = process.communicate()
        rec = re.compile(
            r"ePass finished in (.*?)ns\nlift (.*?)ns\trun (.*?)ns\tcompile (.*?)ns"
        )
        (tott, liftt, runt, compilet) = rec.findall(out.decode())[0]
        tot_times.append(int(tott))
        lift_times.append(int(liftt))
        run_times.append(int(runt))
        compile_times.append(int(compilet))

    mean_tot = sum(tot_times) / len(tot_times) / 1000000
    mean_lift = sum(lift_times) / len(lift_times) / 1000000
    mean_run = sum(run_times) / len(run_times) / 1000000
    mean_compile = sum(compile_times) / len(compile_times) / 1000000
    return mean_tot, mean_lift, mean_run, mean_compile


def load_prog_epass(prog, gopt="", popt="", autoattach=False):
    bname = Path(prog).stem
    # bpftool prog load {prog} /sys/fs/bpf/{bname} epass {gopt} {popt}
    if autoattach:
        ret = os.system(
            f'sudo bpftool prog load {prog} /sys/fs/bpf/{bname} epass "{gopt}" "{popt}" autoattach'
        )
    else:
        ret = os.system(
            f'sudo bpftool prog load {prog} /sys/fs/bpf/{bname} epass "{gopt}" "{popt}"'
        )
    return ret


def load_prog_no_epass(prog, autoattach=False):
    bname = Path(prog).stem
    if autoattach:
        ret = os.system(f"sudo bpftool prog load {prog} /sys/fs/bpf/{bname} autoattach")
    else:
        ret = os.system(f"sudo bpftool prog load {prog} /sys/fs/bpf/{bname}")
    return ret


def attach_prog():
    os.system(f"sudo bpftool net attach xdp name prog dev {CARD}")


def test_null(it=1000):
    # for _ in range(2):
    cmds = f"lat_syscall -N {it} null"
    process = subprocess.Popen(
        cmds.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    _, out = process.communicate()
    out = out.decode()
    rec = re.compile(r"Simple syscall: (.*?) microseconds")
    res = rec.findall(out)[0]
    tot = float(res)
    return tot


def collect_info():
    cmds = "sudo bpftool prog show name prog"
    process = subprocess.Popen(
        cmds.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, _ = process.communicate()
    out = out.decode()
    rec = re.compile(r"run_time_ns (.*?) run_cnt (.*?)\s")
    res = rec.findall(out)[0]
    tot = int(res[0])
    cnt = int(res[1])
    return tot / cnt, cnt


def dettach_prog():
    os.system(f"sudo bpftool net detach xdp dev {CARD}")


def remove_prog(prog):
    bname = Path(prog).stem
    os.system(f"sudo rm -f /sys/fs/bpf/{bname}")


def evaluate_compile_speed():
    llc_time_20 = measure_cmd_time_avg(
        "llc -march=bpf output/evaluation_compile_speed_speed_20.ll -o /dev/null"
    )
    (epass_tot_20o, epass_lift_20o, epass_run_20o, epass_compile_20o) = (
        measure_epass_time_avg(
            "output/evaluation_compile_speed_speed_20.o", "no_prog_check"
        )
    )
    epass_other_20o = epass_tot_20o - epass_lift_20o - epass_run_20o - epass_compile_20o
    (epass_tot_20, epass_lift_20, epass_run_20, epass_compile_20) = (
        measure_epass_time_avg("output/evaluation_compile_speed_speed_20.o")
    )
    epass_other_20 = epass_tot_20 - epass_lift_20 - epass_run_20 - epass_compile_20

    llc_time_50 = measure_cmd_time_avg(
        "llc -march=bpf output/evaluation_compile_speed_speed_50.ll -o /dev/null"
    )
    (epass_tot_50o, epass_lift_50o, epass_run_50o, epass_compile_50o) = (
        measure_epass_time_avg(
            "output/evaluation_compile_speed_speed_50.o", "no_prog_check"
        )
    )
    epass_other_50o = epass_tot_50o - epass_lift_50o - epass_run_50o - epass_compile_50o
    (epass_tot_50, epass_lift_50, epass_run_50, epass_compile_50) = (
        measure_epass_time_avg("output/evaluation_compile_speed_speed_50.o")
    )
    epass_other_50 = epass_tot_50 - epass_lift_50 - epass_run_50 - epass_compile_50

    llc_time_100 = measure_cmd_time_avg(
        "llc -march=bpf output/evaluation_compile_speed_speed_100.ll -o /dev/null"
    )
    (epass_tot_100o, epass_lift_100o, epass_run_100o, epass_compile_100o) = (
        measure_epass_time_avg(
            "output/evaluation_compile_speed_speed_100.o", "no_prog_check"
        )
    )
    epass_other_100o = (
        epass_tot_100o - epass_lift_100o - epass_run_100o - epass_compile_100o
    )
    (epass_tot_100, epass_lift_100, epass_run_100, epass_compile_100) = (
        measure_epass_time_avg("output/evaluation_compile_speed_speed_100.o")
    )
    epass_other_100 = epass_tot_100 - epass_lift_100 - epass_run_100 - epass_compile_100

    categories = ["speed_20", "speed_50", "speed_100"]
    group3 = [llc_time_20, llc_time_50, llc_time_100]

    # Bar width
    bar_width = 0.25

    # x positions for each group of bars
    x = np.arange(len(categories))
    x1 = x - bar_width - 0.02
    x2 = x
    x3 = x + bar_width + 0.02

    x1region1 = [epass_compile_20o, epass_compile_50o, epass_compile_100o]
    x1region2 = [epass_lift_20o, epass_lift_50o, epass_lift_100o]
    x1region3 = [epass_run_20o, epass_run_50o, epass_run_100o]
    x1region4 = [epass_other_20o, epass_other_50o, epass_other_100o]

    x2region1 = [epass_compile_20, epass_compile_50, epass_compile_100]
    x2region2 = [epass_lift_20, epass_lift_50, epass_lift_100]
    x2region3 = [epass_run_20, epass_run_50, epass_run_100]
    x2region4 = [epass_other_20, epass_other_50, epass_other_100]

    print(x1region1, x1region2, x1region3, x1region4)

    print(x2region1, x2region2, x2region3, x2region4)

    print(group3)

    color1 = (0.2, 0.6, 0.9, 0.8)
    color2 = (0.2, 0.8, 0.6, 0.8)
    color3 = (1.0, 0.6, 0.2, 0.8)
    color4 = (0, 0, 0, 0.1)
    color5 = (0.6, 0.3, 0.8, 0.8)

    # Plotting
    plt.bar(x1, x1region1, width=bar_width, label="Compile", color=color1)
    plt.bar(
        x1, x1region2, width=bar_width, bottom=x1region1, label="Lift", color=color2
    )
    plt.bar(
        x1,
        x1region3,
        width=bar_width,
        bottom=np.array(x1region1) + np.array(x1region2),
        label="Run",
        color=color3,
    )
    plt.bar(
        x1,
        x1region4,
        width=bar_width,
        bottom=np.array(x1region1) + np.array(x1region2) + np.array(x1region3),
        label="Other",
        color=color4,
    )

    plt.bar(x2, x2region1, width=bar_width, color=color1)
    plt.bar(x2, x2region2, width=bar_width, bottom=x2region1, color=color2)
    plt.bar(
        x2,
        x2region3,
        width=bar_width,
        bottom=np.array(x2region1) + np.array(x2region2),
        color=color3,
    )
    plt.bar(
        x2,
        x2region4,
        width=bar_width,
        bottom=np.array(x2region1) + np.array(x2region2) + np.array(x2region3),
        color=color4,
    )

    plt.bar(x3, group3, width=bar_width, label="llc", color=color5)

    # Adding labels and title
    # plt.xlabel("Tests")
    plt.ylabel("Time (ms)")
    # plt.title("")
    plt.xticks(x, categories)
    plt.legend(fontsize=8)

    # Show plot
    # plt.show()
    fig = matplotlib.pyplot.gcf()
    fig.set_size_inches(3, 2)
    plt.tight_layout()
    fig.savefig("evalout/compile_speed.pdf", dpi=200)


def evaluate_counter_pass_single(prog_name, use_lat=False):
    prog = f"output/{prog_name}.o"
    remove_prog(prog)
    load_prog_no_epass(prog, autoattach=True)
    print(f"test {prog_name}...")
    n1c = test_null()
    (avg1, cnt) = collect_info()
    # print(avg1, cnt)
    remove_prog(prog)
    time.sleep(0.1)
    print(f"test {prog_name} with insn_counter...")
    load_prog_epass(prog, popt="insn_counter", autoattach=True)
    n2c = test_null()
    (avg2, cnt) = collect_info()
    # print(avg2, cnt)
    remove_prog(prog)
    if use_lat:
        return (n1c, n2c)
    else:
        return (avg1, avg2)


def evaluate_msan_pass_single(prog_name, use_lat=False):
    prog = f"output/{prog_name}.o"
    remove_prog(prog)
    load_prog_no_epass(prog, autoattach=True)
    print(f"test {prog_name}...")
    n1c = test_null(1000)
    (avg1, cnt) = collect_info()
    # print(avg1, cnt)
    remove_prog(prog)
    time.sleep(0.1)
    print(f"test {prog_name} with msan...")
    load_prog_epass(prog, popt="msan", autoattach=True)
    n2c = test_null(1000)
    (avg2, cnt) = collect_info()
    # print(avg2, cnt)
    remove_prog(prog)
    if use_lat:
        return (n1c, n2c)
    else:
        return (avg1, avg2)


def evaluate_counter_pass():
    USE_LATENCY = False
    (l1, l1c) = evaluate_counter_pass_single(
        "evaluation_counter_loop2", use_lat=USE_LATENCY
    )
    print(l1, l1c)
    time.sleep(0.1)
    (l2, l2c) = evaluate_counter_pass_single(
        "evaluation_counter_loop4", use_lat=USE_LATENCY
    )
    print(l2, l2c)
    time.sleep(0.1)
    (l3, l3c) = evaluate_counter_pass_single(
        "evaluation_counter_loop3", use_lat=USE_LATENCY
    )
    print(l3, l3c)
    time.sleep(0.1)
    (l4, l4c) = evaluate_counter_pass_single(
        "evaluation_counter_loop1med", use_lat=USE_LATENCY
    )
    print(l4, l4c)
    time.sleep(0.1)
    (l5, l5c) = evaluate_counter_pass_single(
        "evaluation_counter_loop1sim", use_lat=USE_LATENCY
    )
    print(l5, l5c)

    return

    categories = ["c1", "c2", "c3", "c4", "c5"]
    group1 = [l1, l2, l3, l4, l5]
    group2 = [l1c, l2c, l3c, l4c, l5c]
    # group3 = [4, 6, 0]

    # Bar width
    bar_width = 0.25

    # x positions for each group of bars
    x = np.arange(len(categories))
    x1 = x - bar_width / 2
    x2 = x + bar_width / 2
    # x3 = x + bar_width

    # Plotting
    plt.bar(x1, group1, width=bar_width, label="Group 1")
    plt.bar(x2, group2, width=bar_width, label="Group 2")
    # plt.bar(x3, group3, width=bar_width, label='Group 3')

    # Adding labels and title
    plt.ylabel("Time (μs)")
    # plt.title("")
    plt.xticks(x, categories)
    plt.legend(fontsize=8)

    # Show plot
    # plt.show()
    fig = matplotlib.pyplot.gcf()
    fig.set_size_inches(3, 2)
    plt.tight_layout()
    fig.savefig("evalout/insn_counter.pdf", dpi=200)


def evaluate_counter_pass_percent():
    USE_LATENCY = True
    (l1, l1c) = evaluate_counter_pass_single(
        "evaluation_counter_loop2", use_lat=USE_LATENCY
    )
    oh1 = (l1c - l1) / l1
    print(oh1)
    time.sleep(0.1)
    (l2, l2c) = evaluate_counter_pass_single(
        "evaluation_counter_loop4", use_lat=USE_LATENCY
    )
    oh2 = (l2c - l2) / l2
    print(oh2)
    time.sleep(0.1)
    (l3, l3c) = evaluate_counter_pass_single(
        "evaluation_counter_loop3", use_lat=USE_LATENCY
    )
    oh3 = (l3c - l3) / l3
    print(oh3)
    time.sleep(0.1)
    (l4, l4c) = evaluate_counter_pass_single(
        "evaluation_counter_loop1med", use_lat=USE_LATENCY
    )
    oh4 = (l4c - l4) / l4
    print(oh4)
    time.sleep(0.1)
    (l5, l5c) = evaluate_counter_pass_single(
        "evaluation_counter_loop1sim", use_lat=USE_LATENCY
    )
    oh5 = (l5c - l5) / l5
    print(oh5)
    xs = [oh1, oh2, oh3, oh4, oh5]
    print(xs)
    plt.bar([1, 2, 3, 4, 5], xs)

    # Adding labels and title
    plt.xlabel("Categories")
    plt.ylabel("Values")
    plt.legend()

    fig = matplotlib.pyplot.gcf()
    fig.set_size_inches(3, 2)
    plt.tight_layout()
    fig.savefig("evalout/counter_per.pdf", dpi=200)


def evaluate_counter_pass_efficiency():
    # Test the efficiency of insn_counter, using performance pass
    ret = measure_epass_insns("output/evaluation_counter_loop2.o", popt="insn_counter")
    print(ret)
    ret = measure_epass_insns("output/evaluation_counter_loop4.o", popt="insn_counter")
    print(ret)
    ret = measure_epass_insns("output/evaluation_counter_loop3.o", popt="insn_counter")
    print(ret)
    ret = measure_epass_insns(
        "output/evaluation_counter_loop1med.o", popt="insn_counter"
    )
    print(ret)
    ret = measure_epass_insns(
        "output/evaluation_counter_loop1sim.o", popt="insn_counter"
    )
    print(ret)


def evaluate_msan_pass():
    USE_LATENCY = False
    (l1, l1c) = evaluate_msan_pass_single("evaluation_msan_msan1", use_lat=USE_LATENCY)
    print(l1, l1c)
    time.sleep(0.1)
    (l2, l2c) = evaluate_msan_pass_single("evaluation_msan_msan2", use_lat=USE_LATENCY)
    print(l2, l2c)
    time.sleep(0.1)
    (l3, l3c) = evaluate_msan_pass_single("evaluation_msan_simpl1", use_lat=USE_LATENCY)
    print(l3, l3c)
    time.sleep(0.1)
    (l4, l4c) = evaluate_msan_pass_single("evaluation_msan_simpl2", use_lat=USE_LATENCY)
    print(l4, l4c)
    return

    categories = ["c1", "c2", "c3"]
    group1 = [l1, l2, l3]
    group2 = [l1c, l2c, l3c]
    # group3 = [4, 6, 0]

    # Bar width
    bar_width = 0.25

    # x positions for each group of bars
    x = np.arange(len(categories))
    x1 = x - bar_width / 2
    x2 = x + bar_width / 2
    # x3 = x + bar_width

    # Plotting
    plt.bar(x1, group1, width=bar_width, label="Group 1")
    plt.bar(x2, group2, width=bar_width, label="Group 2")
    # plt.bar(x3, group3, width=bar_width, label='Group 3')

    # Adding labels and title
    plt.ylabel("Time (μs)")
    # plt.title("")
    plt.xticks(x, categories)
    plt.legend(fontsize=8)

    # Show plot
    # plt.show()
    fig = matplotlib.pyplot.gcf()
    fig.set_size_inches(3, 2)
    plt.tight_layout()
    fig.savefig("evalout/msan.pdf", dpi=200)


def evaluate_msan_pass_efficiency():
    ret = measure_epass_insns("output/evaluation_msan_msan1.o", popt="msan")
    print(ret)
    ret = measure_epass_insns("output/evaluation_msan_msan2.o", popt="msan")
    print(ret)
    ret = measure_epass_insns("output/evaluation_msan_simpl1.o", popt="msan")
    print(ret)
    ret = measure_epass_insns("output/evaluation_msan_simpl2.o", popt="msan")
    print(ret)


def evaluate_optimization():
    evaluate_optimization1()
    evaluate_optimization2()
    evaluate_optimization3()


def evaluate_optimization1():
    numbers = []
    for obj in all_objects():
        (r1, r2) = measure_epass_insns(obj)
        if r1 == 0:
            continue  # Ignore buggy programs

        (_, newr2) = measure_epass_insns(obj, "enable_coalesce", "optimize_compaction")
        if newr2 != 0:
            r2 = newr2
        else:
            (_, newr2) = measure_epass_insns(obj, "", "optimize_compaction")
            if newr2 != 0:
                r2 = newr2
        if r2 > r1:
            numbers.append(0)
            continue
        # print(f"{obj} {r1} -> {r2}")
        numbers.append((r1 - r2) / r1)
    numbers = sorted(numbers, reverse=True)
    plt.bar(range(len(numbers)), numbers)

    plt.xlabel("Program Index")
    plt.ylabel("NI Reduced")

    plt.gca().yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))

    fig = matplotlib.pyplot.gcf()
    fig.set_size_inches(3, 2)
    plt.tight_layout()
    fig.savefig("evalout/opt1.pdf", dpi=200)
    plt.clf()
    for n in numbers:
        print(n)
    print("----------------")


def evaluate_optimization2():
    numbers = []
    for obj in all_objects():
        (r2, r1) = measure_epass_insns(obj, popt="optimize_ir(noopt)")
        if r2 == 0:
            continue  # Ignore buggy programs

        (_, newr2) = measure_epass_insns(obj, "enable_coalesce", "optimize_compaction")
        if newr2 != 0:
            r2 = newr2
        else:
            (_, newr2) = measure_epass_insns(obj, "", "optimize_compaction")
            if newr2 != 0:
                r2 = newr2
        if r2 > r1:
            numbers.append(0)
            continue
        # print(f"{obj} {r1} -> {r2}")
        numbers.append((r1 - r2) / r1)
    numbers = sorted(numbers, reverse=True)
    plt.bar(range(len(numbers)), numbers)

    plt.xlabel("Program Index")
    plt.ylabel("NI Reduced")

    plt.gca().yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))

    fig = matplotlib.pyplot.gcf()
    fig.set_size_inches(3, 2)
    plt.tight_layout()
    fig.savefig("evalout/opt2.pdf", dpi=200)
    plt.clf()
    for n in numbers:
        print(n)
    print("----------------")


def evaluate_optimization3():
    numbers = []
    for obj in all_objects():
        (r1, r2) = measure_epass_insns(obj, popt="insn_counter")
        if r1 == 0:
            continue  # Ignore buggy programs

        (_, newr1) = measure_epass_insns(obj, popt="insn_counter(accurate)")
        if newr1 != 0:
            r1 = newr1

        if r2 > r1:
            numbers.append(0)
            continue
        # print(f"{obj} {r1} -> {r2}")
        numbers.append((r1 - r2) / r1)
    numbers = sorted(numbers, reverse=True)
    plt.bar(range(len(numbers)), numbers)

    plt.xlabel("Program Index")
    plt.ylabel("NI Reduced")

    plt.gca().yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))

    fig = matplotlib.pyplot.gcf()
    fig.set_size_inches(3, 2)
    plt.tight_layout()
    fig.savefig("evalout/opt3.pdf", dpi=200)
    plt.clf()
    for n in numbers:
        print(n)
    print("----------------")


def test_comptime(prog):
    bname = Path(prog).stem

    if not os.path.exists(f"output/{bname}.ll"):
        return (0, 0, 0)

    llc = measure_cmd_time_avg(f"llc -march=bpf output/{bname}.ll -o /dev/null")

    process = subprocess.Popen(
        ["epass", "-m", "read", "-p", prog],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, _ = process.communicate()
    rec = re.compile(r"ePass finished in (.*?)ns\n")
    rec2 = re.compile(r"program size: (.*?)->")
    try:
        tott = rec.findall(out.decode())[0]
        size = rec2.findall(out.decode())[0]
        epass = int(tott)
        size = int(size)
    except:
        return (0, 0, 0)
    return (llc, epass/1000000, size)


def test_loadtime(prog):
    process = subprocess.Popen(
        ["epass", "-m", "read", "-p", prog],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, _ = process.communicate()
    rec = re.compile(r"ePass finished in (.*?)ns\n")
    try:
        tott = rec.findall(out.decode())[0]
        epass = int(tott)
    except:
        return (0, 0)

    bname = Path(prog).stem
    process = subprocess.Popen(
        [
            "sudo",
            "bpftool",
            "prog",
            "load",
            prog,
            f"/sys/fs/bpf/{bname}",
            "-d",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _, err = process.communicate()
    out = err.decode()
    rec = re.compile(r"verification time (.*?) usec")
    tot = 0
    try:
        res = rec.findall(out)[0]
        tot = int(res)
    except:
        return (0, 0)
    os.system(f"sudo rm -rf /sys/fs/bpf/{bname}")
    return (tot, epass / 1000)


def evaluate_loadtime():
    tots = []
    eps = []
    for obj in prog_tests:
        print(f"testing {obj}")
        (tot, epass) = test_loadtime(obj)
        if tot == 0:
            continue  # Rejected programs
        tots.append(tot)
        eps.append(epass)
    print(tots, eps)


def evaluate_compile_speed2():
    tots = []
    eps = []
    cnt = []
    for obj in compile_prog_tests:
        print(f"testing {obj}")
        (tot, epass, num) = test_comptime(obj)
        print(tot, epass, num)
        if tot == 0:
            continue  # Rejected programs
        print(obj, tot)
        tots.append(tot)
        eps.append(epass)
        cnt.append(num)
    print(tots, eps, cnt)


if __name__ == "__main__":
    import sys

    arg = sys.argv[1]
    if arg == "init":
        init()
    if arg == "speed":
        evaluate_compile_speed()
    if arg == "speed2":
        evaluate_compile_speed2()
    if arg == "counter":
        evaluate_counter_pass()
    if arg == "counter_eff":
        evaluate_counter_pass_efficiency()
    if arg == "msan":
        evaluate_msan_pass()
    if arg == "msan_eff":
        evaluate_msan_pass_efficiency()
    if arg == "opt":
        evaluate_optimization()
    if arg == "loadtime":
        evaluate_loadtime()
