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

EXPERIMENT_TIMES = 1
CARD = "wlp0s20f3"


def init():
    print("init...")
    os.system("./gen_tests.sh")
    os.system("make all -j$(nproc)")


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


def measure_epass_time_avg(prog, sec, gopt="", popt=""):
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
                "-s",
                sec,
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


def load_prog_epass(prog, gopt="", popt=""):
    bname = Path(prog).stem
    # bpftool prog load {prog} /sys/fs/bpf/{bname} epass {gopt} {popt}
    ret = os.system(
        f"sudo bpftool prog load {prog} /sys/fs/bpf/{bname} epass {gopt} {popt}"
    )
    return ret


def attach_prog_epass():
    os.system(f"sudo bpftool net attach xdp name prog dev {CARD}")


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
    return tot / cnt


def dettach_prog_epass():
    os.system(f"sudo bpftool net detach xdp dev {CARD}")


def remove_prog_epass(prog):
    bname = Path(prog).stem
    os.system(f"sudo rm -f /sys/fs/bpf/{bname}")


def evaluate_compile_speed():
    llc_time_20 = measure_cmd_time_avg(
        "llc -march=bpf output/evaluation_compile_speed_speed_20.ll -o /dev/null"
    )
    (epass_tot_20o, epass_lift_20o, epass_run_20o, epass_compile_20o) = (
        measure_epass_time_avg(
            "output/evaluation_compile_speed_speed_20.o", "prog", "no_prog_check"
        )
    )
    epass_other_20o = epass_tot_20o - epass_lift_20o - epass_run_20o - epass_compile_20o
    (epass_tot_20, epass_lift_20, epass_run_20, epass_compile_20) = (
        measure_epass_time_avg("output/evaluation_compile_speed_speed_20.o", "prog")
    )
    epass_other_20 = epass_tot_20 - epass_lift_20 - epass_run_20 - epass_compile_20

    llc_time_50 = measure_cmd_time_avg(
        "llc -march=bpf output/evaluation_compile_speed_speed_50.ll -o /dev/null"
    )
    (epass_tot_50o, epass_lift_50o, epass_run_50o, epass_compile_50o) = (
        measure_epass_time_avg(
            "output/evaluation_compile_speed_speed_50.o", "prog", "no_prog_check"
        )
    )
    epass_other_50o = epass_tot_50o - epass_lift_50o - epass_run_50o - epass_compile_50o
    (epass_tot_50, epass_lift_50, epass_run_50, epass_compile_50) = (
        measure_epass_time_avg("output/evaluation_compile_speed_speed_50.o", "prog")
    )
    epass_other_50 = epass_tot_50 - epass_lift_50 - epass_run_50 - epass_compile_50

    llc_time_100 = measure_cmd_time_avg(
        "llc -march=bpf output/evaluation_compile_speed_speed_100.ll -o /dev/null"
    )
    (epass_tot_100o, epass_lift_100o, epass_run_100o, epass_compile_100o) = (
        measure_epass_time_avg(
            "output/evaluation_compile_speed_speed_100.o", "prog", "no_prog_check"
        )
    )
    epass_other_100o = (
        epass_tot_100o - epass_lift_100o - epass_run_100o - epass_compile_100o
    )
    (epass_tot_100, epass_lift_100, epass_run_100, epass_compile_100) = (
        measure_epass_time_avg("output/evaluation_compile_speed_speed_100.o", "prog")
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


def evaluate_counter_pass():
    pass


if __name__ == "__main__":
    import sys

    arg = sys.argv[1]
    os.system("sudo /sbin/sysctl -w kernel.bpf_stats_enabled=1")
    if arg == "init":
        init()
    if arg == "speed":
        evaluate_compile_speed()
    if arg == "counter":
        collect_info()
