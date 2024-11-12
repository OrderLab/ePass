"""
Run the program w/ and w/o ePass

Evaluate the time it costs
"""

import os

def init():
    print("init...")
    os.system("sudo /sbin/sysctl -w kernel.bpf_stats_enabled=1")

