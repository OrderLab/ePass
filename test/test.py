#!/usr/bin/env python3

"""
ePass Compiler Testing Suite
"""

import glob, os


def all_objects():
    # Get all .o file paths in the output directory
    o_files = glob.glob(os.path.join("output", "*.o"))
    o_files.remove("output/evaluation_compile_speed_speed_100.o")
    o_files.remove("output/evaluation_compile_speed_speed_50.o")
    o_files.remove("output/evaluation_compile_speed_speed_20.o")
    return o_files

