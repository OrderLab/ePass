import re
import glob
import os

o_files = glob.glob(os.path.join("output", "*.o"))

print("Number of object files: ", len(o_files))
