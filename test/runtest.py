import unittest
import os

def readprog(prog, sec, gopt = "", popt = ""):
    res = os.system(f"epasstool -m read -p {prog} -s {sec} --gopt \"{gopt}\" --popt \"{popt}\"")
    return res

class TestEPass(unittest.TestCase):

    def test_readprog(self):
        pass

if __name__ == '__main__':
    unittest.main()
