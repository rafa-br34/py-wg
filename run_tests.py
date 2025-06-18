import sys
import os

sys.path.insert(0, os.path.abspath("./tests"))

from tests.test_suite import run_tests

run_tests()
