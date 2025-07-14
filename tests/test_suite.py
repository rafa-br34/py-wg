import importlib
import unittest
import platform
import sys

LINE_SEPARATOR = unittest.TextTestResult.separator2
TEST_UNITS = [
	"unit_internet_checksum",
	"unit_ipv4",
	"unit_tcp",
	"unit_udp",
	"unit_icmp",
	"unit_wireguard",
]


def print_env_info():
	print(f"Python: {sys.version}")
	print(f"Platform: {platform.platform()}")
	print(f"Executable: {sys.executable}")
	print(f"Architecture: {platform.architecture()}")
	print(f"Implementation: {platform.python_implementation()}")
	print(LINE_SEPARATOR)


def load_modules(loader: unittest.TestLoader, suite: unittest.TestSuite):
	pad = "   "

	for test_unit in TEST_UNITS:
		print(f"{pad*0}{test_unit}")
		module = importlib.import_module(test_unit, __package__)

		for test_case in module.UNIT_CLASSES:
			suite.addTests(loader.loadTestsFromTestCase(test_case))
			print(f"{pad*1}{test_case.__name__}")

			for test_name in loader.getTestCaseNames(test_case):
				print(f"{pad*2}{test_name}")

	print(LINE_SEPARATOR)


def run_tests():
	print_env_info()

	loader = unittest.TestLoader()
	suite = unittest.TestSuite()

	load_modules(loader, suite)

	runner = unittest.TextTestRunner()
	runner.run(suite)


if __name__ == "__main__":
	run_tests()
else:
	global_scope = globals()

	for test_unit in TEST_UNITS:
		module = importlib.import_module(test_unit, __package__)
		for test_case in module.UNIT_CLASSES:
			global_scope[f"{test_unit}_{test_case.__name__}"] = test_case

	# Clear test_* variables
	test_unit = None
	test_case = None
