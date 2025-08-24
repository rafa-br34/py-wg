from src.wireguard.stack.checksum import Checksum, checksum_compute

import unittest
import random

data_pairs = [
	(b"\x45\x00\x00\x34\x5F\x7C\x40\x00\x40\x06\x00\x00\xC0\xA8\xB2\x14\xC6\xFC\xCE\x19", 0xD374),
	(b"\x0A\x89\x82\x72\x01\x00\x00\x01\x00\x11\x00\x0A\xFF\x22\x00\x50\x00\x0A\x00\x00\x61\x0A", 0x1161)
]


class UnitComputeChecksum(unittest.TestCase):
	def test_equivalence_known_data(self):
		for (data, expected) in data_pairs:
			received = checksum_compute(data)

			self.assertEqual(received, expected, f"0x{received:04X} != 0x{expected:04X}, {data.hex()}")


class UnitRollingChecksum(unittest.TestCase):
	def test_equivalence_known_data(self):
		checksum = Checksum()

		for (data, expected) in data_pairs:
			size = len(data)

			checksum.reset()
			remaining = size
			while remaining > 0:
				step = random.randint(1, remaining)
				start = size - remaining

				checksum.update(data[start:start + step])

				remaining -= step

			received = checksum.finalize()
			self.assertEqual(expected, received, f"0x{received:04X} != 0x{expected:04X}, {data.hex()}")

	def test_equivalence_random_data(self):
		checksum = Checksum()

		for _ in range(512):
			size = random.randint(128, 512)
			data = random.randbytes(size)

			checksum.reset()
			remaining = size
			while remaining > 0:
				step = random.randint(1, remaining)
				start = size - remaining

				checksum.update(data[start:start + step])

				remaining -= step

			expected = checksum_compute(data)
			received = checksum.finalize()

			self.assertEqual(expected, received, f"0x{received:04X} != 0x{expected:04X}, {data.hex()}")


UNIT_CLASSES = [
	UnitComputeChecksum,
	UnitRollingChecksum,
]
