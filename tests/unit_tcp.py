from src.wireguard.stack.tcp import (
	tcp_encode_offset_control,
	tcp_decode_offset_control,
	tcp_opt_encode,
	tcp_opt_decode,
	TCPOptionKind,
	TCPOption,
	TCPPacket,
	TCPFlags,
)

import unittest
import random

from utilities import iter_vec2, compare_list


class UnitBitwiseCodecs(unittest.TestCase):
	def test_codec_offset_control(self):
		for offset, control in iter_vec2(0x000F, 0x0FFF):
			encoded = tcp_encode_offset_control(offset, control)
			dec_offset, dec_control = tcp_decode_offset_control(encoded)

			self.assertEqual(
				offset,
				dec_offset,
				f"Failed to encode/decode offset. Got {dec_offset} expected {offset}",
			)
			self.assertEqual(
				control,
				dec_control,
				f"Failed to encode/decode header length. Got {dec_control} expected {control}",
			)


class UnitOptionsCodecs(unittest.TestCase):
	def _check_state_change(self, options: list[TCPOption]):
		encoded_a = tcp_opt_encode(options)
		decoded_a = list(tcp_opt_decode(encoded_a))

		self.assertNotIn(None, decoded_a, "Got None in the first re-encoding")

		encoded_b = tcp_opt_encode(decoded_a) # type: ignore
		decoded_b = list(tcp_opt_decode(encoded_b))

		self.assertNotIn(None, decoded_b, "Got None in the second re-encoding")

		self.assertEqual(encoded_a, encoded_b, "Encoded results differ between the first and second re-encoding")

		self.assertTrue(
			compare_list(decoded_a, decoded_b),
			"Decoded results differ between the first and second re-encoding",
		)
		self.assertTrue(
			compare_list(options, decoded_b),
			"Decoded results differ between the original and second re-encoding",
		)

	@staticmethod
	def _random_edge_pairs(length: int) -> list[tuple[int, int]]:
		pairs = []

		for _ in range(length):
			pairs.append((random.randrange(0x00000000, 0xFFFFFFFF), random.randrange(0x00000000, 0xFFFFFFFF)))

		return pairs

	@staticmethod
	def _rand_opt_mss():
		return TCPOption(kind = TCPOptionKind.OPT_MSS, mss = random.randrange(0x0000, 0xFFFF))

	@staticmethod
	def _rand_opt_window_scale():
		return TCPOption(kind = TCPOptionKind.OPT_WINDOW, window_scale = random.randrange(0x00, 0xFF))

	@staticmethod
	def _rand_opt_sack():
		pairs = UnitOptionsCodecs._random_edge_pairs(random.randrange(0, (255 - 2) // 8))

		return TCPOption(kind = TCPOptionKind.OPT_SACK, edge_pairs = pairs)

	@staticmethod
	def _rand_modify_opts(options: list[TCPOption], generator):
		if random.random() > 0.40:
			options.append(generator())
		elif len(options):
			options.pop()

	def test_options_mss(self):
		options = []

		for _ in range(32):
			self._rand_modify_opts(options, self._rand_opt_mss)
			self._check_state_change(options)

	def test_options_window_scale(self):
		options = []

		for _ in range(32):
			self._rand_modify_opts(options, self._rand_opt_window_scale)
			self._check_state_change(options)

	def test_options_sack(self):
		options = []

		for _ in range(32):
			self._rand_modify_opts(options, self._rand_opt_sack)
			self._check_state_change(options)

	def test_options_fuzzing(self):
		candidates = [
			self._rand_opt_mss,
			self._rand_opt_window_scale,
			self._rand_opt_sack,
		]
		options = []

		for _ in range(256):
			self._rand_modify_opts(options, random.choice(candidates))
			self._check_state_change(options)


UNIT_CLASSES = [
	UnitBitwiseCodecs,
	UnitOptionsCodecs,
]
