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
	def test_codec_ver_ihl(self):
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

	def test_options_mss(self):
		options = []

		for _ in range(32):
			if random.random() > 0.45:
				options.append(TCPOption(kind = TCPOptionKind.OPT_MSS, mss = random.randrange(0x0000, 0xFFFF)))
			elif len(options):
				options.pop()

			self._check_state_change(options)


UNIT_CLASSES = [
	UnitBitwiseCodecs,
	UnitOptionsCodecs,
]
