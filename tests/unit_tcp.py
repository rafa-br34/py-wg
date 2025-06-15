from src.wireguard.stack.tcp import (
	tcp_encode_offset_control, tcp_decode_offset_control,

	TCPPacket,
	TCPFlags
)

import unittest
import random

from utilities import iter_vec2

class UnitBitwiseCodecs(unittest.TestCase):
	def test_codec_ver_ihl(self):
		for offset, control in iter_vec2(0x000F, 0x0FFF):
			encoded = tcp_encode_offset_control(offset, control)
			dec_offset, dec_control = tcp_decode_offset_control(encoded)

			self.assertEqual(offset, dec_offset, f"Failed to encode/decode offset. Got {dec_offset} expected {offset}")
			self.assertEqual(control, dec_control, f"Failed to encode/decode header length. Got {dec_control} expected {control}")

UNIT_CLASSES = [
	UnitBitwiseCodecs
]