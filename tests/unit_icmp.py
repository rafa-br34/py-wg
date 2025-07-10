import unittest
import random

from src.wireguard.stack.icmp import ICMPPacket, ICMPType, ICMPValues
from src.wireguard.stack.ipv4 import IPv4Packet


class UnitPacketCodec(unittest.TestCase):
	def test_codec_packet(self):
		ipv4_pkt = IPv4Packet()

		send_pkt = ICMPPacket()
		recv_pkt = ICMPPacket()

		requires_ident_seq = (
			ICMPType.MSG_ECHO_REQ,
			ICMPType.MSG_ECHO_RES,
			ICMPType.MSG_TIMESTAMP_REQ,
			ICMPType.MSG_TIMESTAMP_RES,
			ICMPType.MSG_INFO_REQ,
			ICMPType.MSG_INFO_RES,
		)
		requires_payload = (
			ICMPType.MSG_ECHO_REQ,
			ICMPType.MSG_ECHO_RES,
			ICMPType.MSG_DST_UNREACHABLE,
			ICMPType.MSG_TIME_EXCEEDED,
			ICMPType.MSG_SRC_QUENCH,
			ICMPType.MSG_PARAM_PROBLEM,
			ICMPType.MSG_REDIRECT,
		)

		for _ in range(1024):
			msg_type = random.choice(list(ICMPType))
			msg_code = random.randint(0x00, 0xFF)

			values = ICMPValues()

			if msg_type in requires_ident_seq:
				values.identifier = random.randint(0x0000, 0xFFFF)
				values.sequence = random.randint(0x0000, 0xFFFF)

			if msg_type in requires_payload:
				values.payload = random.randbytes(random.randint(28, 1024))

			if msg_type in (ICMPType.MSG_TIMESTAMP_REQ, ICMPType.MSG_TIMESTAMP_RES):
				values.time_origin = random.randint(0x00000000, 0xFFFFFFFF)
				values.time_rx = random.randint(0x00000000, 0xFFFFFFFF)
				values.time_tx = random.randint(0x00000000, 0xFFFFFFFF)

			if msg_type == ICMPType.MSG_REDIRECT:
				values.address = random.randint(0x00000000, 0xFFFFFFFF)

			if msg_type == ICMPType.MSG_PARAM_PROBLEM:
				values.pointer = random.randint(0x00, 0xFF)

			send_pkt.msg_type = msg_type
			send_pkt.msg_code = msg_code
			send_pkt.values = values
			recv_pkt.values = ICMPValues()

			recv_pkt.decode_packet_ipv4(send_pkt.encode_packet_ipv4(ipv4_pkt), ipv4_pkt, True)

			self.assertTrue(recv_pkt.checksum_valid, "Checksum validation failed")

			self.assertEqual(recv_pkt.msg_type, msg_type, "Message type varies")
			self.assertEqual(recv_pkt.msg_code, msg_code, "Message code varies")

			self.assertEqual(send_pkt.values, recv_pkt.values, "Values differ")


UNIT_CLASSES = [UnitPacketCodec]
