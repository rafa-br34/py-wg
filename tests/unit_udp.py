import unittest
import random

from src.wireguard.stack.udp import UDPPacket
from src.wireguard.stack.ipv4 import IPv4Packet


class UnitPacketCodec(unittest.TestCase):
	def test_codec_packet(self):
		ipv4_pkt = IPv4Packet()

		send_pkt = UDPPacket()
		recv_pkt = UDPPacket()

		for _ in range(1024):
			ipv4_pkt.src_addr = random.randint(0x00000000, 0xFFFFFFFF)
			ipv4_pkt.dst_addr = random.randint(0x00000000, 0xFFFFFFFF)

			src_port = random.randint(0x0000, 0xFFFF)
			dst_port = random.randint(0x0000, 0xFFFF)
			payload = random.randbytes(random.randint(0, 1024))

			send_pkt.src_port = src_port
			send_pkt.dst_port = dst_port
			send_pkt.payload = payload

			recv_pkt.decode_packet_ipv4(send_pkt.encode_packet_ipv4(ipv4_pkt), ipv4_pkt, True)

			self.assertTrue(recv_pkt.checksum_valid, "Checksum validation failed")

			self.assertEqual(recv_pkt.src_port, src_port, "Invalid source port")
			self.assertEqual(recv_pkt.dst_port, dst_port, "Invalid destination port")
			self.assertEqual(recv_pkt.payload, payload, "Invalid payload")

			self.assertEqual(send_pkt.__repr__(), recv_pkt.__repr__(), "Representation results differ")


UNIT_CLASSES = [UnitPacketCodec]
