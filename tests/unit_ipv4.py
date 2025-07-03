from wireguard.stack.protocols import InternetProtocol
from src.wireguard.stack.ipv4 import (
	ipv4_encode_ver_ihl,
	ipv4_decode_ver_ihl,
	ipv4_encode_dscp_ecn,
	ipv4_decode_dscp_ecn,
	ipv4_encode_flags_offset,
	ipv4_decode_flags_offset,
	IPv4ServiceType,
	IPv4Congestion,
	IPv4Flags,
	IPv4Packet,
)

import unittest
import random

from utilities import iter_vec2


class UnitBitwiseCodecs(unittest.TestCase):
	def test_codec_ver_ihl(self):
		for ver, ihl in iter_vec2(0x0F, 0x0F):
			encoded = ipv4_encode_ver_ihl(ver, ihl)
			dec_ver, dec_ihl = ipv4_decode_ver_ihl(encoded)

			self.assertEqual(ver, dec_ver, f"Failed to encode/decode header version. Got {dec_ver} expected {ver}")
			self.assertEqual(ihl, dec_ihl, f"Failed to encode/decode header length. Got {dec_ihl} expected {ihl}")

	def test_codec_dscp_ecn(self):
		for dscp, ecn in iter_vec2(0x3F, 0x03):
			encoded = ipv4_encode_dscp_ecn(dscp, ecn)
			dec_dscp, dec_ecn = ipv4_decode_dscp_ecn(encoded)

			self.assertEqual(dscp, dec_dscp, f"Failed to encode/decode DSCP. Got {dec_dscp} expected {dscp}")
			self.assertEqual(ecn, dec_ecn, f"Failed to encode/decode ECN. Got {dec_ecn} expected {ecn}")

	def test_codec_flags_offset(self):
		for flags, offset in iter_vec2(0x07, 0x1FFF):
			encoded = ipv4_encode_flags_offset(flags, offset)
			dec_flags, dec_offset = ipv4_decode_flags_offset(encoded)

			self.assertEqual(
				flags, dec_flags, f"Failed to encode/decode header flags. Got {dec_flags} expected {flags}"
			)
			self.assertEqual(
				offset, dec_offset, f"Failed to encode/decode fragment offset. Got {dec_offset} expected {offset}"
			)


class UnitPacketCodec(unittest.TestCase):
	def test_codec_packet(self):
		send_pkt = IPv4Packet()
		recv_pkt = IPv4Packet()

		for _ in range(1024):
			src_addr = random.randint(0x00000000, 0xFFFFFFFF)
			dst_addr = random.randint(0x00000000, 0xFFFFFFFF)
			protocol = random.choice([val for val in InternetProtocol])
			payload = random.randbytes(random.randint(0, 1024))
			ident = random.randint(0x0000, 0xFFFF)
			dscp = random.choice([val for val in IPv4ServiceType])
			ecn = random.randint(0, 3)
			flags = random.randint(0, 7)
			frag_offset = random.randint(0x0000, 0x1FFF)
			ttl = random.randint(0x00, 0xFF)

			send_pkt.src_addr = src_addr
			send_pkt.dst_addr = dst_addr
			send_pkt.protocol = protocol
			send_pkt.payload = payload
			send_pkt.dscp = dscp
			send_pkt.ecn = ecn
			send_pkt.ident = ident
			send_pkt.flags = flags
			send_pkt.frag_offset = frag_offset
			send_pkt.ttl = ttl

			recv_pkt.decode_packet(send_pkt.encode_packet(), True)

			self.assertTrue(recv_pkt.checksum_valid, "Checksum validation failed")

			self.assertEqual(recv_pkt.src_addr, src_addr, "Invalid source address")
			self.assertEqual(recv_pkt.dst_addr, dst_addr, "Invalid destination address")
			self.assertEqual(recv_pkt.protocol, protocol, "Invalid protocol")
			self.assertEqual(recv_pkt.payload, payload, "Invalid payload")
			self.assertEqual(recv_pkt.dscp, dscp, "Invalid DSCP")
			self.assertEqual(recv_pkt.ecn, ecn, "Invalid ECN")
			self.assertEqual(recv_pkt.ident, ident, "Invalid identifier")
			self.assertEqual(recv_pkt.flags, flags, "Invalid flags")
			self.assertEqual(recv_pkt.frag_offset, frag_offset, "Invalid fragment offset")
			self.assertEqual(recv_pkt.ttl, ttl, "Invalid TTL")

			self.assertEqual(send_pkt.__repr__(), recv_pkt.__repr__(), "Representation results differ")


UNIT_CLASSES = [
	UnitBitwiseCodecs,
	UnitPacketCodec,
]
