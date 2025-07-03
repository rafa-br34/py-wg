import struct

from typing import Optional

from .protocols import InternetProtocol
from .internet_checksum import Checksum
from .ipv4 import IPv4Packet

# yapf: disable
UDP_STRUCT_HDR_PSEUDO_V4 = "!IIxBH"
UDP_STRUCT_HDR_PARAMS    = "!HHH"
UDP_STRUCT_HDR_CHECKSUM  = "!H"
UDP_LENGTH_HDR_PARAMS    = struct.calcsize(UDP_STRUCT_HDR_PARAMS)
UDP_LENGTH_HDR_CHECKSUM  = struct.calcsize(UDP_STRUCT_HDR_CHECKSUM)
UDP_LENGTH_HDR           = UDP_LENGTH_HDR_PARAMS + UDP_LENGTH_HDR_CHECKSUM
# yapf: enable


class UDPPacket:
	def __init__(self, src_port: Optional[int] = None, dst_port: Optional[int] = None, payload: Optional[bytes] = None):
		self._checksum_state = Checksum()

		self.checksum_valid: Optional[bool] = None
		self.checksum: int = 0x0000

		self.src_port = src_port
		self.dst_port = dst_port
		self.payload = payload

	def __repr__(self) -> str:
		return f"UDPPacket(src_port = {self.src_port}, dst_port = {self.dst_port}, checksum = 0x{self.checksum:04X}, checksum_valid = {self.checksum_valid})"

	@property
	def protocol_number(self):
		return InternetProtocol.IP_UDP

	def encode_packet_ipv4(self, ipv4: IPv4Packet):
		payload = self.payload or b""

		length = len(payload) + UDP_LENGTH_HDR

		hdr_pseudo = struct.pack(UDP_STRUCT_HDR_PSEUDO_V4, ipv4.src_addr, ipv4.dst_addr, self.protocol_number, length)
		hdr_params = struct.pack(UDP_STRUCT_HDR_PARAMS, self.src_port, self.dst_port, length)

		checksum_state = self._checksum_state
		checksum_state.reset()
		checksum_state.update(hdr_pseudo)
		checksum_state.update(hdr_params)
		checksum_state.update(payload)

		checksum = checksum_state.finalize()

		self.checksum = checksum
		self.checksum_valid = True

		hdr_checksum = struct.pack(UDP_STRUCT_HDR_CHECKSUM, checksum)

		return hdr_params + hdr_checksum + payload

	def decode_packet_ipv4(self, packet: bytes, ipv4: IPv4Packet, verify_checksum = False):
		pointer = 0

		hdr_params = packet[pointer:pointer + UDP_LENGTH_HDR_PARAMS]
		pointer += UDP_LENGTH_HDR_PARAMS

		hdr_checksum = packet[pointer:pointer + UDP_LENGTH_HDR_CHECKSUM]
		pointer += UDP_LENGTH_HDR_CHECKSUM

		(src_port, dst_port, length) = struct.unpack(UDP_STRUCT_HDR_PARAMS, hdr_params)

		if length != len(packet):
			raise ValueError("Incorrect packet length")

		payload = packet[pointer:pointer + length - UDP_LENGTH_HDR]

		checksum_received = struct.unpack(UDP_STRUCT_HDR_CHECKSUM, hdr_checksum)[0]

		if verify_checksum and checksum_received != 0x0000:
			hdr_pseudo = struct.pack(
				UDP_STRUCT_HDR_PSEUDO_V4, ipv4.src_addr, ipv4.dst_addr, self.protocol_number, length
			)

			checksum_state = self._checksum_state
			checksum_state.reset()
			checksum_state.update(hdr_pseudo)
			checksum_state.update(hdr_params)
			checksum_state.update(payload)

			checksum_expected = checksum_state.finalize()

			self.checksum_valid = checksum_received == checksum_expected
		else:
			self.checksum_valid = None

		self.checksum = checksum_received

		self.src_port = src_port
		self.dst_port = dst_port
		self.payload = payload
