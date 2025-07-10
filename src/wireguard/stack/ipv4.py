import struct

from typing import Optional
from enum import IntEnum

from .protocols import InternetProtocol, internet_protocol_to_str
from .internet_checksum import Checksum


# https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml#dscp-registry-2
# For configuration guidelines and how to use these:
# https://en.wikipedia.org/wiki/Differentiated_services#Classification_and_marking
# RFC 4594
# yapf: disable
class IPv4ServiceType(IntEnum):
	ST_CS0         = 0x00 # Standard forwarding
	ST_LE          = 0x01 # Lower effort forwarding
	ST_CS1         = 0x08 # Low priority data
	ST_AF11        = 0x0A # High throughput, low drop probability
	ST_AF12        = 0x0C # High throughput, medium drop probability
	ST_AF13        = 0x0E # High throughput, high drop probability
	ST_CS2         = 0x10 # Network operations
	ST_AF21        = 0x12 # Low latency, low drop probability
	ST_AF22        = 0x14 # Low latency, medium drop probability
	ST_AF23        = 0x16 # Low latency, high drop probability
	ST_CS3         = 0x18 # Video broadcast
	ST_AF31        = 0x1A # Multimedia streaming, low drop probability
	ST_AF32        = 0x1C # Multimedia streaming, medium drop probability
	ST_AF33        = 0x1E # Multimedia streaming, high drop probability
	ST_CS4         = 0x20 # Real time interactive
	ST_AF41        = 0x22 # Multimedia conferencing, low drop probability
	ST_AF42        = 0x24 # Multimedia conferencing, medium drop probability
	ST_AF43        = 0x26 # Multimedia conferencing, high drop probability
	ST_CS5         = 0x28 # Signaling
	ST_EF          = 0x2E # Expedited forwarding
	ST_VOICE_ADMIT = 0x2C # Capacity-admitted traffic
	ST_CS6         = 0x30 # Routing protocols
	ST_CS7         = 0x38 # Reserved for future use
# yapf: enable


def ipv4_dscp_to_str(dscp: Optional[IPv4ServiceType | int] = None):
	if dscp is None:
		return "None"
	elif isinstance(dscp, IPv4ServiceType):
		return dscp.name

	# @note We don't use x in Enum because of back compatibility with python 3.10.x
	try:
		return IPv4ServiceType(dscp).name
	except ValueError:
		return "Unknown"


# https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml#ecn-field
# yapf: disable
class IPv4Congestion(IntEnum):
	ECN_INCAPABLE   = 0b00 # Incapable of ECN
	ECN_CAPABLE_EXP = 0b01 # Capable of ECN, experimental use only
	ECN_CAPABLE     = 0b10 # Capable of ECN
	ECN_CONGESTED   = 0b11 # Congestion experienced
# yapf: enable


# yapf: disable
class IPv4Flags(IntEnum):
	FG_RESERVED = 1 << 0 # Reserved flag
	FG_DF       = 1 << 1 # Don't fragment
	FG_MF       = 1 << 2 # More fragments
# yapf: enable


def ipv4_flags_to_str(flags: Optional[IPv4Flags | int] = None):
	if flags is None or flags == 0:
		return "None"
	else:
		return " | ".join(filter(None, [flags & flag and flag.name or None for flag in IPv4Flags]))


def ipv4_encode_ver_ihl(ver: int, ihl: int):
	return (ihl & 0x0F) | ((ver & 0x0F) << 4)


def ipv4_decode_ver_ihl(value: int):
	return (value & 0xF0) >> 4, (value & 0x0F)


def ipv4_encode_dscp_ecn(dscp: int, ecn: int):
	return (ecn & 0x03) | ((dscp & 0x3F) << 2)


def ipv4_decode_dscp_ecn(value: int):
	return (value & 0xFC) >> 2, (value & 0x03)


def ipv4_encode_flags_offset(flags: int, offset: int):
	return (offset & 0x1FFF) | ((flags & 0x07) << 13)


def ipv4_decode_flags_offset(value: int):
	return (value & 0xE000) >> 13, (value & 0x1FFF)


# yapf: disable
IPV4_STRUCT_HDR_PARAMS    = "!BBHHHBB"
IPV4_STRUCT_HDR_CHECKSUM  = "!H"
IPV4_STRUCT_HDR_ADDRESSES = "!II"

IPV4_LENGTH_HDR_PARAMS    = struct.calcsize(IPV4_STRUCT_HDR_PARAMS)
IPV4_LENGTH_HDR_CHECKSUM  = struct.calcsize(IPV4_STRUCT_HDR_CHECKSUM)
IPV4_LENGTH_HDR_ADDRESSES = struct.calcsize(IPV4_STRUCT_HDR_ADDRESSES)
IPV4_LENGTH_HDR           = IPV4_LENGTH_HDR_PARAMS + IPV4_LENGTH_HDR_CHECKSUM + IPV4_LENGTH_HDR_ADDRESSES
# yapf: enable


class IPv4Packet:
	def __init__(
		self,
		src_addr: Optional[int] = None,
		dst_addr: Optional[int] = None,
		protocol: Optional[InternetProtocol | int] = None,
		payload = None,
		dscp = IPv4ServiceType.ST_CS0,
		ecn = IPv4Congestion.ECN_INCAPABLE,
		ident = 0x0000,
		flags = 0b000,
		frag_offset = 0,
		ttl = 128
	):
		self._checksum_state = Checksum()

		self.checksum_valid: Optional[bool] = None
		self.checksum: int = 0x0000

		self.src_addr = src_addr
		self.dst_addr = dst_addr
		self.protocol = protocol
		self.payload = payload
		self.ident = ident
		self.frag_offset = frag_offset
		self.flags = flags
		self.dscp = dscp
		self.ecn = ecn
		self.ttl = ttl

	def __repr__(self) -> str:
		return "IPv4Packet(dscp = {}, ecn = {}, ident = {}, flags = {}, frag_offset = {}, ttl = {}, protocol = {}, checksum = 0x{:04X}, checksum_valid = {})".format(
			ipv4_dscp_to_str(self.dscp),
			IPv4Congestion(self.ecn).name,
			self.ident,
			ipv4_flags_to_str(self.flags),
			self.frag_offset,
			self.ttl,
			internet_protocol_to_str(self.protocol),
			self.checksum,
			self.checksum_valid is None and "Unknown" or self.checksum_valid,
		)

	def _encode_payload(self) -> tuple[bytes, int]:
		protocol = self.protocol
		payload = self.payload

		if isinstance(payload, bytes):
			if protocol is not None:
				return payload, protocol
			else:
				raise ValueError("Cannot use a bytes payload without a protocol value set")
		elif payload:
			return payload.encode_packet_ipv4(self), payload.protocol_number
		elif payload is None:
			raise ValueError("Cannot encode a IPv4 packet without a payload set")
		else:
			raise ValueError("Unknown payload type")

	def _decode_payload(self, payload, protocol):
		self.protocol = protocol
		self.payload = payload

	def encode_packet(self):
		# @todo Implement header options and make this dynamic
		header_len = IPV4_LENGTH_HDR // 4
		payload, protocol = self._encode_payload()

		hdr_params = struct.pack(
			IPV4_STRUCT_HDR_PARAMS,
			ipv4_encode_ver_ihl(4, header_len),
			ipv4_encode_dscp_ecn(self.dscp, self.ecn),
			header_len * 4 + len(payload),
			self.ident,
			ipv4_encode_flags_offset(self.flags, self.frag_offset),
			self.ttl,
			protocol,
		)
		hdr_addresses = struct.pack(IPV4_STRUCT_HDR_ADDRESSES, self.src_addr, self.dst_addr)
		# Create hdr_options here

		checksum_state = self._checksum_state
		checksum_state.reset()
		checksum_state.update(hdr_params)
		checksum_state.update(hdr_addresses)

		checksum = checksum_state.finalize()

		hdr_checksum = struct.pack(IPV4_STRUCT_HDR_CHECKSUM, checksum)

		self.checksum = checksum
		self.checksum_valid = True

		return hdr_params + hdr_checksum + hdr_addresses + payload

	def decode_packet(self, packet: bytes, verify_checksum = False):
		pointer = 0

		hdr_params = packet[pointer:pointer + IPV4_LENGTH_HDR_PARAMS]
		pointer += IPV4_LENGTH_HDR_PARAMS

		hdr_checksum = packet[pointer:pointer + IPV4_LENGTH_HDR_CHECKSUM]
		pointer += IPV4_LENGTH_HDR_CHECKSUM

		hdr_addresses = packet[pointer:pointer + IPV4_LENGTH_HDR_ADDRESSES]
		pointer += IPV4_LENGTH_HDR_ADDRESSES

		checksum_received = struct.unpack(IPV4_STRUCT_HDR_CHECKSUM, hdr_checksum)[0]

		if verify_checksum:
			checksum_state = self._checksum_state
			checksum_state.reset()
			checksum_state.update(hdr_params)
			checksum_state.update(hdr_addresses)

			checksum_expected = checksum_state.finalize()

			self.checksum_valid = checksum_received == checksum_expected
		else:
			self.checksum_valid = None

		self.checksum = checksum_received

		(
			ver_ihl,
			dscp_ecn,
			pkt_size,
			ident,
			flags_offset,
			ttl,
			protocol,
		) = struct.unpack(IPV4_STRUCT_HDR_PARAMS, hdr_params)

		(src_addr, dst_addr) = struct.unpack(IPV4_STRUCT_HDR_ADDRESSES, hdr_addresses)

		ver, ihl = ipv4_decode_ver_ihl(ver_ihl)
		dscp, ecn = ipv4_decode_dscp_ecn(dscp_ecn)
		flags, frag_offset = ipv4_decode_flags_offset(flags_offset)

		if ver != 4:
			raise ValueError(f"Expected version number of 4 got {ver}")

		remaining_hdr = ihl * 4 - pointer

		if remaining_hdr > 0:
			# We would parse the header options here
			raise NotImplementedError("Decoding of IPv4 header options is not supported")

		payload_len = pkt_size - ihl * 4

		# @note Pointer stops being updated here
		self._decode_payload(packet[pointer:pointer + payload_len], protocol)

		self.src_addr = src_addr
		self.dst_addr = dst_addr

		self.ident = ident
		self.frag_offset = frag_offset
		self.flags = flags
		self.dscp = dscp
		self.ecn = ecn
		self.ttl = ttl
