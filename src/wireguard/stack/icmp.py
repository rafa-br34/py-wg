import struct

from typing import Optional
from types import SimpleNamespace
from enum import IntEnum

from .internet_checksum import Checksum
from .protocols import InternetProtocol
from .ipv4 import IPv4Packet

# yapf: disable
ICMP_STRUCT_HDR_PARAMS   = "!BB"
ICMP_STRUCT_HDR_CHECKSUM = "!H"
ICMP_STRUCT_MSG_ECHO     = "!HH"
ICMP_STRUCT_MSG_TIME     = "!HHIII"
ICMP_STRUCT_MSG_PARAM    = "!B3x"
ICMP_STRUCT_MSG_REDIRECT = "!I"
ICMP_STRUCT_MSG_INFO     = "!HH"


ICMP_LENGTH_HDR_PARAMS    = struct.calcsize(ICMP_STRUCT_HDR_PARAMS)
ICMP_LENGTH_HDR_CHECKSUM  = struct.calcsize(ICMP_STRUCT_HDR_CHECKSUM)
ICMP_LENGTH_MSG_ECHO      = struct.calcsize(ICMP_STRUCT_MSG_ECHO)
ICMP_LENGTH_MSG_TIME      = struct.calcsize(ICMP_STRUCT_MSG_TIME)
ICMP_LENGTH_MSG_PARAM     = struct.calcsize(ICMP_STRUCT_MSG_PARAM)
ICMP_LENGTH_MSG_REDIRECT  = struct.calcsize(ICMP_STRUCT_MSG_REDIRECT)
ICMP_LENGTH_MSG_INFO      = struct.calcsize(ICMP_STRUCT_MSG_INFO)


class ICMPType(IntEnum):
	MSG_ECHO_RES        = 0
	MSG_DST_UNREACHABLE = 3
	MSG_SRC_QUENCH      = 4
	MSG_REDIRECT        = 5
	MSG_ECHO_REQ        = 8
	MSG_TIME_EXCEEDED   = 11
	MSG_PARAM_PROBLEM   = 12
	MSG_TIMESTAMP_REQ   = 13
	MSG_TIMESTAMP_RES   = 14
	MSG_INFO_REQ        = 15
	MSG_INFO_RES        = 16
# yapf: enable

ICMP_TYPE_MEANING = {
	ICMPType.MSG_ECHO_RES: "Echo response",
	ICMPType.MSG_DST_UNREACHABLE: "Could not reach",
	ICMPType.MSG_SRC_QUENCH: "Gateway failed to buffer packet",
	ICMPType.MSG_REDIRECT: "Redirect towards device",
	ICMPType.MSG_ECHO_REQ: "Echo request",
	ICMPType.MSG_TIME_EXCEEDED: "Time to live exceeded",
	ICMPType.MSG_PARAM_PROBLEM: "Parameter problem",
	ICMPType.MSG_TIMESTAMP_REQ: "Timestamp request",
	ICMPType.MSG_TIMESTAMP_RES: "Timestamp response",
	ICMPType.MSG_INFO_REQ: "Information request",
	ICMPType.MSG_INFO_RES: "Information response",
}
ICMP_CODE_MEANING = {
	ICMPType.MSG_ECHO_RES: [
		"Default",
	],
	ICMPType.MSG_DST_UNREACHABLE: [
		"Network unreachable",
		"Host unreachable",
		"Protocol unreachable",
		"Port unreachable",
		"Fragmentation required with DF set",
		"Source route failed",
	],
	ICMPType.MSG_SRC_QUENCH: [
		"Default",
	],
	ICMPType.MSG_REDIRECT: [
		"Redirect for the network",
		"Redirect for the host",
		"Redirect for the ToS and network",
		"Redirect for the ToS and host",
	],
	ICMPType.MSG_ECHO_REQ: [
		"Default",
	],
	ICMPType.MSG_TIME_EXCEEDED: [
		"Packet time exceeded in transit",
		"Fragment reassembly time exceeded",
	],
	ICMPType.MSG_PARAM_PROBLEM: [
		"Check pointer",
	],
	ICMPType.MSG_TIMESTAMP_REQ: [
		"Default",
	],
	ICMPType.MSG_TIMESTAMP_RES: [
		"Default",
	],
	ICMPType.MSG_INFO_REQ: [
		"Default",
	],
	ICMPType.MSG_INFO_RES: [
		"Default",
	],
}


class ICMPValues(SimpleNamespace):
	def _check_fields(self, *args):
		missing = []

		for (field_name, field_type) in args:
			if field_name not in self.__dict__:
				missing.append(field_name)
				continue

			if not field_type:
				continue

			value = self.__getattribute__(field_name)

			if not isinstance(value, field_type):
				raise ValueError(
					f"Expected field \"{field_name}\" to be of type {field_type} but got {value.__class__}"
				)

		if len(missing):
			raise ValueError(f"Missing fields {missing}")


class ICMPPacket:
	def __init__(self, msg_type: ICMPType = ICMPType(0), msg_code: int = 0):
		self._checksum_state = Checksum()

		self.checksum_valid: Optional[bool] = None
		self.checksum: int = 0x0000

		self.msg_type = msg_type
		self.msg_code = msg_code

		self.values = ICMPValues()

	def __repr__(self):
		return "ICMPPacket(msg_type = {} ({}), msg_code = {} ({}), values = {}, checksum = 0x{:04X}, checksum_valid = {})".format(
			self.get_type_meaning(),
			self.msg_type,
			self.get_code_meaning(),
			self.msg_code,
			self.values,
			self.checksum,
			self.checksum_valid is None and "Unknown" or self.checksum_valid,
		)

	@property
	def protocol_number(self):
		return InternetProtocol.IP_ICMPV4

	def get_type_meaning(self):
		msg_type = self.msg_type

		if msg_type not in ICMP_TYPE_MEANING:
			return "Unknown type"

		return ICMP_TYPE_MEANING[msg_type]

	def get_code_meaning(self):
		msg_type = self.msg_type
		msg_code = self.msg_code

		if msg_type not in ICMP_CODE_MEANING:
			return "Unknown type"

		lookup_table = ICMP_CODE_MEANING[self.msg_type]

		if msg_code >= len(lookup_table):
			return "Unknown code"

		return lookup_table[msg_code]

	def encode_packet_ipv4(self, _ipv4: IPv4Packet):
		msg_type = self.msg_type
		msg_code = self.msg_code
		values = self.values

		if msg_type not in ICMPType:
			raise ValueError("Invalid message type")

		hdr_params = struct.pack(ICMP_STRUCT_HDR_PARAMS, msg_type, msg_code)
		hdr_body = None

		if msg_type in (ICMPType.MSG_ECHO_REQ, ICMPType.MSG_ECHO_RES):
			values._check_fields(
				("identifier", int),
				("sequence", int),
				("payload", bytes),
			)

			hdr_body = struct.pack(ICMP_STRUCT_MSG_ECHO, values.identifier, values.sequence) + values.payload

		if msg_type in (ICMPType.MSG_TIMESTAMP_REQ, ICMPType.MSG_TIMESTAMP_RES):
			values._check_fields(
				("identifier", int),
				("sequence", int),
				("time_origin", int),
				("time_rx", int),
				("time_tx", int),
			)

			hdr_body = struct.pack(
				ICMP_STRUCT_MSG_TIME,
				values.identifier,
				values.sequence,
				values.time_origin,
				values.time_rx,
				values.time_tx,
			)

		if msg_type in (ICMPType.MSG_DST_UNREACHABLE, ICMPType.MSG_TIME_EXCEEDED, ICMPType.MSG_SRC_QUENCH):
			values._check_fields(("payload", bytes))

			hdr_body = b"\x00\x00\x00\x00" + values.payload

		if msg_type == ICMPType.MSG_PARAM_PROBLEM:
			values._check_fields(
				("pointer", int),
				("payload", bytes),
			)

			hdr_body = struct.pack(ICMP_STRUCT_MSG_PARAM, values.pointer) + values.payload

		if msg_type == ICMPType.MSG_REDIRECT:
			values._check_fields(
				("address", int),
				("payload", bytes),
			)

			hdr_body = struct.pack(ICMP_STRUCT_MSG_REDIRECT, values.address) + values.payload

		if msg_type in (ICMPType.MSG_INFO_REQ, ICMPType.MSG_INFO_RES):
			values._check_fields(
				("identifier", int),
				("sequence", int),
			)

			hdr_body = struct.pack(ICMP_STRUCT_MSG_INFO, values.identifier, values.sequence)

		assert hdr_body

		checksum_state = self._checksum_state
		checksum_state.reset()
		checksum_state.update(hdr_params)
		checksum_state.update(hdr_body)

		checksum = checksum_state.finalize()

		self.checksum_valid = True
		self.checksum = checksum

		hdr_checksum = struct.pack(ICMP_STRUCT_HDR_CHECKSUM, checksum)

		return hdr_params + hdr_checksum + hdr_body

	def decode_packet_ipv4(self, packet: bytes, _ipv4: IPv4Packet, verify_checksum = False):
		pointer = 0

		hdr_params = packet[pointer:pointer + ICMP_LENGTH_HDR_PARAMS]
		pointer += ICMP_LENGTH_HDR_PARAMS

		hdr_checksum = packet[pointer:pointer + ICMP_LENGTH_HDR_CHECKSUM]
		pointer += ICMP_LENGTH_HDR_CHECKSUM

		hdr_body = packet[pointer:]
		pointer = 0

		(msg_type, msg_code) = struct.unpack(ICMP_STRUCT_HDR_PARAMS, hdr_params)
		checksum_received = struct.unpack(ICMP_STRUCT_HDR_CHECKSUM, hdr_checksum)[0]

		if verify_checksum:
			checksum_state = self._checksum_state
			checksum_state.reset()
			checksum_state.update(hdr_params)
			checksum_state.update(hdr_body)

			checksum_expected = checksum_state.finalize()

			self.checksum_valid = checksum_received == checksum_expected
		else:
			self.checksum_valid = None

		self.checksum = checksum_received

		self.msg_type = msg_type
		self.msg_code = msg_code

		values = self.values

		if msg_type in (ICMPType.MSG_ECHO_RES, ICMPType.MSG_ECHO_REQ):
			(
				values.identifier,
				values.sequence,
			) = struct.unpack(ICMP_STRUCT_MSG_ECHO, hdr_body[pointer:pointer + ICMP_LENGTH_MSG_ECHO])

			pointer += ICMP_LENGTH_MSG_ECHO

			values.payload = hdr_body[pointer:]

		if msg_type in (ICMPType.MSG_TIMESTAMP_REQ, ICMPType.MSG_TIMESTAMP_RES):
			(
				values.identifier,
				values.sequence,
				values.time_origin,
				values.time_rx,
				values.time_tx,
			) = struct.unpack(ICMP_STRUCT_MSG_TIME, hdr_body[pointer:pointer + ICMP_LENGTH_MSG_TIME])

		if msg_type in (ICMPType.MSG_DST_UNREACHABLE, ICMPType.MSG_TIME_EXCEEDED, ICMPType.MSG_SRC_QUENCH):
			values.payload = hdr_body[pointer + 4:]

		if msg_type == ICMPType.MSG_PARAM_PROBLEM:
			values.pointer = struct.unpack(
				ICMP_STRUCT_MSG_PARAM,
				hdr_body[pointer:pointer + ICMP_LENGTH_MSG_PARAM],
			)[0]

			pointer += ICMP_LENGTH_MSG_PARAM

			values.payload = hdr_body[pointer:]

		if msg_type == ICMPType.MSG_REDIRECT:
			values.address = struct.unpack(
				ICMP_STRUCT_MSG_REDIRECT,
				hdr_body[pointer:pointer + ICMP_LENGTH_MSG_REDIRECT],
			)[0]

			pointer += ICMP_LENGTH_MSG_REDIRECT

			values.payload = hdr_body[pointer:]

		if msg_type in (ICMPType.MSG_INFO_REQ, ICMPType.MSG_INFO_RES):
			(
				values.identifier,
				values.sequence,
			) = struct.unpack(ICMP_STRUCT_MSG_INFO, hdr_body[pointer:pointer + ICMP_LENGTH_MSG_INFO])
