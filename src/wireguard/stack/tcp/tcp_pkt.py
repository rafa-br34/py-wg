import struct

from typing import Optional
from enum import IntEnum

from ..protocols import InternetProtocol
from ..internet_checksum import Checksum
from ..ipv4 import IPv4Packet
from .tcp_opt import TCPOptionKind, TCPOption, tcp_opt_decode, tcp_opt_encode

# yapf: disable
# RFC 9293 @ 3.1
TCP_STRUCT_HDR_PSEUDO_V4 = "!IIxBH"
TCP_STRUCT_HDR_PARAMS    = "!HHIIHH"
TCP_STRUCT_HDR_CHECKSUM  = "!H"
TCP_STRUCT_HDR_URG_PTR   = "!H"
TCP_LENGTH_HDR_PARAMS    = struct.calcsize(TCP_STRUCT_HDR_PARAMS)
TCP_LENGTH_HDR_CHECKSUM  = struct.calcsize(TCP_STRUCT_HDR_CHECKSUM)
TCP_LENGTH_HDR_URG_PTR   = struct.calcsize(TCP_STRUCT_HDR_URG_PTR)

# RFC 9293 @ 3.7.1
TCP_MAX_MSS_V4 = 576 - 40
TCP_MAX_MSS_V6 = 1280 - 60
# yapf: enable


# https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-header-flags
# yapf: disable
class TCPFlags(IntEnum):
	FG_FIN        = 1 << 0
	FG_SYN        = 1 << 1
	FG_RST        = 1 << 2
	FG_PSH        = 1 << 3
	FG_ACK        = 1 << 4
	FG_URG        = 1 << 5
	FG_ECE        = 1 << 6
	FG_CWR        = 1 << 7
	FG_AE         = 1 << 8
	FG_RESERVED_0 = 1 << 9
	FG_RESERVED_1 = 1 << 10
	FG_RESERVED_2 = 1 << 11
# yapf: enable


def tcp_flags_to_str(flags: Optional[TCPFlags | int] = None):
	if flags is None or flags == 0:
		return "None"
	else:
		return " | ".join(filter(None, [flags & flag and flag.name or None for flag in TCPFlags]))


def tcp_encode_offset_control(offset: int, control: int):
	return ((offset & 0x000F) << 12) | (control & 0x0FFF)


def tcp_decode_offset_control(value: int):
	return (value & 0xF000) >> 12, value & 0x0FFF


class TCPPacket:
	def __init__(
		self,
		src_port: Optional[int] = None,
		dst_port: Optional[int] = None,
		flags: int = 0,
		payload: Optional[bytes] = None,
		seq_num: int = 0,
		ack_num: int = 0,
		window: Optional[int] = 0,
		urg_ptr: Optional[int] = 0,
		options: Optional[list] = None
	):
		self._checksum_state = Checksum()

		self.checksum_valid: Optional[bool] = None
		self.checksum: int = 0x0000

		self.src_port = src_port
		self.dst_port = dst_port
		self.seq_num = seq_num
		self.ack_num = ack_num

		self.urg_ptr = urg_ptr
		self.window = window
		self.flags = flags

		self.payload = payload
		self.options = options or []

	def __repr__(self):
		src_port = self.src_port
		dst_port = self.dst_port
		seq_num = f"0x{self.seq_num:08X}"
		ack_num = f"0x{self.ack_num:08X}"

		window = self.window
		urg_ptr = self.urg_ptr

		flags = tcp_flags_to_str(self.flags)

		return f"TCPPacket(src = {src_port}, dst = {dst_port}, flags = {flags}, seq = {seq_num}, ack = {ack_num}, wnd = {window}, urg = {urg_ptr})"

	@property
	def protocol_number(self):
		return InternetProtocol.IP_TCP

	def get_option(self, kind: TCPOptionKind):
		for opt in self.options:
			if opt.kind == kind:
				return opt

	def encode_packet_ipv4(self, ipv4: IPv4Packet):
		payload = self.payload or b""

		hdr_options, hdr_options_size = tcp_opt_encode(self.options)

		header_len = 5 + hdr_options_size // 4

		hdr_pseudo = struct.pack(
			TCP_STRUCT_HDR_PSEUDO_V4,
			ipv4.src_addr,
			ipv4.dst_addr,
			self.protocol_number,
			header_len * 4 + len(payload),
		)
		hdr_params = struct.pack(
			TCP_STRUCT_HDR_PARAMS,
			self.src_port,
			self.dst_port,
			self.seq_num,
			self.ack_num,
			tcp_encode_offset_control(header_len, self.flags),
			self.window,
		)
		hdr_urg_ptr = struct.pack(TCP_STRUCT_HDR_URG_PTR, self.urg_ptr)

		checksum_state = self._checksum_state
		checksum_state.reset()
		checksum_state.update(hdr_pseudo)
		checksum_state.update(hdr_params)
		checksum_state.update(hdr_urg_ptr)
		checksum_state.update(hdr_options)

		checksum = checksum_state.finalize()

		hdr_checksum = struct.pack(TCP_STRUCT_HDR_CHECKSUM, checksum)

		self.checksum = checksum
		self.checksum_valid = True

		return hdr_params + hdr_checksum + hdr_urg_ptr + hdr_options + payload

	def encode_packet_ipv6(self):
		raise NotImplementedError("No support for encode_packet_ipv6")

	def decode_packet_ipv4(self, packet: bytes, ipv4: IPv4Packet, verify_checksum = False):
		pointer = 0

		hdr_params = packet[pointer:pointer + TCP_LENGTH_HDR_PARAMS]
		pointer += TCP_LENGTH_HDR_PARAMS

		hdr_checksum = packet[pointer:pointer + TCP_LENGTH_HDR_CHECKSUM]
		pointer += TCP_LENGTH_HDR_CHECKSUM

		hdr_urg_ptr = packet[pointer:pointer + TCP_LENGTH_HDR_URG_PTR]
		pointer += TCP_LENGTH_HDR_URG_PTR

		(
			src_port,
			dst_port,
			seq_num,
			ack_num,
			offset_control,
			window,
		) = struct.unpack(TCP_STRUCT_HDR_PARAMS, hdr_params)

		checksum_received = struct.unpack(TCP_STRUCT_HDR_CHECKSUM, hdr_checksum)[0]
		urg_ptr = struct.unpack(TCP_STRUCT_HDR_URG_PTR, hdr_urg_ptr)[0]

		hdr_length, flags = tcp_decode_offset_control(offset_control)

		remaining_hdr = hdr_length * 4 - pointer

		if remaining_hdr > 0:
			hdr_options = packet[pointer:pointer + remaining_hdr]

			self.options.clear()

			for option in tcp_opt_decode(hdr_options):
				if option is None:
					break

				self.options.append(option)
		else:
			hdr_options = None

		payload = packet[hdr_length * 4:]

		if verify_checksum:
			hdr_pseudo = struct.pack(
				TCP_STRUCT_HDR_PSEUDO_V4,
				ipv4.src_addr,
				ipv4.dst_addr,
				self.protocol_number,
				len(packet),
			)

			checksum_state = self._checksum_state
			checksum_state.reset()
			checksum_state.update(hdr_pseudo)
			checksum_state.update(hdr_params)
			checksum_state.update(hdr_urg_ptr)

			if hdr_options:
				checksum_state.update(hdr_options)

			checksum_state.update(payload)

			checksum_expected = checksum_state.finalize()

			self.checksum_valid = checksum_received == checksum_expected
		else:
			self.checksum_valid = None

		self.checksum = checksum_received

		self.src_port = src_port
		self.dst_port = dst_port
		self.seq_num = seq_num
		self.ack_num = ack_num

		self.urg_ptr = urg_ptr
		self.window = window
		self.flags = flags

		self.payload = payload

	def decode_packet_ipv6(self):
		raise NotImplementedError("No support for decode_packet_ipv6")
