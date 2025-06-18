import struct

from typing import Optional, Dict
from types import SimpleNamespace
from enum import IntEnum

from .internet_protocols import InternetProtocol
from .internet_checksum import Checksum
from .ipv4 import IPv4Packet

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


# https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1
# yapf: disable
class TCPOptionKind(IntEnum):
	_OPT_EOL         = 0 # End of options list (final padding)
	_OPT_NOP         = 1 # No operation (padding between operations)
	OPT_MSS          = 2 # Maximum segment size (defines the maximum segment size unidirectionally)
	OPT_WINDOW       = 3 # Window scaling
	OPT_SACK_CAPABLE = 4 # Capable of selective acknowledgement
	OPT_SACK         = 5 # Selective acknowledgement
	OPT_ECHO         = 6 # Echo (obsolete in favor of OPT_TIME)
	OPT_ECHO_REPLY   = 7 # Echo reply (obsolete in favor of OPT_TIME)
	OPT_TIMESTAMP    = 8 # Timestamps
	# @todo Implement the rest
# yapf: enable


class TCPOption(SimpleNamespace):
	"""
		Defines a single option value, extra parameters might be added by the decoder.
	"""
	kind: int
	data: bytes

	@property
	def size(self):
		if self.kind in (TCPOptionKind._OPT_EOL, TCPOptionKind._OPT_NOP):
			return 1
		else:
			return len(self.data) + 2

	def __init__(self, kind: int, data: bytes = b"", **kwargs):
		super().__init__(kind = kind, data = data, **kwargs)

	def _check_keys(self, keys: set[str]):
		val_keys = self.__dict__.keys()

		if keys.issubset(val_keys):
			return

		keys.difference_update(val_keys)

		raise ValueError(f"Missing option values {list(keys)}")

	def _check_size(self, size: int):
		if self.size != size:
			raise ValueError(f"Option requires a size of {size} got {self.size}")


class TCPOptionCodec:
	kind: int
	size: int | None

	@staticmethod
	def encode(opt: TCPOption):
		"""
			Encodes opt.data for future use, also indirectly updates opt.size.
		"""
		pass

	@staticmethod
	def decode(opt: TCPOption):
		"""
			Decodes opt.data into its respective keys.
		"""
		pass


TCP_OPTION_REGISTRY: Dict[int, type[TCPOptionCodec]] = {}


def tcp_opt_registry_set(codec: type[TCPOptionCodec]):
	TCP_OPTION_REGISTRY[codec.kind] = codec


def tcp_opt_registry_get(kind: int):
	if kind in TCP_OPTION_REGISTRY:
		return TCP_OPTION_REGISTRY[kind]
	else:
		return None


class TCPOptMSS(TCPOptionCodec):
	kind = TCPOptionKind.OPT_MSS
	size = 4

	@staticmethod
	def encode(opt: TCPOption):
		opt._check_keys({"mss"})
		opt.data = int.to_bytes(opt.mss & 0xFFFF, length = 2, byteorder = "big")

	@staticmethod
	def decode(opt: TCPOption):
		opt.mss = int.from_bytes(opt.data, byteorder = "big", signed = False)


class TCPOptWindow(TCPOptionCodec):
	kind = TCPOptionKind.OPT_WINDOW
	size = 3

	@staticmethod
	def encode(opt: TCPOption):
		opt._check_keys({"window_scale"})
		opt.data = bytes([opt.window_scale])

	@staticmethod
	def decode(opt: TCPOption):
		opt.window_scale = opt.data[0]


# Skip OPT_SACK_CAPABLE


class TCPOptSACK(TCPOptionCodec):
	kind = TCPOptionKind.OPT_SACK
	size = None

	@staticmethod
	def encode(opt: TCPOption):
		opt._check_keys({"edge_pairs"})
		pairs = opt.edge_pairs
		package = b""

		for (a, b) in pairs:
			package += struct.pack("!II", a, b)

		opt.data = package

	@staticmethod
	def decode(opt: TCPOption):
		pair_count = (opt.size - 2) // 8
		buffer = opt.data
		pairs = []

		for index in range(pair_count):
			pairs.append(struct.unpack_from("!II", buffer, index * 8))

		opt.edge_pairs = pairs


tcp_opt_registry_set(TCPOptMSS)
tcp_opt_registry_set(TCPOptWindow)
tcp_opt_registry_set(TCPOptSACK)


def tcp_opt_encode(options: list[TCPOption]):
	total_size = 0

	for option in options:
		kind = option.kind

		codec = tcp_opt_registry_get(kind)

		if codec:
			codec.encode(option)

		total_size += option.size
		total_size += (4 - total_size % 4) % 4

	pointer = 0
	buffer = memoryview(bytearray(total_size))

	for index, option in enumerate(options):
		kind = option.kind
		size = option.size
		data = option.data

		buffer[pointer] = kind
		buffer[pointer + 1] = size
		if data is not None:
			buffer[pointer + 2:pointer + size] = data

		pointer += size

		padding = (4 - pointer % 4) % 4

		if not padding:
			continue

		if index + 1 == len(options):
			pad_val = TCPOptionKind._OPT_EOL
		else:
			pad_val = TCPOptionKind._OPT_NOP

		buffer[pointer:pointer + padding] = bytes([pad_val]) * padding

	return buffer


def tcp_opt_decode(options: bytes | memoryview):
	pointer = 0
	length = len(options)

	while pointer < length:
		kind = options[pointer]

		if kind == TCPOptionKind._OPT_EOL:
			break

		if kind == TCPOptionKind._OPT_NOP:
			pointer += 1
			continue

		# No length field
		if pointer + 1 >= length:
			yield None
			break

		size = options[pointer + 1]

		# Option size is too small or larger than the buffer
		if size < 2 or size + pointer > len(options):
			yield None
			break

		data = options[pointer + 2:pointer + size]

		option = TCPOption(kind, data)

		codec = tcp_opt_registry_get(kind)

		if codec:
			codec.decode(option)

		yield option

		pointer += size


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
		seq_num: Optional[int] = 0,
		ack_num: Optional[int] = 0,
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

		return f"TCPPacket(src_port = {src_port}, dst_port = {dst_port}, flags = {flags}, seq_num = {seq_num}, ack_num = {ack_num}, window = {window}, urg_ptr = {urg_ptr})"

	@property
	def protocol_number(self):
		return InternetProtocol.IP_TCP

	def encode_packet_ipv4(self, ipv4: IPv4Packet):
		header_len = 5
		payload = self.payload or b""

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
		hdr_options = tcp_opt_encode(self.options)

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

			if len(self.options) > 1:
				print(self.options, hdr_options)
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


class TCPConnection:
	def __init__(self):
		self.src_mss: Optional[int] = None
		self.dst_mss: Optional[int] = None
