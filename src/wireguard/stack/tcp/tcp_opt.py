import struct

from typing import Optional, Dict
from types import SimpleNamespace
from enum import IntEnum


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
	size: Optional[int]

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


def tcp_opt_registry_decode(opt: TCPOption):
	codec = tcp_opt_registry_get(opt.kind)

	if codec:
		if codec.size is not None and codec.size != opt.size:
			raise ValueError(f"Size mismatch codec expects size of {codec.size} got {opt.size}")

		codec.decode(opt)


def tcp_opt_registry_encode(opt: TCPOption):
	codec = tcp_opt_registry_get(opt.kind)

	if codec:
		codec.encode(opt)


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


def tcp_opt_encode(options: list[TCPOption]) -> tuple[bytes, int]:
	total_size = 0

	for option in options:
		tcp_opt_registry_encode(option)

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

	return buffer.tobytes(), total_size


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

		tcp_opt_registry_decode(option)

		yield option

		pointer += size
