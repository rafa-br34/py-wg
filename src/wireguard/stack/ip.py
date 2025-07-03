from .ipv4 import IPv4Packet


def ip_packet_val(packet: bytes):
	return (packet[0] & 0xF0) >> 4


def ip_packet_type(packet: bytes):
	match ip_packet_val(packet):
		case 4:
			return IPv4Packet
		case _:
			return None


def ip_addr_val(addr: int):
	match addr.bit_length():
		case 32:
			return 4

		case 128:
			return 6

		case _:
			raise ValueError("Unknown IP version for address")


def ip_addr_type(addr: int):
	bits = addr.bit_length()

	if bits == 32:
		return IPv4Packet
	elif bits == 128:
		return None
	else:
		raise ValueError("Unknown IP version or incorrect address size.")


def ip_check_addr_type(a: int, b: int):
	if ip_addr_val(a) != ip_addr_val(b):
		raise ValueError("Address length mismatch")


__all__ = [
	"ip_packet_val",
	"ip_packet_type",
	"ip_addr_val",
	"ip_addr_type",
	"ip_check_addr_type",
	"IPv4Packet",
]
