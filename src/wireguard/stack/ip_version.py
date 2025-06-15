from .ipv4 import IPv4Packet


def ip_version(packet: bytes):
	return (packet[0] & 0xF0) >> 4

def ip_type(packet: bytes):
	match ip_version(packet):
		case 4:
			return IPv4Packet
		case _:
			return None