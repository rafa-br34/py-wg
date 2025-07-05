import socket


def addr_to_int(addr):
	return int.from_bytes(socket.inet_aton(addr), byteorder = "big", signed = False)


def int_to_addr(addr, length = 4):
	return socket.inet_ntoa(int.to_bytes(addr, length, "big"))


def expand_ports(ports):
	port_list = set()

	for item in ports:
		if isinstance(item, (range, tuple, list, set)):
			port_list.update(item)
		elif isinstance(item, (int, float)):
			port_list.add(item)
		else:
			raise ValueError(f"Unknown item type {item.__class__.__name__}")

	return port_list
