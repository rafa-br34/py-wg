"""
> PYTHONPATH=../ py icmp-round-trip-async-api.py
Transmitting handshake request
Handshake complete! connection established
Ping 1
Round trip time: 0.355
ICMPPacket(msg_type = Echo response (0), msg_code = Default (0), values = ICMPValues(identifier=29917, sequence=1, payload=b'\x97y\x0b\x8c_%\x80k/\'\x1cnWK\x19W\x15\x10\xe6\x07\xa4\xe2B[\x8b5Ew"\x8d\xb7\x94'), checksum = 0xBF2E, checksum_valid = True)
Ping 2
Round trip time: 0.335
ICMPPacket(msg_type = Echo response (0), msg_code = Default (0), values = ICMPValues(identifier=33947, sequence=2, payload=b'\x12\x17\x85\x14\xa1\xe5h,\x82\xf3j\xe8j\xce>\x11\xd58\xefww\x90.\x02P\x8bT\\\xcd\x99v\xad'), checksum = 0xEFF6, checksum_valid = True)
Ping 3
Round trip time: 0.354
ICMPPacket(msg_type = Echo response (0), msg_code = Default (0), values = ICMPValues(identifier=12497, sequence=3, payload=b'p\xca\xc0\x9a\xeeD\x88f;\xbefX6\xd4\x9d\xd8\x1a\x14\xda\xb5\x13\xf9\xa0\xbb\x0fT\xbe#\nu\xb7\xda'), checksum = 0x7711, checksum_valid = True)
Ping 4
...
"""

import asyncio
import random
import time

from src.wireguard.stack.internet import Protocols, internet_protocol_to_str, ip_packet_val
from src.wireguard.stack.ipv4 import IPv4Packet
from src.wireguard.stack.icmp import ICMPPacket, ICMPType
from src.wireguard import AsyncInitiator

from load_environ import (
	client_addr_v4,
	client_key,
	server_addr,
	server_key,
)
from utils import addr_to_int

ICMP_MESSAGE_LEN = 32
ICMP_TIMEOUT = 5
ICMP_SERVER = "8.8.8.8"


async def main():
	initiator = AsyncInitiator(client_key, server_key)

	# Wire up event handlers
	initiator.on_keepalive_rx(lambda: print("Received keepalive"))
	initiator.on_keepalive_tx(lambda: print("Sent keepalive"))
	initiator.on_connection_lost(lambda: print("Connection lost; attempting reconnect"))

	initiator.on_handshake_tx_req(lambda: print("Transmitting handshake request"))

	ipv4_recv = IPv4Packet()
	icmp_recv = ICMPPacket()

	ipv4_send = IPv4Packet()
	icmp_send = ICMPPacket()

	await initiator.start(server_addr)

	if await initiator.wait_handshake_completion():
		print("Handshake complete! connection established")
	else:
		print("Handshake timed out")
		await initiator.stop()
		return

	ping_sent = time.monotonic()
	ping_next = True
	ping_curr = 0
	ping_ident = 0

	try:
		while True:
			if ping_next:
				ping_ident = random.randint(0x0000, 0xFFFF)
				ping_curr += 1

				ipv4_send.src_addr = addr_to_int(client_addr_v4)
				ipv4_send.dst_addr = addr_to_int(ICMP_SERVER)
				ipv4_send.payload = icmp_send

				icmp_send.msg_type = ICMPType.MSG_ECHO_REQ
				icmp_send.msg_code = 0
				icmp_send.values.identifier = ping_ident
				icmp_send.values.sequence = ping_curr
				icmp_send.values.payload = random.randbytes(ICMP_MESSAGE_LEN)

				initiator.tx_packet(ipv4_send.encode_packet())

				ping_sent = time.monotonic()
				ping_next = False

			decoded = await initiator.rx_packet(timeout = 0.1)

			if decoded is None:
				if not ping_next and time.monotonic() - ping_sent > ICMP_TIMEOUT:
					print(f"Ping {ping_curr} timed out")
					ping_next = True
				continue

			ver = ip_packet_val(decoded)

			if ver != 4:
				print(f"Got packet with version {ver}")
				continue

			ipv4_recv.decode_packet(decoded)

			if ipv4_recv.protocol != Protocols.IP_ICMPV4:
				print(f"Received packet of type {internet_protocol_to_str(ipv4_recv.protocol)}")
				continue

			if not ipv4_recv.payload:
				print("Invalid IP payload")
				continue

			icmp_recv.decode_packet_ipv4(ipv4_recv.payload, ipv4_recv, True)

			if icmp_recv.values.identifier != ping_ident:
				print(f"Received ping response for unknown identifier ({icmp_recv.values.identifier})")
				continue

			print("Ping {}\nRound trip time: {:.3f}\n{}".format(
				ping_curr,
				time.monotonic() - ping_sent,
				icmp_recv,
			))

			ping_next = True

	finally:
		await initiator.stop()


if __name__ == "__main__":
	asyncio.run(main())
