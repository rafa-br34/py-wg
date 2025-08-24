"""
> PYTHONPATH=../ py scapy-icmp6.py
Ping 1
Round trip time: 0.468
ICMPv6 Echo Reply (id: 0xdbee seq: 0x1)
Ping 2
Round trip time: 0.453
ICMPv6 Echo Reply (id: 0xa319 seq: 0x2)
Ping 3
Round trip time: 0.453
ICMPv6 Echo Reply (id: 0x43be seq: 0x3)
Ping 4
Round trip time: 0.468
ICMPv6 Echo Reply (id: 0xc969 seq: 0x4)
Ping 5
...
"""

import random
import socket
import base64
import time

from src.wireguard.wireguard import Initiator, PrivateKey, PublicKey
from src.wireguard.functions import wg_pad
from src.wireguard.stack.internet import Protocols, internet_protocol_to_str, ip_packet_val
from src.wireguard.stack.ipv4 import IPv4Packet
from src.wireguard.stack.icmp import ICMPPacket, ICMPType

# pip install scapy
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply

from load_environ import (
	client_addr_v6,
	client_key,
	server_addr,
	server_key,
)
from utils import addr_to_int

ICMP_MESSAGE_LEN = 32
ICMP_TIMEOUT = 5
ICMP_SERVER = "2606:4700:4700::1111"

peer = Initiator(PrivateKey(base64.b64decode(client_key)), PublicKey(base64.b64decode(server_key)))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(False)

ping_sent = time.monotonic()
ping_next = True
ping_curr = 0
ping_ident = 0

while True:
	for packet in peer.update_state():
		sock.sendto(packet, server_addr)

	try:
		(packet, recv_address) = sock.recvfrom(0xFFFF)
	except IOError:
		time.sleep(0.01)
		recv_address = None
		packet = None

	if recv_address != server_addr:
		packet = None

	if peer.state_connected and ping_next:
		ping_ident = random.randint(0x0000, 0xFFFF)
		ping_curr += 1

		pkt_v6 = IPv6(
			src = client_addr_v6,
			dst = ICMP_SERVER,
		)
		pkt_icmp6 = ICMPv6EchoRequest(
			id = ping_ident,
			seq = ping_curr,
			data = random.randbytes(ICMP_MESSAGE_LEN),
		)

		pkt = pkt_v6 / pkt_icmp6
		peer.encode_transport(wg_pad(pkt.build()))

		ping_sent = time.monotonic()
		ping_next = False

	if not packet:
		continue

	decoded = peer.decode_packet(packet)

	if decoded:
		ver = ip_packet_val(decoded)

		if ver != 6:
			print(f"Got packet with version {ver}")
			continue

		try:
			pkt_v6 = IPv6(decoded)
		except Exception as error:
			print(f"Failed to decode IPv6 header with exception {error}")
			continue

		if pkt_v6.nh != 58 or not pkt_v6.haslayer(ICMPv6EchoReply):
			print(f"Received packet of type {pkt_v6.nh}")
			continue

		if bytes(pkt_v6.payload) == b"":
			print("Invalid IP payload")
			continue

		pkt_icmp6 = pkt_v6[ICMPv6EchoReply]
		if pkt_icmp6.id != ping_ident:
			print(f"Received ping response packet to unknown identifier ({getattr(pkt_icmp6, 'id', None)})")
			continue

		print("Ping {}\nRound trip time: {:.3f}\n{}".format(ping_curr, time.monotonic() - ping_sent, pkt_icmp6))

		ping_next = True

	if time.monotonic() - ping_sent > ICMP_TIMEOUT:
		print(f"Query {ping_curr} timed out")
		ping_next = True
