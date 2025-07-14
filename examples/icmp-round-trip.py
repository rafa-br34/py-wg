import random
import socket
import base64
import time

from src.wireguard.wireguard import Initiator, PrivateKey, PublicKey
from src.wireguard.functions import wg_pad
from src.wireguard.stack.ip import ip_packet_val
from src.wireguard.stack.protocols import InternetProtocol, internet_protocol_to_str
from src.wireguard.stack.ipv4 import IPv4Packet
from src.wireguard.stack.icmp import ICMPPacket, ICMPType

from load_environ import (
	client_addr,
	client_key,
	server_addr,
	server_key,
)
from utils import addr_to_int

ICMP_MESSAGE_LEN = 32
ICMP_TIMEOUT = 5
ICMP_SERVER = "8.8.8.8"

peer = Initiator(PrivateKey(base64.b64decode(client_key)), PublicKey(base64.b64decode(server_key)))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(False)

ipv4_recv = IPv4Packet()
icmp_recv = ICMPPacket()

ipv4_send = IPv4Packet()
icmp_send = ICMPPacket()

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

		ipv4_send.src_addr = addr_to_int(client_addr)
		ipv4_send.dst_addr = addr_to_int(ICMP_SERVER)
		ipv4_send.payload = icmp_send

		icmp_send.msg_type = ICMPType.MSG_ECHO_REQ
		icmp_send.msg_code = 0
		icmp_send.values.identifier = ping_ident
		icmp_send.values.sequence = ping_curr
		icmp_send.values.payload = random.randbytes(ICMP_MESSAGE_LEN)

		peer.encode_transport(wg_pad(ipv4_send.encode_packet()))

		ping_sent = time.monotonic()
		ping_next = False

	if not packet:
		continue

	decoded = peer.decode_packet(packet)

	if decoded:
		ver = ip_packet_val(decoded)

		if ver != 4:
			print(f"Got packet with version {ver}")
			continue

		ipv4_recv.decode_packet(decoded)

		if ipv4_recv.protocol != InternetProtocol.IP_ICMPV4:
			print(f"Received packet of type {internet_protocol_to_str(ipv4_recv.protocol)}")
			continue

		if not ipv4_recv.payload:
			print("Invalid IP payload")
			continue

		icmp_recv.decode_packet_ipv4(ipv4_recv.payload, ipv4_recv, True)

		if icmp_recv.values.identifier != ping_ident:
			print(f"Received ping response packet to unknown identifier ({icmp_recv.values.identifier})")
			continue

		print("Ping {}\nRound trip time: {:.3f}\n{}".format(ping_curr, time.monotonic() - ping_sent, icmp_recv))

		ping_next = True

	if time.monotonic() - ping_sent > ICMP_TIMEOUT:
		print(f"Query {ping_curr} timed out")
		ping_next = True
