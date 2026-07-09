import random
import time

from src.wireguard.stack.internet import Protocols, internet_protocol_to_str, ip_packet_val
from src.wireguard.stack.ipv4 import IPv4Packet
from src.wireguard.stack.icmp import ICMPPacket, ICMPType
from src.wireguard import AsyncInitiator

from utils import addr_to_int

initiator = AsyncInitiator(
	initiator_pri = "...",
	responder_pub = "...",
	# preshared_key = "..."
	rx_queue_size = 1024,
	tx_queue_size = 1024,
)


@initiator.on_keepalive_rx
def _keepalive_rx():
	print("Received keepalive")


@initiator.on_keepalive_tx
def _keepalive_tx():
	print("Sent keepalive")


ICMP_MESSAGE_LEN = 32
ICMP_TIMEOUT = 5
ICMP_SERVER = "8.8.8.8"

ping_sent = time.monotonic()
ping_next = True
ping_curr = 0
ping_ident = 0

ipv4_recv = IPv4Packet()
icmp_recv = ICMPPacket()

ipv4_send = IPv4Packet()
icmp_send = ICMPPacket()

while True:
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

	while True:
		packet = initiator.rx_packet()

		# ...
