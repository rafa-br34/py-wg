"""
Query 1
Round trip time: 0.468
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58244
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; QUESTION SECTION:
;www.google.com.                IN      A
;; ANSWER SECTION:
www.google.com.         290     IN      A       142.250.70.228
Query 2
Round trip time: 0.469
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39359
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; QUESTION SECTION:
;www.google.com.                IN      A
;; ANSWER SECTION:
www.google.com.         290     IN      A       142.250.70.228
Query 3
Round trip time: 0.469
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55343
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; QUESTION SECTION:
;www.google.com.                IN      A
;; ANSWER SECTION:
www.google.com.         289     IN      A       142.250.70.228
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
from src.wireguard.stack.udp import UDPPacket

from load_environ import (
	client_addr_v4,
	client_key,
	server_addr,
	server_key,
)
from utils import addr_to_int

# pip install dnslib
from dnslib import DNSRecord

DNS_TIMEOUT = 5
DNS_SERVER = "1.1.1.1"
DNS_QUERY = "www.google.com"
DNS_PORT = 53

peer = Initiator(PrivateKey(base64.b64decode(client_key)), PublicKey(base64.b64decode(server_key)))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(False)

ipv4_recv = IPv4Packet()
udp_recv = UDPPacket()

ipv4_send = IPv4Packet()
udp_send = UDPPacket()

query_sent = time.monotonic()
query_next = True
query_curr = 0
query_port = 0
query_ident = 0

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

	if peer.state_connected and query_next:
		ident = random.randint(0x0000, 0xFFFF)
		port = random.randint(0x0400, 0xFFFE)

		query = DNSRecord.question(DNS_QUERY)
		query.header.id = ident

		udp_send.src_port = port
		udp_send.dst_port = DNS_PORT
		udp_send.payload = query.pack()

		ipv4_send.src_addr = addr_to_int(client_addr_v4)
		ipv4_send.dst_addr = addr_to_int(DNS_SERVER)
		ipv4_send.payload = udp_send

		# Notice how we are manually calling wg_pad here
		# This is specified in the WireGuard paper to make traffic analysis harder (5.4.6 Subsequent Messages: Transport Data Messages)
		# However it was made optional in case the end user desires to save bandwidth
		peer.encode_transport(wg_pad(ipv4_send.encode_packet()))

		query_sent = time.monotonic()
		query_next = False
		query_curr += 1
		query_port = port
		query_ident = ident

	if not packet:
		continue

	decoded = peer.decode_packet(packet)

	if decoded:
		ver = ip_packet_val(decoded)

		if ver != 4:
			print(f"Got packet with version {ver}")
			continue

		ipv4_recv.decode_packet(decoded)

		if ipv4_recv.protocol != Protocols.IP_UDP:
			print(f"Received packet of type {internet_protocol_to_str(ipv4_recv.protocol)}")
			continue

		if not ipv4_recv.payload:
			print("Invalid IP payload")
			continue

		udp_recv.decode_packet_ipv4(ipv4_recv.payload, ipv4_recv)

		if udp_recv.dst_port != query_port:
			print(f"Received UDP packet to unknown port ({udp_recv.payload})")
			continue

		try:
			record = DNSRecord.parse(udp_recv.payload)
		except Exception as error:
			print(f"Failed to parse record with {error}")
			continue

		if record.header.id != query_ident:
			print(f"Record identifier doesn't match {record.header.id} != {query_ident}")
			continue

		print("Query {}\nRound trip time: {:.3f}\n{}".format(
			query_curr,
			time.monotonic() - query_sent,
			record,
		))

		query_next = True

	if time.monotonic() - query_sent > DNS_TIMEOUT:
		print(f"Query {query_curr} timed out")
		query_next = True
