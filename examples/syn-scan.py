import random
import socket
import base64
import time
import copy

from src.wireguard.wireguard import Initiator, PrivateKey, PublicKey
from src.wireguard.functions import wg_pad
from src.wireguard.stack.ip import ip_packet_val
from src.wireguard.stack.protocols import InternetProtocol, internet_protocol_to_str
from src.wireguard.stack.ipv4 import IPv4Packet
from src.wireguard.stack.tcp import TCPPacket, TCPFlags

from load_environ import (
	client_addr,
	client_key,
	server_addr,
	server_key,
)
from utils import addr_to_int, int_to_addr, expand_ports


class Target:
	def __init__(self, address, mask, ports):
		address = addr_to_int(address)

		if address.bit_length() > 32 or mask > 32:
			raise ValueError("Only IPv4 addresses are supported")

		net_range = 2 ** (32 - mask)
		net_mask = 0xFFFFFFFF >> (32 - mask)

		self.net_range = net_range
		self.net_mask = net_mask
		self.net_addr = address & net_mask
		self.net_ports = list(expand_ports(ports))

		self.curr_addr_idx = 0
		self.curr_port_idx = 0

	def next_available(self):
		return not (self.curr_addr_idx == self.net_range and self.curr_port_idx + 1 == len(self.net_ports))

	def next_address(self):
		if self.curr_addr_idx >= self.net_range:
			self.curr_addr_idx = 0
			self.curr_port_idx += 1

		addr = self.net_addr + self.curr_addr_idx

		if self.curr_port_idx >= len(self.net_ports):
			self.curr_port_idx = 0

		port = self.net_ports[self.curr_port_idx]

		self.curr_addr_idx += 1

		return addr, port


SCAN_TARGETS = [
	Target("45.33.32.156", 32, range(1, 65536)) # scanme.nmap.org
]
SCAN_RATE = 1024
SCAN_WAIT = 20

peer = Initiator(PrivateKey(base64.b64decode(client_key)), PublicKey(base64.b64decode(server_key)))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(False)

ipv4_recv = IPv4Packet()
tcp_recv = TCPPacket()

ipv4_send = IPv4Packet()
tcp_send = TCPPacket()

tcp_send.flags = TCPFlags.FG_SYN

ipv4_send.src_addr = addr_to_int(client_addr)
ipv4_send.payload = tcp_send

scan_src_addr = addr_to_int(client_addr)
scan_mapping_sent = {}
scan_mapping_recv = {}
scan_delay = 1 / SCAN_RATE
scan_target_list = copy.deepcopy(SCAN_TARGETS)
scan_target_idx = 0
scan_time_front = time.monotonic()
scan_time_back = scan_time_front
scan_last_syn = 0
scan_last_gc = 0
scan_done = False

while True:
	scan_time_front = time.monotonic()

	for packet in peer.update_state():
		sock.sendto(packet, server_addr)

	try:
		(packet, recv_address) = sock.recvfrom(0xFFFF)
	except IOError:
		time.sleep(0.001)
		recv_address = None
		packet = None

	if recv_address != server_addr:
		packet = None

	if peer.state_connected:
		while not scan_done and scan_time_front > scan_time_back:
			src_port = random.randint(0x0400, 0xFFFF)
			seq_num = random.randint(0x00000001, 0xFFFFFFFF)
			candidates = len(scan_target_list)

			if candidates == 0:
				scan_done = True
				print(f"Finished scanning, waiting {SCAN_WAIT} seconds")
				break

			target = scan_target_list[scan_target_idx % candidates]

			if not target.next_available():
				scan_target_list.remove(target)
				continue

			# Send SYN
			addr, port = target.next_address()

			ipv4_send.dst_addr = addr

			tcp_send.src_port = src_port
			tcp_send.dst_port = port
			tcp_send.seq_num = seq_num

			scan_mapping_sent[(src_port << 32) + seq_num] = scan_time_front

			peer.encode_transport(ipv4_send.encode_packet())

			# Update state
			scan_last_syn = scan_time_front
			scan_time_back += scan_delay
			scan_target_idx += 1

	if scan_time_front - scan_last_gc > SCAN_WAIT:
		scan_last_gc = scan_time_front
		marked = []

		for key, sent in scan_mapping_sent.items():
			if scan_time_front - sent > SCAN_WAIT:
				marked.append(key)

		for key in marked:
			del scan_mapping_sent[key]

		marked.clear()

		for key, sent in scan_mapping_recv.items():
			if scan_time_front - sent > SCAN_WAIT:
				marked.append(key)

		for key in marked:
			del scan_mapping_recv[key]

	if scan_done and scan_time_front - scan_last_syn > SCAN_WAIT:
		print("Done waiting")
		break

	if not packet:
		continue

	decoded = peer.decode_packet(packet)

	if decoded:
		ver = ip_packet_val(decoded)

		if ver != 4:
			print(f"Got packet with version {ver}")
			continue

		ipv4_recv.decode_packet(decoded)

		if ipv4_recv.protocol != InternetProtocol.IP_TCP:
			print(f"Received packet of type {internet_protocol_to_str(ipv4_recv.protocol)}")
			continue

		if not ipv4_recv.payload:
			print("Invalid IP payload")
			continue

		tcp_recv.decode_packet_ipv4(ipv4_recv.payload, ipv4_recv)

		assert tcp_recv.dst_port

		key = (tcp_recv.dst_port << 32) + (tcp_recv.ack_num - 1)

		# Ignore retransmissions
		if key in scan_mapping_recv:
			continue
		else:
			scan_mapping_recv[key] = scan_time_front

		if key in scan_mapping_sent:
			time_taken = "{:.3f}".format(scan_time_front - scan_mapping_sent[key])

			del scan_mapping_sent[key]
		else:
			time_taken = "None (Possible retransmission?)"

		state = "UNKNOWN"

		if tcp_recv.flags & TCPFlags.FG_ACK and tcp_recv.flags & TCPFlags.FG_SYN:
			state = "OPEN"
		elif tcp_recv.flags & TCPFlags.FG_RST:
			state = "CLOSED"

		# Optionally remove this check
		if state == "OPEN":
			print("[{}] {}:{} {}".format(state, int_to_addr(ipv4_recv.src_addr), tcp_recv.src_port, time_taken))
