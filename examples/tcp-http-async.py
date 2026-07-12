"""
> PYTHONPATH=../ py tcp-round-trip-async.py

TCP over WireGuard using the AsyncInitiator + built-in TCP FSM (TCPConnection).
"""
import asyncio
import random
import time
import sys

sys.path.insert(0, "..")
from src.wireguard import AsyncInitiator, PrivateKey, PublicKey
from src.wireguard.constants import MessageTypes
from src.wireguard.functions import wg_pad
from src.wireguard.initiator import wg_ident_header
from src.wireguard.stack.ipv4 import IPv4Packet
from src.wireguard.stack.internet import Protocols, ip_packet_val
from src.wireguard.stack.tcp import TCPConnection, TCPState, TCPPacket, TCPFlags
from load_environ import client_addr_v4, client_key, server_addr, server_key
from utils import addr_to_int

TARGET_IP = "45.33.32.156" # scanme.nmap.org
TARGET_PORT = 80
HTTP_REQUEST = b"GET / HTTP/1.1\r\nHost: scanme.nmap.org\r\nConnection: close\r\n\r\n"

SRC_ADDR = addr_to_int(client_addr_v4)
DST_ADDR = addr_to_int(TARGET_IP)


def drain_and_send(initiator, conn):
	"""Pull queued TCP packets from the FSM, wrap in IPv4+WG, and send."""
	while conn.dst_retransmit:
		tcp_pkt = conn.dst_retransmit.popleft()
		ipv4 = IPv4Packet()
		ipv4.src_addr = SRC_ADDR
		ipv4.dst_addr = DST_ADDR
		ipv4.payload = tcp_pkt
		initiator.tx_packet(ipv4.encode_packet())


async def main():
	initiator = AsyncInitiator(client_key, server_key)

	await initiator.start(server_addr)
	print("[*] Handshake complete")

	if not await initiator.wait_handshake_completion():
		print("Handshake timed out")
		await initiator.stop()
		return

	# ── TCP: open connection ─────────────────────────────────────
	src_port = random.randint(0x4000, 0xFFFE)
	conn = TCPConnection()
	conn.event_open(SRC_ADDR, src_port, DST_ADDR, TARGET_PORT)
	drain_and_send(initiator, conn)
	print("[>] SYN src_port=%s" % src_port, flush = True)

	conn.on_state_change(lambda old, new: print(f"[*] TCP State: {old.name} -> {new.name}"))

	# ── Wait for TCP handshake ────────────────────────────────────
	t0 = time.monotonic()
	while time.monotonic() - t0 < 15 and conn.state != TCPState.STATE_ESTABLISHED:
		conn.tick()
		drain_and_send(initiator, conn)

		decoded = await initiator.rx_packet(timeout = 0.1)
		if not decoded or ip_packet_val(decoded) != 4:
			continue

		ipv4_rx = IPv4Packet()
		ipv4_rx.decode_packet(decoded)
		if ipv4_rx.protocol != Protocols.IP_TCP or not ipv4_rx.payload:
			continue

		tcp_rx = TCPPacket()
		tcp_rx.decode_packet_ipv4(ipv4_rx.payload, ipv4_rx)
		if tcp_rx.dst_port != src_port:
			continue
		conn._recv_packet(tcp_rx)
		drain_and_send(initiator, conn)

	if conn.state != TCPState.STATE_ESTABLISHED:
		print("TCP handshake failed (state=%s)" % conn.state, flush = True)
		await initiator.stop()
		return

	print("[<] SYN-ACK -> ESTABLISHED", flush = True)

	# ── Send HTTP request ────────────────────────────────────────
	conn.event_send(HTTP_REQUEST)
	drain_and_send(initiator, conn)
	print("[>] HTTP %d bytes" % len(HTTP_REQUEST), flush = True)

	# ── Receive response ─────────────────────────────────────────
	response = b""
	t0 = time.monotonic()
	while time.monotonic() - t0 < 15:
		conn.tick()
		drain_and_send(initiator, conn)

		decoded = await initiator.rx_packet(timeout = 0.1)
		if not decoded or ip_packet_val(decoded) != 4:
			continue

		ipv4_rx = IPv4Packet()
		ipv4_rx.decode_packet(decoded)
		if ipv4_rx.protocol != Protocols.IP_TCP or not ipv4_rx.payload:
			continue

		tcp_rx = TCPPacket()
		tcp_rx.decode_packet_ipv4(ipv4_rx.payload, ipv4_rx)
		if tcp_rx.dst_port != src_port:
			continue

		conn._recv_packet(tcp_rx)
		drain_and_send(initiator, conn)

		try:
			chunk = conn.event_receive(65536)
			if chunk:
				response += chunk
				print("[<] RX:", chunk[:20], f" (+{len(chunk)} bytes)")
		except ValueError:
			pass

		if conn.state in (TCPState.STATE_CLOSED, TCPState.STATE_TIME_WAIT, TCPState.STATE_CLOSE_WAIT):
			break

	print()
	print("=" * 60)
	print("[*] Response: %d bytes" % len(response))

	if response:
		print(response.decode(errors = "replace"))

	await initiator.stop()


if __name__ == "__main__":
	asyncio.run(main())
