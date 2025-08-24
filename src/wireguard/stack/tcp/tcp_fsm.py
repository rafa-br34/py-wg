import collections
import hashlib
import random
import struct
import time

from typing import Optional
from enum import IntEnum

from ..ipv4 import IPv4Packet
from .tcp_pkt import TCPPacket, TCPFlags, TCP_MAX_MSS_V4, TCP_MAX_MSS_V6
from .tcp_opt import TCPOption, TCPOptionKind

# 128-bit salt, this is probably way overkill for this implementation.
TCP_ISN_SALT_0 = random.randrange(0x0000000000000000, 0xFFFFFFFFFFFFFFFF)
TCP_ISN_SALT_1 = random.randrange(0x0000000000000000, 0xFFFFFFFFFFFFFFFF)

TCP_MSL = 60


# RFC 9293 @ 3.4.1
# Here we remove the src_addr and dst_addr for simplicity sake
def initial_sequence_number(src_port, dst_port):
	packed = struct.pack(
		"@HQHQ",
		src_port,
		TCP_ISN_SALT_0,
		dst_port,
		TCP_ISN_SALT_1,
	)
	hashed = hashlib.blake2s(packed).digest()
	counter = int(time.monotonic() * 250000) & 0xFFFFFFFF

	return (counter + int.from_bytes(hashed[:4])) & 0xFFFFFFFF


# RFC 9293 @ 3.3.2
# yapf: disable
class TCPState(IntEnum):
	STATE_LISTEN       = 0
	STATE_SYN_SENT     = 1
	STATE_SYN_RECEIVED = 2
	STATE_ESTABLISHED  = 3
	STATE_FIN_WAIT_1   = 4
	STATE_FIN_WAIT_2   = 5
	STATE_CLOSE_WAIT   = 6
	STATE_CLOSING      = 7
	STATE_LAST_ACK     = 8
	STATE_TIME_WAIT    = 9
	STATE_CLOSED       = 10
# yapf: enable

TCP_STATE_CLOSING = (
	TCPState.STATE_FIN_WAIT_1,
	TCPState.STATE_FIN_WAIT_2,
	TCPState.STATE_CLOSING,
	TCPState.STATE_LAST_ACK,
	TCPState.STATE_TIME_WAIT,
)
TCP_STATE_ESTABLISHING = (
	TCPState.STATE_SYN_SENT,
	TCPState.STATE_SYN_RECEIVED,
)


class TCPConnection:
	"""
		Our "Transmission Control Block", responsible for managing the connection state.
		Represents the state of a 2-way connection between two peers.
	"""
	def __init__(self):
		self.reinitialize(TCPState.STATE_CLOSED)

	def reinitialize(self, initial_state: TCPState):
		self.state = initial_state

		# RFC 9293 @ 3.3.1
		self.send_una = 0 # SND.UNA
		self.send_nxt = 0 # SND.NXT
		self.send_wnd = 0 # SND.WND
		self.send_urg = 0 # SND.UP
		self.send_isn = 0 # ISS (Initial send sequence number)
		self.send_wnd_seq = 0 # SND.WL1
		self.send_wnd_ack = 0 # SND.WL2

		self.recv_nxt = 0 # RCV.NXT
		self.recv_wnd = 0 # RCV.WND
		self.recv_urg = 0 # RCV.UP
		self.recv_isn = 0 # IRS (Initial receive sequence number)

		self.dst_retransmit = collections.deque()
		self.dst_staged_buffer = collections.deque()
		self.dst_staged_index = 0
		self.dst_addr = 0
		self.dst_port = 0
		self.dst_mss = 0

		self.src_addr = 0
		self.src_port = 0
		self.src_mss = 0

	def _enqueue_outbound(self, packet: TCPPacket):
		packet.src_port = self.src_port
		packet.dst_port = self.dst_port

		self.dst_retransmit.append(packet)

	def _advance_state(self, state: TCPState):
		print(f"next state: {state.name}")
		self.state = state

	# RFC 9293 @ 3.10.7.1
	def _state_closed(self, packet: TCPPacket):
		fg_rst = packet.flags & TCPFlags.FG_RST
		fg_ack = packet.flags & TCPFlags.FG_ACK

		if fg_rst:
			return

		if fg_ack:
			self._enqueue_outbound(TCPPacket(flags = TCPFlags.FG_RST, seq_num = packet.ack_num))
		else:
			self._enqueue_outbound(TCPPacket(flags = TCPFlags.FG_RST | TCPFlags.FG_ACK, seq_num = 0))

	# RFC 9293 @ 3.10.7.2
	def _state_listen(self, packet: TCPPacket):
		fg_syn = packet.flags & TCPFlags.FG_SYN
		fg_rst = packet.flags & TCPFlags.FG_RST
		fg_ack = packet.flags & TCPFlags.FG_ACK

		if fg_rst:
			return

		if fg_ack:
			self._enqueue_outbound(TCPPacket(flags = TCPFlags.FG_RST, seq_num = packet.ack_num))
			return

		if not fg_syn:
			return

		self.recv_nxt = packet.seq_num + 1
		self.recv_isn = packet.seq_num

		isn = initial_sequence_number(self.src_port, self.dst_port)

		self.send_isn = isn
		self.send_nxt = isn + 1
		self.send_una = isn

		self._enqueue_outbound(
			TCPPacket(
				flags = TCPFlags.FG_ACK | TCPFlags.FG_SYN,
				seq_num = isn,
				ack_num = self.recv_nxt,
			)
		)
		self._advance_state(TCPState.STATE_SYN_RECEIVED)

	# RFC 9293 @ 3.10.7.3
	def _state_syn_sent(self, packet: TCPPacket):
		fg_syn = packet.flags & TCPFlags.FG_SYN
		fg_rst = packet.flags & TCPFlags.FG_RST
		fg_ack = packet.flags & TCPFlags.FG_ACK

		if fg_ack:
			if packet.ack_num <= self.send_isn or packet.ack_num > self.send_nxt:
				if fg_rst:
					return
				self._enqueue_outbound(TCPPacket(flags = TCPFlags.FG_RST, seq_num = packet.ack_num))

				return

			if not (self.send_una < packet.ack_num and packet.ack_num <= self.send_nxt):
				return False
		else:
			# @todo For this to be fully RFC compliant simultaneous open should be supported
			return

		if fg_rst:
			self._advance_state(TCPState.STATE_CLOSED)
			raise ValueError("Connection reset")

		if fg_syn:
			self.recv_nxt = packet.seq_num + 1
			self.recv_isn = packet.seq_num

		if fg_ack and packet.ack_num > self.send_una:
			self.send_una = packet.ack_num

		if self.send_una > self.send_isn:
			self._enqueue_outbound(
				TCPPacket(
					flags = TCPFlags.FG_ACK,
					seq_num = self.send_nxt,
					ack_num = self.recv_nxt,
				)
			)
			self._advance_state(TCPState.STATE_ESTABLISHED)
		else:
			self._enqueue_outbound(
				TCPPacket(
					flags = TCPFlags.FG_ACK | TCPFlags.FG_SYN,
					seq_num = self.send_isn,
					ack_num = self.recv_nxt,
				)
			)
			self._advance_state(TCPState.STATE_SYN_RECEIVED)

			self.send_wnd = packet.window
			self.send_wnd_seq = packet.seq_num
			self.send_wnd_ack = packet.ack_num

	# RFC 9293 @ 3.10.7
	def _recv_packet(self, packet: TCPPacket):
		match self.state:
			case TCPState.STATE_CLOSED:
				self._state_closed(packet)
				return

			case TCPState.STATE_LISTEN:
				self._state_listen(packet)
				return

			case TCPState.STATE_SYN_SENT:
				self._state_syn_sent(packet)
				return

	# RFC 9293 @ 3.10.1
	def event_open(self, src_addr: int, src_port: int, dst_addr: Optional[int] = None, dst_port: Optional[int] = None):
		if self.state not in (TCPState.STATE_CLOSED, TCPState.STATE_LISTEN):
			raise ValueError("Connection already exists")

		if not isinstance(src_addr, int):
			raise ValueError("Invalid type for src_addr")

		src_type = 4 #ip_addr_val(src_addr)
		self.src_addr = src_addr
		self.src_port = src_port

		if dst_addr is None and dst_port is None:
			self._advance_state(TCPState.STATE_LISTEN)
			return

		if dst_addr is None:
			raise ValueError("Got dst_port but not dst_addr")
		if dst_port is None:
			raise ValueError("Got dst_addr but not dst_port")

		if not isinstance(dst_addr, int):
			raise ValueError("Invalid type for dst_addr")

		dst_type = 4 #ip_addr_val(dst_addr)
		self.dst_addr = dst_addr
		self.dst_port = dst_port

		if src_type != dst_type:
			raise ValueError(f"Address type mismatch ({src_type} != {dst_type}).")

		if src_type == 4:
			conn_mss = TCP_MAX_MSS_V4
		elif src_type == 6:
			conn_mss = TCP_MAX_MSS_V6
		else:
			raise ValueError("Unknown src_type")

		isn = initial_sequence_number(src_port, dst_port)

		self.send_isn = isn
		self.send_una = isn
		self.send_nxt = isn + 1

		self.src_mss = conn_mss
		self.dst_mss = conn_mss

		packet = TCPPacket(flags = TCPFlags.FG_SYN, seq_num = isn)
		packet.opt_set(TCPOptionKind.OPT_MSS, mss = conn_mss)

		self._enqueue_outbound(packet)
		self._advance_state(TCPState.STATE_SYN_SENT)

	# RFC 9293 @ 3.10.2
	def event_send(self, data: bytes, dst_addr: Optional[int] = None, dst_port: Optional[int] = None):
		if self.state == TCPState.STATE_CLOSED:
			raise ValueError("Connection inexistent")

		if self.state in TCP_STATE_CLOSING:
			raise ValueError("Connection closing")

		# @todo Implement STATE_LISTEN

		if self.state in (TCPState.STATE_SYN_SENT, TCPState.STATE_SYN_RECEIVED):
			self.dst_staged_buffer.append(data)
			return

		if self.state in (TCPState.STATE_ESTABLISHED, TCPState.STATE_CLOSE_WAIT):
			self.dst_staged_buffer.append(data)
			return


class TCPListener:
	pass
