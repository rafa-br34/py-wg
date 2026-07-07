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
from .tcp_timers import TCPTimers, time_ms

# 128-bit salt, this is probably way overkill for this implementation.
TCP_ISN_SALT_0 = random.randrange(0x0000000000000000, 0xFFFFFFFFFFFFFFFF)
TCP_ISN_SALT_1 = random.randrange(0x0000000000000000, 0xFFFFFFFFFFFFFFFF)

TCP_MSL = 60


# RFC 9293 @ 3.4.1
def initial_sequence_number(src_addr, src_port, dst_addr, dst_port):
	packed = struct.pack(
		"@IHQIHQ",
		src_addr,
		src_port,
		TCP_ISN_SALT_0,
		dst_addr,
		dst_port,
		TCP_ISN_SALT_1,
	)
	hashed = hashlib.md5(packed).digest()

	# 4µs~ per tick
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

		self._passive_open = False # Whether SYN-RECEIVED came from passive OPEN (MUST-11)

		self.recv_buffer = bytearray()
		self.recv_out_of_order = []
		self.recv_buff_max = 65535

		self._ack_needed = False
		self._ack_immediate = False

		self._timers = TCPTimers(self._on_timer)

		self._send_buffer = bytearray()
		self._nagle_enabled = True

		self._in_flight = []
		self._srtt = None
		self._rttvar = None
		self._rto = 1000
		self._cwnd = 0
		self._ssthresh = 65535
		self._dup_ack_count = 0
		self._last_ack = 0

		self.dst_retransmit = collections.deque()
		self.dst_staged_buffer = collections.deque()
		self.dst_staged_index = 0
		self.dst_addr = 0
		self.dst_port = 0
		self.dst_mss = 0

		self._send_shift = 0
		self._recv_shift = 0

		self.src_addr = 0
		self.src_port = 0
		self.src_mss = 0

	def _enqueue_outbound(self, packet: TCPPacket):
		packet.src_port = self.src_port
		packet.dst_port = self.dst_port

		self.dst_retransmit.append(packet)

	def _advance_state(self, state: TCPState):
		self.state = state

	# --- Error helpers ---

	@staticmethod
	def _fail_conn_closing():
		raise ValueError("Connection closing")

	@staticmethod
	def _fail_conn_does_not_exist():
		raise ValueError("Connection does not exist")

	@staticmethod
	def _fail_conn_already_exists():
		raise ValueError("Connection already exists")

	@staticmethod
	def _fail_conn_reset():
		raise ValueError("Connection reset")

	@staticmethod
	def _fail_conn_refused():
		raise ValueError("Connection refused")

	@staticmethod
	def _fail_conn_not_established():
		raise ValueError("Connection not established")

	# --- Timer delegates (RFC 9293 @ 3.10.8) ---

	def _schedule_timer(self, name: str, delay_ms: int):
		self._timers.schedule(name, delay_ms)

	def _cancel_timer(self, name: str):
		self._timers.cancel(name)

	def _timer_active(self, name: str) -> bool:
		return self._timers.active(name)

	def _fire_timer(self, name: str):
		self._timers.fire(name)

	def tick(self):
		self._timers.tick()

	def _on_timer(self, name: str):
		if name == "TIME_WAIT":
			self._advance_state(TCPState.STATE_CLOSED)

		elif name == "DELAYED_ACK":
			self._send_ack()

		elif name == "RTO":
			self._retransmit()

		elif name == "ZERO_WINDOW_PROBE":
			self._zero_window_probe()

	# --- Utilities for sequence numbers (RFC 9293 @ 3.4) ---

	@staticmethod
	def _seq_lt(a: int, b: int) -> bool:
		return ((a - b) & 0xFFFFFFFF) >= 0x80000000

	@staticmethod
	def _seq_leq(a: int, b: int) -> bool:
		return a == b or ((a - b) & 0xFFFFFFFF) >= 0x80000000

	@staticmethod
	def _seg_len(packet: TCPPacket) -> int:
		length = len(packet.payload or b"")

		if packet.flags & TCPFlags.FG_SYN:
			length += 1

		if packet.flags & TCPFlags.FG_FIN:
			length += 1

		return length

	# RFC 9293 @ 3.10.7.4
	# Table 6: Segment Acceptability Tests.
	def _segment_acceptable(self, seg_seq: int, seg_len: int) -> bool:
		if seg_len == 0 and self.recv_wnd == 0:
			return seg_seq == self.recv_nxt

		if seg_len == 0 and self.recv_wnd > 0:
			return self._seq_leq(self.recv_nxt, seg_seq) and self._seq_lt(seg_seq, self.recv_nxt + self.recv_wnd)

		if seg_len > 0 and self.recv_wnd == 0:
			return False

		if seg_len > 0 and self.recv_wnd > 0:
			seg_end = (seg_seq + seg_len - 1) & 0xFFFFFFFF
			start_ok = self._seq_leq(self.recv_nxt, seg_seq) and self._seq_lt(seg_seq, self.recv_nxt + self.recv_wnd)
			end_ok = self._seq_leq(self.recv_nxt, seg_end) and self._seq_lt(seg_end, self.recv_nxt + self.recv_wnd)

			return start_ok or end_ok

		return False

	# --- Segment-arrives handlers (RFC 9293 Section 3.10.7) ---

	# RFC 9293 @ 3.10.7.1
	def _state_closed(self, packet: TCPPacket):
		fg_rst = packet.flags & TCPFlags.FG_RST
		fg_ack = packet.flags & TCPFlags.FG_ACK

		if fg_rst:
			return

		if fg_ack:
			self._enqueue_outbound(TCPPacket(flags = TCPFlags.FG_RST, seq_num = packet.ack_num))
		else:
			seg_len = self._seg_len(packet)
			self._enqueue_outbound(
				TCPPacket(
					flags = TCPFlags.FG_RST | TCPFlags.FG_ACK,
					seq_num = 0,
					ack_num = (packet.seq_num + seg_len) & 0xFFFFFFFF,
				)
			)

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
		self.recv_wnd = self.recv_buff_max - len(self.recv_buffer)

		isn = initial_sequence_number(self.src_addr, self.src_port, self.dst_addr, self.dst_port)

		self.send_isn = isn
		self.send_nxt = isn + 1
		self.send_una = isn

		self._enqueue_outbound(
			TCPPacket(
				flags = TCPFlags.FG_ACK | TCPFlags.FG_SYN,
				seq_num = isn,
				ack_num = self.recv_nxt,
				window = self.recv_wnd,
			)
		)
		self._passive_open = True
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
				return
		else:
			# Simultaneous open: SYN arrives without ACK (MUST-10)
			opt_ws = packet.opt_get(TCPOptionKind.OPT_WINDOW)

			if opt_ws is not None:
				self._send_shift = opt_ws.window_scale

			self._passive_open = False
			self.recv_nxt = packet.seq_num + 1
			self.recv_isn = packet.seq_num
			self.recv_wnd = self.recv_buff_max - len(self.recv_buffer)

			self._enqueue_outbound(
				TCPPacket(
					flags = TCPFlags.FG_ACK | TCPFlags.FG_SYN,
					seq_num = self.send_isn,
					ack_num = self.recv_nxt,
					window = self.recv_wnd,
				)
			)

			self._advance_state(TCPState.STATE_SYN_RECEIVED)
			return

		if fg_rst:
			self._advance_state(TCPState.STATE_CLOSED)
			self._fail_conn_reset()

		if fg_syn:
			self.recv_nxt = packet.seq_num + 1
			self.recv_isn = packet.seq_num

			opt_mss = packet.opt_get(TCPOptionKind.OPT_MSS)
			if opt_mss is not None:
				self.dst_mss = opt_mss.mss

			opt_ws = packet.opt_get(TCPOptionKind.OPT_WINDOW)
			if opt_ws is not None:
				self._send_shift = opt_ws.window_scale

		if fg_ack and packet.ack_num > self.send_una:
			self.send_una = packet.ack_num

		if self.send_una > self.send_isn:
			assert packet.window is not None

			self.recv_wnd = self.recv_buff_max - len(self.recv_buffer)
			self.send_wnd = packet.window << self._send_shift
			self.send_wnd_seq = packet.seq_num
			self.send_wnd_ack = packet.ack_num
			self._cwnd = self._initial_window()
			self._enqueue_outbound(
				TCPPacket(
					flags = TCPFlags.FG_ACK,
					seq_num = self.send_nxt,
					ack_num = self.recv_nxt,
					window = self.recv_wnd,
				)
			)
			self._advance_state(TCPState.STATE_ESTABLISHED)
		else:
			self.recv_wnd = self.recv_buff_max - len(self.recv_buffer)
			self._enqueue_outbound(
				TCPPacket(
					flags = TCPFlags.FG_ACK | TCPFlags.FG_SYN,
					seq_num = self.send_isn,
					ack_num = self.recv_nxt,
					window = self.recv_wnd,
				)
			)
			self._advance_state(TCPState.STATE_SYN_RECEIVED)

			assert packet.window is not None

			self.send_wnd = packet.window << self._send_shift
			self.send_wnd_seq = packet.seq_num
			self.send_wnd_ack = packet.ack_num

	# --- Synchronized-state pipeline (RFC 9293 @ 3.10.7.4) ---

	def _send_ack(self):
		self._enqueue_outbound(
			TCPPacket(
				flags = TCPFlags.FG_ACK,
				seq_num = self.send_nxt,
				ack_num = self.recv_nxt,
				window = self.recv_wnd,
			)
		)

	def _send_fin(self):
		self._cancel_timer("DELAYED_ACK")
		self.send_nxt = (self.send_nxt + 1) & 0xFFFFFFFF

		self._enqueue_outbound(
			TCPPacket(
				flags = TCPFlags.FG_FIN | TCPFlags.FG_ACK,
				seq_num = (self.send_nxt - 1) & 0xFFFFFFFF,
				ack_num = self.recv_nxt,
				window = self.recv_wnd,
			)
		)

	def _process_otherwise(self, packet: TCPPacket):
		seg_seq = packet.seq_num
		seg_len = self._seg_len(packet)

		fg_rst = packet.flags & TCPFlags.FG_RST
		fg_syn = packet.flags & TCPFlags.FG_SYN
		fg_ack = packet.flags & TCPFlags.FG_ACK
		fg_urg = packet.flags & TCPFlags.FG_URG
		fg_fin = packet.flags & TCPFlags.FG_FIN

		# 1: check sequence number
		if not self._segment_acceptable(seg_seq, seg_len):
			if not fg_rst:
				self._send_ack()

			return

		# 2: check RST bit
		if fg_rst:
			if self._segment_acceptable(seg_seq, seg_len):
				if seg_seq == self.recv_nxt:
					self._handle_rst_synchronized()
				else:
					self._send_ack()
			return

		# 3: security check — skipped

		# 4: check SYN bit
		if fg_syn:
			self._handle_syn_synchronized()
			return

		# 5: check ACK field
		if not fg_ack:
			return

		self._process_ack(packet)

		# 6: check URG bit
		if fg_urg:
			if self.state in (TCPState.STATE_ESTABLISHED, TCPState.STATE_FIN_WAIT_1, TCPState.STATE_FIN_WAIT_2):
				assert packet.urg_ptr is not None

				self.recv_urg = max(self.recv_urg, packet.urg_ptr)

		# 7: process segment text
		if packet.payload:
			self._process_segment_text(packet)

		# 8: check FIN bit
		if fg_fin:
			self._handle_fin()

		if self._ack_needed:
			if self._ack_immediate:
				self._cancel_timer("DELAYED_ACK")
				self._send_ack()
			elif not self._timer_active("DELAYED_ACK"):
				self._schedule_timer("DELAYED_ACK", 200)

			self._ack_needed = False
			self._ack_immediate = False

	# --- Pipeline sub-steps ---

	def _handle_rst_synchronized(self):
		match self.state:
			case TCPState.STATE_SYN_RECEIVED:
				if self._passive_open:
					self._advance_state(TCPState.STATE_LISTEN)
				else:
					self._advance_state(TCPState.STATE_CLOSED)
					self._fail_conn_refused()

			case TCPState.STATE_ESTABLISHED | TCPState.STATE_FIN_WAIT_1 | TCPState.STATE_FIN_WAIT_2 | TCPState.STATE_CLOSE_WAIT:
				self._advance_state(TCPState.STATE_CLOSED)
				self._fail_conn_reset()

			case TCPState.STATE_CLOSING | TCPState.STATE_LAST_ACK | TCPState.STATE_TIME_WAIT:
				self._advance_state(TCPState.STATE_CLOSED)

	def _handle_syn_synchronized(self):
		match self.state:
			case TCPState.STATE_SYN_RECEIVED:
				if self._passive_open:
					self._advance_state(TCPState.STATE_LISTEN)

			case _:
				# RFC 5961: challenge ACK
				self._send_ack()

	def _process_ack(self, packet: TCPPacket):
		seg_ack = packet.ack_num

		if not self._seq_leq(self.send_una, seg_ack):
			return

		if self._seq_lt(self.send_nxt, seg_ack):
			self._send_ack()
			return

		acked_new = self._seq_lt(self.send_una, seg_ack)

		if acked_new:
			bytes_acked = (seg_ack - self.send_una) & 0xFFFFFFFF
			self._clean_in_flight(seg_ack)
			self._update_cwnd(bytes_acked)
			self.send_una = seg_ack
			self._dup_ack_count = 0
			self._last_ack = seg_ack
			self._flush_send_buffer()

			if self._in_flight:
				self._cancel_timer("RTO")
				self._schedule_timer("RTO", self._rto)
			else:
				self._cancel_timer("RTO")

		elif seg_ack == self._last_ack and self._in_flight:
			self._dup_ack_count += 1

			if self._dup_ack_count == 3:
				self._fast_retransmit()
		else:
			self._last_ack = seg_ack

		newer_segment = self._seq_lt(self.send_wnd_seq, packet.seq_num)
		same_segment_newer_ack = self.send_wnd_seq == packet.seq_num and self._seq_leq(self.send_wnd_ack, seg_ack)

		if newer_segment or same_segment_newer_ack:
			assert packet.window, "packet.window was None"

			self.send_wnd = packet.window << self._send_shift
			self.send_wnd_seq = packet.seq_num
			self.send_wnd_ack = seg_ack

		match self.state:
			case TCPState.STATE_SYN_RECEIVED:
				self.recv_wnd = self.recv_buff_max - len(self.recv_buffer)
				self._cwnd = self._initial_window()
				self._advance_state(TCPState.STATE_ESTABLISHED)

			case TCPState.STATE_FIN_WAIT_1:
				if self.send_una == self.send_nxt:
					self._advance_state(TCPState.STATE_FIN_WAIT_2)

			case TCPState.STATE_CLOSING:
				if self.send_una == self.send_nxt:
					self._advance_state(TCPState.STATE_TIME_WAIT)
					self._schedule_timer("TIME_WAIT", 2 * TCP_MSL * 1000)

			case TCPState.STATE_LAST_ACK:
				if self.send_una == self.send_nxt:
					self._advance_state(TCPState.STATE_CLOSED)

			case TCPState.STATE_TIME_WAIT:
				pass

	def _process_segment_text(self, packet: TCPPacket):
		if self.state not in (TCPState.STATE_ESTABLISHED, TCPState.STATE_FIN_WAIT_1, TCPState.STATE_FIN_WAIT_2):
			return

		data = packet.payload
		if not data:
			return

		seg_seq = packet.seq_num

		if seg_seq == self.recv_nxt:
			self.recv_buffer.extend(data)
			self.recv_nxt = (self.recv_nxt + len(data)) & 0xFFFFFFFF
			self._merge_out_of_order()

		elif self._seq_lt(self.recv_nxt, seg_seq):
			self.recv_out_of_order.append((seg_seq, data))
			self.recv_out_of_order.sort(key = lambda x: x[0])
			self._ack_immediate = True

		free = self.recv_buff_max - len(self.recv_buffer)

		if free >= min(self.recv_buff_max // 2, self.effective_send_mss):
			self.recv_wnd = free

		self._ack_needed = True

	def _merge_out_of_order(self):
		while self.recv_out_of_order:
			seq, data = self.recv_out_of_order[0]

			if seq == self.recv_nxt:
				self.recv_buffer.extend(data)
				self.recv_nxt = (self.recv_nxt + len(data)) & 0xFFFFFFFF
				self.recv_out_of_order.pop(0)

			elif self._seq_lt(seq, self.recv_nxt):
				overlap = (self.recv_nxt - seq) & 0xFFFFFFFF

				if overlap < len(data):
					self.recv_buffer.extend(data[overlap:])
					self.recv_nxt = (self.recv_nxt + len(data) - overlap) & 0xFFFFFFFF

				self.recv_out_of_order.pop(0)
			else:
				break

	def _handle_fin(self):
		self.recv_nxt = (self.recv_nxt + 1) & 0xFFFFFFFF
		self._ack_needed = True
		self._ack_immediate = True

		match self.state:
			case TCPState.STATE_SYN_RECEIVED | TCPState.STATE_ESTABLISHED:
				self._advance_state(TCPState.STATE_CLOSE_WAIT)

			case TCPState.STATE_FIN_WAIT_1:
				self._advance_state(TCPState.STATE_CLOSING)

			case TCPState.STATE_FIN_WAIT_2:
				self._advance_state(TCPState.STATE_TIME_WAIT)
				self._schedule_timer("TIME_WAIT", 2 * TCP_MSL * 1000)

			case TCPState.STATE_TIME_WAIT:
				# @todo Phase 4: restart 2MSL timer
				pass

	# --- Individual synchronized-state handlers ---

	def _state_syn_received(self, packet: TCPPacket):
		self._process_otherwise(packet)

	def _state_established(self, packet: TCPPacket):
		self._process_otherwise(packet)

	def _state_fin_wait_1(self, packet: TCPPacket):
		self._process_otherwise(packet)

	def _state_fin_wait_2(self, packet: TCPPacket):
		self._process_otherwise(packet)

	def _state_close_wait(self, packet: TCPPacket):
		self._process_otherwise(packet)

	def _state_closing(self, packet: TCPPacket):
		self._process_otherwise(packet)

	def _state_last_ack(self, packet: TCPPacket):
		self._process_otherwise(packet)

	def _state_time_wait(self, packet: TCPPacket):
		self._process_otherwise(packet)

	# --- User/TCP interface events (RFC 9293 Section 3.10) ---

	# RFC 9293 @ 3.10.7
	def _recv_packet(self, packet: TCPPacket):
		match self.state:
			case TCPState.STATE_CLOSED:
				self._state_closed(packet)

			case TCPState.STATE_LISTEN:
				self._state_listen(packet)

			case TCPState.STATE_SYN_SENT:
				self._state_syn_sent(packet)

			case TCPState.STATE_SYN_RECEIVED:
				self._state_syn_received(packet)

			case TCPState.STATE_ESTABLISHED:
				self._state_established(packet)

			case TCPState.STATE_FIN_WAIT_1:
				self._state_fin_wait_1(packet)

			case TCPState.STATE_FIN_WAIT_2:
				self._state_fin_wait_2(packet)

			case TCPState.STATE_CLOSE_WAIT:
				self._state_close_wait(packet)

			case TCPState.STATE_CLOSING:
				self._state_closing(packet)

			case TCPState.STATE_LAST_ACK:
				self._state_last_ack(packet)

			case TCPState.STATE_TIME_WAIT:
				self._state_time_wait(packet)

	# RFC 9293 @ 3.10.1
	def event_open(self, src_addr: int, src_port: int, dst_addr: Optional[int] = None, dst_port: Optional[int] = None):
		if self.state not in (TCPState.STATE_CLOSED, TCPState.STATE_LISTEN):
			self._fail_conn_already_exists()

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

		isn = initial_sequence_number(src_addr, src_port, dst_addr, dst_port)

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
	def event_send(self, data: bytes):
		if self.state == TCPState.STATE_CLOSED:
			self._fail_conn_does_not_exist()

		if self.state in TCP_STATE_CLOSING:
			self._fail_conn_closing()

		if self.state in (TCPState.STATE_SYN_SENT, TCPState.STATE_SYN_RECEIVED):
			self.dst_staged_buffer.append(data)
			return

		if self.state in (TCPState.STATE_ESTABLISHED, TCPState.STATE_CLOSE_WAIT):
			self._send_buffer.extend(data)
			self._flush_send_buffer()

	# --- Send path (RFC 9293 @ 3.7, 3.8.6.2.1) ---

	@property
	def effective_send_mss(self) -> int:
		return self.dst_mss or 536

	def _send_window_available(self) -> int:
		if self.send_wnd == 0:
			return 0

		return (self.send_una + self.send_wnd - self.send_nxt) & 0xFFFFFFFF

	def _nagle_ok(self, data_len: int) -> bool:
		if not self._nagle_enabled:
			return True

		if self.send_una == self.send_nxt:
			return True

		if data_len >= self.effective_send_mss:
			return True

		return False

	def _send_segment(self, data: bytes):
		self._cancel_timer("DELAYED_ACK")

		seq = self.send_nxt
		self.send_nxt = (self.send_nxt + len(data)) & 0xFFFFFFFF

		self._enqueue_outbound(
			TCPPacket(
				flags = TCPFlags.FG_ACK,
				seq_num = seq,
				ack_num = self.recv_nxt,
				window = self.recv_wnd,
				payload = data,
			)
		)

		send_time_ms = time_ms()
		self._in_flight.append((seq, len(data), data, send_time_ms, 0))

		if not self._timer_active("RTO"):
			self._schedule_timer("RTO", self._rto)

	def _flush_send_buffer(self):
		while self._send_buffer:
			window = self._send_window_available()
			cwnd_avail = self._cwnd - self._bytes_in_flight()
			available = min(window, cwnd_avail)
			if available <= 0:
				break

			chunk_size = min(available, self.effective_send_mss, len(self._send_buffer))

			if not self._nagle_ok(chunk_size):
				break

			chunk = self._send_buffer[:chunk_size]
			self._send_buffer = self._send_buffer[chunk_size:]

			self._send_segment(bytes(chunk))

		if self._send_buffer and self.send_wnd == 0 and not self._timer_active("ZERO_WINDOW_PROBE"):
			self._schedule_timer("ZERO_WINDOW_PROBE", self._rto)

	# --- Retransmission & congestion control (RFC 6298, RFC 5681) ---

	def _initial_window(self) -> int:
		mss = self.effective_send_mss
		return min(4 * mss, max(2 * mss, 4380))

	def _bytes_in_flight(self) -> int:
		return sum(length for _, length, _, _, _ in self._in_flight)

	def _update_rtt(self, rtt_sample: int):
		if self._srtt is None:
			self._srtt = rtt_sample
			self._rttvar = rtt_sample // 2
		else:
			assert self._rttvar is not None

			self._rttvar = (3 * self._rttvar + abs(self._srtt - rtt_sample)) // 4
			self._srtt = (7 * self._srtt + rtt_sample) // 8

		self._rto = max(200, self._srtt + max(100, 4 * self._rttvar))

	def _update_cwnd(self, bytes_acked: int):
		mss = self.effective_send_mss

		if self._cwnd < self._ssthresh:
			self._cwnd += min(bytes_acked, mss)
		else:
			self._cwnd += (mss * bytes_acked) // self._cwnd

	def _clean_in_flight(self, ack_num: int):
		while self._in_flight:
			seq, length, _, send_time, retrans_count = self._in_flight[0]
			seg_end = (seq + length) & 0xFFFFFFFF

			if not self._seq_leq(seg_end, ack_num):
				break

			self._in_flight.pop(0)

			if retrans_count == 0:
				rtt_sample = time_ms() - send_time
				self._update_rtt(rtt_sample)

	def _retransmit(self):
		if not self._in_flight:
			return

		seq, length, data, _, retrans_count = self._in_flight[0]

		self._rto = min(self._rto * 2, 120000)
		self._ssthresh = max(self._cwnd // 2, 2 * self.effective_send_mss)
		self._cwnd = self.effective_send_mss
		self._dup_ack_count = 0

		self._cancel_timer("DELAYED_ACK")
		self._enqueue_outbound(
			TCPPacket(
				flags = TCPFlags.FG_ACK,
				seq_num = seq,
				ack_num = self.recv_nxt,
				window = self.recv_wnd,
				payload = data,
			)
		)

		send_time_ms = time_ms()
		self._in_flight[0] = (seq, length, data, send_time_ms, retrans_count + 1)
		self._schedule_timer("RTO", self._rto)

	def _fast_retransmit(self):
		if not self._in_flight:
			return

		seq, length, data, _, retrans_count = self._in_flight[0]

		self._ssthresh = max(self._cwnd // 2, 2 * self.effective_send_mss)
		self._cwnd = self._ssthresh + 3 * self.effective_send_mss

		self._cancel_timer("DELAYED_ACK")
		self._enqueue_outbound(
			TCPPacket(
				flags = TCPFlags.FG_ACK,
				seq_num = seq,
				ack_num = self.recv_nxt,
				window = self.recv_wnd,
				payload = data,
			)
		)

		send_time_ms = time_ms()
		self._in_flight[0] = (seq, length, data, send_time_ms, retrans_count + 1)

	def _zero_window_probe(self):
		if not self._send_buffer:
			return

		self._send_segment(bytes(self._send_buffer[:1]))
		self._send_buffer = self._send_buffer[1:]

		self._rto = min(self._rto * 2, 120000)
		self._schedule_timer("ZERO_WINDOW_PROBE", self._rto)

	# RFC 9293 @ 3.10.3
	def event_receive(self, max_bytes: int) -> bytes:
		if self.state in (TCPState.STATE_CLOSED, TCPState.STATE_LISTEN, TCPState.STATE_SYN_SENT,
							TCPState.STATE_SYN_RECEIVED):
			self._fail_conn_not_established()

		if self.state in (TCPState.STATE_CLOSING, TCPState.STATE_LAST_ACK, TCPState.STATE_TIME_WAIT):
			if not self.recv_buffer:
				self._fail_conn_closing()

		data = bytes(self.recv_buffer[:max_bytes])
		self.recv_buffer = self.recv_buffer[len(data):]

		free = self.recv_buff_max - len(self.recv_buffer)
		if free >= min(self.recv_buff_max // 2, self.effective_send_mss):
			self.recv_wnd = free

		return data

	# RFC 9293 @ 3.10.4
	def event_close(self):
		match self.state:
			case TCPState.STATE_CLOSED:
				self._fail_conn_does_not_exist()

			case TCPState.STATE_LISTEN:
				self._advance_state(TCPState.STATE_CLOSED)

			case TCPState.STATE_SYN_SENT:
				self._advance_state(TCPState.STATE_CLOSED)

			case TCPState.STATE_SYN_RECEIVED:
				self._send_fin()
				self._advance_state(TCPState.STATE_FIN_WAIT_1)

			case TCPState.STATE_ESTABLISHED:
				self._send_fin()
				self._advance_state(TCPState.STATE_FIN_WAIT_1)

			case TCPState.STATE_FIN_WAIT_1 | TCPState.STATE_FIN_WAIT_2:
				pass

			case TCPState.STATE_CLOSE_WAIT:
				self._send_fin()
				self._advance_state(TCPState.STATE_LAST_ACK)

			case TCPState.STATE_CLOSING | TCPState.STATE_LAST_ACK | TCPState.STATE_TIME_WAIT:
				self._fail_conn_closing()

	# RFC 9293 @ 3.10.5
	def event_abort(self):
		match self.state:
			case TCPState.STATE_CLOSED:
				self._fail_conn_does_not_exist()

			case TCPState.STATE_LISTEN | TCPState.STATE_SYN_SENT:
				self._advance_state(TCPState.STATE_CLOSED)

			case TCPState.STATE_SYN_RECEIVED | TCPState.STATE_ESTABLISHED | TCPState.STATE_FIN_WAIT_1 | TCPState.STATE_FIN_WAIT_2 | TCPState.STATE_CLOSE_WAIT:
				self._enqueue_outbound(TCPPacket(
					flags = TCPFlags.FG_RST,
					seq_num = self.send_nxt,
				))
				self._advance_state(TCPState.STATE_CLOSED)

			case TCPState.STATE_CLOSING | TCPState.STATE_LAST_ACK | TCPState.STATE_TIME_WAIT:
				self._advance_state(TCPState.STATE_CLOSED)


class TCPListener:
	def __init__(self, src_addr: int, src_port: int):
		self.src_addr = src_addr
		self.src_port = src_port
		self._accept_queue = collections.deque()
		self._pending = {}

	def _recv_packet(self, packet: TCPPacket):
		if packet.dst_port != self.src_port:
			return None

		if not (packet.flags & TCPFlags.FG_SYN) or (packet.flags & TCPFlags.FG_ACK):
			key = (packet.src_port, packet.dst_port)
			conn = self._pending.get(key)

			if conn:
				conn._recv_packet(packet)

			return None

		assert packet.src_port

		conn = TCPConnection()
		conn._passive_open = True
		conn.src_addr = self.src_addr
		conn.src_port = self.src_port
		conn.dst_addr = 0
		conn.dst_port = packet.src_port
		conn.recv_nxt = packet.seq_num + 1
		conn.recv_isn = packet.seq_num
		conn.recv_wnd = conn.recv_buff_max

		opt_ws = packet.opt_get(TCPOptionKind.OPT_WINDOW)
		if opt_ws is not None:
			conn._send_shift = opt_ws.window_scale

		opt_mss = packet.opt_get(TCPOptionKind.OPT_MSS)
		if opt_mss is not None:
			conn.dst_mss = opt_mss.mss

		isn = initial_sequence_number(self.src_addr, self.src_port, 0, packet.src_port)
		conn.send_isn = isn
		conn.send_nxt = isn + 1
		conn.send_una = isn
		conn._cwnd = conn._initial_window()

		conn._enqueue_outbound(
			TCPPacket(
				flags = TCPFlags.FG_ACK | TCPFlags.FG_SYN,
				seq_num = isn,
				ack_num = conn.recv_nxt,
				window = conn.recv_wnd,
			)
		)
		conn._advance_state(TCPState.STATE_SYN_RECEIVED)

		key = (packet.src_port, packet.dst_port)
		self._pending[key] = conn

		return None

	def accept(self):
		for key, conn in tuple(self._pending.items()):
			if conn.state == TCPState.STATE_ESTABLISHED:
				del self._pending[key]
				self._accept_queue.append(conn)

		if self._accept_queue:
			return self._accept_queue.popleft()

		return None
