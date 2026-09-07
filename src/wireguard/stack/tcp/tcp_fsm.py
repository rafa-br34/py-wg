import collections
import hashlib
import random
import struct
import time

from typing import Optional, Callable
from enum import IntEnum

from ...events import Events
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

	# MD5 is outdated asf but it's what the standard recommends
	hashed = hashlib.md5(packed).digest()

	# 4µs~ per tick
	counter = int(time.monotonic() * 250000) & 0xFFFFFFFF

	return (counter + int.from_bytes(hashed[:4], "big")) & 0xFFFFFFFF


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
		self._events = Events()

		self._send_buffer = bytearray()
		self._nagle_enabled = True

		self._close_pending = False # CLOSE requested while send data is still queued (RFC 9293 @ 3.10.4)
		self._recv_fin_seq: Optional[int] = None # Absolute FIN seq received out-of-order (RFC 9293 @ 3.10.7.4)
		self._peer_fin_received = False # The peer's FIN has been consumed

		self._in_flight = []
		self._srtt = None
		self._rttvar = None
		self._rto = 1000
		self._cwnd = 0
		self._ssthresh = 65535
		self._dup_ack_count = 0
		self._last_ack = 0

		# RFC 9293 @ 3.8.3 (R2): abort once a segment has been retransmitted this
		# many times (None disables the abort). Default 9 retransmissions exceeds
		# the ~100 s SHOULD (SHLD-11) and the 3-minute SYN minimum (MUST-23).
		self.max_retransmissions: Optional[int] = 9

		self.dst_retransmit = collections.deque()
		self.dst_staged_buffer = collections.deque()
		self.dst_addr = 0
		self.dst_port = 0
		self.dst_mss = 0

		# Window scaling is never enabled: we do not advertise the Window Scale
		# option, so by RFC 7323 @ 2.2 peer window fields must be decoded with a
		# shift of 0. (_send_shift is kept as the knob if WS support is added.)
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
		old = self.state
		self.state = state
		self._events.fire_handler("state_change", (old, state))

		if state == TCPState.STATE_ESTABLISHED:
			self._events.fire_handler("connection_established")
		elif state in (TCPState.STATE_CLOSED, TCPState.STATE_TIME_WAIT):
			self._events.fire_handler("connection_closed")

	# --- Event registration ---

	def on_state_change(self, func: "Callable[[TCPState, TCPState], None]"):
		self._events.attach_handler("state_change", func)

	def on_connection_established(self, func: Callable[[], None]):
		self._events.attach_handler("connection_established", func)

	def on_connection_closed(self, func: Callable[[], None]):
		self._events.attach_handler("connection_closed", func)

	def on_data_received(self, func: Callable[[bytes], None]):
		self._events.attach_handler("data_received", func)

	def on_data_sent(self, func: Callable[[bytes], None]):
		self._events.attach_handler("data_sent", func)

	def on_retransmit(self, func: Callable[[], None]):
		self._events.attach_handler("retransmit", func)

	def on_urgent_data(self, func: Callable[[int], None]):
		# RFC 9293 @ 3.8.5 (MUST-32): async notification when urgent data arrives
		# or the urgent pointer advances. Receives the absolute sequence number of
		# the octet following the urgent data.
		self._events.attach_handler("urgent_data", func)

	def on_connection_failed(self, func: Callable[[], None]):
		self._events.attach_handler("connection_failed", func)

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

		# Second, check the RST bit (RFC 9293 @ 3.10.7.3). An RST is only acted
		# upon when its ACK is acceptable (SND.UNA < SEG.ACK =< SND.NXT); an RST
		# without an ACK (or with an unacceptable ACK) is dropped silently and
		# must never provoke a reply.
		if fg_rst:
			ack_acceptable = (
				fg_ack and self._seq_lt(self.send_una, packet.ack_num) and self._seq_leq(packet.ack_num, self.send_nxt)
			)

			if ack_acceptable:
				self._advance_state(TCPState.STATE_CLOSED)
				self._fail_conn_reset()

			return

		# First, check the ACK bit (RFC 9293 @ 3.10.7.3).
		if fg_ack:
			if packet.ack_num <= self.send_isn or packet.ack_num > self.send_nxt:
				self._enqueue_outbound(TCPPacket(flags = TCPFlags.FG_RST, seq_num = packet.ack_num))

				return

			if not (self._seq_lt(self.send_una, packet.ack_num) and self._seq_leq(packet.ack_num, self.send_nxt)):
				return

			if not fg_syn:
				# An ACK-only segment cannot complete the handshake; the peer must
				# acknowledge our SYN with a SYN-ACK. Drop it.
				return
		else:
			# Simultaneous open: SYN arrives without ACK (MUST-10)
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

		# Fourth, check the SYN bit: reachable with an acceptable ACK only.
		self.recv_nxt = packet.seq_num + 1
		self.recv_isn = packet.seq_num

		opt_mss = packet.opt_get(TCPOptionKind.OPT_MSS)
		if opt_mss is not None:
			self.dst_mss = opt_mss.mss

		# The window scale option is not applied: we never offered it, so scaling
		# was not negotiated (RFC 7323 @ 2.2) and peer windows must not be scaled.
		self.send_una = packet.ack_num

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

		# RFC 9293 @ 3.4: our SYN was acknowledged by this SYN-ACK, remove it
		# from the retransmission queue and stop its RTO so an idle ESTABLISHED
		# connection does not keep re-sending it. (No RTT sample is taken for the
		# SYN, matching RFC 6298 handling of the initial exchange.)
		while self._in_flight:
			seq, length, _, _, _, flags = self._in_flight[0]

			if not (flags & TCPFlags.FG_SYN):
				break

			seg_end = (seq + length) & 0xFFFFFFFF

			if not self._seq_leq(seg_end, self.send_una):
				break

			self._in_flight.pop(0)

		if not self._in_flight:
			self._cancel_timer("RTO")

		self._advance_state(TCPState.STATE_ESTABLISHED)
		self._on_established()

	# --- Synchronized-state pipeline (RFC 9293 @ 3.10.7.4) ---

	def _on_established(self):
		# RFC 9293 @ 3.10.2: data queued while SYN-SENT/SYN-RECEIVED is
		# transmitted once the connection enters ESTABLISHED.
		while self.dst_staged_buffer:
			self._send_buffer.extend(self.dst_staged_buffer.popleft())

		self._flush_send_buffer()

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

		seq = self.send_nxt
		self.send_nxt = (self.send_nxt + 1) & 0xFFFFFFFF

		self._enqueue_outbound(
			TCPPacket(
				flags = TCPFlags.FG_FIN | TCPFlags.FG_ACK,
				seq_num = seq,
				ack_num = self.recv_nxt,
				window = self.recv_wnd,
			)
		)

		# RFC 9293 @ 3.6: all segments preceding and including the FIN are
		# retransmitted until acknowledged, so the FIN is tracked on the
		# retransmission queue like any other segment.
		self._in_flight.append((seq, 1, b"", time_ms(), 0, TCPFlags.FG_FIN | TCPFlags.FG_ACK))

		if not self._timer_active("RTO"):
			self._schedule_timer("RTO", self._rto)

	def _begin_close(self):
		# RFC 9293 @ 3.10.4: the FIN is formed only once all preceding SENDs have
		# been segmentized; queued data must not be left behind the FIN.
		self._close_pending = True
		self._maybe_send_close_fin()

	def _maybe_send_close_fin(self):
		if not self._close_pending:
			return

		if self._send_buffer or self.dst_staged_buffer:
			return

		self._close_pending = False
		self._send_fin()

	def _process_otherwise(self, packet: TCPPacket):
		seg_seq = packet.seq_num
		seg_len = self._seg_len(packet)

		fg_rst = packet.flags & TCPFlags.FG_RST
		fg_syn = packet.flags & TCPFlags.FG_SYN
		fg_ack = packet.flags & TCPFlags.FG_ACK
		fg_urg = packet.flags & TCPFlags.FG_URG
		fg_fin = packet.flags & TCPFlags.FG_FIN

		# RFC 9293 Figure 7 (MUST-10): simultaneous-open completion. Both peers
		# entered SYN-RECEIVED from an active OPEN and have already consumed each
		# other's bare SYN. The peer's SYN-ACK re-carries the SYN we consumed
		# (SEG.SEQ == RCV.IRS == RCV.NXT - 1) plus the ACK of our SYN; only the
		# ACK is meaningful, so route it to ACK processing instead of letting the
		# sequence/SYN checks below drop or challenge it.
		if (self.state == TCPState.STATE_SYN_RECEIVED and not self._passive_open and fg_syn and fg_ack
			and seg_seq == self.recv_isn):
			self._process_ack(packet)
			return

		# 1: check sequence number
		if not self._segment_acceptable(seg_seq, seg_len):
			if self.state == TCPState.STATE_TIME_WAIT and fg_fin and seg_seq == ((self.recv_nxt - 1) & 0xFFFFFFFF):
				# RFC 9293 @ 3.10.7.4: a retransmitted FIN in TIME-WAIT restarts
				# the 2*MSL time-wait timeout.
				if self._timer_active("TIME_WAIT"):
					self._cancel_timer("TIME_WAIT")
					self._schedule_timer("TIME_WAIT", 2 * TCP_MSL * 1000)

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

		# 3: security check (skipped)

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

				# RFC 9293 @ 3.8.5 (MUST-62): the urgent pointer is a positive
				# offset from the segment's sequence number; RCV.UP tracks the
				# absolute octet following the urgent data.
				urgent = (packet.seq_num + packet.urg_ptr) & 0xFFFFFFFF
				advances = self.recv_urg == 0 or self._seq_lt(self.recv_urg, urgent)

				if advances:
					self.recv_urg = urgent
					self._events.fire_handler("urgent_data", (self.recv_urg, ))

		# 7: process segment text
		if packet.payload:
			self._process_segment_text(packet)

		# 8: check FIN bit
		if fg_fin:
			self._handle_fin(packet)

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

		if self.state == TCPState.STATE_SYN_RECEIVED:
			# RFC 9293 @ 3.10.7.4 step 5, SYN-RECEIVED STATE: ESTABLISHED is entered
			# only when our SYN is acknowledged (SND.UNA < SEG.ACK =< SND.NXT);
			# any other ACK forms <SEQ=SEG.ACK><CTL=RST> and is discarded.
			if not (self._seq_lt(self.send_una, seg_ack) and self._seq_leq(seg_ack, self.send_nxt)):
				self._enqueue_outbound(TCPPacket(flags = TCPFlags.FG_RST, seq_num = seg_ack))
				return
		else:
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

		window_was_zero = self.send_wnd == 0

		if (newer_segment or same_segment_newer_ack) and packet.window is not None:
			# A zero window is meaningful (RFC 9293 @ 3.8.6): it suspends sending.
			self.send_wnd = packet.window << self._send_shift
			self.send_wnd_seq = packet.seq_num
			self.send_wnd_ack = seg_ack

		if window_was_zero and self.send_wnd > 0:
			# The peer's receive window opened: resume sending queued data and,
			# if closing, finally emit the deferred FIN.
			self._flush_send_buffer()

		match self.state:
			case TCPState.STATE_SYN_RECEIVED:
				self.recv_wnd = self.recv_buff_max - len(self.recv_buffer)
				self._cwnd = self._initial_window()
				self._advance_state(TCPState.STATE_ESTABLISHED)
				self._on_established()

			case TCPState.STATE_FIN_WAIT_1:
				# Our FIN may still be queued behind user data (_close_pending);
				# only once it is sent and acknowledged do we leave FIN-WAIT-1.
				if not self._close_pending and self.send_una == self.send_nxt:
					if self._peer_fin_received:
						self._advance_state(TCPState.STATE_TIME_WAIT)
						self._schedule_timer("TIME_WAIT", 2 * TCP_MSL * 1000)
					else:
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
			self._accept_receive_data(data)
		elif self._seq_lt(self.recv_nxt, seg_seq):
			self.recv_out_of_order.append((seg_seq, data))
			self.recv_out_of_order.sort(key = lambda x: x[0])
			self._ack_immediate = True
		else:
			# SEG.SEQ < RCV.NXT: the segment overlaps data already received.
			# RFC 9293 @ 3.10.7.4: if the contents straddle the boundary between
			# old and new, only the new parts are processed.
			overlap = (self.recv_nxt - seg_seq) & 0xFFFFFFFF

			if overlap < len(data):
				self._accept_receive_data(data[overlap:])

		# RCV.WND tracks the actual free receive space, so it can drop to 0 once
		# the receive buffer fills (RFC 9293 @ 3.8.6.2.2 MUST-39). Increases are
		# advertised only once the SWS threshold is crossed (see event_receive).
		self.recv_wnd = self.recv_buff_max - len(self.recv_buffer)

		self._ack_needed = True

	def _accept_receive_data(self, data):
		# Accept in-order data but never buffer beyond recv_buff_max: the part
		# that does not fit lies beyond our advertised window and will be
		# retransmitted by the peer once space frees up.
		space = self.recv_buff_max - len(self.recv_buffer)

		if space <= 0:
			return

		if len(data) > space:
			data = data[:space]

		self.recv_buffer.extend(data)
		self.recv_nxt = (self.recv_nxt + len(data)) & 0xFFFFFFFF
		self._merge_out_of_order()

	def _merge_out_of_order(self):
		while self.recv_out_of_order and len(self.recv_buffer) < self.recv_buff_max:
			seq, data = self.recv_out_of_order[0]

			if seq == self.recv_nxt:
				space = self.recv_buff_max - len(self.recv_buffer)
				chunk = data if len(data) <= space else data[:space]

				self.recv_buffer.extend(chunk)
				self.recv_nxt = (self.recv_nxt + len(chunk)) & 0xFFFFFFFF
				self.recv_out_of_order.pop(0)

			elif self._seq_lt(seq, self.recv_nxt):
				overlap = (self.recv_nxt - seq) & 0xFFFFFFFF

				if overlap < len(data):
					space = self.recv_buff_max - len(self.recv_buffer)
					tail = data[overlap:]

					if len(tail) > space:
						tail = tail[:space]

					if tail:
						self.recv_buffer.extend(tail)
						self.recv_nxt = (self.recv_nxt + len(tail)) & 0xFFFFFFFF

				self.recv_out_of_order.pop(0)
			else:
				break

		self._maybe_consume_fin()

	def _handle_fin(self, packet: TCPPacket):
		# The FIN occupies the sequence number that follows this segment's payload.
		fin_seq = (packet.seq_num + len(packet.payload or b"")) & 0xFFFFFFFF

		if self._seq_lt(fin_seq, self.recv_nxt):
			# Duplicate/old FIN: re-acknowledge only (RFC 9293 @ 3.10.7.4).
			self._ack_needed = True
			self._ack_immediate = True
			return

		if fin_seq != self.recv_nxt:
			# Out-of-order FIN: hold it until every preceding octet has arrived so
			# RCV.NXT is never advanced across a gap (RFC 9293 @ 3.10.7.4 SHLD-31).
			self._recv_fin_seq = fin_seq
			self._ack_needed = True
			self._ack_immediate = True
			return

		self._recv_fin_seq = None
		self.recv_nxt = (self.recv_nxt + 1) & 0xFFFFFFFF
		self._ack_needed = True
		self._ack_immediate = True

		self._consume_fin_state()

	def _maybe_consume_fin(self):
		if self._recv_fin_seq is not None and self._recv_fin_seq == self.recv_nxt:
			self._recv_fin_seq = None
			self.recv_nxt = (self.recv_nxt + 1) & 0xFFFFFFFF
			self._ack_needed = True
			self._ack_immediate = True

			self._consume_fin_state()

	def _consume_fin_state(self):
		self._peer_fin_received = True

		match self.state:
			case TCPState.STATE_SYN_RECEIVED | TCPState.STATE_ESTABLISHED:
				self._advance_state(TCPState.STATE_CLOSE_WAIT)

			case TCPState.STATE_FIN_WAIT_1:
				if self._close_pending:
					# Our FIN is still queued behind user data; finish sending it
					# before moving on (the FIN_WAIT_1 ACK handler below will enter
					# TIME-WAIT once our FIN is acknowledged).
					return

				self._advance_state(TCPState.STATE_CLOSING)

			case TCPState.STATE_FIN_WAIT_2:
				self._advance_state(TCPState.STATE_TIME_WAIT)
				self._schedule_timer("TIME_WAIT", 2 * TCP_MSL * 1000)

			case TCPState.STATE_TIME_WAIT:
				# A second in-order FIN cannot occur in TIME-WAIT; retransmitted
				# FINs are handled by the sequence check in _process_otherwise.
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
		# Track SYN in _in_flight so RTO can retransmit it
		self._in_flight.append((isn, 0, b"", time_ms(), 0, TCPFlags.FG_SYN))
		if not self._timer_active("RTO"):
			self._schedule_timer("RTO", self._rto)
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

		# RFC 9293 @ 3.8.6 (MUST-34): the usable window is bounded by the peer's
		# right window edge; it becomes 0 (never wraps around) when the peer
		# shrinks its window below our outstanding data.
		right = (self.send_una + self.send_wnd) & 0xFFFFFFFF

		if not self._seq_lt(self.send_nxt, right):
			return 0

		return (right - self.send_nxt) & 0xFFFFFFFF

	def _nagle_ok(self, data_len: int) -> bool:
		if not self._nagle_enabled:
			return True

		if self.send_una == self.send_nxt:
			return True

		if data_len >= self.effective_send_mss:
			return True

		return False

	@property
	def nagle_enabled(self) -> bool:
		# RFC 9293 @ 3.7.4 (MUST-17): the Nagle algorithm can be disabled per
		# connection.
		return self._nagle_enabled

	@nagle_enabled.setter
	def nagle_enabled(self, enabled: bool):
		self._nagle_enabled = bool(enabled)

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
		self._in_flight.append((seq, len(data), data, send_time_ms, 0, TCPFlags.FG_ACK))

		self._events.fire_handler("data_sent", (data, ))

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

		self._maybe_send_close_fin()

	# --- Retransmission & congestion control (RFC 6298, RFC 5681) ---

	def _initial_window(self) -> int:
		mss = self.effective_send_mss
		return min(4 * mss, max(2 * mss, 4380))

	def _bytes_in_flight(self) -> int:
		return sum(length for _, length, _, _, _, _ in self._in_flight)

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
			seq, length, _, send_time, retrans_count, _ = self._in_flight[0]
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

		seq, length, data, _, retrans_count, flags = self._in_flight[0]
		retrans_count += 1

		# RFC 9293 @ 3.8.3 (R2): close the connection once a segment has been
		# retransmitted max_retransmissions times. A zero-window peer is not lost:
		# only retransmissions against an open window - or of an unacknowledged
		# SYN - count toward the abort.
		if (self.max_retransmissions is not None and retrans_count >= self.max_retransmissions
			and (flags & TCPFlags.FG_SYN or self.send_wnd > 0)):
			self._abort_retransmit_timeout()
			return

		self._rto = min(self._rto * 2, 120000)
		self._ssthresh = max(self._cwnd // 2, 2 * self.effective_send_mss)
		self._cwnd = self.effective_send_mss
		self._dup_ack_count = 0

		self._cancel_timer("DELAYED_ACK")
		self._enqueue_outbound(
			TCPPacket(
				flags = flags,
				seq_num = seq,
				ack_num = self.recv_nxt,
				window = self.recv_wnd,
				payload = data,
			)
		)

		self._events.fire_handler("retransmit")

		send_time_ms = time_ms()
		self._in_flight[0] = (seq, length, data, send_time_ms, retrans_count, flags)
		self._schedule_timer("RTO", self._rto)

	def _abort_retransmit_timeout(self):
		# RFC 9293 @ 3.8.3: the R2 retransmission bound was reached; abort.
		self._cancel_timer("RTO")
		self._cancel_timer("DELAYED_ACK")
		self._cancel_timer("ZERO_WINDOW_PROBE")
		self._in_flight.clear()
		self._send_buffer.clear()
		self.dst_staged_buffer.clear()

		self._events.fire_handler("connection_failed")
		self._advance_state(TCPState.STATE_CLOSED)

	def _fast_retransmit(self):
		if not self._in_flight:
			return

		seq, length, data, _, retrans_count, flags = self._in_flight[0]

		self._ssthresh = max(self._cwnd // 2, 2 * self.effective_send_mss)
		self._cwnd = self._ssthresh + 3 * self.effective_send_mss

		self._cancel_timer("DELAYED_ACK")
		self._enqueue_outbound(
			TCPPacket(
				flags = flags,
				seq_num = seq,
				ack_num = self.recv_nxt,
				window = self.recv_wnd,
				payload = data,
			)
		)

		self._events.fire_handler("retransmit")

		send_time_ms = time_ms()
		self._in_flight[0] = (seq, length, data, send_time_ms, retrans_count + 1, flags)

	def _zero_window_probe(self):
		if not self._send_buffer:
			self._maybe_send_close_fin()
			return

		self._send_segment(bytes(self._send_buffer[:1]))
		self._send_buffer = self._send_buffer[1:]

		self._rto = min(self._rto * 2, 120000)
		self._schedule_timer("ZERO_WINDOW_PROBE", self._rto)
		self._maybe_send_close_fin()

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

		if data:
			self._events.fire_handler("data_received", (data, ))

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
				self._begin_close()
				self._advance_state(TCPState.STATE_FIN_WAIT_1)

			case TCPState.STATE_ESTABLISHED:
				self._begin_close()
				self._advance_state(TCPState.STATE_FIN_WAIT_1)

			case TCPState.STATE_FIN_WAIT_1 | TCPState.STATE_FIN_WAIT_2:
				pass

			case TCPState.STATE_CLOSE_WAIT:
				self._begin_close()
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

		# Window scaling is not applied: we never advertise the Window Scale
		# option, so it was not negotiated (RFC 7323 @ 2.2) and the peer's window
		# fields must be decoded with a shift of 0.

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

	def accept(self) -> TCPConnection | None:
		for key, conn in tuple(self._pending.items()):
			if conn.state == TCPState.STATE_ESTABLISHED:
				del self._pending[key]
				self._accept_queue.append(conn)

		if self._accept_queue:
			return self._accept_queue.popleft()

		return None
