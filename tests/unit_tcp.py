from src.wireguard.stack.tcp import (
	tcp_encode_offset_control,
	tcp_decode_offset_control,
	tcp_opt_encode,
	tcp_opt_decode,
	TCPOptionKind,
	TCPOption,
	TCPPacket,
	TCPFlags,
	TCPState,
	TCPConnection,
	TCPListener,
	initial_sequence_number,
)
from src.wireguard.stack.ipv4 import IPv4Packet

import unittest
import random

from utilities import iter_vec2, compare_list
from typing import cast


class UnitBitwiseCodecs(unittest.TestCase):
	def test_codec_offset_control(self):
		for offset, control in iter_vec2(0x000F, 0x0FFF):
			encoded = tcp_encode_offset_control(offset, control)
			dec_offset, dec_control = tcp_decode_offset_control(encoded)

			self.assertEqual(
				offset,
				dec_offset,
				f"Failed to encode/decode offset. Got {dec_offset} expected {offset}",
			)
			self.assertEqual(
				control,
				dec_control,
				f"Failed to encode/decode header length. Got {dec_control} expected {control}",
			)


class UnitOptionsCodecs(unittest.TestCase):
	def _check_state_change(self, options: list[TCPOption]):
		encoded_a, _size = tcp_opt_encode(options)
		decoded_a = list(tcp_opt_decode(encoded_a))

		self.assertNotIn(None, decoded_a, "Got None in the first re-encoding")
		self.assertIsNotNone(decoded_a)

		encoded_b, _size = tcp_opt_encode(cast(list[TCPOption], decoded_a))
		decoded_b = list(tcp_opt_decode(encoded_b))

		self.assertNotIn(None, decoded_b, "Got None in the second re-encoding")

		self.assertEqual(encoded_a, encoded_b, "Encoded results differ between the first and second re-encoding")

		self.assertTrue(
			compare_list(decoded_a, decoded_b),
			"Decoded results differ between the first and second re-encoding",
		)
		self.assertTrue(
			compare_list(options, decoded_a),
			"Decoded results differ between the original and first re-encoding",
		)
		self.assertTrue(
			compare_list(options, decoded_b),
			"Decoded results differ between the original and second re-encoding",
		)

	@staticmethod
	def _random_edge_pairs(length: int) -> list[tuple[int, int]]:
		pairs = []

		for _ in range(length):
			pairs.append((random.randrange(0x00000000, 0xFFFFFFFF), random.randrange(0x00000000, 0xFFFFFFFF)))

		return pairs

	@staticmethod
	def _rand_opt_mss():
		return TCPOption(kind = TCPOptionKind.OPT_MSS, mss = random.randrange(0x0000, 0xFFFF))

	@staticmethod
	def _rand_opt_window_scale():
		return TCPOption(kind = TCPOptionKind.OPT_WINDOW, window_scale = random.randrange(0x00, 0xFF))

	@staticmethod
	def _rand_opt_sack():
		pairs = UnitOptionsCodecs._random_edge_pairs(random.randrange(0, (255 - 2) // 8))

		return TCPOption(kind = TCPOptionKind.OPT_SACK, edge_pairs = pairs)

	@staticmethod
	def _rand_opt_timestamp():
		return TCPOption(
			kind = TCPOptionKind.OPT_TIMESTAMP,
			tsval = random.randrange(0x00000000, 0xFFFFFFFF),
			tsecr = random.randrange(0x00000000, 0xFFFFFFFF),
		)

	@staticmethod
	def _rand_modify_opts(options: list[TCPOption], generator):
		if random.random() > 0.40:
			options.append(generator())
		elif len(options):
			options.pop()

	def test_options_mss(self):
		options = []

		for _ in range(32):
			self._rand_modify_opts(options, self._rand_opt_mss)
			self._check_state_change(options)

	def test_options_window_scale(self):
		options = []

		for _ in range(32):
			self._rand_modify_opts(options, self._rand_opt_window_scale)
			self._check_state_change(options)

	def test_options_sack(self):
		options = []

		for _ in range(32):
			self._rand_modify_opts(options, self._rand_opt_sack)
			self._check_state_change(options)

	def test_options_timestamp(self):
		options = []

		for _ in range(32):
			self._rand_modify_opts(options, self._rand_opt_timestamp)
			self._check_state_change(options)

	def test_options_sack_capable(self):
		opt = TCPOption(kind = TCPOptionKind.OPT_SACK_CAPABLE)
		encoded, size = tcp_opt_encode([opt])
		decoded = list(tcp_opt_decode(encoded))

		self.assertEqual(len(decoded), 1)
		self.assertEqual(cast(TCPOption, decoded[0]).kind, TCPOptionKind.OPT_SACK_CAPABLE)

	def test_options_fuzzing(self):
		candidates = [
			self._rand_opt_mss,
			self._rand_opt_window_scale,
			self._rand_opt_sack,
			self._rand_opt_timestamp,
		]
		options = []

		for _ in range(256):
			self._rand_modify_opts(options, random.choice(candidates))
			self._check_state_change(options)


class UnitSequenceHelpers(unittest.TestCase):
	def test_seq_lt(self):
		conn = TCPConnection()
		self.assertTrue(conn._seq_lt(0, 1))
		self.assertFalse(conn._seq_lt(1, 0))
		self.assertFalse(conn._seq_lt(0, 0))
		self.assertTrue(conn._seq_lt(0xFFFFFFFF, 0))

	def test_seq_leq(self):
		conn = TCPConnection()
		self.assertTrue(conn._seq_leq(0, 1))
		self.assertTrue(conn._seq_leq(0, 0))
		self.assertTrue(conn._seq_leq(0xFFFFFFFF, 0))
		self.assertFalse(conn._seq_leq(0, 0xFFFFFFFF))

	def test_seg_len(self):
		conn = TCPConnection()
		pkt = TCPPacket(flags = TCPFlags.FG_SYN, payload = b"hello")
		self.assertEqual(conn._seg_len(pkt), 6)

		pkt = TCPPacket(flags = TCPFlags.FG_FIN)
		self.assertEqual(conn._seg_len(pkt), 1)

		pkt = TCPPacket(flags = TCPFlags.FG_ACK, payload = b"test")
		self.assertEqual(conn._seg_len(pkt), 4)

	def test_segment_acceptable(self):
		conn = TCPConnection()
		conn.recv_nxt = 100
		conn.recv_wnd = 50

		self.assertTrue(conn._segment_acceptable(100, 0))
		self.assertFalse(conn._segment_acceptable(99, 0))
		self.assertTrue(conn._segment_acceptable(100, 10))
		self.assertFalse(conn._segment_acceptable(90, 10))
		self.assertTrue(conn._segment_acceptable(145, 10))
		self.assertFalse(conn._segment_acceptable(155, 10))

		conn.recv_wnd = 0
		self.assertTrue(conn._segment_acceptable(100, 0))
		self.assertFalse(conn._segment_acceptable(99, 0))
		self.assertFalse(conn._segment_acceptable(100, 1))

	def test_isn_uniqueness(self):
		seen = set()

		for _ in range(100):
			isn = initial_sequence_number(
				random.randrange(0, 0xFFFFFFFF),
				random.randrange(1, 65535),
				random.randrange(0, 0xFFFFFFFF),
				random.randrange(1, 65535),
			)
			self.assertNotIn(isn, seen)
			seen.add(isn)


class UnitConnectionEstablishment(unittest.TestCase):
	def _handshake(self, conn: TCPConnection):
		conn._recv_packet(
			TCPPacket(
				src_port = conn.dst_port,
				dst_port = conn.src_port,
				flags = TCPFlags.FG_SYN | TCPFlags.FG_ACK,
				seq_num = 5000,
				ack_num = conn.send_isn + 1,
				window = 65535,
			)
		)

	def test_active_open(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self.assertEqual(conn.state, TCPState.STATE_SYN_SENT)
		self.assertNotEqual(conn.send_isn, 0)

	def test_passive_open(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 80)
		self.assertEqual(conn.state, TCPState.STATE_LISTEN)

	def test_handshake_active(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		self.assertEqual(conn.state, TCPState.STATE_ESTABLISHED)
		self.assertEqual(conn.recv_nxt, 5001)

	def test_handshake_passive(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 80)
		conn._recv_packet(
			TCPPacket(
				src_port = 12345,
				dst_port = 80,
				flags = TCPFlags.FG_SYN,
				seq_num = 5000,
				window = 65535,
			)
		)
		self.assertEqual(conn.state, TCPState.STATE_SYN_RECEIVED)
		self.assertTrue(conn._passive_open)

	def test_simultaneous_open(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_SYN,
				seq_num = 5000,
				window = 65535,
			)
		)
		self.assertEqual(conn.state, TCPState.STATE_SYN_RECEIVED)
		self.assertFalse(conn._passive_open)

	def test_double_open_fails(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		with self.assertRaises(ValueError):
			conn.event_open(0x0A000001, 12345, 0x0A000002, 80)

	def test_mss_option_parsed(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		syn_ack = TCPPacket(
			src_port = 80,
			dst_port = 12345,
			flags = TCPFlags.FG_SYN | TCPFlags.FG_ACK,
			seq_num = 5000,
			ack_num = conn.send_isn + 1,
			window = 65535,
		)
		syn_ack.opt_set(TCPOptionKind.OPT_MSS, mss = 1460)
		conn._recv_packet(syn_ack)
		self.assertEqual(conn.dst_mss, 1460)


class UnitDataTransfer(unittest.TestCase):
	def _handshake(self, conn: TCPConnection):
		conn._recv_packet(
			TCPPacket(
				src_port = conn.dst_port,
				dst_port = conn.src_port,
				flags = TCPFlags.FG_SYN | TCPFlags.FG_ACK,
				seq_num = 5000,
				ack_num = conn.send_isn + 1,
				window = 65535,
			)
		)

	def test_send_basic(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn.event_send(b"Hello")
		self.assertGreater(conn._bytes_in_flight(), 0)
		self.assertEqual(conn.send_nxt, conn.send_isn + 1 + 5)

	def test_receive_basic(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_una,
				payload = b"World",
				window = 65535,
			)
		)
		data = conn.event_receive(100)
		self.assertEqual(data, b"World")

	def test_receive_out_of_order(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_ACK,
				seq_num = 5007,
				ack_num = conn.send_una,
				payload = b"World",
				window = 65535,
			)
		)
		self.assertEqual(len(conn.recv_out_of_order), 1)
		self.assertEqual(len(conn.recv_buffer), 0)

		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_una,
				payload = b"Hello ",
				window = 65535,
			)
		)
		data = conn.event_receive(100)
		self.assertEqual(data, b"Hello World")

	def test_send_respects_window(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn.send_wnd = 10
		conn.event_send(b"A" * 100)
		self.assertLessEqual(conn._bytes_in_flight(), 10)

	def test_nagle_coalescing(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn.event_send(b"A" * 536)
		before = conn.send_nxt
		conn.event_send(b"B")
		self.assertEqual(conn.send_nxt, before)
		conn.event_send(b"C" * 535)
		self.assertGreater(conn.send_nxt, before)

	def test_ack_piggyback(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_una,
				payload = b"Data",
				window = 65535,
			)
		)
		self.assertTrue(conn._timer_active("DELAYED_ACK"))
		conn.event_send(b"Response")
		self.assertFalse(conn._timer_active("DELAYED_ACK"))


class UnitConnectionClose(unittest.TestCase):
	def _handshake(self, conn: TCPConnection):
		conn._recv_packet(
			TCPPacket(
				src_port = conn.dst_port,
				dst_port = conn.src_port,
				flags = TCPFlags.FG_SYN | TCPFlags.FG_ACK,
				seq_num = 5000,
				ack_num = conn.send_isn + 1,
				window = 65535,
			)
		)

	def test_active_close(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn.event_close()
		self.assertEqual(conn.state, TCPState.STATE_FIN_WAIT_1)

	def test_active_close_full_sequence(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn.event_close()
		self.assertEqual(conn.state, TCPState.STATE_FIN_WAIT_1)
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_nxt,
				window = 65535,
			)
		)
		self.assertEqual(conn.state, TCPState.STATE_FIN_WAIT_2)
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_FIN | TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_una,
				window = 65535,
			)
		)
		self.assertEqual(conn.state, TCPState.STATE_TIME_WAIT)
		self.assertTrue(conn._timer_active("TIME_WAIT"))

	def test_passive_close(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_FIN | TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_una,
				window = 65535,
			)
		)
		self.assertEqual(conn.state, TCPState.STATE_CLOSE_WAIT)
		conn.event_close()
		self.assertEqual(conn.state, TCPState.STATE_LAST_ACK)

	def test_simultaneous_close(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn.event_close()
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_FIN | TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_una,
				window = 65535,
			)
		)
		self.assertEqual(conn.state, TCPState.STATE_CLOSING)

	def test_abort(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn.event_abort()
		self.assertEqual(conn.state, TCPState.STATE_CLOSED)

	def test_send_on_closing_fails(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn.event_close()
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_nxt,
				window = 65535,
			)
		)
		with self.assertRaises(ValueError):
			conn.event_send(b"data")

	def test_close_on_closing_fails(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn.event_close()
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_FIN | TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_una,
				window = 65535,
			)
		)
		self.assertEqual(conn.state, TCPState.STATE_CLOSING)
		with self.assertRaises(ValueError):
			conn.event_close()


class UnitCongestionControl(unittest.TestCase):
	def _handshake(self, conn: TCPConnection):
		conn._recv_packet(
			TCPPacket(
				src_port = conn.dst_port,
				dst_port = conn.src_port,
				flags = TCPFlags.FG_SYN | TCPFlags.FG_ACK,
				seq_num = 5000,
				ack_num = conn.send_isn + 1,
				window = 65535,
			)
		)

	def test_initial_window(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		self.assertEqual(conn._cwnd, conn._initial_window())

	def test_rto_backoff(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn.event_send(b"A" * 536)
		old_rto = conn._rto
		conn._fire_timer("RTO")
		self.assertEqual(conn._rto, min(old_rto * 2, 120000))
		self.assertEqual(conn._cwnd, conn.effective_send_mss)

	def test_fast_retransmit(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn.event_send(b"X" * 536)
		conn.event_send(b"Y" * 536)

		dup_ack = conn.send_isn + 1
		for _ in range(4):
			conn._recv_packet(
				TCPPacket(
					src_port = 80,
					dst_port = 12345,
					flags = TCPFlags.FG_ACK,
					seq_num = 5001,
					ack_num = dup_ack,
					window = 65535,
				)
			)
		self.assertGreater(conn._cwnd, conn._initial_window())

	def test_cwnd_growth(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn.event_send(b"A" * 536)

		initial_cwnd = conn._cwnd
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_isn + 1 + 536,
				window = 65535,
			)
		)
		self.assertGreater(conn._cwnd, initial_cwnd)


class UnitRstHandling(unittest.TestCase):
	def _handshake(self, conn: TCPConnection):
		conn._recv_packet(
			TCPPacket(
				src_port = conn.dst_port,
				dst_port = conn.src_port,
				flags = TCPFlags.FG_SYN | TCPFlags.FG_ACK,
				seq_num = 5000,
				ack_num = conn.send_isn + 1,
				window = 65535,
			)
		)

	def test_rst_exact_match_resets(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		with self.assertRaises(ValueError):
			conn._recv_packet(
				TCPPacket(
					src_port = 80,
					dst_port = 12345,
					flags = TCPFlags.FG_RST | TCPFlags.FG_ACK,
					seq_num = 5001,
					ack_num = conn.send_una,
					window = 65535,
				)
			)
		self.assertEqual(conn.state, TCPState.STATE_CLOSED)

	def test_rst_inexact_challenges(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_RST | TCPFlags.FG_ACK,
				seq_num = 5002,
				ack_num = conn.send_una,
				window = 65535,
			)
		)
		self.assertEqual(conn.state, TCPState.STATE_ESTABLISHED)

	def test_rst_in_listen_ignored(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 80)
		conn._recv_packet(
			TCPPacket(
				src_port = 12345,
				dst_port = 80,
				flags = TCPFlags.FG_RST,
				seq_num = 5000,
				window = 65535,
			)
		)
		self.assertEqual(conn.state, TCPState.STATE_LISTEN)


class UnitTimers(unittest.TestCase):
	def _handshake(self, conn: TCPConnection):
		conn._recv_packet(
			TCPPacket(
				src_port = conn.dst_port,
				dst_port = conn.src_port,
				flags = TCPFlags.FG_SYN | TCPFlags.FG_ACK,
				seq_num = 5000,
				ack_num = conn.send_isn + 1,
				window = 65535,
			)
		)

	def test_time_wait_timer(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn.event_close()
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_nxt,
				window = 65535,
			)
		)
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_FIN | TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_una,
				window = 65535,
			)
		)
		self.assertTrue(conn._timer_active("TIME_WAIT"))
		conn._fire_timer("TIME_WAIT")
		self.assertEqual(conn.state, TCPState.STATE_CLOSED)

	def test_delayed_ack_fires(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(conn)
		conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_una,
				payload = b"Data",
				window = 65535,
			)
		)
		self.assertTrue(conn._timer_active("DELAYED_ACK"))
		before = len(conn.dst_retransmit)
		conn._fire_timer("DELAYED_ACK")
		self.assertEqual(len(conn.dst_retransmit), before + 1)


class UnitListener(unittest.TestCase):
	def test_accept_connection(self):
		ln = TCPListener(0x0A000001, 80)
		ln._recv_packet(
			TCPPacket(
				src_port = 12345,
				dst_port = 80,
				flags = TCPFlags.FG_SYN,
				seq_num = 5000,
				window = 65535,
			)
		)
		self.assertEqual(len(ln._pending), 1)
		conn = list(ln._pending.values())[0]
		self.assertEqual(conn.state, TCPState.STATE_SYN_RECEIVED)

		conn._recv_packet(
			TCPPacket(
				src_port = 12345,
				dst_port = 80,
				flags = TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = conn.send_nxt,
				window = 65535,
			)
		)

		accepted = ln.accept()
		self.assertIsNotNone(accepted)
		self.assertEqual(cast(TCPConnection, accepted).state, TCPState.STATE_ESTABLISHED)

	def test_accept_returns_none_before_established(self):
		ln = TCPListener(0x0A000001, 80)
		ln._recv_packet(
			TCPPacket(
				src_port = 12345,
				dst_port = 80,
				flags = TCPFlags.FG_SYN,
				seq_num = 5000,
				window = 65535,
			)
		)
		self.assertIsNone(ln.accept())


class UnitEvents(unittest.TestCase):
	"""TCPConnection event hooks."""
	def setUp(self):
		self.conn = TCPConnection()

	def test_state_change_fires(self):
		states = []
		self.conn.on_state_change(lambda old, new: states.append((old, new)))
		self.conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self.assertEqual(len(states), 1)
		self.assertEqual(states[0], (TCPState.STATE_CLOSED, TCPState.STATE_SYN_SENT))

	def test_connection_established_fires(self):
		called = []
		self.conn.on_connection_established(lambda: called.append(1))
		self.conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(self.conn)
		self.assertEqual(called, [1])

	def test_connection_closed_fires_on_abort(self):
		called = []
		self.conn.on_connection_closed(lambda: called.append(1))
		self.conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(self.conn)
		self.conn.event_abort()
		self.assertEqual(called, [1])

	def test_data_sent_fires(self):
		called = []
		self.conn.on_data_sent(lambda data: called.append(data))
		self.conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(self.conn)
		self.conn.event_send(b"hello")
		self.assertEqual(len(called), 1)
		self.assertEqual(called[0], b"hello")

	def test_data_received_fires(self):
		called = []
		self.conn.on_data_received(lambda data: called.append(data))
		self.conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		self._handshake(self.conn)
		self.conn._recv_packet(
			TCPPacket(
				src_port = 80,
				dst_port = 12345,
				flags = TCPFlags.FG_ACK,
				seq_num = 5001,
				ack_num = self.conn.send_una,
				payload = b"world",
				window = 65535,
			)
		)
		data = self.conn.event_receive(100)
		self.assertEqual(len(called), 1)
		self.assertEqual(called[0], b"world")
		self.assertEqual(data, b"world")

	def test_retransmit_fires(self):
		called = []
		self.conn.on_retransmit(lambda: called.append(1))
		self.conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		# Fire RTO directly to trigger retransmit
		self.conn._fire_timer("RTO")
		self.assertEqual(called, [1])

	def _handshake(self, conn):
		conn._recv_packet(
			TCPPacket(
				src_port = conn.dst_port,
				dst_port = conn.src_port,
				flags = TCPFlags.FG_SYN | TCPFlags.FG_ACK,
				seq_num = 5000,
				ack_num = conn.send_isn + 1,
				window = 65535,
			)
		)


class UnitRetransmit(unittest.TestCase):
	"""SYN retransmit: verify the SYN is re-enqueued with FG_SYN on RTO."""
	def test_syn_retransmit_preserves_flags(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)

		# The original SYN should be in dst_retransmit and in_flight
		self.assertEqual(len(conn.dst_retransmit), 1)
		orig_syn = conn.dst_retransmit[0]
		self.assertTrue(orig_syn.flags & TCPFlags.FG_SYN)
		self.assertEqual(len(conn._in_flight), 1)

		# Drain the original SYN (simulate sending it)
		conn.dst_retransmit.clear()

		# Fire RTO — should re-enqueue a SYN (not an ACK)
		conn._fire_timer("RTO")
		self.assertEqual(len(conn.dst_retransmit), 1)
		retrans = conn.dst_retransmit[0]
		self.assertTrue(retrans.flags & TCPFlags.FG_SYN, "Retransmitted SYN must have SYN flag")

	def test_syn_rto_backoff(self):
		conn = TCPConnection()
		conn.event_open(0x0A000001, 12345, 0x0A000002, 80)
		conn.dst_retransmit.clear()
		initial_rto = conn._rto

		conn._fire_timer("RTO")
		self.assertGreater(conn._rto, initial_rto, "RTO should double on retransmit")


class UnitTCPPacketEncodeDecode(unittest.TestCase):
	"""Round-trip encode/decode for tcp_pkt."""
	def test_syn_encode_decode(self):
		ipv4 = IPv4Packet()
		ipv4.src_addr = 0x0A000001
		ipv4.dst_addr = 0x0A000002

		tcp = TCPPacket(
			src_port = 12345,
			dst_port = 80,
			flags = TCPFlags.FG_SYN,
			seq_num = 0x12345678,
			ack_num = 0,
			window = 65535,
		)
		ipv4.payload = tcp
		raw = ipv4.encode_packet()
		tcp_raw = raw[20:] # skip IPv4 header

		tcp2 = TCPPacket()
		tcp2.decode_packet_ipv4(tcp_raw, ipv4, verify_checksum = True)
		self.assertTrue(tcp2.checksum_valid)
		self.assertEqual(tcp2.src_port, 12345)
		self.assertEqual(tcp2.dst_port, 80)
		self.assertTrue(tcp2.flags & TCPFlags.FG_SYN)

	def test_data_encode_decode(self):
		ipv4 = IPv4Packet()
		ipv4.src_addr = 0x0A000001
		ipv4.dst_addr = 0x0A000002

		tcp = TCPPacket(
			src_port = 12345,
			dst_port = 80,
			flags = TCPFlags.FG_ACK | TCPFlags.FG_PSH,
			seq_num = 100,
			ack_num = 200,
			window = 65535,
			payload = b"hello world",
		)
		ipv4.payload = tcp
		raw = ipv4.encode_packet()
		tcp_raw = raw[20:]

		tcp2 = TCPPacket()
		tcp2.decode_packet_ipv4(tcp_raw, ipv4, verify_checksum = True)
		self.assertTrue(tcp2.checksum_valid)
		self.assertEqual(tcp2.payload, b"hello world")
		self.assertEqual(tcp2.seq_num, 100)
		self.assertEqual(tcp2.ack_num, 200)

	def test_fin_encode_decode(self):
		ipv4 = IPv4Packet()
		ipv4.src_addr = 0x0A000001
		ipv4.dst_addr = 0x0A000002

		tcp = TCPPacket(
			src_port = 12345,
			dst_port = 80,
			flags = TCPFlags.FG_FIN | TCPFlags.FG_ACK,
			seq_num = 300,
			ack_num = 400,
			window = 65535,
		)
		ipv4.payload = tcp
		raw = ipv4.encode_packet()
		tcp_raw = raw[20:]

		tcp2 = TCPPacket()
		tcp2.decode_packet_ipv4(tcp_raw, ipv4, verify_checksum = True)
		self.assertTrue(tcp2.checksum_valid)
		self.assertTrue(tcp2.flags & TCPFlags.FG_FIN)
		self.assertTrue(tcp2.flags & TCPFlags.FG_ACK)


UNIT_CLASSES = [
	UnitBitwiseCodecs,
	UnitOptionsCodecs,
	UnitSequenceHelpers,
	UnitConnectionEstablishment,
	UnitDataTransfer,
	UnitConnectionClose,
	UnitCongestionControl,
	UnitRstHandling,
	UnitTimers,
	UnitListener,
	UnitEvents,
	UnitRetransmit,
	UnitTCPPacketEncodeDecode,
]
