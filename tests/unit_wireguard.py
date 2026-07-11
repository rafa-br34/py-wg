import src.wireguard as wg

from src.wireguard.constants import TEMPLATE_EMPTY_MAC, STATE_COOKIE_LIFETIME, LEN_MACS
from src.wireguard.exceptions import WireguardHandshakeException
from src.wireguard.functions import wg_pad
from src.wireguard.packet_replay import PacketReplay

import unittest
import random
import time

from nacl.public import PrivateKey


def check_handshake_equality(unit: unittest.TestCase, src_handshake: wg.Handshake, dst_handshake: wg.Handshake):
	unit.assertEqual(src_handshake.handshake_hash, dst_handshake.handshake_hash, "Handshake hash mismatch")
	unit.assertEqual(src_handshake.chaining_key, dst_handshake.chaining_key, "Chaining key mismatch")


def check_derivation(unit: unittest.TestCase, src_handshake: wg.Handshake, dst_handshake: wg.Handshake):
	src_keypair = wg.KeyPair()
	dst_keypair = wg.KeyPair()

	src_handshake.derive_keypair(src_keypair)
	dst_handshake.derive_keypair(dst_keypair)

	unit.assertEqual(
		src_keypair.send_key, dst_keypair.recv_key, "Key derivation failed src_keypair.send_key != dst_keypair.recv_key"
	)
	unit.assertEqual(
		dst_keypair.send_key, src_keypair.recv_key, "Key derivation failed dst_keypair.send_key != src_keypair.recv_key"
	)


class UnitHandshake(unittest.TestCase):
	def setUp(self):
		src_key_pri = PrivateKey.generate()
		dst_key_pri = PrivateKey.generate()
		dst_key_pub = dst_key_pri.public_key

		self.src_handshake = wg.Handshake(src_key_pri, dst_key_pub)
		self.dst_handshake = wg.Handshake(dst_key_pri, None)

	def test_key_derivation(self):
		src_handshake = self.src_handshake
		dst_handshake = self.dst_handshake

		for _ in range(64):
			# (Initiator) Handshake request -> (Responder)
			encoded_req = src_handshake.encode_handshake_req()
			dst_handshake.decode_handshake_req(encoded_req)

			# (Responder) Handshake response -> (Initiator)
			encoded_res = dst_handshake.encode_handshake_res()
			src_handshake.decode_handshake_res(encoded_res)

			check_handshake_equality(self, src_handshake, dst_handshake)
			check_derivation(self, src_handshake, dst_handshake)

	def test_key_derivation_preshared(self):
		src_handshake = self.src_handshake
		dst_handshake = self.dst_handshake

		for _ in range(64):
			preshared_key = random.randbytes(32)
			src_handshake.preshared_key = preshared_key
			dst_handshake.preshared_key = preshared_key

			# (Initiator) Handshake request -> (Responder)
			encoded_req = src_handshake.encode_handshake_req()
			dst_handshake.decode_handshake_req(encoded_req)

			# (Responder) Handshake response -> (Initiator)
			encoded_res = dst_handshake.encode_handshake_res()
			src_handshake.decode_handshake_res(encoded_res)

			check_handshake_equality(self, src_handshake, dst_handshake)
			check_derivation(self, src_handshake, dst_handshake)

	def test_timestamp_replay_rejection(self):
		"""5.1: responder must reject handshake requests with timestamps <= last seen."""
		src_handshake = self.src_handshake
		dst_handshake = self.dst_handshake

		encoded_req = src_handshake.encode_handshake_req()
		dst_handshake.decode_handshake_req(encoded_req)

		with self.assertRaises(WireguardHandshakeException):
			dst_handshake.decode_handshake_req(encoded_req)

	def test_key_derivation_cookie(self):
		src_handshake = self.src_handshake
		dst_handshake = self.dst_handshake

		for _ in range(64):
			address = random.randbytes(random.choice([4 + 2, 16 + 2]))

			dst_handshake.cookie_expected = False

			# (Initiator) Handshake request -> (Responder)
			encoded_req = src_handshake.encode_handshake_req()
			dst_handshake.decode_handshake_req(encoded_req)

			# (Responder) Cookie reply -> (Initiator)
			encoded_cookie = dst_handshake.encode_cookie_reply(address)
			src_handshake.decode_cookie_reply(encoded_cookie)

			# (Initiator) Handshake request -> (Responder)
			encoded_req = src_handshake.encode_handshake_req()
			dst_handshake.decode_handshake_req(encoded_req)

			# (Responder) Handshake response -> (Initiator)
			encoded_res = dst_handshake.encode_handshake_res()
			src_handshake.decode_handshake_res(encoded_res)

			check_handshake_equality(self, src_handshake, dst_handshake)
			check_derivation(self, src_handshake, dst_handshake)


class UnitTimedLogic(unittest.TestCase):
	def setUp(self):
		self._monotonic_function = time.monotonic
		self._monotonic_time = 0

		def monotonic_hook():
			return self._monotonic_time

		time.monotonic = monotonic_hook

	def clock_delta(self, delta):
		self._monotonic_time += delta

	def test_cookie_timer_logic(self):
		src_key_pri = PrivateKey.generate()
		dst_key_pri = PrivateKey.generate()
		dst_key_pub = dst_key_pri.public_key

		src_handshake = wg.Handshake(src_key_pri, dst_key_pub)
		dst_handshake = wg.Handshake(dst_key_pri, None)

		for _ in range(16):
			address = random.randbytes(random.choice([4 + 2, 16 + 2]))

			# (Initiator) Handshake request -> (Responder)
			encoded_req = src_handshake.encode_handshake_req()
			dst_handshake.decode_handshake_req(encoded_req)

			# (Responder) Cookie reply -> (Initiator)
			encoded_cookie = dst_handshake.encode_cookie_reply(address)
			src_handshake.decode_cookie_reply(encoded_cookie)

			self.clock_delta(STATE_COOKIE_LIFETIME + 5)

			self.assertEqual(
				src_handshake._encode_macs(b"")[LEN_MACS // 2:],
				TEMPLATE_EMPTY_MAC,
				"Initiator was expected to ditch MAC 2 after cookie expiration.",
			)

			try:
				# (Initiator) Handshake request -> (Responder)
				encoded_req = src_handshake.encode_handshake_req()
				dst_handshake.decode_handshake_req(encoded_req)
			except WireguardHandshakeException as error:
				# @todo An exception is raised by unittest in this "catch" block thus adding noise to the output log.
				self.fail(f"Responder was expected to accept the request, got \"{error}\" instead.")

			# Finish handshake to check for proper key derivation

			# (Responder) Handshake response -> (Initiator)
			encoded_res = dst_handshake.encode_handshake_res()
			src_handshake.decode_handshake_res(encoded_res)

			check_handshake_equality(self, src_handshake, dst_handshake)
			check_derivation(self, src_handshake, dst_handshake)

	def tearDown(self):
		time.monotonic = self._monotonic_function


class UnitPacketReplay(unittest.TestCase):
	def setUp(self):
		self.replay = PacketReplay()

	def test_valid_sequence(self):
		for i in range(1, 10):
			self.assertTrue(self.replay.check(i), f"Counter {i} should be accepted")

	def test_accept_zero(self):
		self.assertTrue(self.replay.check(0), "Counter zero must be accepted")

	def test_reject_zero_replay(self):
		self.assertTrue(self.replay.check(0))
		self.assertFalse(self.replay.check(0), "Same counter zero must be rejected as replay")

	def test_reject_replay(self):
		self.assertTrue(self.replay.check(1))
		self.assertFalse(self.replay.check(1), "Same counter must be rejected as replay")

	def test_reject_too_old(self):
		self.assertTrue(self.replay.check(100))
		self.assertFalse(self.replay.check(1), "Counter outside window must be rejected")

	def test_out_of_order_within_window(self):
		self.assertTrue(self.replay.check(10))
		self.assertTrue(self.replay.check(5), "Out-of-order within window should be accepted")
		self.assertFalse(self.replay.check(5), "Same out-of-order must be rejected as replay")

	def test_window_sliding(self):
		for i in range(1, 50):
			self.assertTrue(self.replay.check(i))

		self.assertFalse(self.replay.check(1), "Fallen outside window must be rejected")
		self.assertTrue(self.replay.check(50), "New highest counter should be accepted")

	def test_reset(self):
		self.assertTrue(self.replay.check(1))
		self.replay.reset()
		self.assertTrue(self.replay.check(1), "After reset, old counter should be accepted again")


class UnitPadding(unittest.TestCase):
	def test_pad_empty(self):
		self.assertEqual(wg_pad(b""), b"")

	def test_pad_already_aligned(self):
		self.assertEqual(wg_pad(b"A" * 16), b"A" * 16)

	def test_pad_needs_padding(self):
		result = wg_pad(b"A" * 20)
		self.assertEqual(len(result), 32)
		self.assertEqual(result[:20], b"A" * 20)
		self.assertEqual(result[20:], b"\x00" * 12)

	def test_pad_single_byte(self):
		result = wg_pad(b"\x01")
		self.assertEqual(len(result), 16)
		self.assertEqual(result[0:1], b"\x01")
		self.assertEqual(result[1:], b"\x00" * 15)


UNIT_CLASSES = [
	UnitHandshake,
	UnitTimedLogic,
	UnitPacketReplay,
	UnitPadding,
]
