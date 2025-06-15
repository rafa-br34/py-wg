import src.wireguard.wireguard as wg

import unittest
import random

from nacl.public import (
	PrivateKey,
	PublicKey
)



class UnitHandshake(unittest.TestCase):
	def setUp(self):
		src_key_pri = PrivateKey.generate()
		dst_key_pri = PrivateKey.generate()
		dst_key_pub = dst_key_pri.public_key

		self.src_handshake = wg.Handshake(src_key_pri, dst_key_pub)
		self.dst_handshake = wg.Handshake(dst_key_pri, None)

		self.src_keypair = wg.KeyPair()
		self.dst_keypair = wg.KeyPair()

	def check_handshake_equality(self, src_handshake: wg.Handshake, dst_handshake: wg.Handshake):
		self.assertEqual(src_handshake.handshake_hash, dst_handshake.handshake_hash, "Handshake hash mismatch")
		self.assertEqual(src_handshake.chaining_key, dst_handshake.chaining_key, "Chaining key mismatch")

	def check_derivation(self, src_handshake: wg.Handshake, dst_handshake: wg.Handshake):
		src_keypair = self.src_keypair
		dst_keypair = self.dst_keypair
	
		src_handshake.derive_keypair(src_keypair)
		dst_handshake.derive_keypair(dst_keypair)

		self.assertEqual(src_keypair.send_key, dst_keypair.recv_key, "Key derivation failed src_keypair.send_key != dst_keypair.recv_key, preshared key not set.")
		self.assertEqual(dst_keypair.send_key, src_keypair.recv_key, "Key derivation failed dst_keypair.send_key != src_keypair.recv_key, preshared key not set.")

	def test_key_derivation(self):
		src_handshake = self.src_handshake
		dst_handshake = self.dst_handshake

		for _ in range(64):
			encoded_req = src_handshake.encode_handshake_req()
			dst_handshake.decode_handshake_req(encoded_req)

			encoded_res = dst_handshake.encode_handshake_res()
			src_handshake.decode_handshake_res(encoded_res)

			self.check_handshake_equality(src_handshake, dst_handshake)
			self.check_derivation(src_handshake, dst_handshake)

	def test_key_derivation_preshared(self):
		src_handshake = self.src_handshake
		dst_handshake = self.dst_handshake

		for _ in range(64):
			preshared_key = random.randbytes(32)
			src_handshake.preshared_key = preshared_key
			dst_handshake.preshared_key = preshared_key

			encoded_req = src_handshake.encode_handshake_req()
			dst_handshake.decode_handshake_req(encoded_req)

			encoded_res = dst_handshake.encode_handshake_res()
			src_handshake.decode_handshake_res(encoded_res)

			self.check_handshake_equality(src_handshake, dst_handshake)
			self.check_derivation(src_handshake, dst_handshake)

	def test_key_derivation_cookie(self):
		src_handshake = self.src_handshake
		dst_handshake = self.dst_handshake

		for _ in range(64):
			address = random.randbytes(random.choice([4 + 2, 16 + 2]))

			dst_handshake.cookie_expected = False

			encoded_req = src_handshake.encode_handshake_req()
			dst_handshake.decode_handshake_req(encoded_req)

			encoded_cookie = dst_handshake.encode_cookie_reply(address)
			src_handshake.decode_cookie_reply(encoded_cookie)

			encoded_req = src_handshake.encode_handshake_req()
			dst_handshake.decode_handshake_req(encoded_req)

			encoded_res = dst_handshake.encode_handshake_res()
			src_handshake.decode_handshake_res(encoded_res)

			self.check_handshake_equality(src_handshake, dst_handshake)
			self.check_derivation(src_handshake, dst_handshake)

UNIT_CLASSES = [
	UnitHandshake
]

