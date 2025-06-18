import hashlib
import random
import hmac
import math
import time

from nacl.bindings import (
	crypto_aead_chacha20poly1305_ietf_encrypt as chacha20poly1305_encrypt,
	crypto_aead_chacha20poly1305_ietf_decrypt as chacha20poly1305_decrypt,
	crypto_aead_xchacha20poly1305_ietf_encrypt as xchacha20poly1305_encrypt,
	crypto_aead_xchacha20poly1305_ietf_decrypt as xchacha20poly1305_decrypt,
	crypto_scalarmult as wg_x25519_exchange,
)


def wg_hash(val: bytes) -> bytes:
	return hashlib.blake2s(val, digest_size = 32).digest()


def wg_mac(key: bytes, msg: bytes):
	return hashlib.blake2s(msg, digest_size = 16, key = key).digest()


def wg_hmac(key: bytes, msg: bytes) -> bytes:
	return hmac.new(key, msg, hashlib.blake2s).digest()


def wg_kdf1(key: bytes, msg: bytes) -> bytes:
	chain = wg_hmac(key, msg)
	a = wg_hmac(chain, b'\x01')

	return a


def wg_kdf2(key: bytes, msg: bytes) -> tuple[bytes, bytes]:
	chain = wg_hmac(key, msg)
	a = wg_hmac(chain, b'\x01')
	b = wg_hmac(chain, a + b'\x02')

	return (a, b)


def wg_kdf3(key: bytes, msg: bytes) -> tuple[bytes, bytes, bytes]:
	chain = wg_hmac(key, msg)
	a = wg_hmac(chain, b'\x01')
	b = wg_hmac(chain, a + b'\x02')
	c = wg_hmac(chain, b + b'\x03')

	return (a, b, c)


def wg_aead_encrypt(key: bytes, idx: int, msg: bytes, associated_data: bytes) -> bytes:
	return chacha20poly1305_encrypt(
		msg,
		associated_data,
		b"\x00\x00\x00\x00" + idx.to_bytes(8, "little", signed = False),
		key,
	)


def wg_aead_decrypt(key: bytes, idx: int, msg: bytes, associated_data: bytes) -> bytes:
	return chacha20poly1305_decrypt(
		msg,
		associated_data,
		b"\x00\x00\x00\x00" + idx.to_bytes(8, "little", signed = False),
		key,
	)


def wg_xaead_encrypt(key: bytes, nonce: bytes, msg: bytes, associated_data: bytes) -> bytes:
	return xchacha20poly1305_encrypt(msg, associated_data, nonce, key)


def wg_xaead_decrypt(key: bytes, nonce: bytes, msg: bytes, associated_data: bytes) -> bytes:
	return xchacha20poly1305_decrypt(msg, associated_data, nonce, key)


def wg_pad(msg: bytes, block: int = 16):
	msg_len = len(msg)
	pad_len = math.ceil(msg_len / block) - msg_len

	return msg + (b"\x00" * pad_len)


def wg_random_bytes(size: int):
	return random.randbytes(size)


def wg_random_int(minimum: int, maximum: int):
	return random.randint(minimum, maximum)


def wg_time():
	return time.monotonic()


__all__ = [
	"wg_x25519_exchange",
	"wg_hash",
	"wg_mac",
	"wg_hmac",
	"wg_kdf1",
	"wg_kdf2",
	"wg_kdf3",
	"wg_aead_encrypt",
	"wg_aead_decrypt",
	"wg_xaead_encrypt",
	"wg_xaead_decrypt",
	"wg_pad",
	"wg_random_bytes",
	"wg_random_int",
	"wg_time",
]
