import collections
import hashlib
import struct
import random
import hmac
import time

from typing import Optional
from nacl.public import (
	PrivateKey,
	PublicKey
)


from .exceptions import (
	WireguardException,
	WireguardHandshakeException,
	WireguardCodecException
)
from .functions import (
	wg_hash,
	wg_mac,
	wg_hmac,
	wg_kdf1,
	wg_kdf2,
	wg_kdf3,
	wg_aead_encrypt,
	wg_aead_decrypt,
	wg_xaead_encrypt,
	wg_xaead_decrypt,
	wg_x25519_exchange,
	wg_pad
)
from .constants import (
	TEMPLATE_CONSTRUCTION,
	TEMPLATE_IDENTIFIER,
	TEMPLATE_LABEL_MAC,
	TEMPLATE_LABEL_COOKIE,
	TEMPLATE_EMPTY_MAC,
	TEMPLATE_EMPTY_KEY,

	MessageTypes,

	STRUCT_HEADER,
	STRUCT_MACS,
	STRUCT_HANDSHAKE_REQ,
	STRUCT_HANDSHAKE_RES,
	STRUCT_COOKIE_REPLY,
	STRUCT_TRANSPORT,

	LEN_HEADER,
	LEN_MACS,
	LEN_HANDSHAKE_REQ,
	LEN_HANDSHAKE_REQ_TOTAL,
	LEN_HANDSHAKE_RES,
	LEN_COOKIE_REPLY,
	LEN_TRANSPORT,

	STATE_REKEY_AFTER_MSGS,
	STATE_REJECT_AFTER_MSGS,
	STATE_REKEY_AFTER_TIME,
	STATE_REJECT_AFTER_TIME,
	STATE_REKEY_ATTEMPT_TIME,
	STATE_REKEY_TIMEOUT,
	STATE_KEEPALIVE_TIMEOUT,
	STATE_COOKIE_LIFETIME,

	INITIAL_CHAINING_KEY,
	INITIAL_HANDSHAKE_HASH,
)
from .tai64n import (
	current_tai64n,
	encode_tai64n,
	decode_tai64n
)
from .packet_replay import PacketReplay


def wg_ident_header(pkt: bytes) -> MessageTypes:
	if len(pkt) < LEN_HEADER:
		raise WireguardCodecException("Provided packet is smaller than the header size")

	return MessageTypes(*struct.unpack(STRUCT_HEADER, pkt[:LEN_HEADER]))

class KeyPair:
	def __init__(self):
		self.reset()

	def reset(self):
		self.send_count: int = 0
		self.send_last: float = 0
		self.send_key: bytes = b""

		self.recv_count: int = 0
		self.recv_last: float = 0
		self.recv_key: bytes = b""

		self.created: float = 0
		self.valid: bool = False

		self.replay = PacketReplay()

		self.src_ident = 0 # The local identifier
		self.dst_ident = 0 # The remote identifier

	def derive_keypair(self, value: "Handshake"):
		self.send_count = 0
		self.send_last = value.handshake_done

		self.recv_count = 0
		self.recv_last = value.handshake_done

		self.created = value.handshake_done
		self.valid = True

		self.replay.reset()

		self.src_ident = value.src_ident
		self.dst_ident = value.dst_ident

		if value.initiator:
			(self.send_key, self.recv_key) = wg_kdf2(value.chaining_key, b"")
		else:
			(self.recv_key, self.send_key) = wg_kdf2(value.chaining_key, b"")


class Handshake:
	def __init__(self, src_key_pri: Optional[PrivateKey], dst_key_pub: Optional[PublicKey], preshared_key: Optional[bytes] = None):
		self.reinitialize(src_key_pri, dst_key_pub, preshared_key)

	def update_src_key(self, src_key_pri: Optional[PrivateKey]):
		if src_key_pri:
			src_key_pub = src_key_pri.public_key

			self.src_key_pri = src_key_pri
			self.src_key_pub = src_key_pub
		else:
			src_key_pub = None

			self.src_key_pri = None
			self.src_key_pub = None

		if src_key_pub:
			self.src_cookie_hash = wg_hash(TEMPLATE_LABEL_COOKIE + src_key_pub.encode())
			self.src_mac_hash = wg_hash(TEMPLATE_LABEL_MAC + src_key_pub.encode())
		else:
			self.src_cookie_hash = None
			self.src_mac_hash = None

	def update_dst_key(self, dst_key_pub: Optional[PublicKey]):
		if dst_key_pub:
			self.dst_key_pub = dst_key_pub
		else:
			self.dst_key_pub = None

		if dst_key_pub:
			self.dst_cookie_hash = wg_hash(TEMPLATE_LABEL_COOKIE + dst_key_pub.encode())
			self.dst_mac_hash = wg_hash(TEMPLATE_LABEL_MAC + dst_key_pub.encode())
		else:
			self.dst_cookie_hash = None
			self.dst_mac_hash = None

	def update_preshared_key(self, preshared_key: Optional[bytes] = None):
		if preshared_key:
			assert len(preshared_key) == 32, "Pre-shared key must be 32-bytes in length when provided"
			self.preshared_key = preshared_key
		else:
			self.preshared_key = TEMPLATE_EMPTY_KEY

	def reinitialize(self, src_key_pri: Optional[PrivateKey], dst_key_pub: Optional[PublicKey], preshared_key: Optional[bytes] = None):
		self.src_ephemeral: Optional[PrivateKey] = None # The ephemeral private key we generated for ourselves
		self.dst_ephemeral: Optional[PublicKey]  = None # The ephemeral public key we received from the peer

		self.handshake_done: float
		self.handshake_hash: bytes
		self.chaining_key: bytes
		self.timestamp: float

		self.initiator: Optional[bool] = None

		self.src_ident: int = 0 # The local identifier
		self.dst_ident: int = 0 # The remote identifier

		self.src_cookie_hash: Optional[bytes] = None # For encrypting cookie replies
		self.dst_cookie_hash: Optional[bytes] = None # For decrypting cookie replies
		self.cookie_expected: bool = False
		self.cookie_time: float = 0
		self.cookie_key: Optional[bytes] = None
		self.cookie_val: Optional[bytes] = None

		self.src_key_pri: Optional[PrivateKey] = None
		self.src_key_pub: Optional[PublicKey] = None
		self.dst_key_pub: Optional[PublicKey] = None

		self.preshared_key: bytes = TEMPLATE_EMPTY_KEY

		self.src_last_mac_a: Optional[bytes] = None # Last MAC A that we sent
		self.dst_last_mac_a: Optional[bytes] = None # Last MAC A that we received

		self.src_mac_hash: Optional[bytes] = None # For inbound MAC addresses
		self.dst_mac_hash: Optional[bytes] = None # For outbound MAC addresses

		self.update_src_key(src_key_pri)
		self.update_dst_key(dst_key_pub)

		self.update_preshared_key(preshared_key)

	def _update_ephemeral(self):
		ephemeral_pri = PrivateKey.generate()
		ephemeral_pub = ephemeral_pri.public_key

		src_ident = random.randint(0x00000001, 0xFFFFFFFE)

		self.src_ephemeral = ephemeral_pri
		self.src_ident = src_ident

		return ephemeral_pri.encode(), ephemeral_pub.encode(), src_ident

	def _update_cookie_key(self):
		current_time = time.monotonic()

		if not self.cookie_key or current_time - self.cookie_time > STATE_COOKIE_LIFETIME:
			self.cookie_expected = False
			self.cookie_time = current_time
			self.cookie_key = random.randbytes(24)
			self.cookie_val = None

		return self.cookie_key

	def _validate_mac_a(self, packet: bytes, mac_a: bytes):
		if not self.src_mac_hash:
			raise WireguardHandshakeException("Cannot validate MAC 1 without the source mac hash")

		if wg_mac(self.src_mac_hash, packet[:-LEN_MACS]) != mac_a:
			raise WireguardHandshakeException("Failed to validate MAC 1 value")

	def _validate_mac_b(self, packet: bytes, mac_b: bytes):
		if self.initiator:
			return

		if not self.cookie_expected and mac_b == TEMPLATE_EMPTY_MAC:
			return
		
		if not self.cookie_val:
			raise WireguardHandshakeException("Cannot check MAC 2 without the cookie value")

		if wg_mac(self.cookie_val, packet[:-LEN_MACS // 2]) != mac_b:
			raise WireguardHandshakeException("Failed to validate MAC 2 value")

	def _validate_macs(self, packet: bytes, mac_a: bytes, mac_b: bytes):
		self._validate_mac_a(packet, mac_a)
		self._validate_mac_b(packet, mac_b)

		self.dst_last_mac_a = mac_a

	def _encode_macs(self, packet: bytes):
		if not self.dst_mac_hash:
			raise WireguardHandshakeException("Cannot encode MAC 1 without the destination mac hash")

		mac_a = wg_mac(self.dst_mac_hash, packet)

		cookie_data = self.cookie_val
		cookie_time = self.cookie_time

		if cookie_data and time.monotonic() - cookie_time < STATE_COOKIE_LIFETIME:
			mac_b = wg_mac(cookie_data, packet + mac_a)
		else:
			mac_b = TEMPLATE_EMPTY_MAC

		self.src_last_mac_a = mac_a

		return struct.pack(
			STRUCT_MACS,
			mac_a, mac_b
		)

	def _ensure_initiator(self, action: str):
		if not self.initiator:
			raise WireguardHandshakeException(f"Cannot {action} as the responder")

	def _ensure_responder(self, action: str):
		if self.initiator:
			raise WireguardHandshakeException(f"Cannot {action} as the initiator")

	def _become_initiator(self):
		self.initiator = True

	def _become_responder(self):
		self.initiator = False

	def _handshake_complete(self):
		self.handshake_done = time.monotonic()

	def derive_keypair(self, pair: KeyPair):
		pair.send_count = 0
		pair.send_last = self.handshake_done

		pair.recv_count = 0
		pair.recv_last = self.handshake_done

		pair.created = self.handshake_done
		pair.valid = True

		pair.replay.reset()

		pair.src_ident = self.src_ident
		pair.dst_ident = self.dst_ident

		if self.initiator:
			(pair.send_key, pair.recv_key) = wg_kdf2(self.chaining_key, b"")
		else:
			(pair.recv_key, pair.send_key) = wg_kdf2(self.chaining_key, b"")

	# 5.4.2 First Message: Initiator to Responder
	def encode_handshake_req(self):
		self._become_initiator()

		if not self.dst_key_pub:
			raise WireguardHandshakeException("Cannot encode handshake request without the destination (responder) static public key set")

		if not self.src_key_pri or not self.src_key_pub:
			raise WireguardHandshakeException("Cannot encode handshake request without the source (initiator) static keys set")

		(ephemeral_pri, ephemeral_pub, src_ident) = self._update_ephemeral()

		initiator_pri = self.src_key_pri.encode()
		initiator_pub = self.src_key_pub.encode()
		responder_pub = self.dst_key_pub.encode()

		current_time = time.time()

		handshake_hash = INITIAL_HANDSHAKE_HASH
		chaining_key = INITIAL_CHAINING_KEY

		handshake_hash = wg_hash(handshake_hash + responder_pub)
		handshake_hash = wg_hash(handshake_hash + ephemeral_pub)

		chaining_key = wg_kdf1(chaining_key, ephemeral_pub)

		(chaining_key, key) = wg_kdf2(chaining_key, wg_x25519_exchange(ephemeral_pri, responder_pub))

		encrypted_static = wg_aead_encrypt(key, 0, initiator_pub, handshake_hash)

		handshake_hash = wg_hash(handshake_hash + encrypted_static)

		(chaining_key, key) = wg_kdf2(chaining_key, wg_x25519_exchange(initiator_pri, responder_pub))

		encrypted_timestamp = wg_aead_encrypt(key, 0, encode_tai64n(current_time), handshake_hash)
		handshake_hash = wg_hash(handshake_hash + encrypted_timestamp)

		handshake_hdr = struct.pack(STRUCT_HEADER, MessageTypes.MSG_HANDSHAKE_REQ)
		handshake_pkt = handshake_hdr + struct.pack(
			STRUCT_HANDSHAKE_REQ,
			src_ident,
			ephemeral_pub,
			encrypted_static,
			encrypted_timestamp
		)
		handshake_macs = self._encode_macs(handshake_pkt)

		self.handshake_hash = handshake_hash
		self.chaining_key = chaining_key
		self.timestamp = current_time

		return handshake_pkt + handshake_macs

	# 5.4.2 First Message: Initiator to Responder
	def decode_handshake_req(self, packet: bytes):
		self._become_responder()

		if not self.src_key_pri or not self.src_key_pub:
			raise WireguardHandshakeException("Cannot decode handshake request without the source (responder) static keys set")

		(dst_ident, dst_ephemeral, encrypted_static, encrypted_timestamp) = struct.unpack(STRUCT_HANDSHAKE_REQ, packet[LEN_HEADER:-LEN_MACS])
		(mac_a, mac_b) = struct.unpack(STRUCT_MACS, packet[-LEN_MACS:])

		self._validate_macs(packet, mac_a, mac_b)

		handshake_hash = INITIAL_HANDSHAKE_HASH
		chaining_key = INITIAL_CHAINING_KEY

		responder_pri = self.src_key_pri.encode()
		responder_pub = self.src_key_pub.encode()

		handshake_hash = wg_hash(handshake_hash + responder_pub)
		handshake_hash = wg_hash(handshake_hash + dst_ephemeral)

		chaining_key = wg_kdf1(chaining_key, dst_ephemeral)

		(chaining_key, key) = wg_kdf2(chaining_key, wg_x25519_exchange(responder_pri, dst_ephemeral))

		initiator_pub = wg_aead_decrypt(key, 0, encrypted_static, handshake_hash)

		handshake_hash = wg_hash(handshake_hash + encrypted_static)

		(chaining_key, key) = wg_kdf2(chaining_key, wg_x25519_exchange(responder_pri, initiator_pub))

		decrypted_timestamp = wg_aead_decrypt(key, 0, encrypted_timestamp, handshake_hash)

		handshake_hash = wg_hash(handshake_hash + encrypted_timestamp)

		self.dst_ephemeral = PublicKey(dst_ephemeral)
		self.dst_mac_hash = wg_hash(TEMPLATE_LABEL_MAC + initiator_pub) # For outbound MAC addresses
		self.dst_key_pub = PublicKey(initiator_pub)
		self.dst_ident = dst_ident

		self.handshake_hash = handshake_hash
		self.chaining_key = chaining_key
		self.timestamp = decode_tai64n(decrypted_timestamp)

	# 5.4.3 Second Message: Responder to Initiator
	def encode_handshake_res(self):
		self._ensure_responder("encode handshake response")

		if not self.dst_key_pub:
			raise WireguardHandshakeException("Cannot encode handshake response without a destination (initiator) static public key set")

		if not self.dst_ephemeral:
			raise WireguardHandshakeException("Cannot encode handshake response without a destination (initiator) ephemeral public key set")

		(ephemeral_pri, ephemeral_pub, src_ident) = self._update_ephemeral()

		initiator_pub = self.dst_key_pub.encode()
		dst_ephemeral = self.dst_ephemeral.encode()
		dst_ident = self.dst_ident

		handshake_hash = self.handshake_hash
		chaining_key = self.chaining_key

		chaining_key = wg_kdf1(chaining_key, ephemeral_pub)

		handshake_hash = wg_hash(handshake_hash + ephemeral_pub)

		chaining_key = wg_kdf1(chaining_key, wg_x25519_exchange(ephemeral_pri, dst_ephemeral))
		chaining_key = wg_kdf1(chaining_key, wg_x25519_exchange(ephemeral_pri, initiator_pub))

		(chaining_key, tau, key) = wg_kdf3(chaining_key, self.preshared_key)

		handshake_hash = wg_hash(handshake_hash + tau)

		encrypted_empty = wg_aead_encrypt(key, 0, b"", handshake_hash)

		handshake_hash = wg_hash(handshake_hash + encrypted_empty)

		handshake_hdr = struct.pack(STRUCT_HEADER, MessageTypes.MSG_HANDSHAKE_RES)
		handshake_pkt = handshake_hdr + struct.pack(
			STRUCT_HANDSHAKE_RES,
			src_ident, dst_ident,
			ephemeral_pub,
			encrypted_empty
		)
		handshake_macs = self._encode_macs(handshake_pkt)

		self.handshake_hash = handshake_hash
		self.chaining_key = chaining_key

		self._handshake_complete()

		return handshake_pkt + handshake_macs

	# 5.4.3 Second Message: Responder to Initiator
	def decode_handshake_res(self, packet: bytes):
		self._ensure_initiator("decode handshake response")

		if not self.src_key_pri:
			raise WireguardHandshakeException("Cannot decode handshake response without a source (initiator) static private key set")

		if not self.src_ephemeral:
			raise WireguardHandshakeException("Cannot decode handshake response without a source (initiator) ephemeral key set")

		(dst_ident, src_ident, dst_ephemeral, encrypted_empty) = struct.unpack(STRUCT_HANDSHAKE_RES, packet[LEN_HEADER:-LEN_MACS])
		(mac_a, mac_b) = struct.unpack(STRUCT_MACS, packet[-LEN_MACS:])

		self._validate_macs(packet, mac_a, mac_b)

		if self.src_ident != src_ident:
			raise WireguardHandshakeException("Invalid identity for handshake response")

		src_ephemeral = self.src_ephemeral.encode()
		initiator_pri = self.src_key_pri.encode()

		handshake_hash = self.handshake_hash
		chaining_key = self.chaining_key

		chaining_key = wg_kdf1(chaining_key, dst_ephemeral)

		handshake_hash = wg_hash(handshake_hash + dst_ephemeral)

		chaining_key = wg_kdf1(chaining_key, wg_x25519_exchange(src_ephemeral, dst_ephemeral))
		chaining_key = wg_kdf1(chaining_key, wg_x25519_exchange(initiator_pri, dst_ephemeral))

		(chaining_key, tau, key) = wg_kdf3(chaining_key, self.preshared_key)

		handshake_hash = wg_hash(handshake_hash + tau)

		wg_aead_decrypt(key, 0, encrypted_empty, handshake_hash)

		handshake_hash = wg_hash(handshake_hash + encrypted_empty)

		self.handshake_hash = handshake_hash
		self.chaining_key = chaining_key

		self.dst_ephemeral = PublicKey(dst_ephemeral)
		self.dst_ident = dst_ident

		self._handshake_complete()

	# 5.4.7 Under Load: Cookie Reply Message
	def encode_cookie_reply(self, address: bytes):
		self._ensure_responder("encode cookie reply")

		if not self.dst_last_mac_a:
			raise WireguardHandshakeException("Cannot encode a cookie reply without a message being received (dst_last_mac_a is not set)")
		
		if not self.src_cookie_hash:
			raise WireguardHandshakeException("Cannot encode a cookie reply without the cookie hash set (are our static keys initialized?)")

		cookie_key = self._update_cookie_key()
		cookie_val = wg_mac(cookie_key, address)

		message_nonce = random.randbytes(24)
		encrypted_cookie = wg_xaead_encrypt(self.src_cookie_hash, message_nonce, cookie_val, self.dst_last_mac_a)

		cookie_hdr = struct.pack(STRUCT_HEADER, MessageTypes.MSG_COOKIE_REPLY)
		cookie_pkt = struct.pack(
			STRUCT_COOKIE_REPLY,
			self.dst_ident,
			message_nonce,
			encrypted_cookie
		)

		self.cookie_expected = True
		self.cookie_val = cookie_val

		return cookie_hdr + cookie_pkt

	# 5.4.7 Under Load: Cookie Reply Message
	def decode_cookie_reply(self, packet: bytes):
		self._ensure_initiator("decode cookie reply")

		if not self.src_last_mac_a:
			raise WireguardHandshakeException("Cannot decode a cookie reply without a message being sent (src_last_mac_a is not set)")
		
		if not self.dst_cookie_hash:
			raise WireguardHandshakeException("Cannot decode a cookie reply without the cookie hash set (are the keys of the responder initialized?)")

		(src_ident, message_nonce, encrypted_cookie) = struct.unpack(STRUCT_COOKIE_REPLY, packet[LEN_HEADER:])

		if self.src_ident != src_ident:
			raise WireguardHandshakeException("Invalid identity for cookie reply")

		self.cookie_val = wg_xaead_decrypt(self.dst_cookie_hash, message_nonce, encrypted_cookie, self.src_last_mac_a)
		self.cookie_time = time.monotonic()



class Peer:
	def __init__(self, initiator_pri: Optional[PrivateKey] = None, responder_pub: Optional[PublicKey] = None, preshared_key: Optional[bytes] = None):
		"""
			Exists at a **invalid state** if created without arguments, in such case call `reinitialize` before use.
		"""

		if initiator_pri != None and responder_pub != None:
			self.reinitialize(initiator_pri, responder_pub, preshared_key)
			return

		if initiator_pri != None or responder_pub != None:
			raise ValueError("Received only one of the two keys (initiator private key, responder public key)")

	def reinitialize(self, initiator_pri: PrivateKey, responder_pub: PublicKey, preshared_key: Optional[bytes] = None):
		self.responder_pub = responder_pub

		self.initiator_pri = initiator_pri
		self.initiator_pub = initiator_pri.public_key

		self.prev_keypair = KeyPair()
		self.curr_keypair = KeyPair()
		self.next_keypair = KeyPair()

		self.staged_outbound = collections.deque() # What needs to be sent to the server
		self.handshake = Handshake(initiator_pri, responder_pub, preshared_key)

		self.state_keepalive_last = 0
		self.state_rekey_inbound = False
		self.state_rekey_last = 0

	def get_keypair(self, src_ident = None, dst_ident = None):
		for keypair in (self.curr_keypair, self.next_keypair, self.prev_keypair):
			if keypair.valid and (keypair.src_ident == src_ident or keypair.dst_ident == dst_ident):
				return keypair

	def encode_transport(self, packet):
		keypair = self.curr_keypair

		if not keypair.valid:
			raise WireguardException("Cannot prepare packet for transmission without a valid current key-pair")

		transport_hdr = struct.pack(STRUCT_HEADER, MessageTypes.MSG_TRANSPORT) + struct.pack(
			STRUCT_TRANSPORT,
			keypair.dst_ident,
			keypair.send_count
		)

		transport_pkt = wg_aead_encrypt(keypair.send_key, keypair.send_count, packet, b"")
	
		keypair.send_count += 1
		keypair.send_last = time.monotonic()

		self.staged_outbound.append(transport_hdr + transport_pkt)

	def decode_transport(self, packet):
		packet = packet[LEN_HEADER:]

		header_length = struct.calcsize(STRUCT_TRANSPORT)
		packet_header = packet[:header_length]
		packet_content = packet[header_length:]

		(dst_ident, counter) = struct.unpack(STRUCT_TRANSPORT, packet_header)

		keypair = self.get_keypair(dst_ident)

		if not keypair:
			raise WireguardException("Could not find keypair for identifier")

		data = wg_aead_decrypt(keypair.recv_key, counter, packet_content, b"")

		keypair.recv_count += 1
		keypair.recv_last = time.monotonic()

		if data == b"":
			print("Keep alive received")
			return None

		return data

	def decode_packet(self, packet):
		packet_type = wg_ident_header(packet)

		#print(f"decode_packet: {packet_type.name}")
		match packet_type:
			case MessageTypes.MSG_HANDSHAKE_REQ:
				print("Received a handshake request as the client")
				pass

			case MessageTypes.MSG_HANDSHAKE_RES:
				if not self.state_rekey_inbound:
					return print("Received a handshake response that we didn't ask for")

				self.state_rekey_inbound = False

				a = self.prev_keypair
				b = self.curr_keypair
				self.curr_keypair = a
				self.prev_keypair = b

				self.handshake.decode_handshake_res(packet)
				self.handshake.derive_keypair(a)

				print("Rekey complete")

			case MessageTypes.MSG_COOKIE_REPLY:
				print("Received a cookie response")
				pass

			case MessageTypes.MSG_TRANSPORT:
				return self.decode_transport(packet)

	def _update_keypair(self):
		curr_keypair = self.curr_keypair
		curr_time = time.monotonic()
		handshake = self.handshake

		# Can we try to rekey again?
		if self.state_rekey_inbound and curr_time - self.state_rekey_last <= STATE_REKEY_TIMEOUT:
			return

		state_rekey_time = curr_time - curr_keypair.created >= STATE_REKEY_AFTER_TIME
		state_rekey_msgs = curr_keypair.send_count >= STATE_REKEY_AFTER_MSGS

		if not curr_keypair.valid or state_rekey_time or state_rekey_msgs:
			self.state_rekey_inbound = True
			self.state_rekey_last = curr_time
			self.staged_outbound.append(handshake.encode_handshake_req())
			print("Rekey scheduled")
	
	def _update_keepalive(self):
		curr_keypair = self.curr_keypair
		curr_time = time.monotonic()

		if not curr_keypair.valid:
			return

		if curr_time - self.state_keepalive_last <= STATE_KEEPALIVE_TIMEOUT:
			return

		if curr_time - curr_keypair.send_last > STATE_KEEPALIVE_TIMEOUT:
			self.state_keepalive_last = curr_time
			self.encode_transport(b"")
			print("Keep alive scheduled")

	def update_state(self):
		self._update_keypair()
		self._update_keepalive()

		while len(self.staged_outbound):
			yield self.staged_outbound.popleft()

