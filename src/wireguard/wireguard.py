import collections
import struct
import time

from typing import Optional
from nacl.public import (PrivateKey, PublicKey)

from .exceptions import (WireguardException)
from .functions import (
	wg_aead_encrypt,
	wg_aead_decrypt,
)
from .constants import (
	MessageTypes,
	STRUCT_HEADER,
	STRUCT_TRANSPORT,
	LEN_HEADER,
	STATE_REKEY_AFTER_MSGS,
	STATE_REKEY_AFTER_TIME,
	STATE_REKEY_TIMEOUT,
	STATE_KEEPALIVE_TIMEOUT,
	HDR_TRANSPORT,
)

from .handshake import Handshake
from .keypair import KeyPair


def wg_ident_header(pkt: memoryview) -> Optional[int]:
	if len(pkt) < LEN_HEADER:
		return None

	return struct.unpack(STRUCT_HEADER, pkt[:LEN_HEADER])[0]


class Peer:
	def __init__(
		self,
		initiator_pri: Optional[PrivateKey] = None,
		responder_pub: Optional[PublicKey] = None,
		preshared_key: Optional[bytes] = None
	):
		"""
			Exists at a **invalid state** if created without arguments, in such case call `reinitialize` before use.
		"""

		if initiator_pri is not None and responder_pub is not None:
			self.reinitialize(initiator_pri, responder_pub, preshared_key)
			return

		if initiator_pri is not None or responder_pub is not None:
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

		transport_pkt = HDR_TRANSPORT
		transport_pkt += struct.pack(STRUCT_TRANSPORT, keypair.dst_ident, keypair.send_count)
		transport_pkt += wg_aead_encrypt(keypair.send_key, keypair.send_count, packet, b"")

		keypair.send_count += 1
		keypair.send_last = time.monotonic()

		self.staged_outbound.append(transport_pkt)

	def decode_transport(self, packet: bytes):
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
