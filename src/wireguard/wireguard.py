import collections
import struct
import time

from typing import Optional
from nacl.public import PrivateKey, PublicKey

from .exceptions import WireguardException
from .functions import wg_aead_encrypt, wg_aead_decrypt
from .constants import (
	MessageTypes,
	STRUCT_HEADER,
	STRUCT_TRANSPORT,
	LEN_HEADER,
	HDR_TRANSPORT,
)
from .constants import (
	STATE_REKEY_AFTER_MSGS,
	STATE_REJECT_AFTER_MSGS,
	STATE_REKEY_AFTER_TIME,
	STATE_REJECT_AFTER_TIME,
	STATE_REKEY_ATTEMPT_TIME,
	STATE_REKEY_TIMEOUT,
	STATE_KEEPALIVE_TIMEOUT,
	STATE_COOKIE_LIFETIME,
)
from .handshake import Handshake
from .keypair import KeyPair


def wg_ident_header(pkt: memoryview) -> Optional[int]:
	if len(pkt) < LEN_HEADER:
		return None

	return struct.unpack(STRUCT_HEADER, pkt[:LEN_HEADER])[0]


class Initiator:
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

		self.staged_outbound = collections.deque() # What needs to be sent to the server
		self.handshake = Handshake(initiator_pri, responder_pub, preshared_key)

		self.state_connected = False
		self.state_reconnect_begin = None
		self.state_reconnect_timer = 0
		self.state_rekey_begin = None
		self.state_rekey_staged = False

	def get_keypair(self, src_ident = None, dst_ident = None):
		for keypair in (self.curr_keypair, self.prev_keypair):
			if keypair.src_ident == src_ident or keypair.dst_ident == dst_ident:
				return keypair

	def _stage_packet(self, packet):
		self.staged_outbound.append(packet)

	def _stage_handshake_req(self):
		self._stage_packet(self.handshake.encode_handshake_req())

	def _stage_handshake_res(self):
		self._stage_packet(self.handshake.encode_handshake_res())

	def encode_transport(self, packet):
		keypair = self.curr_keypair

		if not self.state_connected:
			raise WireguardException("Can't encode transport data without being connected.")

		transport_pkt = HDR_TRANSPORT
		transport_pkt += struct.pack(STRUCT_TRANSPORT, keypair.dst_ident, keypair.send_count)
		transport_pkt += wg_aead_encrypt(keypair.send_key, keypair.send_count, packet, b"")

		keypair.next_send()

		self._stage_packet(transport_pkt)

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

		keypair.next_recv()

		if data == b"":
			return None

		return data

	def decode_packet(self, packet):
		packet_type = wg_ident_header(packet)

		renew_session = self.state_rekey_staged or self.state_reconnect_begin
		renew_keypair = False

		match packet_type:
			case MessageTypes.MSG_HANDSHAKE_REQ:
				if renew_session:
					self.handshake.decode_handshake_req(packet)
					self._stage_handshake_res()

					renew_keypair = True

			case MessageTypes.MSG_HANDSHAKE_RES:
				if renew_session:
					self.handshake.decode_handshake_res(packet)

					renew_keypair = True

			case MessageTypes.MSG_COOKIE_REPLY:
				if renew_session:
					self.handshake.decode_cookie_reply(packet)
					self._stage_handshake_req()

			case MessageTypes.MSG_TRANSPORT:
				return self.decode_transport(packet)

		if renew_keypair:
			a = self.prev_keypair
			b = self.curr_keypair
			self.curr_keypair = a
			self.prev_keypair = b

			self.handshake.derive_keypair(a)

			self.state_reconnect_begin = None
			self.state_reconnect_timer = 0
			self.state_rekey_staged = False
			self.state_rekey_begin = None
			self.state_connected = True

	def _state_rekey(self):
		begin = self.state_rekey_begin

		if begin is None:
			return

		if time.monotonic() - begin > STATE_REKEY_TIMEOUT:
			self.state_rekey_staged = False
			self.state_rekey_begin = None
			return

		if not self.state_rekey_staged:
			self._stage_handshake_req()
			self.state_rekey_staged = True

	# 6.2 Transport Message Limits
	def _state_update_transport(self):
		curr_keypair = self.curr_keypair
		curr_time = time.monotonic()

		rekey_msgs = curr_keypair.send_count > STATE_REKEY_AFTER_MSGS
		# Should be only checked after tx
		rekey_time = curr_time - curr_keypair.lifetime > STATE_REKEY_AFTER_TIME
		# No need to check rx (Reject-After-Time - Keepalive-Timeout - Rekey-Timeout).
		# This runs every iteration and tx will always fire first anyways.
		if (rekey_time or rekey_msgs) and self.state_rekey_begin is None:
			self.state_rekey_begin = time.monotonic()

	# 6.5 Passive Keepalive
	def _state_update_keepalive(self):
		curr_keypair = self.curr_keypair
		curr_time = time.monotonic()

		# @todo This FSM is still very inaccurate to the WireGuard paper.

		state_timeout_src = curr_time - curr_keypair.send_last > STATE_REKEY_TIMEOUT
		state_timeout_dst = curr_time - curr_keypair.recv_last > STATE_KEEPALIVE_TIMEOUT + STATE_REKEY_TIMEOUT

		if (state_timeout_src and state_timeout_dst) and self.state_connected:
			self.state_connected = False
			self.state_reconnect_begin = curr_time
			self.state_reconnect_timer = curr_time

		reconnect_begin = self.state_reconnect_begin
		reconnect_timer = self.state_reconnect_timer

		if reconnect_begin is not None:
			if curr_time - reconnect_begin >= STATE_REKEY_ATTEMPT_TIME:
				self.state_reconnect_begin = None
			elif curr_time - reconnect_timer >= STATE_REKEY_TIMEOUT:
				self.state_reconnect_timer = curr_time
				self._stage_handshake_req()

		if not self.state_connected:
			return

		state_send_keepalive = curr_time - curr_keypair.send_last > STATE_KEEPALIVE_TIMEOUT

		if state_send_keepalive:
			self.encode_transport(b"")

	def update_state(self):
		self._state_update_transport()
		self._state_update_keepalive()
		self._state_rekey()

		while len(self.staged_outbound):
			yield self.staged_outbound.popleft()
