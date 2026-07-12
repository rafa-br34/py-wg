import collections
import random
import struct
import time

from typing import Optional

from .exceptions import WireguardException
from .events import Events
from .functions import (
	wg_aead_encrypt,
	wg_aead_decrypt,
	wg_pad,
	WireguardPubKey,
	WireguardPriKey,
	wg_as_pub_key,
	wg_as_pri_key,
)
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
	STATE_REJECT_AFTER_TIME_RX,
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
		initiator_pri: Optional[WireguardPriKey] = None,
		responder_pub: Optional[WireguardPubKey] = None,
		preshared_key: Optional[bytes] = None,
	):
		"""
			Exists at a **invalid state** if created without arguments, in such case call `reinitialize` before use.
		"""

		if initiator_pri is not None and responder_pub is not None:
			self.reinitialize(initiator_pri, responder_pub, preshared_key)
			return

		if initiator_pri is not None or responder_pub is not None:
			raise ValueError("Received only one of the two keys (initiator private key, responder public key)")

	def reinitialize(
		self,
		initiator_pri: WireguardPriKey,
		responder_pub: WireguardPubKey,
		preshared_key: Optional[bytes] = None,
	):
		_initiator_pri = wg_as_pri_key(initiator_pri)
		_responder_pub = wg_as_pub_key(responder_pub)

		self.responder_pub = _responder_pub

		self.initiator_pri = _initiator_pri
		self.initiator_pub = _initiator_pri.public_key

		self.prev_keypair = KeyPair()
		self.curr_keypair = KeyPair()
		self.next_keypair = KeyPair()

		self._events = Events()

		self.staged_outbound = collections.deque() # What needs to be sent to the server
		self.handshake = Handshake(_initiator_pri, _responder_pub, preshared_key)
		self.handshake._become_initiator()

		self.state_connected = False
		self.state_reconnect_begin = None
		self.state_reconnect_timer = 0
		self.state_rekey_begin = None
		self.state_rekey_staged = False

	def on_keepalive_tx(self, func):
		self._events.attach_handler("keepalive_tx", func)

	def on_keepalive_rx(self, func):
		self._events.attach_handler("keepalive_rx", func)

	def on_message_rx(self, func):
		self._events.attach_handler("message_rx", func)

	def on_handshake_complete(self, func):
		self._events.attach_handler("handshake_complete", func)

	def on_connection_lost(self, func):
		self._events.attach_handler("connection_lost", func)

	def on_handshake_tx_req(self, func):
		self._events.attach_handler("handshake_tx_req", func)

	def on_handshake_tx_res(self, func):
		self._events.attach_handler("handshake_tx_res", func)

	def get_keypair(self, src_ident = None, dst_ident = None):
		for keypair in (self.curr_keypair, self.prev_keypair, self.next_keypair):
			if keypair.src_ident == src_ident or keypair.dst_ident == dst_ident:
				return keypair

	def _stage_packet(self, packet):
		self.staged_outbound.append(packet)

	def _stage_handshake_req(self):
		self._stage_packet(self.handshake.encode_handshake_req())
		self._events.fire_handler("handshake_tx_req")

	def _stage_handshake_res(self):
		self._stage_packet(self.handshake.encode_handshake_res())
		self._events.fire_handler("handshake_tx_res")

	def encode_transport(self, packet):
		keypair = self.curr_keypair

		if not self.state_connected:
			raise WireguardException("Can't encode transport data without being connected.")

		# 6.2 refuse to send after Reject-After limits
		if keypair.send_count >= STATE_REJECT_AFTER_MSGS:
			raise WireguardException("Reject-After-Messages limit reached")

		if time.monotonic() - keypair.lifetime >= STATE_REJECT_AFTER_TIME:
			raise WireguardException("Reject-After-Time limit reached")

		transport_pkt = HDR_TRANSPORT
		transport_pkt += struct.pack(STRUCT_TRANSPORT, keypair.dst_ident, keypair.send_count)
		transport_pkt += wg_aead_encrypt(keypair.send_key, keypair.send_count, wg_pad(packet), b"")

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

		# 5.4.6 replay attack protection using sliding window
		if not keypair.replay.check(counter):
			raise WireguardException("Replayed transport message detected")

		# 6.2 refuse to receive after Reject-After limits
		if keypair.recv_count >= STATE_REJECT_AFTER_MSGS:
			raise WireguardException("Reject-After-Messages limit reached on receive")

		if time.monotonic() - keypair.lifetime >= STATE_REJECT_AFTER_TIME:
			raise WireguardException("Reject-After-Time limit reached on receive")

		data = wg_aead_decrypt(keypair.recv_key, counter, packet_content, b"")

		keypair.next_recv()

		if data == b"":
			self._events.fire_handler("keepalive_rx")
			return None

		self._events.fire_handler("message_rx", (data, ))
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
					# 6.6 do not immediately retransmit; let the Rekey-Timeout timer handle it

			case MessageTypes.MSG_TRANSPORT:
				return self.decode_transport(packet)

		if renew_keypair:
			# 6.3 three-slot key rotation: prev <- curr <- next
			old_prev = self.prev_keypair
			self.prev_keypair = self.curr_keypair
			self.curr_keypair = self.next_keypair
			self.next_keypair = old_prev

			self.handshake.derive_keypair(self.curr_keypair)

			self.state_reconnect_begin = None
			self.state_reconnect_timer = 0
			self.state_rekey_staged = False
			self.state_rekey_begin = None
			self.state_connected = True

			self._events.fire_handler("handshake_complete")

	def _state_rekey(self):
		begin = self.state_rekey_begin

		if begin is None:
			return

		# Reconnect already handles the handshake; don't fire a duplicate
		if self.state_reconnect_begin is not None:
			self.state_rekey_staged = False
			self.state_rekey_begin = None
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
		# 6.2 time-based rekey restricted to initiator of current session
		rekey_time_send = (self.state_connected and self.handshake.initiator and curr_time - curr_keypair.lifetime > STATE_REKEY_AFTER_TIME)
		rekey_time_recv = (
			self.state_connected and self.handshake.initiator and curr_keypair.recv_last > 0
			and curr_time - curr_keypair.lifetime > STATE_REJECT_AFTER_TIME_RX
		)
		if (rekey_time_send or rekey_msgs or rekey_time_recv) and self.state_rekey_begin is None:
			self.state_rekey_begin = time.monotonic()

	# 6.5 Passive Keepalive
	def _state_update_keepalive(self):
		curr_keypair = self.curr_keypair
		curr_time = time.monotonic()

		# 6.5 dead connection detection: no data received for Keepalive-Timeout + Rekey-Timeout
		state_timeout_dst = (
			curr_keypair.recv_last > 0
			and curr_time - curr_keypair.recv_last > STATE_KEEPALIVE_TIMEOUT + STATE_REKEY_TIMEOUT
		)

		if state_timeout_dst and self.state_connected:
			self.state_connected = False
			self.state_reconnect_begin = curr_time
			self.state_reconnect_timer = curr_time

			self._events.fire_handler("connection_lost")

		reconnect_begin = self.state_reconnect_begin
		reconnect_timer = self.state_reconnect_timer

		if reconnect_begin is not None:
			if curr_time - reconnect_begin >= STATE_REKEY_ATTEMPT_TIME:
				self.state_reconnect_begin = None
			elif curr_time - reconnect_timer >= STATE_REKEY_TIMEOUT:
				# 6.1 add jitter to prevent thundering herd
				jitter = random.uniform(0, STATE_REKEY_TIMEOUT / 3)

				self.state_reconnect_timer = curr_time + jitter
				self._stage_handshake_req()

		if not self.state_connected:
			# Auto-trigger the initial handshake if no handshake is in progress
			if self.state_reconnect_begin is None and self.state_rekey_begin is None:
				self.state_reconnect_begin = curr_time
				self.state_reconnect_timer = curr_time - STATE_REKEY_TIMEOUT
			return

		# 6.5 send keepalive when we have received data but haven't sent recently
		state_has_received = curr_keypair.recv_last > 0
		state_send_stale = curr_time - curr_keypair.send_last > STATE_KEEPALIVE_TIMEOUT

		if state_has_received and state_send_stale:
			self.encode_transport(b"")
			self._events.fire_handler("keepalive_tx")

	def update_state(self):
		self._state_update_transport()
		self._state_update_keepalive()
		self._state_rekey()

		while len(self.staged_outbound):
			yield self.staged_outbound.popleft()
