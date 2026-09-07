import collections
import random
import struct
import time

from typing import Optional

from .exceptions import WireguardException, WireguardHandshakeException, WireguardCookieRequired
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
	LEN_TRANSPORT,
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
	# STATE_COOKIE_LIFETIME,
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
		*,
		max_handshake_attempts: Optional[int] = None,
	):
		"""
			Exists at a **invalid state** if created without arguments, in such case call `reinitialize` before use.
		"""

		self.max_handshake_attempts = max_handshake_attempts

		if initiator_pri is not None and responder_pub is not None:
			self.reinitialize(
				initiator_pri, responder_pub, preshared_key, max_handshake_attempts = max_handshake_attempts
			)
			return

		if initiator_pri is not None or responder_pub is not None:
			raise ValueError("Received only one of the two keys (initiator private key, responder public key)")

	def reinitialize(
		self,
		initiator_pri: WireguardPriKey,
		responder_pub: WireguardPubKey,
		preshared_key: Optional[bytes] = None,
		*,
		max_handshake_attempts: Optional[int] = None,
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

		# Avoid re-advertising a sender index that is already in use by one of our
		# keypair slots (handshake.py §5.4 regenerates on collision).
		self.handshake._ident_in_use = self._handshake_ident_in_use

		# DoS posture; see Handshake.under_load (wireguard.pdf §5.3).
		self.handshake.under_load = False

		self.state_connected = False
		self.state_reconnect_begin = None
		self.state_reconnect_timer = 0
		self.state_rekey_begin = None
		self.state_rekey_staged = False

		# F6: bound how many handshake initiations are sent before giving up on an
		# unreachable peer (None = keep retrying, RFC analog wireguard.pdf §6.4).
		self.max_handshake_attempts = max_handshake_attempts
		self.state_handshake_gave_up = False
		self._reconnect_attempts = 0

	@property
	def under_load(self) -> bool:
		return self.handshake.under_load

	@under_load.setter
	def under_load(self, value: bool):
		self.handshake.under_load = bool(value)

	def on_handshake_failed(self, func):
		self._events.attach_handler("handshake_failed", func)

	def _reset_handshake_attempts(self):
		self.state_handshake_gave_up = False
		self._reconnect_attempts = 0

	def request_handshake(self):
		"""Start (or restart) the connection handshake immediately.

		Also re-arms the handshake after ``max_handshake_attempts`` was exhausted
		(§6.4: the attempt counter resets when the user explicitly wants to send).
		"""
		self._reset_handshake_attempts()
		self.state_reconnect_begin = time.monotonic()
		self.state_reconnect_timer = self.state_reconnect_begin - STATE_REKEY_TIMEOUT

	def _handshake_ident_in_use(self, ident: int) -> bool:
		for keypair in (self.curr_keypair, self.prev_keypair, self.next_keypair):
			if keypair.src_ident == ident or keypair.dst_ident == ident:
				return True

		return False

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

		self._rekey_after_send()

		self._stage_packet(transport_pkt)

	def decode_transport(self, packet: bytes):
		# Fixed minimum size: header + receiver/counter + AEAD tag (5.4.6).
		if len(packet) < LEN_HEADER + LEN_TRANSPORT + 16:
			raise WireguardException("Malformed transport message")

		packet = packet[LEN_HEADER:]

		header_length = struct.calcsize(STRUCT_TRANSPORT)
		packet_header = packet[:header_length]
		packet_content = packet[header_length:]

		(dst_ident, counter) = struct.unpack(STRUCT_TRANSPORT, packet_header)

		keypair = self.get_keypair(dst_ident)

		if not keypair:
			raise WireguardException("Could not find keypair for identifier")

		# 6.2 refuse to receive after Reject-After limits
		if keypair.recv_count >= STATE_REJECT_AFTER_MSGS:
			raise WireguardException("Reject-After-Messages limit reached on receive")

		if time.monotonic() - keypair.lifetime >= STATE_REJECT_AFTER_TIME:
			raise WireguardException("Reject-After-Time limit reached on receive")

		# 5.4.6 a counter at/above Reject-After-Messages must be refused outright:
		# the sliding window cannot represent it without ambiguity near 2**64.
		if counter >= STATE_REJECT_AFTER_MSGS:
			raise WireguardException("Reject-After-Messages limit reached on receive")

		# 5.4.6 the AEAD tag is verified first; only authenticated messages may
		# advance the replay window, so forged datagrams cannot poison it.
		data = wg_aead_decrypt(keypair.recv_key, counter, packet_content, b"")

		if not keypair.replay.check(counter):
			raise WireguardException("Replayed transport message detected")

		keypair.next_recv()

		# 6.3 a session we answered as responder is confirmed by the initiator's
		# first authenticated transport data message: promote next -> current.
		if keypair is self.next_keypair:
			old_prev = self.prev_keypair
			self.prev_keypair = self.curr_keypair
			self.curr_keypair = keypair
			self.next_keypair = KeyPair()

			self._session_confirmed()

		# 6.5 authenticated data proves the peer is alive: revive a connection
		# that was (perhaps spuriously) flagged disconnected by the keepalive
		# timeout so outbound traffic is not silently dropped.
		if not self.state_connected:
			self.state_connected = True
			self.state_reconnect_begin = None
			self.state_reconnect_timer = 0
			self._reset_handshake_attempts()

		# 6.2 receive-path rekey trigger (see _rekey_after_recv)
		self._rekey_after_recv()

		if data == b"":
			self._events.fire_handler("keepalive_rx")
			return None

		self._events.fire_handler("message_rx", (data, ))
		return data

	def decode_packet(self, packet, src_address: Optional[bytes] = None):
		packet_type = wg_ident_header(packet)

		match packet_type:
			case MessageTypes.MSG_HANDSHAKE_REQ:
				self._decode_handshake_req_incoming(packet, src_address)

			case MessageTypes.MSG_HANDSHAKE_RES:
				try:
					self.handshake.decode_handshake_res(packet)
				except WireguardCookieRequired:
					self._stage_cookie_reply(packet, src_address)
					return
				except WireguardHandshakeException:
					# Not for us (e.g. no outstanding initiation) or invalid: ignore.
					return

				# Our own initiation was answered: as session initiator we promote
				# immediately and rotate the three-slot keypair chain (5.4.3).
				self._promote_initiated_session()

			case MessageTypes.MSG_COOKIE_REPLY:
				try:
					self.handshake.decode_cookie_reply(packet)
				except WireguardHandshakeException:
					# 6.6 do not immediately retransmit; let Rekey-Timeout handle it
					return

			case MessageTypes.MSG_TRANSPORT:
				return self.decode_transport(packet)

	def _decode_handshake_req_incoming(self, packet: bytes, src_address: Optional[bytes] = None):
		# An initiation from our (configured) peer is answered at any time: the
		# initiator/responder roles are symmetric (5.3) and the session initiator
		# may begin a rekey at any moment.
		try:
			self.handshake.decode_handshake_req(packet, expected_initiator_pub = self.responder_pub.encode())
		except WireguardCookieRequired:
			self._stage_cookie_reply(packet, src_address)
			return
		except WireguardHandshakeException:
			# Invalid MAC 1 / unknown identity / replayed timestamp: stay silent.
			return

		# The peer began a new session. Stop any reconnect initiation of our own
		# (the peer is demonstrably alive) and answer. The new session is held in
		# the "next" slot until the peer's first authenticated transport data
		# message confirms it (6.3), at which point next rotates to current.
		self.state_reconnect_begin = None
		self.state_reconnect_timer = 0
		self.state_rekey_staged = False
		self.state_rekey_begin = None

		self._stage_handshake_res()

		self.handshake.derive_keypair(self.next_keypair)

	def _stage_cookie_reply(self, packet: bytes, src_address: Optional[bytes] = None):
		if src_address is None:
			return # without a source address no cookie can be bound to the peer

		try:
			reply = self.handshake.encode_cookie_reply_for(packet, src_address)
		except WireguardHandshakeException:
			return

		self._stage_packet(reply)

	def _promote_initiated_session(self):
		# 6.3 three-slot key rotation: prev <- curr <- next
		old_prev = self.prev_keypair
		self.prev_keypair = self.curr_keypair
		self.curr_keypair = self.next_keypair
		self.next_keypair = old_prev

		self.handshake.derive_keypair(self.curr_keypair)

		self._session_confirmed()

	def _session_confirmed(self):
		"""A new secure session is usable: clear timers and mark the peer connected."""
		self.state_reconnect_begin = None
		self.state_reconnect_timer = 0
		self.state_rekey_staged = False
		self.state_rekey_begin = None
		self.state_connected = True
		self._reset_handshake_attempts()

		self._events.fire_handler("handshake_complete")

	def _give_up_handshake(self):
		self.state_reconnect_begin = None
		self.state_reconnect_timer = 0
		self.state_handshake_gave_up = True

		self._events.fire_handler("handshake_failed")

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

	# 6.2 Transport Message Limits (send path)
	def _rekey_after_send(self):
		keypair = self.curr_keypair

		if self.state_rekey_begin is not None:
			return

		rekey_msgs = keypair.send_count > STATE_REKEY_AFTER_MSGS
		is_connected = self.state_connected and self.handshake.initiator
		age = time.monotonic() - keypair.lifetime

		# 6.2 the message-count rekey applies to either role; the time-based
		# send-path rekey is restricted to the initiator of the current session.
		if rekey_msgs or (is_connected and age > STATE_REKEY_AFTER_TIME):
			self.state_rekey_begin = time.monotonic()

	# 6.2 Transport Message Limits (receive path)
	def _rekey_after_recv(self):
		if self.state_rekey_begin is not None:
			return

		# 6.2 time-based opportunistic rekeying is restricted to the initiator of
		# the current session and fires once, after an authenticated transport
		# data message is received on a session older than
		# (Reject-After-Time - Keepalive-Timeout - Rekey-Timeout) seconds.
		if not (self.state_connected and self.handshake.initiator):
			return

		if time.monotonic() - self.curr_keypair.lifetime > STATE_REJECT_AFTER_TIME_RX:
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
			self._reset_handshake_attempts()

			self._events.fire_handler("connection_lost")

		reconnect_begin = self.state_reconnect_begin
		reconnect_timer = self.state_reconnect_timer

		if reconnect_begin is not None:
			if curr_time - reconnect_begin >= STATE_REKEY_ATTEMPT_TIME:
				# 6.4 attempts span Rekey-Attempt-Time. Unless a bounded-retry option
				# is configured we simply re-arm below (the FSM never gives up on its
				# own); otherwise the attempt counter decides when to stop.
				self.state_reconnect_begin = None
				self.state_reconnect_timer = 0
			elif curr_time - reconnect_timer >= STATE_REKEY_TIMEOUT:
				if (self.max_handshake_attempts is not None
					and self._reconnect_attempts >= self.max_handshake_attempts):
					self._give_up_handshake()
				else:
					self._reconnect_attempts += 1

					# 6.1 add jitter to prevent thundering herd
					jitter = random.uniform(0, STATE_REKEY_TIMEOUT / 3)

					self.state_reconnect_timer = curr_time + jitter
					self._stage_handshake_req()

		if not self.state_connected:
			# Auto-trigger the initial handshake if no handshake is in progress
			# (never after max_handshake_attempts gave up; restart via request_handshake).
			if (self.state_reconnect_begin is None and self.state_rekey_begin is None
				and not self.state_handshake_gave_up):
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
		# Transport-message-limit rekey triggers live on the send/receive paths
		# (see _rekey_after_send / _rekey_after_recv in encode_transport and
		# decode_transport, RFC 9293 analog wireguard.pdf §6.2).
		self._state_update_keepalive()
		self._state_rekey()

		while len(self.staged_outbound):
			yield self.staged_outbound.popleft()
