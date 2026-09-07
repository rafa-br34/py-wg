import unittest
import time
import asyncio

from nacl.public import PrivateKey as NaClPrivateKey

from src.wireguard import Initiator, AsyncInitiator, Handshake
from src.wireguard.constants import (
	STATE_KEEPALIVE_TIMEOUT,
	STATE_REKEY_TIMEOUT,
	STATE_REKEY_AFTER_TIME,
	STATE_REJECT_AFTER_TIME_RX,
	STATE_REJECT_AFTER_MSGS,
)
from src.wireguard.exceptions import WireguardException
from src.wireguard.functions import wg_pad

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_responder_keys():
	"""Generate (responder_pri, responder_pub); the keypair the initiator will trust."""
	pri = NaClPrivateKey.generate()
	return pri, pri.public_key


def _complete_handshake(peer: Initiator, responder_pri: NaClPrivateKey):
	"""Drive *peer* through a complete handshake using *responder_pri*.

	The initiator must have been created with ``responder_pri.public_key`` as its
	trusted responder public key.
	"""
	responder = Handshake(responder_pri, None)

	# Stage a handshake request from the initiator
	peer._stage_handshake_req()
	req = peer.staged_outbound.popleft()

	# Simulate the responder receiving and replying
	responder.decode_handshake_req(req)
	res = responder.encode_handshake_res()

	# Feed the response back into the initiator
	peer.state_rekey_staged = True # so decode_packet accepts the response
	peer.decode_packet(res)


def _complete_handshake_pair(
	initiator: Initiator,
	responder: Initiator,
):
	"""Perform a handshake between two peers.

	*initiator* must know *responder*'s public key.  *responder* must NOT know
	*initiator*'s public key (it learns it from the handshake). After this the
	initiator is connected; the responder session is pending until confirmed by
	the initiator's first transport data message (§6.3) - see
	_confirm_responder_session.
	"""
	initiator._stage_handshake_req()
	req = initiator.staged_outbound.popleft()

	# Feed the request through the responder's decode_packet so that key
	# rotation happens on the responder side as well.
	responder.decode_packet(req)
	res = responder.staged_outbound.popleft()

	initiator.decode_packet(res)


def _confirm_responder_session(initiator: Initiator, responder: Initiator):
	"""Confirm a responder-side session with the initiator's first transport data.

	wireguard.pdf §6.3: the responder cannot use (or send on) the new session
	until it has received the initiator's first authenticated transport message.
	"""
	initiator.encode_transport(b"")
	pkt = initiator.staged_outbound.popleft()

	responder.decode_packet(pkt)

	assert responder.state_connected, "Responder session must be confirmed after the first transport message"


# ---------------------------------------------------------------------------
# UnitEvents verify event callbacks fire from the base Initiator
# ---------------------------------------------------------------------------


class UnitEvents(unittest.TestCase):
	def setUp(self):
		self._real_monotonic = time.monotonic
		self._clock = 0.0
		time.monotonic = lambda: self._clock

		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		self._responder_pri = responder_pri
		self.peer = Initiator(initiator_pri, responder_pub)

	def tearDown(self):
		time.monotonic = self._real_monotonic

	def _tick(self, delta: float):
		self._clock += delta

	# -- attach / detach --------------------------------------------------

	def test_attach_and_fire(self):
		called = []
		self.peer.on_keepalive_rx(lambda: called.append(1))
		self.peer._events.fire_handler("keepalive_rx")
		self.assertEqual(called, [1])

	def test_detach_handler(self):
		called = []

		def cb():
			called.append(1)

		self.peer.on_keepalive_rx(cb)
		self.peer._events.detach_handler("keepalive_rx", cb)
		self.peer._events.fire_handler("keepalive_rx")
		self.assertEqual(called, [])

	def test_multiple_handlers(self):
		called = []
		self.peer.on_keepalive_rx(lambda: called.append(1))
		self.peer.on_keepalive_rx(lambda: called.append(2))
		self.peer._events.fire_handler("keepalive_rx")
		self.assertEqual(called, [1, 2])

	# -- message_rx event -------------------------------------------------

	def test_message_rx_fires_on_transport_data(self):
		called = []
		self.peer.on_message_rx(lambda data: called.append(data))
		self.peer._events.fire_handler("message_rx", (b"test-data", ))

		self.assertEqual(len(called), 1)
		self.assertEqual(called[0], b"test-data")

	# -- keepalive_rx event -----------------------------------------------

	def test_keepalive_rx_fires_on_empty_transport(self):
		called = []
		self.peer.on_keepalive_rx(lambda: called.append(1))
		self.peer._events.fire_handler("keepalive_rx")
		self.assertEqual(called, [1])

	# -- decode_transport fires events (integration with real transport) --

	def test_decode_transport_fires_message_rx(self):
		"""End-to-end: responder encodes, initiator decodes → message_rx fires."""
		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		initiator = Initiator(initiator_pri, responder_pub)
		responder = Initiator(responder_pri, initiator_pri.public_key)
		responder.handshake.initiator = False

		_complete_handshake_pair(initiator, responder)
		_confirm_responder_session(initiator, responder)

		called = []
		initiator.on_message_rx(lambda data: called.append(data))

		responder.encode_transport(b"hello")
		pkt = responder.staged_outbound.popleft()
		initiator.decode_packet(pkt)

		self.assertEqual(len(called), 1)
		self.assertEqual(called[0], wg_pad(b"hello"))

	def test_decode_transport_fires_keepalive_rx(self):
		"""End-to-end: responder encodes empty transport → keepalive_rx fires."""
		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		initiator = Initiator(initiator_pri, responder_pub)
		responder = Initiator(responder_pri, initiator_pri.public_key)
		responder.handshake.initiator = False

		_complete_handshake_pair(initiator, responder)
		_confirm_responder_session(initiator, responder)

		called = []
		initiator.on_keepalive_rx(lambda: called.append(1))

		responder.encode_transport(b"")
		pkt = responder.staged_outbound.popleft()
		initiator.decode_packet(pkt)

		self.assertEqual(called, [1])

	# -- handshake_complete event -----------------------------------------

	def test_handshake_complete_fires(self):
		called = []
		self.peer.on_handshake_complete(lambda: called.append(1))

		self.assertFalse(self.peer.state_connected)
		_complete_handshake(self.peer, self._responder_pri)

		self.assertTrue(self.peer.state_connected)
		self.assertEqual(called, [1])

	# -- connection_lost event --------------------------------------------

	def test_connection_lost_fires_on_timeout(self):
		called = []
		self.peer.on_connection_lost(lambda: called.append(1))

		_complete_handshake(self.peer, self._responder_pri)
		self.assertTrue(self.peer.state_connected)

		# recv_last is 0 because the handshake completed at clock=0.
		# Set it to a positive value so the dead-peer check triggers.
		self.peer.curr_keypair.recv_last = 1
		self._tick(STATE_KEEPALIVE_TIMEOUT + STATE_REKEY_TIMEOUT + 2)

		self.peer._state_update_keepalive()
		self.assertFalse(self.peer.state_connected)
		self.assertEqual(called, [1])

	# -- keepalive_tx event -----------------------------------------------

	def test_keepalive_tx_fires(self):
		called = []
		self.peer.on_keepalive_tx(lambda: called.append(1))

		_complete_handshake(self.peer, self._responder_pri)

		# Simulate having received data, then advance clock past keepalive
		# timeout so a keepalive is triggered.
		self.peer.curr_keypair.recv_last = 1
		self._tick(STATE_KEEPALIVE_TIMEOUT + 1)

		self.peer._state_update_keepalive()
		self.assertEqual(called, [1])

	# -- initiator role set correctly -------------------------------------

	def test_initiator_role_set_on_reinitialize(self):
		"""After reinitialize, handshake.initiator must be True."""
		self.assertTrue(self.peer.handshake.initiator)

	# -- initial handshake trigger ----------------------------------------

	def test_initial_handshake_staged_on_update_state(self):
		"""Setting state_reconnect_begin triggers a handshake via update_state."""
		self.peer.state_reconnect_begin = self._clock
		self.peer.state_reconnect_timer = self._clock - STATE_REKEY_TIMEOUT
		packets = list(self.peer.update_state())
		self.assertGreater(len(packets), 0, "Expected a handshake request to be staged")

	# -- handshake_tx_req / handshake_tx_res events -----------------------

	def test_handshake_tx_req_fires_on_stage(self):
		called = []
		self.peer.on_handshake_tx_req(lambda: called.append(1))
		self.peer._stage_handshake_req()
		self.assertEqual(called, [1])

	def test_handshake_tx_res_fires_on_stage(self):
		called = []
		self.peer.on_handshake_tx_res(lambda: called.append(1))
		self.peer._events.fire_handler("handshake_tx_res")
		self.assertEqual(called, [1])

	def test_handshake_tx_res_fires_during_handshake(self):
		"""When receiving a handshake request, the response event fires."""
		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		initiator = Initiator(initiator_pri, responder_pub)
		responder = Initiator(responder_pri, initiator_pri.public_key)
		responder.handshake.initiator = False

		called = []
		responder.on_handshake_tx_res(lambda: called.append(1))

		_complete_handshake_pair(initiator, responder)

		self.assertEqual(called, [1])

	def test_handshake_tx_req_fires_during_update_state(self):
		"""Reconnect path triggers _stage_handshake_req → event fires."""
		called = []
		self.peer.on_handshake_tx_req(lambda: called.append(1))
		self.peer.state_reconnect_begin = self._clock
		self.peer.state_reconnect_timer = self._clock - STATE_REKEY_TIMEOUT
		list(self.peer.update_state())
		self.assertEqual(called, [1])


# ---------------------------------------------------------------------------
# UnitAsyncInitiator subclass mechanics and queue behavior
# ---------------------------------------------------------------------------


class UnitAsyncInitiator(unittest.TestCase):
	def setUp(self):
		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		self._responder_pri = responder_pri
		self.peer = AsyncInitiator(initiator_pri, responder_pub)

	def test_is_subclass_of_initiator(self):
		self.assertIsInstance(self.peer, Initiator)
		self.assertIsInstance(self.peer, AsyncInitiator)

	def test_reinitialize_preserves_subclass(self):
		responder_pri2, responder_pub2 = _make_responder_keys()
		initiator_pri2 = NaClPrivateKey.generate()

		self.peer.reinitialize(initiator_pri2, responder_pub2)
		self.assertIsInstance(self.peer, AsyncInitiator)

	def test_rx_packet_nowait_empty(self):
		self.assertIsNone(self.peer.rx_packet_nowait())

	def test_tx_packet_stages_data(self):
		_complete_handshake(self.peer, self._responder_pri)

		self.peer.tx_packet(b"test-payload")

		self.assertEqual(len(self.peer.staged_outbound), 1)

	def test_events_inherited(self):
		called = []

		self.peer.on_keepalive_rx(lambda: called.append(1))
		self.peer._events.fire_handler("keepalive_rx")

		self.assertEqual(called, [1])

	def test_rx_queue_push_pop(self):
		msg = b"decoded-message"

		self.peer._rx_queue_threadsafe.put_nowait(msg)

		self.assertEqual(self.peer.rx_packet_nowait(), msg)
		self.assertIsNone(self.peer.rx_packet_nowait())

	def test_tx_packet_triggers_handshake_when_disconnected(self):
		"""tx_packet on a disconnected peer triggers the handshake."""
		self.assertFalse(self.peer.state_connected)
		self.assertIsNone(self.peer.state_reconnect_begin)

		self.peer.tx_packet(b"should-not-raise")

		self.assertIsNotNone(self.peer.state_reconnect_begin)

	def test_tx_packet_does_not_raise_when_disconnected(self):
		"""tx_packet must not raise even when not connected."""
		self.assertFalse(self.peer.state_connected)

		# Should not raise
		self.peer.tx_packet(b"data-before-handshake")

		self.assertEqual(len(self.peer.staged_outbound), 0)


# ---------------------------------------------------------------------------
# UnitAsyncInitiatorIntegration full asyncio lifecycle on loopback
# ---------------------------------------------------------------------------


class UnitAsyncInitiatorIntegration(unittest.IsolatedAsyncioTestCase):
	async def test_start_stop_lifecycle(self):
		"""Start and stop an AsyncInitiator; the socket binds without error."""
		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()

		peer = AsyncInitiator(initiator_pri, responder_pub)

		await peer.start(("127.0.0.1", 0))
		self.assertTrue(peer._running)
		self.assertIsNotNone(peer._transport)

		await peer.stop()
		self.assertFalse(peer._running)
		self.assertIsNone(peer._transport)

	async def test_async_context_manager(self):
		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()

		async with AsyncInitiator(initiator_pri, responder_pub) as peer:
			await peer.start(("127.0.0.1", 0))
			self.assertTrue(peer._running)

		self.assertFalse(peer._running)
		self.assertIsNone(peer._transport)

	async def test_tx_packet_stages_and_sends(self):
		"""A staged transport packet is sent by the background sender loop."""
		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		peer = AsyncInitiator(initiator_pri, responder_pub)

		_complete_handshake(peer, responder_pri)

		await peer.start(("127.0.0.1", 0))
		peer.tx_packet(b"hello-asyncio")

		await asyncio.sleep(0.05)

		# After sending, staged_outbound should be drained
		self.assertEqual(len(peer.staged_outbound), 0)

		await peer.stop()

	async def test_rx_packet_waits_for_data(self):
		"""rx_packet blocks until data arrives, rx_packet_nowait returns None."""
		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		peer = AsyncInitiator(initiator_pri, responder_pub)

		await peer.start(("127.0.0.1", 0))

		# Push a message into the queue from outside
		peer._rx_queue.put_nowait(b"async-message")

		result = await asyncio.wait_for(peer.rx_packet(), timeout = 0.1)
		self.assertEqual(result, b"async-message")

		await peer.stop()

	async def test_wait_handshake_completion_already_connected(self):
		"""Returns True immediately if already connected."""
		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		peer = AsyncInitiator(initiator_pri, responder_pub)

		_complete_handshake(peer, responder_pri)
		self.assertTrue(peer.state_connected)

		# Should return True instantly without needing start()
		result = await peer.wait_handshake_completion(timeout = 0.1)
		self.assertTrue(result)

	async def test_wait_handshake_completion_timeout(self):
		"""Returns False on timeout when not connected."""
		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		peer = AsyncInitiator(initiator_pri, responder_pub)

		self.assertFalse(peer.state_connected)

		result = await peer.wait_handshake_completion(timeout = 0.1)
		self.assertFalse(result)


# ---------------------------------------------------------------------------
# UnitTransportSecurity: receive-path hardening (paper §5.4.6, §6.5)
# ---------------------------------------------------------------------------


class UnitTransportSecurity(unittest.TestCase):
	def setUp(self):
		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		self.initiator = Initiator(initiator_pri, responder_pub)
		self.responder = Initiator(responder_pri, initiator_pri.public_key)
		self.responder.handshake.initiator = False

		_complete_handshake_pair(self.initiator, self.responder)
		_confirm_responder_session(self.initiator, self.responder)

	def test_forged_packet_does_not_poison_replay_window(self):
		"""§5.4.6: the replay window is only advanced by authenticated messages."""
		self.responder.encode_transport(b"hello")
		genuine = bytearray(self.responder.staged_outbound.popleft())
		forged = bytearray(genuine)
		forged[-1] ^= 0xFF # corrupt the AEAD tag/ciphertext

		with self.assertRaises(Exception):
			self.initiator.decode_packet(bytes(forged))

		# The genuine message with the same counter must still be accepted
		self.assertIsNotNone(self.initiator.decode_packet(bytes(genuine)))

	def test_counter_at_reject_after_messages_is_refused(self):
		"""§5.4.6: counters at/above Reject-After-Messages are refused."""
		self.responder.encode_transport(b"hi")
		pkt = bytearray(self.responder.staged_outbound.popleft())

		# Rewrite the 64-bit counter (bytes 8..16) to REJECT_AFTER_MSGS
		pkt[8:16] = STATE_REJECT_AFTER_MSGS.to_bytes(8, "little")

		with self.assertRaises(WireguardException):
			self.initiator.decode_packet(bytes(pkt))

	def test_authenticated_data_revives_disconnected_peer(self):
		"""§6.5: valid transport data proves the peer alive and clears reconnect."""
		self.initiator.state_connected = False
		self.initiator.state_reconnect_begin = 123.0
		self.initiator.state_reconnect_timer = 123.0

		self.responder.encode_transport(b"still here")
		pkt = self.responder.staged_outbound.popleft()
		self.initiator.decode_packet(pkt)

		self.assertTrue(self.initiator.state_connected)
		self.assertIsNone(self.initiator.state_reconnect_begin)
		self.assertEqual(self.initiator.state_reconnect_timer, 0)


# ---------------------------------------------------------------------------
# UnitRekeyLogic: §6.2 rekey triggers live on the send/receive paths
# ---------------------------------------------------------------------------


class UnitRekeyLogic(unittest.TestCase):
	def setUp(self):
		self._real_monotonic = time.monotonic
		self._clock = 0.0
		time.monotonic = lambda: self._clock

		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		self.initiator = Initiator(initiator_pri, responder_pub)
		self.responder = Initiator(responder_pri, initiator_pri.public_key)
		self.responder.handshake.initiator = False

		_complete_handshake_pair(self.initiator, self.responder)
		_confirm_responder_session(self.initiator, self.responder)

	def tearDown(self):
		time.monotonic = self._real_monotonic

	def test_idle_ticks_do_not_trigger_rekey(self):
		"""§6.2: rekey is not armed by clock ticks alone on an idle session."""
		self._clock += STATE_REKEY_AFTER_TIME + 60 # well past Rekey-After-Time
		list(self.initiator.update_state())
		list(self.responder.update_state())

		self.assertIsNone(self.initiator.state_rekey_begin)
		self.assertEqual(len(self.initiator.staged_outbound), 0)

	def test_send_path_triggers_rekey(self):
		"""§6.2: sending on a session older than Rekey-After-Time arms a rekey."""
		self._clock += STATE_REKEY_AFTER_TIME + 1

		self.initiator.encode_transport(b"poke")

		self.assertIsNotNone(self.initiator.state_rekey_begin)

	def test_receive_path_triggers_rekey(self):
		"""§6.2: receiving on an old session arms the receive-path rekey once."""
		self._clock += STATE_REJECT_AFTER_TIME_RX + 1

		self.responder.encode_transport(b"poke")
		pkt = self.responder.staged_outbound.popleft()
		self.initiator.decode_packet(pkt)

		self.assertIsNotNone(self.initiator.state_rekey_begin)

	def test_responder_role_never_time_rekeys(self):
		"""§6.2: time-based rekeying is restricted to the session initiator."""
		self._clock += STATE_REKEY_AFTER_TIME + 10

		self.responder.encode_transport(b"poke") # responder sending -> no rekey arm

		self.assertIsNone(self.responder.state_rekey_begin)


# ---------------------------------------------------------------------------
# UnitResponderPolicy: responder identity, under-load cookies, and rekeys
# ---------------------------------------------------------------------------


class UnitResponderPolicy(unittest.TestCase):
	def _make_pair(self):
		"""Build a responder-mode peer and the initiator it is configured for."""
		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		initiator = Initiator(initiator_pri, responder_pub)
		responder = Initiator(responder_pri, initiator_pri.public_key)
		responder.handshake.initiator = False
		return initiator, responder, responder_pub

	def test_unknown_initiator_identity_is_ignored(self):
		"""5.1: a responder must not answer initiations from unknown identities."""
		_, responder, responder_pub = self._make_pair()

		# An attacker knows the responder's public key and forges an initiation.
		attacker = Initiator(NaClPrivateKey.generate(), responder_pub)
		attacker._stage_handshake_req()
		forged = attacker.staged_outbound.popleft()

		responder.decode_packet(forged)

		self.assertEqual(len(responder.staged_outbound), 0, "No response to an unknown identity")
		self.assertFalse(responder.state_connected)
		self.assertEqual(responder.next_keypair.send_key, b"", "No session must be derived")

		# The legitimate peer still works afterwards.
		legit, responder, _ = self._make_pair()
		legit._stage_handshake_req()
		req = legit.staged_outbound.popleft()
		responder.decode_packet(req)
		self.assertEqual(len(responder.staged_outbound), 1, "Legitimate initiation must be answered")

	def test_not_under_load_accepts_without_mac2(self):
		"""5.3: a valid MAC 1 is sufficient while not under load."""
		initiator, responder, _ = self._make_pair()

		initiator._stage_handshake_req()
		req = initiator.staged_outbound.popleft()
		self.assertEqual(req[-16:], b"\x00" * 16, "No cookie yet: MAC 2 is empty")

		responder.decode_packet(req)

		self.assertEqual(len(responder.staged_outbound), 1, "Initiation must be processed")
		self.assertTrue(responder.staged_outbound[0][0] == 0x02)

	def test_under_load_answers_with_cookie_reply(self):
		"""5.4.7: under load a missing/invalid MAC 2 is answered with a cookie reply."""
		initiator, responder, _ = self._make_pair()
		responder.under_load = True

		initiator._stage_handshake_req()
		req = initiator.staged_outbound.popleft()
		address = b"\x0a\x00\x00\x01\x94\x6c" # 10.0.0.1:38028

		responder.decode_packet(req, address)

		self.assertEqual(len(responder.staged_outbound), 1)
		self.assertTrue(responder.staged_outbound[0][0] == 0x03, "Expected a cookie reply under load")

		# The initiator consumes the cookie and retries with a valid MAC 2.
		initiator.decode_packet(responder.staged_outbound.popleft())
		initiator._stage_handshake_req()
		req2 = initiator.staged_outbound.popleft()
		self.assertNotEqual(req2[-16:], b"\x00" * 16, "MAC 2 must now be present")

		responder.decode_packet(req2, address)
		self.assertEqual(len(responder.staged_outbound), 1)
		self.assertTrue(responder.staged_outbound[0][0] == 0x02, "Cookie-authenticated initiation must be answered")

	def test_healthy_responder_answers_peer_rekey(self):
		"""6.2/6.3: a session's responder answers its initiator's rekey at any time."""
		initiator, responder, _ = self._make_pair()

		_complete_handshake_pair(initiator, responder)
		_confirm_responder_session(initiator, responder)

		# The session initiator starts a rekey while the responder is healthy.
		initiator._stage_handshake_req()
		req = initiator.staged_outbound.popleft()

		responder.decode_packet(req)
		self.assertEqual(len(responder.staged_outbound), 1, "Healthy responder must answer the rekey")
		res = responder.staged_outbound.popleft()

		# Initiator promotes its new session; responder's copy is confirmed by the
		# first transport data message of the new session (6.3).
		initiator.decode_packet(res)

		initiator.encode_transport(b"rekeyed")
		pkt = initiator.staged_outbound.popleft()
		responder.decode_packet(pkt)
		self.assertTrue(responder.state_connected)

		called = []
		initiator.on_message_rx(lambda data: called.append(data))
		responder.encode_transport(b"reply")
		pkt = responder.staged_outbound.popleft()
		initiator.decode_packet(pkt)
		self.assertEqual(called, [wg_pad(b"reply")])


# ---------------------------------------------------------------------------
# UnitHandshakeRetryOption: bounded handshake retries (F6 user option)
# ---------------------------------------------------------------------------


class UnitHandshakeRetryOption(unittest.TestCase):
	def setUp(self):
		self._real_monotonic = time.monotonic
		self._clock = 0.0
		time.monotonic = lambda: self._clock

		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		self.peer = Initiator(initiator_pri, responder_pub, max_handshake_attempts = 2)
		self.peer.request_handshake()

	def tearDown(self):
		time.monotonic = self._real_monotonic

	def _tick(self, delta = 8.0): # > Rekey-Timeout + max jitter
		self._clock += delta
		return list(self.peer.update_state())

	def test_gives_up_after_configured_attempts(self):
		failed = []
		self.peer.on_handshake_failed(lambda: failed.append(1))

		packets = []
		packets += self._tick() # attempt 1
		packets += self._tick() # attempt 2
		packets += self._tick() # give-up fires here
		packets += self._tick()
		packets += self._tick()

		self.assertEqual(len(failed), 1, "handshake_failed must fire exactly once")
		self.assertTrue(self.peer.state_handshake_gave_up)
		self.assertEqual(len(packets), 2, "No initiations may be sent after giving up")

	def test_default_never_gives_up(self):
		responder_pri, responder_pub = _make_responder_keys()
		peer = Initiator(NaClPrivateKey.generate(), responder_pub)
		peer.request_handshake()

		sent = 0
		for _ in range(5):
			sent += len(self._collect(peer))
		self.assertFalse(peer.state_handshake_gave_up)
		self.assertGreaterEqual(sent, 5)

	def _collect(self, peer):
		self._clock += 8.0
		return list(peer.update_state())

	def test_request_handshake_rearms_after_give_up(self):
		self._tick()
		self._tick()
		self._tick() # gave up
		self.assertTrue(self.peer.state_handshake_gave_up)

		self.peer.request_handshake()
		self.assertFalse(self.peer.state_handshake_gave_up)

		packets = self._tick()
		self.assertEqual(len(packets), 1, "A fresh handshake attempt must be staged after re-arming")


UNIT_CLASSES = [
	UnitEvents,
	UnitAsyncInitiator,
	UnitAsyncInitiatorIntegration,
	UnitTransportSecurity,
	UnitRekeyLogic,
	UnitResponderPolicy,
	UnitHandshakeRetryOption,
]
