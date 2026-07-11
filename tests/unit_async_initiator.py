import unittest
import time
import asyncio

from nacl.public import PrivateKey as NaClPrivateKey

from src.wireguard import Initiator, AsyncInitiator, Handshake, KeyPair
from src.wireguard.constants import (
	STATE_KEEPALIVE_TIMEOUT,
	STATE_REKEY_TIMEOUT,
)
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
	"""Perform a handshake between two peers.  After this both are connected.

	*initiator* must know *responder*'s public key.  *responder* must NOT know
	*initiator*'s public key (it learns it from the handshake).
	"""
	initiator._stage_handshake_req()
	req = initiator.staged_outbound.popleft()

	# Feed the request through the responder's decode_packet so that key
	# rotation happens on the responder side as well.
	responder.state_rekey_staged = True
	responder.decode_packet(req)
	res = responder.staged_outbound.popleft()

	initiator.state_rekey_staged = True
	initiator.decode_packet(res)


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

		self.peer._rx_queue.put_nowait(msg)

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
		result = await peer.wait_handshake_completion(timeout=0.1)
		self.assertTrue(result)

	async def test_wait_handshake_completion_timeout(self):
		"""Returns False on timeout when not connected."""
		responder_pri, responder_pub = _make_responder_keys()
		initiator_pri = NaClPrivateKey.generate()
		peer = AsyncInitiator(initiator_pri, responder_pub)

		self.assertFalse(peer.state_connected)

		result = await peer.wait_handshake_completion(timeout=0.1)
		self.assertFalse(result)


UNIT_CLASSES = [
	UnitEvents,
	UnitAsyncInitiator,
	UnitAsyncInitiatorIntegration,
]
