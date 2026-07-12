import asyncio
import queue
import time

from typing import Optional

from .initiator import Initiator
from .functions import WireguardPubKey, WireguardPriKey
from .constants import STATE_REKEY_TIMEOUT, STATE_REKEY_ATTEMPT_TIME


class _WGProtocol(asyncio.DatagramProtocol):
	"""Internal asyncio DatagramProtocol that bridges datagrams to the AsyncInitiator."""
	def __init__(self, on_datagram, on_error = None):
		self.on_datagram = on_datagram
		self.on_error = on_error
		self.transport = None

	def connection_made(self, transport):
		self.transport = transport

	def datagram_received(self, data, addr):
		self.on_datagram(data, addr)

	def error_received(self, exc):
		if self.on_error:
			self.on_error(exc)

	def connection_lost(self, exc):
		pass


class AsyncInitiator(Initiator):
	"""High-level asyncio WireGuard initiator with built-in UDP socket handling.

	Inherits all WireGuard protocol logic from Initiator and adds:
	- A background asyncio task that drives ``update_state()`` and sends staged packets via UDP.
	- A receive path that pushes decoded transport messages onto an ``asyncio.Queue``.
	- Convenience methods: ``tx_packet``, ``rx_packet``, ``rx_packet_nowait``.
	- Inherited event hooks: ``on_keepalive_tx``, ``on_keepalive_rx``, ``on_message_rx``,
	  ``on_handshake_complete``, ``on_connection_lost``.
	"""
	def __init__(
		self,
		initiator_pri: Optional[WireguardPriKey] = None,
		responder_pub: Optional[WireguardPubKey] = None,
		preshared_key: Optional[bytes] = None,
		*,
		rx_queue_size: int = 1024,
		tx_queue_size: int = 1024,
	):
		super().__init__(initiator_pri, responder_pub, preshared_key)

		self._rx_queue: asyncio.Queue = asyncio.Queue(maxsize = rx_queue_size)
		self._rx_queue_threadsafe: queue.Queue = queue.Queue(maxsize = rx_queue_size)
		self._tx_queue_size = tx_queue_size

		self._transport = None
		self._protocol = None
		self._loop_task: Optional[asyncio.Task] = None
		self._running = False

	async def start(self, server_addr: tuple[str, int]):
		"""Bind a UDP socket to *server_addr* and start the background send/recv loop.

		Must be called inside a running asyncio event loop.  Safe to call after
		``reinitialize`` to restart on a new address.
		"""
		if self._running:
			await self.stop()

		loop = asyncio.get_running_loop()

		def on_datagram(data, addr):
			# Only accept datagrams from the configured server
			if addr != server_addr:
				return
			try:
				decoded = self.decode_packet(data)
			except Exception:
				return
			if decoded is not None:
				try:
					self._rx_queue.put_nowait(decoded)
				except asyncio.QueueFull:
					pass # drop if consumer is too slow
				try:
					self._rx_queue_threadsafe.put_nowait(decoded)
				except queue.Full:
					pass

		self._transport, self._protocol = await loop.create_datagram_endpoint(
			lambda: _WGProtocol(on_datagram),
			remote_addr = server_addr,
		)

		self._running = True
		self._loop_task = asyncio.create_task(self._run_loop(server_addr))

		# Trigger the initial handshake immediately if we aren't already connected
		if not self.state_connected and self.state_reconnect_begin is None:
			self.state_reconnect_begin = time.monotonic()
			self.state_reconnect_timer = time.monotonic() - STATE_REKEY_TIMEOUT

	async def stop(self):
		"""Stop the background loop and close the UDP socket."""
		self._running = False

		if self._loop_task is not None:
			self._loop_task.cancel()
			try:
				await self._loop_task
			except asyncio.CancelledError:
				pass
			self._loop_task = None

		if self._transport is not None:
			self._transport.close()
			self._transport = None
			self._protocol = None

	async def __aenter__(self):
		return self

	async def __aexit__(self, exc_type, exc_val, exc_tb):
		await self.stop()
		return False

	async def rx_packet(self, timeout: Optional[float] = None) -> Optional[bytes]:
		"""Await the next decoded transport message.

		If *timeout* is given, returns ``None`` after *timeout* seconds
		instead of raising ``asyncio.TimeoutError``.
		"""
		if timeout is None:
			return await self._rx_queue.get()
		try:
			return await asyncio.wait_for(self._rx_queue.get(), timeout = timeout)
		except asyncio.TimeoutError:
			return None

	def rx_packet_nowait(self) -> Optional[bytes]:
		"""Return a decoded message if one is available, otherwise ``None``.

		Thread-safe — may be called from outside the asyncio event loop.
		"""
		try:
			return self._rx_queue_threadsafe.get_nowait()
		except queue.Empty:
			return None

	def tx_packet(self, data: bytes):
		"""Stage *data* for WireGuard transport encoding.

		The actual send happens inside the background loop on the next ``update_state`` tick; you do not need to await it.

		If not yet connected, the handshake is triggered automatically and
		*data* is silently dropped (callers should wait for
		``state_connected`` or ``on_handshake_complete`` before sending).
		"""
		if not self.state_connected:
			# Ensure a handshake is in progress
			if self.state_reconnect_begin is None and self.state_rekey_begin is None:
				self.state_reconnect_begin = time.monotonic()
				self.state_reconnect_timer = time.monotonic() - STATE_REKEY_TIMEOUT

			return

		self.encode_transport(data)

	async def wait_handshake_completion(self, timeout: Optional[float] = None) -> bool:
		"""Wait for the handshake to complete.

		Returns ``True`` if the handshake succeeded within *timeout* seconds,
		``False`` on timeout.  If already connected, returns ``True`` immediately.

		Default timeout is ``STATE_REKEY_ATTEMPT_TIME`` (90 s), matching how
		long the initiator retries before giving up.
		"""
		if self.state_connected:
			return True

		if timeout is None:
			timeout = STATE_REKEY_ATTEMPT_TIME

		event = asyncio.Event()

		def _on_complete():
			event.set()

		self.on_handshake_complete(_on_complete)

		try:
			await asyncio.wait_for(event.wait(), timeout = timeout)
			return True
		except asyncio.TimeoutError:
			return False
		finally:
			self._events.detach_handler("handshake_complete", _on_complete)

	# ---- Internal helpers ----

	async def _run_loop(self, _server_addr: tuple[str, int]):
		"""Background task: sender loop.  The receiver runs via _WGProtocol callbacks."""
		SLEEP_INTERVAL = 0.01 # 10 ms tick for timer-driven state updates

		while self._running:
			for packet in self.update_state():
				if self._transport is not None:
					self._transport.sendto(packet)

			await asyncio.sleep(SLEEP_INTERVAL)
