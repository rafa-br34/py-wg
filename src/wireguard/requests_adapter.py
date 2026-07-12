"""
WireGuard + TCP FSM socket adapter for ``requests`` / urllib3.

Uses :class:`AsyncInitiator` — the caller must run inside an asyncio
event loop.  The adapter's proxy thread reads from the thread-safe
queue so that the asyncio background task handles all UDP I/O.

Usage::

    import asyncio, requests
    from src.wireguard.requests_adapter import WGProxyHTTPAdapter, connect_wg_async
    from utils import addr_to_int

    async def main():
        peer = await connect_wg_async(client_key, server_key, server_addr)
        session = requests.Session()
        session.mount("http://", WGProxyHTTPAdapter(peer, addr_to_int(client_addr_v4)))
        r = await asyncio.to_thread(session.get, "http://scanme.nmap.org")
        print(r.status_code)
        await peer.stop()

    asyncio.run(main())
"""
import socket
import selectors
import threading
import time

from .async_initiator import AsyncInitiator
from .stack.internet import ip_packet_val, Protocols
from .stack.ipv4 import IPv4Packet
from .stack.tcp import TCPConnection, TCPState, TCPPacket, TCPFlags

from typing import cast, Any

# @todo Improve this mess


class WGProxySocket:
	"""A socket-like object that tunnels TCP through WireGuard."""
	def __init__(self, initiator: AsyncInitiator, src_addr: int):
		self._peer = initiator
		self._src_addr = src_addr
		self._tap_a, self._tap_b = socket.socketpair()
		self._tap_b.setblocking(False) # non-blocking for the selector

		# _tap_a stays blocking. SSL needs a blocking socket
		self._sel = selectors.DefaultSelector()
		self._running = False
		self._conn = None
		self._dst_addr = 0
		self._thread = None

	def connect(self, addr: tuple):
		host, port = addr
		dst_ip = socket.gethostbyname(host)
		self._dst_addr = int.from_bytes(socket.inet_aton(dst_ip), "big")
		src_port = 32768 + (threading.get_ident() % 32768)

		self._conn = TCPConnection()
		self._conn.event_open(self._src_addr, src_port, self._dst_addr, port)
		self._drain_fsm()

		# Drain any stale transport data from previous connections
		while self._peer.rx_packet_nowait() is not None:
			pass

		# print("[TCP] SYN sent to %s:%s" % (host, port), flush = True)
		t0 = time.monotonic()
		while time.monotonic() - t0 < 30 and self._conn.state != TCPState.STATE_ESTABLISHED:
			self._conn.tick()
			self._drain_fsm()
			self._receive_feed()
			time.sleep(0.01)

		if self._conn.state != TCPState.STATE_ESTABLISHED:
			raise ConnectionError("TCP handshake failed after 30s")

		# print("[TCP] Handshake complete", flush = True)
		self._running = True
		self._sel.register(self._tap_b, selectors.EVENT_READ)
		self._thread = threading.Thread(target = self._proxy_loop, daemon = True)
		self._thread.start()

	# ── socket-like interface ──────────────────────────────────────

	def send(self, data, *args, **kwargs):
		return self._tap_a.send(data, *args, **kwargs)

	def sendall(self, data, *args, **kwargs):
		return self._tap_a.sendall(data, *args, **kwargs)

	def recv(self, length, *args, **kwargs):
		return self._tap_a.recv(length, *args, **kwargs)

	def fileno(self):
		return self._tap_a.fileno()

	def close(self):
		self._running = False
		if self._conn:
			try:
				self._conn.event_abort()
			except Exception:
				pass
		try:
			self._tap_a.close()
		except Exception:
			pass
		try:
			self._tap_b.close()
		except Exception:
			pass

	def settimeout(self, timeout):
		self._tap_a.settimeout(timeout)

	def gettimeout(self):
		return self._tap_a.gettimeout()

	def getsockopt(self, *args, **kwargs):
		return self._tap_a.getsockopt(*args, **kwargs)

	def shutdown(self, how):
		self._tap_a.shutdown(how)

	def detach(self):
		return self._tap_a.detach()

	def __getattr__(self, name):
		return getattr(self._tap_a, name)

	# ── internals ──────────────────────────────────────────────────

	def _stage_one(self, tcp_tx: TCPPacket):
		ipv4_tx = IPv4Packet()
		ipv4_tx.src_addr = self._src_addr
		ipv4_tx.dst_addr = self._dst_addr
		ipv4_tx.payload = tcp_tx
		self._peer.tx_packet(ipv4_tx.encode_packet())

	def _drain_fsm(self):
		assert self._conn

		while self._conn.dst_retransmit:
			self._stage_one(self._conn.dst_retransmit.popleft())

	def _receive_feed(self):
		assert self._conn

		while True:
			data = self._peer.rx_packet_nowait()
			if data is None:
				break

			if ip_packet_val(data) != 4:
				continue

			ipv4_rx = IPv4Packet()
			ipv4_rx.decode_packet(data)
			if ipv4_rx.protocol != Protocols.IP_TCP or not ipv4_rx.payload:
				continue

			tcp_rx = TCPPacket()
			tcp_rx.decode_packet_ipv4(ipv4_rx.payload, ipv4_rx)
			if tcp_rx.dst_port != self._conn.src_port:
				continue

			try:
				self._conn._recv_packet(tcp_rx)
			except ValueError:
				pass # RST or terminal event; connect loop will detect state

	def _proxy_loop(self):
		assert self._conn

		while self._running:
			try:
				events = self._sel.select(timeout = 0.05)
				for key, _ in events:
					if key.fileobj is self._tap_b:
						try:
							data = self._tap_b.recv(16384)
						except OSError:
							continue
						if not data:
							self._running = False
							break
						self._conn.event_send(data)

				self._conn.tick()
				self._drain_fsm()
				self._receive_feed()
				try:
					app_data = self._conn.event_receive(65536)

					if app_data:
						self._tap_b.sendall(app_data)
				except ValueError:
					pass
			except Exception:
				import traceback
				traceback.print_exc()
				self._running = False


# ── Helper: handshake an AsyncInitiator ──────────────────────────


async def connect_wg_async(
	initiator_pri,
	responder_pub,
	server_addr: tuple,
	preshared_key = None,
	timeout = 30,
) -> AsyncInitiator:
	"""Create an AsyncInitiator, handshake, and return it.

	Must be called inside a running asyncio event loop.
	"""
	peer = AsyncInitiator(initiator_pri, responder_pub, preshared_key)

	await peer.start(server_addr)

	if not await peer.wait_handshake_completion(timeout = timeout):
		await peer.stop()
		raise ConnectionError("WG handshake failed")

	return peer


# ── urllib3 / requests integration ───────────────────────────────

_current_initiator: "AsyncInitiator | None" = None
_current_src_addr: int = 0

try:
	from urllib3.connection import HTTPConnection, HTTPSConnection
	from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
	from urllib3.poolmanager import PoolManager
	from requests.adapters import HTTPAdapter

	class _WGProxyHTTPConnection(HTTPConnection):
		def _new_conn(self):
			assert _current_initiator

			sock = WGProxySocket(_current_initiator, _current_src_addr)
			sock.connect((self.host, self.port))

			return cast(socket.socket, sock)

	class _WGProxyHTTPSConnection(HTTPSConnection):
		def _new_conn(self):
			assert _current_initiator

			sock = WGProxySocket(_current_initiator, _current_src_addr)
			sock.connect((self.host, self.port))

			return cast(socket.socket, sock)

	class _WGProxyHTTPConnectionPool(HTTPConnectionPool):
		# The accurate type is a BaseHTTPConnection, but urllib3 doesn't expose it
		ConnectionCls = cast(Any, _WGProxyHTTPConnection)

	class _WGProxyHTTPSConnectionPool(HTTPSConnectionPool):
		# The accurate type is a BaseHTTPConnection, but urllib3 doesn't expose it
		ConnectionCls = cast(Any, _WGProxyHTTPSConnection)

	class _WGProxyPoolManager(PoolManager):
		def __init__(self, *args, **kwargs):
			super().__init__(*args, **kwargs)

			self.pool_classes_by_scheme["http"] = _WGProxyHTTPConnectionPool
			self.pool_classes_by_scheme["https"] = _WGProxyHTTPSConnectionPool

	class WGProxyHTTPAdapter(HTTPAdapter):
		"""Mount on a ``requests.Session`` to route HTTP through WireGuard."""
		def __init__(self, initiator: AsyncInitiator, src_addr: int):
			self._wg_initiator = initiator
			self._wg_src_addr = src_addr

			super().__init__()

		def init_poolmanager(self, connections, maxsize, block = False, **kw):
			self.poolmanager = _WGProxyPoolManager(
				num_pools = connections,
				maxsize = maxsize,
				block = block,
				**kw,
			)

		def send(self, request, *args, **kwargs):
			global _current_initiator, _current_src_addr
			_current_initiator = self._wg_initiator
			_current_src_addr = self._wg_src_addr

			return super().send(request, *args, **kwargs)

except ImportError:
	WGProxyHTTPAdapter = cast(type["WGProxyHTTPAdapter"], None)
	connect_wg_async = cast(Any, None)
