import time

from .packet_replay import PacketReplay


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

		self.lifetime: float = 0

		self.replay = PacketReplay()

		self.src_ident = 0 # The local identifier
		self.dst_ident = 0 # The remote identifier

	def next_recv(self):
		self.recv_count += 1
		self.recv_last = time.monotonic()

	def next_send(self):
		self.send_count += 1
		self.send_last = time.monotonic()
