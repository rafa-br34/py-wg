import time

from typing import Callable


def time_ms():
	return int(time.monotonic() * 1000)


class TCPTimers:
	def __init__(self, callback: Callable[[str], None]):
		self._timers: dict[str, int] = {}
		self._callback = callback

	def schedule(self, name: str, delay_ms: int):
		self._timers[name] = time_ms() + delay_ms

	def cancel(self, name: str):
		self._timers.pop(name, None)

	def active(self, name: str) -> bool:
		return name in self._timers

	def fire(self, name: str):
		del self._timers[name]
		self._callback(name)

	def tick(self):
		now_ms = time_ms()
		expired = [name for name, deadline in self._timers.items() if now_ms >= deadline]

		for name in expired:
			self.fire(name)
