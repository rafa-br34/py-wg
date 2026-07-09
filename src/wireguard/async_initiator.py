from .initiator import Initiator
from .functions import WireguardPubKey, WireguardPriKey
from .events import Events

from typing import Optional
from collections.abc import Callable


class AsyncInitiator:
	def __init__(
		self,
		initiator_pri: Optional[WireguardPriKey] = None,
		responder_pub: Optional[WireguardPubKey] = None,
		preshared_key: Optional[bytes] = None
	):
		self._initiator = Initiator(initiator_pri, responder_pub, preshared_key)
		self._events = Events()

	def reinitialize(
		self,
		initiator_pri: WireguardPriKey,
		responder_pub: WireguardPubKey,
		preshared_key: Optional[bytes] = None,
	):
		self._initiator.reinitialize(initiator_pri, responder_pub, preshared_key)

	def on_keepalive_tx(self, func: Callable):
		self._events.attach_handler("keepalive_tx", func)

	def on_keepalive_rx(self, func: Callable):
		self._events.attach_handler("keepalive_rx", func)

	def on_message_rx(self, func: Callable[[bytes], None]):
		self._events.attach_handler("message_rx", func)
