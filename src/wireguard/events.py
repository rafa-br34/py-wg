from typing import Dict, List, Tuple, Any, Callable


class Events:
	def __init__(self):
		self._events: Dict[str, List[Callable]] = {}

	def list_handlers(self, name):
		if name in self._events:
			return self._events[name]
		else:
			handler_list = []
			self._events[name] = handler_list

			return handler_list

	def attach_handler(self, name: str, func):
		self.list_handlers(name).append(func)

	def detach_handler(self, name: str, func):
		self.list_handlers(name).remove(func)

	def fire_handler(self, name: str, args: Tuple[Any], kwargs: Dict[str, Any]):
		for handler in self.list_handlers(name):
			handler(*args, **kwargs)
