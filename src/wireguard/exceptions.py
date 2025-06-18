class WireguardException(Exception):
	"""
		Parent class of all Wireguard exceptions.
	"""
	pass


class WireguardStateException(WireguardException):
	"""
		Some invalid state was reached.
		When a exceptions like this is thrown, the source should be investigated.
	"""
	pass


class WireguardHandshakeException(WireguardException):
	"""
		Exceptions raised during handshake.
	"""
	pass


class WireguardCodecException(WireguardException):
	pass
