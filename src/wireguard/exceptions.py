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


class WireguardCookieRequired(WireguardHandshakeException):
	"""
		Raised while under load when a handshake message carries a missing or
		invalid MAC 2; the receiver should answer with a cookie reply (5.4.7).
	"""
	pass


class WireguardCodecException(WireguardException):
	pass
