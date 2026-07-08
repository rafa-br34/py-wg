from src.wireguard import AsyncInitiator

initiator = AsyncInitiator(
	initiator_pri = "PrivateKey | base64 string | bytes",
	responder_pub = "PublicKey | base64 string | bytes",
)


@initiator.on_keepalive_rx
def _handshake_complete():
	print("Completed handshake")
