import os

from dotenv import load_dotenv

load_dotenv()

env = os.environ

_client_addr_v4 = env.get("WG_INITIATOR_PKT_ADDR_V4")
_client_addr_v6 = env.get("WG_INITIATOR_PKT_ADDR_V6")
_client_key = env.get("WG_INITIATOR_KEY_PRI")

_server_addr = env.get("WG_RESPONDER_ADDR")
_server_port = env.get("WG_RESPONDER_PORT")
_server_key = env.get("WG_RESPONDER_KEY_PUB")

assert _client_addr_v4 is not None, "Missing WG_INITIATOR_PKT_ADDR_V4"
assert _client_addr_v6 is not None, "Missing WG_INITIATOR_PKT_ADDR_V6"
assert _client_key is not None, "Missing WG_INITIATOR_KEY_PRI"
assert _server_addr is not None, "Missing WG_RESPONDER_ADDR"
assert _server_port is not None, "Missing WG_RESPONDER_PORT"
assert _server_key is not None, "Missing WG_RESPONDER_KEY_PUB"

client_addr_v4: str = _client_addr_v4
client_addr_v6: str = _client_addr_v6
client_key: str = _client_key
server_key: str = _server_key
server_addr = (_server_addr, int(_server_port))
