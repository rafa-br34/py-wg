"""
> PYTHONPATH=../ py requests_adapter.py

``requests.get`` through WireGuard using WGProxyHTTPAdapter + AsyncInitiator.
Requires:  pip install requests
"""
import asyncio
import sys

sys.path.insert(0, '..')
import requests
from src.wireguard.requests_adapter import WGProxyHTTPAdapter, connect_wg_async
from load_environ import client_addr_v4, client_key, server_addr, server_key
from utils import addr_to_int


async def main():
	print("[*] WG handshake ...")
	peer = await connect_wg_async(client_key, server_key, server_addr)
	print("[*] WG connected")

	session = requests.Session()

	session.mount("http://", WGProxyHTTPAdapter(peer, addr_to_int(client_addr_v4)))
	session.mount("https://", WGProxyHTTPAdapter(peer, addr_to_int(client_addr_v4)))

	async def get_url(url):
		print(f"[*] GET {url} ...")
		r = await asyncio.to_thread(session.get, url, timeout = 30)
		print(f"[*] {r.status_code}  {len(r.content)} bytes")
		print(r.text)

	await get_url("http://v4.ident.me")
	await get_url("https://v4.ident.me")

	await peer.stop()


if __name__ == "__main__":
	asyncio.run(main())
