import argparse
import ipaddress
import base64
import json
import sys

from urllib.parse import quote

import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

HEADERS = {
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0",
	"Accept-Language": "en-US,en;q=0.9",
	"Referer": "https://mullvad.net/en/account/login",
	"X-Sveltekit-Action": "true",
	"Origin": "https://mullvad.net",
	"Sec-Fetch-Dest": "empty",
	"Sec-Fetch-Mode": "cors",
	"Sec-Fetch-Site": "same-origin",
	"DNT": "1",
	"Sec-GPC": "1",
	"Priority": "u=0",
	"Pragma": "no-cache",
	"Cache-Control": "no-cache",
	"TE": "trailers",
}


def main() -> None:
	parser = argparse.ArgumentParser(description = "Generate Mullvad WireGuard credentials")
	parser.add_argument("--account", required = True, help = "Your Mullvad account number")

	args = parser.parse_args()

	session = requests.session()

	print("Logging in...", file = sys.stderr)
	resp = session.post(
		"https://mullvad.net/en/account/login",
		data = {"account_number": args.account},
		headers = {
			**HEADERS,
			"Accept": "application/json",
			"Content-Type": "application/x-www-form-urlencoded",
		},
	)

	if not resp.ok:
		print(f"Login failed: {resp.status_code} {resp.text}", file = sys.stderr)
		sys.exit(1)

	pri_key = X25519PrivateKey.generate()
	pub_key = pri_key.public_key()
	pri_key_b64 = base64.b64encode(pri_key.private_bytes_raw()).decode()
	pub_key_b64 = base64.b64encode(pub_key.public_bytes_raw()).decode()

	print("Registering key...", file = sys.stderr)
	resp = session.post(
		"https://mullvad.net/en/account/wireguard-config?/add-wg-key",
		data = f"pubkey={quote(pub_key_b64)}",
		headers = {
			**HEADERS,
			"Accept": "application/json",
			"Content-Type": "application/x-www-form-urlencoded",
		},
	)
	if not resp.ok:
		print(
			f"Key registration failed: {resp.status_code} {resp.text}",
			file = sys.stderr,
		)
		sys.exit(1)

	data = resp.json()

	# The response uses SvelteKit's devalue wire format:
	#   {"type":"success","status":200,"data":"[{...},true,{field→idx},...values]"}
	# The field map at index 2 maps names to positions in the array.
	raw = json.loads(data["data"])
	fields = raw[2] # {"id":3,"name":4,"pubkey":5,...,"ipv4_address":7,...}

	def get_field(name):
		idx = fields.get(name)
		return raw[idx] if idx is not None else None

	print(f'\nWG_INITIATOR_KEY_PRI="{pri_key_b64}"')

	server_pub = get_field("pubkey")
	if server_pub:
		print(f'WG_RESPONDER_KEY_PUB="{server_pub}"')

	ipv4 = get_field("ipv4_address")
	ipv6 = get_field("ipv6_address")

	if ipv4:
		print(f'WG_INITIATOR_PKT_ADDR_V4="{ipaddress.ip_interface(ipv4).ip}"')
	if ipv6:
		print(f'WG_INITIATOR_PKT_ADDR_V6="{ipaddress.ip_interface(ipv6).ip}"')

	print("# The add-wg-key endpoint doesn't provide a default endpoint")
	print("# pick one from https://api.mullvad.net/www/relays/all/ and fill WG_RESPONDER_{ADDR/PORT} manually.")

	print("\n# Raw API response (for debugging):", file = sys.stderr)
	print(data, file = sys.stderr)


if __name__ == "__main__":
	main()
