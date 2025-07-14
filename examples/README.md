# Examples

## Contents

- [Examples](#examples)
  - [Contents](#contents)
  - [Configuring and running the examples](#configuring-and-running-the-examples)
    - [Configuring with Mullvad](#configuring-with-mullvad)
  - [List of examples and their purpose](#list-of-examples-and-their-purpose)

## Configuring and running the examples

To setup the wireguard parameters `.env-template` file with the appropriate values and rename it to `.env`. The examples will read the configuration from this file.
Here's a brief overview of the required variables:

- `WG_INITIATOR_KEY_PRI`: The private key of the initiator.
- `WG_INITIATOR_PKT_ADDR`: The source address of the tunneled packets (interface address).
- `WG_RESPONDER_KEY_PUB`: The public key of the responder.
- `WG_RESPONDER_ADDR`: The IP address of the responder.
- `WG_RESPONDER_PORT`: The port on which the responder is listening for incoming connections.

The examples are meant to be ran in this directory without the module installed, so you can run them by using `PYTHONPATH=../ py <example_name>.py` in this directory.
If you desire to run the examples with the module installed, you will first need remove the `src` part from the imports.

### Configuring with Mullvad

When using Mullvad for the WireGuard config manually generate a configuration file. The generated configuration file might look like this:

```ini
[Interface]
# Device: [REDACTED]
PrivateKey = [REDACTED]
Address = 10.0.36.21/32,fc00:bbbb:bbbb:bbbb::a:e621/128
DNS = [REDACTED]

[Peer]
PublicKey = [REDACTED]
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = 123.45.67.89:51820
```

Where:

- `PrivateKey` is the `WG_INITIATOR_KEY_PRI`.
- `Address` is the `WG_INITIATOR_PKT_ADDR` for IPv4 and IPv6 respectively.
- `PublicKey` is the `WG_RESPONDER_KEY_PUB`.
- `Endpoint` is the `WG_RESPONDER_ADDR` and `WG_RESPONDER_PORT`.

Alternatively if you don't want to delete a device, you can manually request the Mullvad API to regenerate the keys for a device, like so:

```python
import requests
import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

ACCOUNT_NUMBER = "[REDACTED]"
ACCOUNT_DEVICE = "[REDACTED]"

session = requests.session()

result = session.post("https://api.mullvad.net/auth/v1/token", json = {"account_number": str(ACCOUNT_NUMBER)})

session.headers["Authorization"] = "Bearer " + result.json()["access_token"]

result = session.get("https://api.mullvad.net/accounts/v1/devices")

for device in result.json():
    if device["name"] != ACCOUNT_DEVICE.lower():
        continue

    pri_key = X25519PrivateKey.generate()
    pub_key = pri_key.public_key()

    pri_key = base64.b64encode(pri_key.private_bytes_raw()).decode()
    pub_key = base64.b64encode(pub_key.public_bytes_raw()).decode()

    ident = device["id"]

    result = session.put(f"https://api.mullvad.net/accounts/v1/devices/{ident}/pubkey", json = {"pubkey": pub_key})
    device = result.json()

    print(
        "IPv4: {}\nIPv6: {}\nPrivate key: {}\nPublic key: {}".format(
            device["ipv4_address"],
            device["ipv6_address"],
            pri_key,
            pub_key,
        )
    )
    break
```

To get the servers simply open [api.mullvad.net/www/relays/all](https://api.mullvad.net/www/relays/all/) in your browser and select the desired server.

## List of examples and their purpose

- `icmp-round-trip.py`: Demonstrates how to perform an ICMP ping over WireGuard.
- `udp-round-trip.py`: Demonstrates how to connect a WireGuard peer and send UDP packets to DNS servers using `dnslib`.
- `syn-scan.py`: Demonstrates how to perform a SYN scan over WireGuard.

In the future more examples will be added to demonstrate different use cases of the library, such as:

- Creating a WireGuard server.
- Establishing a 2-way TCP connection over WireGuard.
- Performing a full HTTP(S) request over WireGuard + `requests`.
