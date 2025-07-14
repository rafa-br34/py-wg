# Python WireGuard

![Tests](https://github.com/rafa-br34/py-wg/actions/workflows/tests.yml/badge.svg?branch=main)
![PyPI](https://img.shields.io/pypi/v/wireguard-protocol?color=blue&label=PyPI)
![Downloads](https://img.shields.io/pypi/dm/wireguard-protocol)

A pure python implementation of the WireGuard protocol.

## Table of contents

- [Python WireGuard](#python-wireguard)
  - [Table of contents](#table-of-contents)
  - [Motivation](#motivation)
  - [Performance](#performance)
  - [Usage](#usage)
  - [Testing and troubleshooting](#testing-and-troubleshooting)
  - [References](#references)

## Motivation

Existing Python libraries for WireGuard rely on the system daemon, which limits flexibility, requires root access, and causes global network changes. A user-mode implementation avoids these issues, making setup easier and safer for isolated use cases. It also enables custom packet injection (IPv4/IPv6) without raw sockets, making it useful for things like anonymous SYN scans (given proper spoofing), dynamic IP hopping for scraping, or building VPN-like tools without system-wide impact.
And finally, because why not? It's a fun project to learn about the WireGuard protocol and networking in general.

## Performance

One major drawback of this implementation is its speed. While rewriting it in a faster language like C++ with Python bindings could solve this, it would also add significant complexity. For now, the focus is on optimizing the existing Python code as much as possible.

## Usage

For usage examples please refer to the [examples](/examples/README.md) directory. The examples demonstrate how to use the library to create WireGuard peers, encode packets, send packets, and manage inbound packets.

A documentation will be added in the future, but for now, the examples should provide enough information to get started.

## Testing and troubleshooting

If you encounter any issues while using the library run the test suite to check if any tests are failing. The tests can be run by using `python run_tests.py` in the root directory of the project.
If anything fails or doesn't work properly please feel free to open an issue on the repository with the details of the issue and the output of the tests.

## References

The following references were used while building this project:

- [WireGuard paper](https://www.wireguard.com/papers/wireguard.pdf)
- [WireGuard website](https://www.wireguard.com)
- [wireguard-lwip](https://github.com/smartalock/wireguard-lwip) by [smartalock](https://github.com/smartalock)
- [RFC 792](https://datatracker.ietf.org/doc/html/rfc792) (ICMP standard)
- [RFC 791](https://datatracker.ietf.org/doc/html/rfc791) (IPv4 standard)
- [RFC 8200](https://datatracker.ietf.org/doc/html/rfc8200) (IPv6 standard)
- [IANA DSCP & ECN](https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml) (IPv4/IPv6 DSCP and ECN)
- [IANA Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml) (IPv4/IPv6 Protocol Numbers)
- [RFC 768](https://datatracker.ietf.org/doc/html/rfc768) (UDP standard)
- [RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293) (TCP standard)
- [IANA TCP Parameters](https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml) (TCP enumerators, options, etc)
