# Python WireGuard

A pure python implementation of the WireGuard protocol.

## Table of contents

- [Python WireGuard](#python-wireguard)
  - [Table of contents](#table-of-contents)
  - [Motivation](#motivation)
  - [Performance](#performance)
  - [References](#references)

## Motivation

Existing Python libraries for WireGuard rely on the system daemon, which limits flexibility, requires root access, and causes global network changes. A user-mode implementation avoids these issues, making setup easier and safer for isolated use cases. It also enables custom packet injection (IPv4/IPv6) without raw sockets, useful for things like anonymous SYN scans, dynamic IP hopping for scraping, or building VPN-like tools without system-wide impact.

## Performance

One major drawback of this implementation is its speed. While rewriting it in a faster language like C++ with Python bindings could solve this, it would also add significant complexity. For now, the focus is on optimizing the existing Python code as much as possible.

## References

The following references were used while building this project:

- [WireGuard paper](https://www.wireguard.com/papers/wireguard.pdf)
- [WireGuard website](https://www.wireguard.com)
- [wireguard-lwip](https://github.com/smartalock/wireguard-lwip) by [smartalock](https://github.com/smartalock)
- [RFC 791](https://datatracker.ietf.org/doc/html/rfc791) (IPv4 standard)
- [IANA DSCP & ECN](https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml) (IPv4/IPv6 DSCP and ECN)
- [IANA Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml) (IPv4/IPv6 Protocol Numbers)
- [RFC 768](https://datatracker.ietf.org/doc/html/rfc768) (UDP standard)
- [RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293) (TCP standard)
- [IANA TCP Parameters](https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml) (TCP enumerators, options, etc)
