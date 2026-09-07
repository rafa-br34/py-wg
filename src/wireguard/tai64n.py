import time
import math


def encode_tai64n(timestamp: float) -> bytes:
	seconds = math.floor(timestamp)
	floating = timestamp - seconds

	ts_tai64 = int(seconds + 0x4000000000000000)
	ts_n = int(floating * 1000000000)

	return ts_tai64.to_bytes(8, "big", signed = True) + ts_n.to_bytes(4, "big", signed = False)


def decode_tai64n(timestamp: bytes) -> float:
	assert len(timestamp) == 12, "TAI64N value must be 12-bytes"

	ts_tai64 = int.from_bytes(timestamp[:8], "big", signed = True) - 0x4000000000000000
	ts_n = int.from_bytes(timestamp[8:], "big", signed = False) / 1000000000

	return ts_tai64 + ts_n


def tai64n_next(timestamp: bytes) -> bytes:
	"""The smallest TAI64N (12-byte big-endian) value strictly greater than *timestamp*.

	WireGuard timestamps (wireguard.pdf §5.1) are per-peer monotonically
	increasing 96-bit numbers compared with memcmp() on the raw encoding, so the
	successor is computed in the integer/nanosecond domain rather than through
	floats (which cannot represent sub-microsecond increments at epoch scale).
	"""
	assert len(timestamp) == 12, "TAI64N value must be 12-bytes"

	seconds = int.from_bytes(timestamp[:8], "big", signed = True)
	nanos = int.from_bytes(timestamp[8:], "big", signed = False) + 1

	if nanos >= 1000000000:
		nanos = 0
		seconds += 1

	return seconds.to_bytes(8, "big", signed = True) + nanos.to_bytes(4, "big", signed = False)


def current_tai64n(precision: int | None = None) -> bytes:
	current = time.time()

	if precision is None:
		return encode_tai64n(current)
	else:
		exponent = 10 ** precision
		current = int(exponent * current) / exponent

		return encode_tai64n(current)
