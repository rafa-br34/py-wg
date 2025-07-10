def checksum_compute(data: bytes) -> int:
	checksum = 0
	length = len(data)
	index = 0

	while length > 1:
		checksum += (data[index] << 8) + data[index + 1]
		length -= 2
		index += 2

	if length == 1:
		checksum += data[index] << 8

	checksum &= 0xFFFFFFFF

	while checksum >> 16:
		checksum = (checksum & 0xFFFF) + (checksum >> 16)

	return ~checksum & 0xFFFF


class Checksum:
	def __init__(self):
		self.reset()

	def reset(self):
		self._remainder = None
		self._checksum = 0

	def update(self, data: bytes):
		length = len(data)
		index = 0

		if self._remainder is not None:
			self._checksum += self._remainder + data[index]
			index += 1
			length -= 1

		while length > 1:
			self._checksum += (data[index] << 8) + data[index + 1]
			length -= 2
			index += 2

		if length == 1:
			self._remainder = data[index] << 8
		else:
			self._remainder = None

	def finalize(self) -> int:
		if self._remainder is not None:
			self._checksum += self._remainder

		checksum = self._checksum & 0xFFFFFFFF

		while checksum >> 16:
			checksum = (checksum & 0xFFFF) + (checksum >> 16)

		return ~checksum & 0xFFFF
