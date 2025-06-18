class PacketReplay:
	def __init__(self, width = 32):
		assert width >= 32 and width <= 64
		self.reset(width)

	def reset(self, bitmap_width = 32):
		self.bitmap_width = bitmap_width
		self.bitmap_mask = (1 << bitmap_width) - 1
		self.bitmap = 0
		self.count = 0

	def check(self, sequence):
		if sequence == 0:
			return False

		bitmap_width = self.bitmap_width
		bitmap = self.bitmap
		count = self.count

		if sequence > count:
			# Make sure we don't shift a value too high
			diff = min(bitmap_width, sequence - count)

			if diff < bitmap_width:
				bitmap = (bitmap << diff) | 1
			else:
				bitmap = 1

			count = sequence
		else:
			diff = count - sequence

			if diff >= bitmap_width:
				return False # Too far behind

			if bitmap & (1 << diff):
				return False # Already seen
			else:
				bitmap |= (1 << diff)

		self.bitmap = bitmap & self.bitmap_mask
		self.count = count

		return True
