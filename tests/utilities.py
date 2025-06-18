def iter_vec2(a, b):
	for val_a in range(a + 1):
		for val_b in range(b + 1):
			yield val_a, val_b


def compare_list(a, b):
	for v in a:
		if v not in b:
			return False

	for v in b:
		if v not in a:
			return False

	return True
