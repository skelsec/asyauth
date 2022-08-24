
def str_one(x):
	return str(x[0])

def int_one(x):
	return int(x[0])

def bool_one(x):
	return bool(int_one(x))

def int_list(x):
	return [int(y) for y in x]