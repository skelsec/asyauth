
def hexdump( src, length=16, sep='.', start = 0):
	'''
	@brief Return {src} in hex dump.
	@param[in] length	{Int} Nb Bytes by row.
	@param[in] sep		{Char} For the text part, {sep} will be used for non ASCII char.
	@return {Str} The hexdump
	@note Full support for python2 and python3 !
	'''
	result = []
	if src is None:
		return ''

	# Python3 support
	try:
		xrange(0,1)
	except NameError:
		xrange = range

	for i in xrange(0, len(src), length):
		subSrc = src[i:i+length]
		hexa = ''
		isMiddle = False
		for h in xrange(0,len(subSrc)):
			if h == length/2:
				hexa += ' '
			h = subSrc[h]
			if not isinstance(h, int):
				h = ord(h)
			h = hex(h).replace('0x','')
			if len(h) == 1:
				h = '0'+h
			hexa += h+' '
		hexa = hexa.strip(' ')
		text = ''
		for c in subSrc:
			if not isinstance(c, int):
				c = ord(c)
			if 0x20 <= c < 0x7F:
				text += chr(c)
			else:
				text += sep
		if start == 0:
			result.append(('%08x:  %-'+str(length*(2+1)+1)+'s  |%s|') % (i, hexa, text))
		else:
			result.append(('%08x(+%04x):  %-'+str(length*(2+1)+1)+'s  |%s|') % (start+i, i, hexa, text))
	return '\n'.join(result)