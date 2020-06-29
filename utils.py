'''
LLDB utils functions
Author : peternguyen
'''
from struct import *

def p32(value):
	return pack('<I', value)

def p64(value):
	return pack('<Q', value)

def get_default_frame(debugger):
	process = debugger.GetSelectedTarget().GetProcess()
	thread = process.GetThreadAtIndex(0)
	frame = thread.GetFrameAtIndex(0)
	return frame

def find_module_by_name(target, module_name):
	for module in target.modules:
		if module.file.basename == module_name:
			return module

	return None

def get_text_section(module):
	for section in module.sections:
		if section.GetName() == '__TEXT':
			return section

	return None

def resolve_mem_map(target, addr):
	found = False
	module_name = ''
	offset = -1

	# found in load image
	for module in target.modules:
		for section in module.sections:
			if section.GetLoadAddress(target) == 0xffffffffffffffff:
				continue

			start_addr = section.GetLoadAddress(target)
			end_addr = start_addr + section.GetFileByteSize()

			if start_addr <= addr <= end_addr:
				module_name = module.file.basename
				text_section = get_text_section(module)
				base_addr = text_section.GetLoadAddress(target)
				offset = addr - base_addr
				found = True
				break

		if found:
			break

	return module_name, offset

def parse_number(str_num):

	if not str_num:
		return -1

	try:
		if str_num.startswith('0x'):
			str_num = int(str_num, 16)
		else:
			str_num = int(str_num)
	except ValueError:
		try:
			str_num = int(str_num, 16)
		except ValueError:
			return -1

	return str_num

def de_bruijn(charset , n = 4, maxlen = 0x10000):
		# string cyclic function
		# this code base on https://github.com/Gallopsled/pwntools/blob/master/pwnlib/util/cyclic.py
		# Taken from https://en.wikipedia.org/wiki/De_Bruijn_sequence but changed to a generator
		"""de_bruijn(charset = string.ascii_lowercase, n = 4) -> generator

		Generator for a sequence of unique substrings of length `n`. This is implemented using a
		De Bruijn Sequence over the given `charset`.

		The returned generator will yield up to ``len(charset)**n`` elements.

		Arguments:
		  charset: List or string to generate the sequence over.
		  n(int): The length of subsequences that should be unique.
		"""
		k = len(charset)
		a = [0] * k * n
		sequence = []
		def db(t, p):
			if len(sequence) == maxlen:
				return
			if t > n:
				if n % p == 0:
					for j in range(1	, p + 1):
						sequence.append(charset[a[j]])
						if len(sequence) == maxlen:
							return
			else:
				a[t] = a[t - p]
				db(t + 1, p)

				for j in range(a[t - p] + 1, k):
					a[t] = j
					db(t + 1, t)
		db(1,1)
		return bytearray(sequence)

# generate a cyclic string
def cyclic(length = None, n = 4):
	charset = [b'ABCDEFGHIJKLMNOPQRSTUVWXYZ', b'%$-;abcdefghijklmopqrtuvwxyz', b'sn()0123456789']
	mixed_charset = mixed = b''
	k = 0
	while True:
		for i in range(0, len(charset)): mixed += charset[i][k:k+1]
		if not mixed: break
		mixed_charset += mixed
		mixed = b''
		k+=1

	pattern = de_bruijn(mixed_charset, 3, length)
	return pattern

def cyclic_find(subseq, length = 0x10000):
	# finding subseq in generator then return pos of this subseq
	# if it doens't find then return -1
	generator = cyclic(length)

	if isinstance(subseq, int): # subseq might be a number or hex value
		try:
			subseq = p32(subseq)
		except error: # struct.error
			try:
				subseq = p64(subseq)
			except error: # struct.error
				return -1
	
	if not isinstance(subseq, bytes):
		return -1
	# finding position of subseq
	subseq = bytearray(subseq)
	saved = bytearray([])
	pos = 0

	for c in generator:
		saved.append(c)
		if len(saved) > len(subseq):
			saved.pop(0)
			pos += 1
		if saved == subseq: # if subseq equal saved then return pos of subseq
			return pos
	return -1