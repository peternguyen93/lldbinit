#
# symbols.py
# Author: peternguyen
# Include all APIs that resolve address to debug symbol
#
from typing_extensions import Self
from typing import Optional, TypedDict, Dict, Any, List, TypeVar, Callable, Optional
from utils import get_target, get_pointer_size, is_x64, strip_kernel_or_userPAC, \
				is_aarch64, get_gp_register, get_current_sp, read_pointer_from, \
				LLDBMemoryException, ESBValue, get_current_pc
from lldb import SBAddress, SBSymbol, SBTarget, SBInstruction, \
				SBInstructionList, SBModule, SBDebugger, SBCommandReturnObject, \
				SBCommandInterpreter, SBSection
from dataclasses import dataclass
# import bisect
import ctypes
import re
import json

T = TypeVar('T')

POINTER_SIZE = 8 # assume target architecture is 64 bits

def bisect_left(a: List[T],
				x: T,
				lo: int=0,
				hi: Optional[int]=None,
				*,
				key: Optional[Callable[[Any], Any]]=None) -> int:
	"""Return the index where to insert item x in list a, assuming a is sorted.

	The return value i is such that all e in a[:i] have e < x, and all e in
	a[i:] have e >= x.  So if x already appears in the list, a.insert(i, x) will
	insert just before the leftmost x already there.

	Optional args lo (default 0) and hi (default len(a)) bound the
	slice of a to be searched.

	A custom key function can be supplied to customize the sort order.
	"""

	if lo < 0:
		raise ValueError('lo must be non-negative')
	if hi is None:
		hi = len(a)
	# Note, the comparison uses "<" to match the
	# __lt__() logic in list.sort() and in heapq.
	if key is None:
		while lo < hi:
			mid = (lo + hi) // 2
			if a[mid] < x:
				lo = mid + 1
			else:
				hi = mid
	else:
		while lo < hi:
			mid = (lo + hi) // 2
			if key(a[mid]) < x:
				lo = mid + 1
			else:
				hi = mid
	return lo

def get_ret_address() -> int:
	global POINTER_SIZE

	if is_aarch64():
		return get_gp_register('lr')

	stack_addr = get_current_sp()
	if stack_addr == 0:
		print("[-] error: Current SP address is empty.")
		return -1
	
	if POINTER_SIZE:
		POINTER_SIZE = get_pointer_size()
	
	try:
		ret_addr = read_pointer_from(stack_addr, POINTER_SIZE)
	except LLDBMemoryException:
		print("[-] error: Failed to read memory at 0x{:x}.".format(stack_addr))
		return -1
	
	return ret_addr

PAC_BL_INSTS = (
	'blraa', 'blraaz', 'blrab', 'blrabz', 'braa', 'braaz', 'brab', 'brabz'
)

def is_bl_pac_inst(mnemonic: str) -> bool:
	return mnemonic in PAC_BL_INSTS

def read_instruction(target: SBTarget, address: int) -> Optional[SBInstruction]:
	if is_x64():
		instruction_list: SBInstructionList = target.ReadInstructions(\
										SBAddress(address, target), 1, 'intel')
	else:
		instruction_list: SBInstructionList = target.ReadInstructions(SBAddress(address, target), 1)
	
	if instruction_list.GetSize() == 0:
		print("[-] error: not enough instructions disassembled.")
		return None

	return instruction_list.GetInstructionAtIndex(0)

def read_instructions(target: SBTarget, start_addr: int, n_inst: int) -> SBInstructionList:
	if is_x64():
		instruction_list: SBInstructionList = \
			target.ReadInstructions(SBAddress(start_addr, target), n_inst, 'intel')
	else:
		instruction_list: SBInstructionList = \
				target.ReadInstructions(SBAddress(start_addr, target), n_inst)
	return instruction_list

def get_instruction_count(start: int, end: int, max_inst: int) -> int:
	'''
		Return how many instructions from start address to end address
	'''

	target = get_target()
	sb_start = SBAddress(start, target)
	sb_end = SBAddress(end, target)

	instructions = read_instructions(target, start, max_inst)
	return instructions.GetInstructionsCount(sb_start, sb_end, False)

def get_current_pc_inst() -> SBInstruction:
	target = get_target()
	cur_instruction = read_instruction(target, get_current_pc())
	assert cur_instruction != None
	return cur_instruction

# return the instruction mnemonic at input address
def get_mnemonic(target_addr: int) -> str:
	target = get_target()
	cur_instruction = read_instruction(target, target_addr)
	if cur_instruction == None:
		return ''
	
	# much easier to use the mnemonic output instead of disassembling via cmd line and parse
	mnemonic = cur_instruction.GetMnemonic(target)
	return mnemonic

def get_operands(source_address: int) -> str:
	# returns the instruction operands
	target = get_target()
	# use current memory address
	# needs to be this way to workaround SBAddress init bug
	cur_instruction = read_instruction(target, source_address)
	return '' if cur_instruction == None else cur_instruction.GetOperands(target)

def get_inst_size(target_addr: int) -> int:
	# find out the size of an instruction using internal disassembler
	target = get_target()
	cur_instruction = read_instruction(target, target_addr)
	return 0 if cur_instruction == None else cur_instruction.size

def get_custom_symbol_from_address(address: int) -> str:
	# use custom symbol
	func_name = CUSTOM_SYMBOLS.query_func_name(address)
	if func_name:
		return func_name

	var_name = CUSTOM_SYMBOLS.query_var_name(address)
	if var_name:
		return var_name
	
	return ''

def get_symbol_from_address(address: int) -> str:
	'''
		Return a symbold corresponding with an address
	'''
	target = get_target()

	# because address could less than zero -> force it into unsigned int
	pz = get_pointer_size()
	if pz == 4:
		address = ctypes.c_uint32(address).value
	elif pz == 8:
		address = ctypes.c_uint64(address).value
	
	try:
		sb_addr = SBAddress(address, target)
		addr_sym: SBSymbol = sb_addr.GetSymbol()
		
		if addr_sym.IsValid():
			sym_name = addr_sym.GetName()
			# return '' if sym_name == None else sym_name
			if sym_name != None:
				return sym_name
		
		return get_custom_symbol_from_address(address)

	except TypeError:
		# use custom symbol
		return get_custom_symbol_from_address(address)

def arm64_resolve_dispatch_function_name(target: SBTarget, target_address: int) -> int:
	'''
		target: SBTarget
		target_address : target call address bl <addr>
		@return : a symbol if error return empty string

		dyld_shared_cache of iOS alway dispatch an other module function by:
		libdispatch:__stubs:00000001800B2E28                 ADRP            X16, #0x193E1A460@PAGE
		libdispatch:__stubs:00000001800B2E2C                 ADD             X16, X16, #0x193E1A460@PAGEOFF
		libdispatch:__stubs:00000001800B2E30                 BR              X16

		out goal to resolve symbol for this address
	'''
	instructions = read_instructions(target, target_address, 3)
	instruction_0: SBInstruction = instructions.GetInstructionAtIndex(0)
	instruction_1: SBInstruction = instructions.GetInstructionAtIndex(1)
	instruction_2: SBInstruction = instructions.GetInstructionAtIndex(2)

	if instruction_0.GetMnemonic(target) != 'adrp' or \
		instruction_1.GetMnemonic(target) != 'add' or \
		(instruction_2.GetMnemonic(target) != 'br' and \
			   instruction_2.GetOperands(target).startswith('x')):
		return 0
	
	page_shift = int(instruction_0.GetOperands(target).split(',')[1])
	target_page = (target_address + page_shift * 0x1000) & 0xFFFFFFFFFFFFF000
	call_offset = int(instruction_1.GetOperands(target).split(',')[2].strip(' #'), 16)
	call_func_ptr = target_page + call_offset 

	return call_func_ptr

# retrieve the module full path name an address belongs to
def get_module_name(src_addr: int) -> str:
	target = get_target()
	src_module: SBModule = SBAddress(src_addr, target).module
	if src_module.IsValid():
		module_name = src_module.file.fullpath
		if module_name != None:
			return module_name
	
	if CUSTOM_SYMBOLS.is_loaded:
		# use custom symbol if it was loaded
		return CUSTOM_SYMBOLS.query_segment_name(src_addr)
	
	return ''

ARM_CALL_INDIRECT_INSTRUCTIONS = ('bl', 'br', 'b', 'blr')
X86_CALL_INDIRECT_INSTRUCTIONS = ('call', 'jmp')

def get_indirect_dest_from(inst: SBInstruction) -> int:
	'''
		Given an instruction, try to resolve indirect call address
		On success: return address
		On failure: return 0
	'''
	# operand = get_operands(source_address).lower()
	# mnemonic = get_mnemonic(source_address)
	target = get_target()
	mnemonic: str = inst.GetMnemonic(target)
	operand: str = inst.GetOperands(target)

	if mnemonic not in X86_CALL_INDIRECT_INSTRUCTIONS and \
		mnemonic not in ARM_CALL_INDIRECT_INSTRUCTIONS and \
			mnemonic not in PAC_BL_INSTS:
		return 0

	# calls into a deferenced memory address
	if "qword" in operand:
		'''
			Handle call, jmp in x86 only
				call [<register> + <offset>]
				jmp [<register> + <offset>]
		'''
		deref_addr = 0
		# first we need to find the address to dereference
		if '+' in operand:
			x = re.search(r'\[([a-z0-9]{2,3} \+ 0x[0-9a-z]+)\]', operand)
			if x == None:
				return 0

			value = ESBValue.init_with_expression(f'${x.group(1)}')
			deref_addr = value.int_value
			if "rip" in operand:
				# deref_addr = deref_addr + get_inst_size(source_address)
				deref_addr = deref_addr + inst.size
		else:
			x = re.search(r'\[([a-z0-9]{2,3})\]', operand)
			if x == None:
				return 0
				
			value = ESBValue.init_with_expression(f'${x.group(1)}')
			deref_addr = value.int_value
		
		# now we can dereference and find the call target
		return read_pointer_from(deref_addr, POINTER_SIZE)

	# calls into a register included x86_64 and aarch64
	elif operand.startswith('r') or operand.startswith('e') or operand.startswith('x') or \
			operand in ('lr', 'sp', 'fp'):
		'''
			Handle those instructions:
			- call [x64 register] (begin with "r")
			- call [x86 register] (begin with "e")
			- bl/b [arm64 register] (begin with "x")
			- blraa [arm64 register], [arm64 register]
			- braa [arm64 register], [arm64 register]
		'''

		if is_bl_pac_inst(mnemonic):
			# handle branch with link register with pointer authentication
			operand = operand.split(',')[0].strip(' ')

		operand_value = ESBValue.init_with_expression(f'${operand}')
		return operand_value.int_value

	# RIP relative calls
	elif operand.startswith('0x'):
		# the disassembler already did the dirty work for us
		# so we just extract the address
		x = re.search(r'(0x[0-9a-z]+)', operand)
		if x != None:
			return int(x.group(1), 16)
	
	return 0

def get_indirect_address_from(inst: SBInstruction) -> int:
	'''
		Given a instruction verify it is indirect call
		@return: indirect address from instruction
	'''
	target = get_target()

	mnemonic: str = inst.GetMnemonic(target)
	# if "ret" in cur_instruction.mnemonic:
	if mnemonic == 'ret': # ret
		print(f'ret: ', get_ret_address())
		return get_ret_address()
	
	if mnemonic == 'retab' or mnemonic == 'retaa':
		print(f'{mnemonic}: ', get_ret_address())
		# decode PAC pointer
		return strip_kernel_or_userPAC(get_ret_address())

	# trace both x86_64 and arm64
	if mnemonic in X86_CALL_INDIRECT_INSTRUCTIONS or \
		mnemonic in ARM_CALL_INDIRECT_INSTRUCTIONS or \
			is_bl_pac_inst(mnemonic):
		# don't care about RIP relative jumps
		operands: str = inst.GetOperands(target)
		if operands.startswith('0x'):
			return int(operands, 16)
		
		# indirect_addr = get_indirect_flow_target(src_addr)
		indirect_addr = get_indirect_dest_from(inst)
		if is_bl_pac_inst(mnemonic):
			return strip_kernel_or_userPAC(indirect_addr)

		return indirect_addr

	# all other branches just return 0
	return 0

def get_indirect_flow_address(src_addr: int) -> int:
	'''
		Wrapper of get_indirect_address_from
		@args: take src address
		@return: indirect call address if src_address contains indirect call instructions
				else return 0
	'''

	target = get_target()
	inst = read_instruction(target, src_addr)
	if inst == None:
		print("[!] error: not enough instructions disassembled.")
		return 0

	if not inst.DoesBranch():
		return 0
	
	return get_indirect_address_from(inst)

def get_indirect_flow_dest(src_addr: int) -> int:
	target = get_target()
	inst = read_instruction(target, src_addr)
	if inst == None:
		print("[!] error: not enough instructions disassembled.")
		return 0
	
	return get_indirect_dest_from(inst)

@dataclass
class ModuleInfo:
	module_name: str = ''
	section_name: str = ''
	perms: int = 0
	offset: int = -1
	abs_offset: int = -1

def get_module_info_from_address(target: SBTarget, addr: int) -> ModuleInfo:
	module_info = ModuleInfo()

	# trying to find in SBModules
	for module in target.modules:
		module: SBModule
		absolute_offset = 0
		for section in module.sections:
			section: SBSection = section
			if section.GetLoadAddress(target) == 0xffffffffffffffff:
				continue

			start_addr = section.GetLoadAddress(target)
			end_addr = start_addr + section.GetFileByteSize()
			if start_addr <= addr <= end_addr:
				module_info = ModuleInfo(
					module.file.basename,
					section.GetName(),
					section.GetPermissions(),
					addr - start_addr,
					absolute_offset + (addr - start_addr)
				)
				return module_info

			absolute_offset += section.GetFileByteSize()

	# using CUSTOM_SYMBOLS
	if CUSTOM_SYMBOLS.is_loaded:
		# query segment from custom symbols and return to caller instead
		segment = CUSTOM_SYMBOLS.query_segment(addr)
		if segment:
			sect_name = ''
			seg_name = segment['name']
			if ':' in segment['name']:
				split_str = segment['name'].split(':')
				sect_name = split_str[1].upper()
				seg_name = split_str[0]
			return ModuleInfo(seg_name,
								sect_name, 0,
								addr - segment['start'])

	return module_info

class SegmentSymbol(TypedDict):
	name: str
	start: int
	end: int

class CustomSymbols:
	funcs: Dict[int, str]
	variables: Dict[int, str]
	segments: List[SegmentSymbol]
	is_loaded: bool

	def __init__(self: Self):
		self.funcs = {}
		self.variables = {}
		self.is_loaded = False

	def load_symbols(self: Self, symbol_path: str):
		with open(symbol_path, 'r') as f:
			sym_infos = json.load(f)

		func_syms = sym_infos['functions']
		var_syms = sym_infos['variables']

		# json key alway is str,
		# convert address as str in key to int
		for key in func_syms:
			self.funcs[int(key)] = func_syms[key]
		
		# convert address as str in key to int
		for key in var_syms:
			self.variables[int(key)] = var_syms[key]
		
		self.funcs = dict(sorted(self.funcs.items()))
		self.variables = dict(sorted(self.variables.items()))
		self.segments = sorted(sym_infos['segments'], key=lambda seg: seg['start'])
		self.is_loaded = True

	def query_segment(self: Self, addr: int) -> Optional[SegmentSymbol]:
		# in python3.9 which is used in LLDB bisec.bisect_left doesn't support key argument
		# we have to get all start_ea to a list and bisect_left it
		idx = bisect_left(self.segments, addr, key=lambda o: o['start'])
		if idx > 0:
			return self.segments[idx - 1]
		return None

	def query_segment_name(self: Self, addr: int) -> str:
		segment = self.query_segment(addr)
		if segment == None:
			return ''
		return segment['name']
	
	def query_func_name(self: Self, func_addr: int) -> str:
		try:
			return self.funcs[func_addr]
		except KeyError:
			# use bisect to search if func_addr falling in middle between 2 addresses
			keys_list = list(self.funcs.keys())
			idx = bisect_left(keys_list, func_addr)
			if idx > 0:
				# match address should be idx - 1
				found_addr = keys_list[idx - 1]
				return self.funcs[found_addr]
			return ''
	
	def query_var_name(self: Self, var_addr: int) -> str:
		try:
			return self.variables[var_addr]
		except KeyError:
			# use bisect to search if func_addr falling in middle between 2 addresses
			keys_list = list(self.variables.keys())
			idx = bisect_left(keys_list, var_addr)
			if idx > 0:
				# match address should be idx - 1
				found_addr = keys_list[idx - 1]
				return self.variables[found_addr]
			return ''

CUSTOM_SYMBOLS = CustomSymbols()

def load_custom_symbols(symbol_path: str):
	CUSTOM_SYMBOLS.load_symbols(symbol_path)

def custom_sym_backtrace(debugger: SBDebugger):
	if not CUSTOM_SYMBOLS.is_loaded:
		print('[!] Custom symbols did not loaded')
		return

	res = SBCommandReturnObject()
	ci: SBCommandInterpreter = debugger.GetCommandInterpreter()
	ci.HandleCommand("bt", res)

	if not res.Succeeded():
		print('[!] Unable to parse `bt` command output')
		return
	
	output: str = res.GetOutput()

	# parse frame and produce output
	for line in output.split('\n'):
		if line.startswith('* thread'):
			print(line)
			continue

		if not line:
			continue
		
		_match = re.match(r'\s.+frame #(\d+):.*(0x[0-9a-fA-F]*)', line)
		if not _match:
			print('[!] Unable to parse frame for output')
			break

		str_addr = _match[2]
		addr = strip_kernel_or_userPAC(int(str_addr, 16))
		func_name = CUSTOM_SYMBOLS.query_func_name(addr)
		if not func_name:
			# couldn't resolve function name just print it
			print(line)
		else:
			idx = line.index(str_addr) + len(str_addr)
			print(line[:idx] + f' - {func_name}' + line[idx:])