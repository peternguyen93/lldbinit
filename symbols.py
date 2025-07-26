#
# symbols.py
# Author: peternguyen
# Include all APIs that resolve address to debug symbol
#
from typing import Optional
from utils import get_target, get_pointer_size, is_x64
from lldb import SBAddress, SBSymbol, SBTarget, SBInstruction, SBInstructionList, SBModule
import ctypes

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
			return addr_sym.GetName()
	except TypeError:
		pass
	
	return ''

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
	module_name = src_module.file.fullpath
	return module_name if module_name != None else ''