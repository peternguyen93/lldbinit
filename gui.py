'''
gui rendering for lldbinit: everything that draws the stop-hook context
(registers, stack, data, flow and code windows) plus the output buffer they
render into. lldbinit owns the commands, the stop-hook and when the context
is displayed, this module owns how it is displayed.

Keep this module free of lldbinit imports (utils/symbols/vmmap are the leaves).
'''
from __future__ import print_function

import sys
import re
import os

import lldb
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from utils import *
from symbols import get_symbol_from_address, arm64_resolve_dispatch_function_name,\
					get_inst_size, get_mnemonic, get_operands, \
					read_instructions, get_module_name, \
					get_current_pc_inst, get_indirect_address_from, get_indirect_flow_address, \
					get_indirect_flow_dest, \
					get_active_symbols, get_symbols_generation, \
					get_module_info_from_address, POINTER_SIZE, \
					UNNAMED_SYMBOL_RE, query_func_name_from_file
from vmmap import *

#
# gui-owned configuration (writers in lldbinit must set gui.ATTR, a bare
# assignment would only rebind lldbinit's star-imported copy)
#
CONFIG_ENABLE_COLOR = 1
CONFIG_REGISTER_PWN_STYLE = 1 # aarch64 register display: 0 = classic grid, 1 = annotated (pwndbg style), toggle with 'regstyle'
DATA_WINDOW_ADDRESS = 0

old_register: Dict[str, int] = {}

GlobalListOutput = []

flag_regs = ('rflags', 'eflags', 'cpsr')
segment_regs = ("cs", "ds", "es", "gs", "fs", "ss", "cs", "gs", "fs")

x86_registers = [
	"eax", "ebx", "ebp", "esp", "eflags", "edi", "esi", "edx", "ecx", "eip"
	"cs", "ds", "es", "gs", "fs", "ss"
]

x86_64_registers = [
	"rax", "rbx", "rbp", "rsp", "rflags", "rdi", "rsi", "rdx", "rcx", "rip",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "cs", "gs", "fs"
]

arm_32_registers = [
	"r0", "r1", "r2", "r3", "cpsr", "r4", "r5", "r6", "r7", "r8",
	"r9", "r10", "r11", "r12", "sp", "lr", "pc"
]

aarch64_registers = [
	'x0', 'x1', 'x2', 'x3', 'cpsr',
	'x4', 'x5', 'x6', 'x7', 
	'x8', 'x9', 'x10', 'x11',
	'x12', 'x13', 'x14', 'x15', 
	'x16', 'x17', 'x18', 'x19', 
	'x20', 'x21', 'x22', 'x23', 
	'x24', 'x25', 'x26', 'x27', 
	'x28', 'x29', 'lr', 'sp', 'pc', 'fpcr', 'fpsr'
]

# ----------------------------------------------------------
# Color Related Functions
# ----------------------------------------------------------

def get_color_status(addr: int) -> str:
	target = get_target()
	if target == None:
		return ''

	process = get_process()
	if process == None:
		return ''

	module_map = get_module_info_from_address(target, addr)
	if module_map.section_name.startswith('__TEXT'):
		# address is excutable page
		return "RED"
	elif module_map.section_name.startswith('__DATA'):
		return "MAGENTA"

	return "WHITE" if not readable(addr) else "CYAN"

def frame_file_pc(frame: SBFrame, unused: Any) -> str:
    addr = frame.GetPCAddress().GetFileAddress()
    if addr == lldb.LLDB_INVALID_ADDRESS:
        return "????????"
    return f"{addr:x}"

def color(x: str):
	out_col = ""
	if CONFIG_ENABLE_COLOR == 0:
		output(out_col)
		return    
	output(COLORS[x])

# append data to the output that we display at the end of the hook-stop
def output(x: str):
	global GlobalListOutput
	GlobalListOutput.append(x)

def display_map_info(map_info: MapInfo):
	perm = map_info.perm.split('/')
	if 'x' in perm[0]:
		print(COLORS['RED'], end='')
	elif 'rw' in perm[0]:
		print(COLORS['MAGENTA'], end='')
	elif map_info.map_type.startswith('Stack'):
		print(COLORS['YELLOW'], end='')
	elif map_info.map_type.startswith('MALLOC'):
		print(COLORS['CYAN'], end='')
	elif map_info.map_type.startswith('__TEXT'):
		print(COLORS['RED'], end='')
	elif map_info.map_type.startswith('__DATA'):
		print(COLORS['MAGENTA'], end='')
	
	print(map_info.map_type + ' [', end='')

	if POINTER_SIZE == 4:
		print("0x%.08X - 0x%.08X" % (map_info.start, map_info.end), end='')
	else:
		print("0x%.016lX - 0x%.016lX" % (map_info.start, map_info.end), end='')

	print(') - ', end='')
	print(map_info.perm, end='')
	print(' {0} {1}'.format(map_info.shm, map_info.region), end='')
	print(COLORS['RESET'])

# the disassembler we use on stop context
# we can customize output here instead of using the cmdline as before and grabbing its output
def disassemble(start_address: int, count: int):
	target = get_target()

	# read instructions from start_address
	instructions_file = read_instructions(target, start_address, count)

	# find out the biggest instruction lenght and mnemonic length
	# so we can have a uniform output
	max_size = 0
	max_mnem_size = 0

	for instr in instructions_file:
		instr: SBInstruction = instr
		if instr.size > max_size:
			max_size = instr.size

		mnem_len = len(instr.GetMnemonic(target))
		if mnem_len > max_mnem_size:
			max_mnem_size = mnem_len
	
	current_pc = get_current_pc()
	# get info about module if there is a symbol
	module_name = get_module_name(start_address)

	count = 0
	blockstart_sbaddr: Optional[SBAddress] = None
	blockend_sbaddr: Optional[SBAddress] = None
	# for mem_inst in instructions_mem:
	for mem_inst in instructions_file:
		mem_inst: SBInstruction = mem_inst
		# get the same instruction but from the file version because we need some info from it
		file_inst: SBInstruction = instructions_file.GetInstructionAtIndex(count)
		# try to extract the symbol name from this location if it exists
		# needs to be referenced to file because memory it doesn't work
		symbol_name = file_inst.addr.GetSymbol().GetName()
		# if there is no symbol just display module where current instruction is
		# also get rid of unnamed symbols since they are useless
		if not symbol_name or "___lldb_unnamed_symbol" in symbol_name:
			if count == 0:
				if CONFIG_ENABLE_COLOR == 1:
					color(COLOR_SYMBOL_NAME)
					output("@ {}:".format(module_name) + "\n")
					color("RESET")
				else:
					output("@ {}:".format(module_name) + "\n")			
		
		elif symbol_name:
			# print the first time there is a symbol name and save its interval
			# so we don't print again until there is a different symbol
			cur_load_addr = file_inst.GetAddress().GetLoadAddress(target)

			blockstart_addr = 0
			if blockstart_sbaddr:
				blockstart_addr = blockstart_sbaddr.GetLoadAddress(target)

			blockend_addr = 0
			if blockend_sbaddr:
				blockend_addr = blockend_sbaddr.GetLoadAddress(target)

			if not blockstart_addr or (cur_load_addr < blockstart_addr) \
																or (cur_load_addr >= blockend_addr):
				if CONFIG_ENABLE_COLOR == 1:
					color(COLOR_SYMBOL_NAME)
					output("{} @ {}:".format(symbol_name, module_name) + "\n")
					color("RESET")
				else:
					output("{} @ {}:".format(symbol_name, module_name) + "\n")
				blockstart_sbaddr = file_inst.addr.GetSymbol().GetStartAddress()
				blockend_sbaddr = file_inst.addr.GetSymbol().GetEndAddress()
		
		# get the instruction bytes formatted as uint8
		inst_data = mem_inst.GetData(target).uint8
		# mnem = mem_inst.mnemonic
		mnem: str = mem_inst.GetMnemonic(target)
		# operands = mem_inst.operands
		operands: str = mem_inst.GetOperands(target)
		bytes_string = ""
		total_fill = max_size - mem_inst.size
		total_spaces = mem_inst.size - 1
		
		for x in inst_data:
			bytes_string += "{:02x}".format(x)
			if total_spaces > 0:
				bytes_string += " "
				total_spaces -= 1
		
		if total_fill > 0:
			# we need one more space because the last byte doesn't have space
			# and if we are smaller than max size we are one space short
			bytes_string += "  " * total_fill
			bytes_string += " " * total_fill
		
		mnem_len = len(mem_inst.GetMnemonic(target))
		if mnem_len < max_mnem_size:
			missing_spaces = max_mnem_size - mnem_len
			mnem += " " * missing_spaces

		# the address the current instruction is loaded at
		# we need to extract the address of the instruction and then find its loaded address
		memory_addr = mem_inst.addr.GetLoadAddress(target)
		# the address of the instruction in the current module
		# for main exe it will be the address before ASLR if enabled, otherwise the same as current
		# for modules it will be the address in the module code, not the address it's loaded at
		# so we can use this address to quickly get to current instruction in module loaded at a disassembler
		# without having to rebase everything etc
		file_addr = file_inst.addr.GetFileAddress()

		# fix dyld_shared_arm64 dispatch function to correct symbol name
		dyld_resolve_name = ''
		dyld_call_addr = 0
		if is_aarch64() and file_inst.GetMnemonic(target) in ('bl', 'b'):
			indirect_addr = get_indirect_flow_dest(memory_addr)
			dyld_call_addr = arm64_resolve_dispatch_function_name(target, indirect_addr)
			dyld_resolve_name = get_symbol_from_address(dyld_call_addr)
			# same ___lldb_unnamed_symbol_<file_addr> placeholder swap as above,
			# for resolved dispatch stubs whose target lldb cannot name
			unnamed = UNNAMED_SYMBOL_RE.search(dyld_resolve_name or '')
			if unnamed:
				real_name = query_func_name_from_file(int(unnamed.group(1), 16))
				if real_name:
					dyld_resolve_name = real_name
		
		if not dyld_resolve_name:
			comment:str = file_inst.GetComment(target)
			if comment:
				# lldb comments carry the useless ___lldb_unnamed_symbol_<file_addr>
				# placeholder for dyld shared cache branches - swap it for the
				# active symbol source's name (static db or live server), the
				# embedded file address is the ida address, no slide math needed
				unnamed = UNNAMED_SYMBOL_RE.search(comment)
				if unnamed:
					real_name = query_func_name_from_file(int(unnamed.group(1), 16))
					if real_name:
						comment = UNNAMED_SYMBOL_RE.sub(real_name, comment, count=1)
				comment = f" ; {comment}"
		else:
			comment = f" ; resolve symbol stub: j___{dyld_resolve_name}"

		if current_pc == memory_addr:
			# try to retrieve extra information if it's a branch instruction
			# used to resolve indirect branches and try to extract Objective-C selectors
			if mem_inst.DoesBranch():

				if dyld_call_addr:
					flow_addr = dyld_call_addr
				else:
					flow_addr = get_indirect_flow_address(mem_inst.GetAddress().GetLoadAddress(target))
					
				if flow_addr > 0:
					flow_module_name = get_module_name(flow_addr)
					symbol_info = ""
					# try to solve the symbol for the target address
					# target_symbol_name = lldb.SBAddress(flow_addr,target).GetSymbol().GetName()
					target_symbol_name = get_symbol_from_address(flow_addr)
					# if there is a symbol append to the string otherwise
					# it will be empty and have no impact in output
					if target_symbol_name:
						symbol_info = target_symbol_name + " @ "
					
					if not comment:
						# remove space for instructions without operands
						# if mem_inst.operands == "":
						if mem_inst.GetOperands(target):
							comment = f'; {symbol_info}{flow_addr:x} @ {flow_module_name}'
						else:
							comment = f' ; {symbol_info}{flow_addr:x} @ {flow_module_name}'
					else:
						comment+= f' {flow_addr:x} @ {flow_module_name}'
				
				# handle objective C call
				objc = ''
				if dyld_call_addr:
					objc = get_objectivec_selector_at(dyld_call_addr)
				else:
					objc = get_objectivec_selector(current_pc)
				
				if objc != "":
					comment+= f' -> {objc}'

			if CONFIG_ENABLE_COLOR == 1:
				color("BOLD")
				color(COLOR_CURRENT_PC)
				output("->  0x{:x} (0x{:x}): {}  {}   {}{}".format(memory_addr, file_addr, bytes_string, mnem, operands, comment) + "\n")
				color("RESET")
			else:
				output("->  0x{:x} (0x{:x}): {}  {}   {}{}".format(memory_addr, file_addr, bytes_string, mnem, operands, comment) + "\n")
		else:
			output("    0x{:x} (0x{:x}): {}  {}   {}{}".format(memory_addr, file_addr, bytes_string, mnem, operands, comment) + "\n")

		count += 1

# ------------------------------------------------------------
# stop-hook windows
# ------------------------------------------------------------

def display_stack():
	'''Hex dump current stack pointer'''
	stack_addr = get_current_sp()
	if stack_addr == 0:
		return

	membuff = read_mem(stack_addr, 0x100)
	if len(membuff) == 0:
		print("[-] error: not enough bytes read.")
		return

	output(hexdump(stack_addr, membuff, " ", 16, 4))

def display_data():
	'''Hex dump current data window pointer'''
	data_addr = DATA_WINDOW_ADDRESS
	if data_addr == 0:
		return

	membuff = read_mem(data_addr, 0x100)
	if len(membuff) == 0:
		print("[-] error: not enough bytes read.")
		return

	output(hexdump(data_addr, membuff, " ", 16, 4))

# workaround for lldb bug regarding RIP addressing outside main executable
def get_rip_relative_addr(source_address: int) -> int:
	inst_size = get_inst_size(source_address)
	if inst_size <= 1:
		print("[-] error: instruction size too small.")
		return 0
	# XXX: problem because it's not just 2 and 5 bytes
	# 0x7fff53fa2180 (0x1180): 0f 85 84 01 00 00     jne    0x7fff53fa230a ; stack_not_16_byte_aligned_error

	offset_bytes = read_mem(source_address+1, inst_size-1)
	if not len(offset_bytes):
		print("[-] error: Failed to read memory at 0x{:x}.".format(source_address))
		return 0

	data = 0
	if inst_size == 2:
		data = int.from_bytes(offset_bytes, byteorder='little')
	elif inst_size == 5:
		data = int.from_bytes(offset_bytes, byteorder='little')
		
	rip_call_addr = source_address + inst_size + data
	return rip_call_addr

def get_ret_address() -> int:
	if is_aarch64():
		return get_gp_register('lr')

	stack_addr = get_current_sp()
	if stack_addr == 0:
		print("[-] error: Current SP address is empty.")
		return -1
	
	try:
		ret_addr = read_pointer_from(stack_addr, POINTER_SIZE)
	except LLDBMemoryException:
		print("[-] error: Failed to read memory at 0x{:x}.".format(stack_addr))
		return -1
	
	return ret_addr

# XXX: x64 only
def display_objc():
	options = lldb.SBExpressionOptions()
	options.SetLanguage(lldb.eLanguageTypeObjC)
	options.SetTrapExceptions(False)

	className = objc_get_classname(get_objc_instance_object())
	if not className:
		return
	
	if is_x64():
		selector_addr = get_gp_register("rsi")
	elif is_aarch64():
		selector_addr = get_gp_register("x1")
	else:
		return

	membuff = read_mem(selector_addr, 0x100)
	if not len(membuff):
		print('[!] Unable to read selector of objc')
		return

	selector = membuff.split(b'\x00')
	if len(selector) != 0:
		color("RED")
		output('Class: ')
		color("RESET")
		output(className)
		color("RED")
		output(' Selector: ')
		color("RESET")
		output(selector[0].decode('utf-8'))

def display_indirect_flow():
	target = get_target()
	cur_inst = get_current_pc_inst()

	indirect_addr = get_indirect_address_from(cur_inst)
	indirect_symbol = ''
	if indirect_addr:
		indirect_symbol = get_symbol_from_address(indirect_addr)

	# mnemonic: str = cur_inst.GetMnemonic(target)
	if not indirect_symbol:
		return
	
	output(f"0x{indirect_addr:x} -> {COLORS['RED']}{get_symbol_from_address(indirect_addr)}{COLORS['RESET']}")
	if indirect_symbol.startswith('objc_msgSend'):
		output("\n")
		display_objc()
	output("\n")

def get_objectivec_selector_at(call_addr: int) -> str:
	symbol_name = get_symbol_from_address(call_addr)
	if not symbol_name:
		return ''

	# XXX: add others?
	if (not symbol_name.startswith("objc_msgSend")) and \
			(symbol_name not in ('objc_alloc', 'objc_opt_class')):
		return ""
	
	objc = get_objc_instance_object()
	class_name = objc_get_classname(objc)
	if not class_name and symbol_name != 'objc_msgSendSuper2':
		return ''
	
	if symbol_name == 'objc_msgSendSuper2':
		dereference = read_u64(objc)
		class_name = objc_get_classname(dereference)
	
	if not class_name:
		return ''
	
	if is_x64():
		selector_addr = get_gp_register("rsi")
	else:
		selector_addr = get_gp_register("x1")

	'''
		In modern Objective C, binary usually has another link layout to setup
		objc_msgSend like dissasembly below, so that we don't need to reply on
		selector table in register (x1) but linker also imply method after '$'
		so we can extract

		objc_msgSend$addItemToInventory: @ objCPointer:
		0x100000da0 (0x100000da0): 41 00 00 90  adrp   x1, 8
		0x100000da4 (0x100000da4): 21 9c 40 f9  ldr    x1, [x1, #0x138]
		0x100000da8 (0x100000da8): 30 00 00 90  adrp   x16, 4
		0x100000dac (0x100000dac): 10 16 40 f9  ldr    x16, [x16, #0x28]
		->  0x100000db0 (0x100000db0): 00 02 1f d6  br     x16; objc_msgSend 
	'''
	selector_name = ''
	selector_idx = symbol_name.find('$')
	if selector_idx >= 0:
		selector_name = symbol_name[selector_idx + 1:]
	else:
		membuf = read_mem(selector_addr, 0x100)
		selector = membuf.split(b'\00')
		selector_name = selector[0].decode('utf-8')
	
	if selector_name:
		return f'[{class_name} {selector_name}]'

	return f'[{class_name} unknown:]'

def get_objectivec_selector(src_addr: int) -> str:

	if not is_x64() and not is_aarch64():
		return ''

	call_addr = get_indirect_flow_dest(src_addr)
	if call_addr == 0:
		return ''
		
	return get_objectivec_selector_at(call_addr)

# ------------------------------------------------------------
# The heart of lldbinit - when lldb stop this is where we land 
# ------------------------------------------------------------

def print_cpu_registers(register_names: List[str]):
	registers = get_gp_registers()
	break_flag = False
	reg_flag_val = -1
	reg_val = -1

	for i, register_name in enumerate(register_names):		
		try:
			reg_val = registers[register_name]
		except KeyError:
			if is_aarch64():
				if register_name == 'x29':
					reg_val = registers['fp']
				elif register_name == 'x30':
					reg_val = registers['lr']

		if register_name in flag_regs:
			output("  ")
			color("BOLD")
			color("UNDERLINE")
			color(COLOR_CPUFLAGS)
			if is_arm() or is_aarch64():
				dump_cpsr(reg_val)
			elif is_i386() or is_x64():
				dump_eflags(reg_val)
			color("RESET")
			reg_flag_val = reg_val
		
		else:
			if (not break_flag) and (register_name in segment_regs):
				output('\n')
				break_flag = True

			color(COLOR_REGNAME)
			output("  {0:<4}: ".format(register_name.upper().ljust(4, ' ')))

			try:

				if register_name in ('rsp', 'esp', 'sp'):
					color("BLUE")

				elif register_name in ('rip', 'eip', 'pc'):
					color("RED")

				else:
					if reg_val == old_register[register_name]:
						color(get_color_status(reg_val))
					else:
						color(COLOR_REGVAL_MODIFIED)
			except KeyError:
				color(get_color_status(reg_val))

			if register_name in segment_regs:
				output("%.04X" % (reg_val))
			else:
				if is_x64() or is_aarch64():
					output("0x%.016lX" % (reg_val))
				else:
					output("0x%.08X" % (reg_val))

			old_register[register_name] = reg_val

		if (not break_flag) and (i % 4 == 0) and i != 0:
			output('\n')

	if is_x64() or is_i386():
		dump_jumpx86(reg_flag_val)
	elif is_aarch64():
		dump_jump_arm64(reg_flag_val)
	
	output("\n")

# ------------------------------------------------------------
# aarch64 annotated register display (pwndbg style, optional)
# switched with the 'regstyle' command, classic grid stays default
# ------------------------------------------------------------

REG_ANN_MAX = 30 # max annotation length per cell
REG_COL_WIDTH = 2 + 4 + 2 + 18 + 2 + REG_ANN_MAX # indent + name + ': ' + value + gap + annotation

REG_ANN_CACHE: Dict[str, Tuple[int, str]] = {} # register name -> (value, annotation) of the previous stop
REG_ANN_CONTEXT: Optional[tuple] = None # (region snapshot fingerprint, symbols generation) the cache was built with
REG_SNAPSHOT: Optional[Tuple[int, List[MapInfo]]] = None # (pid, held region snapshot) reused across stops
REG_SNAPSHOT_RELOAD: bool = False # set when a register fails to resolve against the held snapshot

def find_map_info_pwn(map_infos: List[MapInfo], addr: int) -> Optional[MapInfo]:
	'''find the MapInfo region containing addr, linear scan is fine (few hundred regions x ~34 registers)'''
	for map_info in map_infos:
		if map_info.start <= addr < map_info.end:
			return map_info

	return None

def get_reg_snapshot(reload: bool = False) -> List[MapInfo]:
	'''held region snapshot for the register display: reused across stops and
	   only reloaded when the process changed or a resolution failed against
	   it (fresh mmap / stack growth), so stepping costs no vmmap/wire queries'''
	global REG_SNAPSHOT

	try:
		pid = get_process().GetProcessID()
	except Exception:
		return []

	if not reload and REG_SNAPSHOT and REG_SNAPSHOT[0] == pid:
		return REG_SNAPSHOT[1]

	try:
		cache = VMMapCacheBase.get_cache()
		if isinstance(cache, MacOSVMMapCache):
			# the vmmap binary backend caches internally, force past it
			cache.cache_load(force_reload = True)

		map_infos = cache.get_map_infos()
	except Exception:
		map_infos = []

	REG_SNAPSHOT = (pid, map_infos)
	return map_infos

def get_reg_symbol_pwn(addr: int) -> Optional[Tuple[str, int]]:
	'''resolve addr to (function name, function start) via the active symbol source, lldb native symbols as fallback'''
	try:
		name = get_active_symbols().query_func_name(addr)
		if name:
			start = get_active_symbols().query_func_addr(name)
			if start is not None:
				return (name, start)
	except Exception:
		pass

	# lldb native symbol from the loaded modules (unstripped binary/dylibs)
	try:
		target = get_target()
		symbol = lldb.SBAddress(addr, target).GetSymbol()
		if symbol and symbol.IsValid():
			name = symbol.GetName()
			start = symbol.GetStartAddress().GetLoadAddress(target)
			if name and start != lldb.LLDB_INVALID_ADDRESS:
				return (name, start)
	except Exception:
		pass

	return None

def get_reg_annotation_pwn(register_name: str, reg_val: int, map_infos: List[MapInfo], context_changed: bool) -> str:
	'''pwndbg style heuristic chain: small int skip, PAC strip, region lookup, symbol refine.
	   the chain only runs for registers that changed since the previous stop (or when
	   the region snapshot / symbol source changed), unchanged registers reuse the
	   cached annotation since the same value resolves to the same thing'''
	# flags/control registers are never pointers
	if register_name in ('cpsr', 'fpcr', 'fpsr'):
		return ''

	# 1. values below 64K are plain integers, not pointers
	if reg_val < 0x10000:
		return ''

	# unchanged register in an unchanged session: previous annotation still holds
	cached = REG_ANN_CACHE.get(register_name)
	if not context_changed and cached and cached[0] == reg_val:
		return cached[1]

	# 2. strip PAC so arm64e pointers can resolve, tag it when stripped
	stripped = strip_kernel_or_userPAC(reg_val)
	pac_tag = stripped != reg_val

	# 3. region lookup from the held snapshot
	map_info = find_map_info_pwn(map_infos, stripped)
	if map_info is None:
		if map_infos:
			# not in any known region - most likely fresh memory mapped
			# since the snapshot was taken (mmap / stack growth), ask for
			# one reload and retry with the fresh regions
			global REG_SNAPSHOT_RELOAD
			REG_SNAPSHOT_RELOAD = True
			ann = 'unmapped'
		else:
			# regions unsupported by the target, make no claim
			ann = ''

		REG_ANN_CACHE[register_name] = (reg_val, ann)
		return ann

	name, base = map_info.map_type.strip(), map_info.start

	# 4. executable regions (and pc/lr) refine to a function symbol
	if 'x' in map_info.perm or register_name in ('pc', 'lr'):
		sym_ann = get_reg_symbol_pwn(stripped)
		if sym_ann:
			sname, sbase = sym_ann
			# reject bogus nearest-preceding matches that fall far outside the function
			if 0 <= stripped - sbase <= 0x10000:
				name, base = sname, sbase

	# 5. compose the final annotation
	off = stripped - base
	ann = name if off == 0 else '{0}+0x{1:X}'.format(name, off)
	if pac_tag:
		ann = '[pac] ' + ann

	if len(ann) > REG_ANN_MAX:
		ann = ann[:REG_ANN_MAX - 1] + '…'

	REG_ANN_CACHE[register_name] = (reg_val, ann)

	return ann

def render_reg_cell_pwn(register_name: str, reg_val: int, map_infos: List[MapInfo], context_changed: bool, prev_value: Optional[int]) -> Tuple[List[Tuple[str, str]], int]:
	'''render one cell as (color segments, visible length), same value color rules as the classic display'''
	if register_name in ('rsp', 'esp', 'sp'):
		value_color = "BLUE"
	elif register_name in ('rip', 'eip', 'pc'):
		value_color = "RED"
	else:
		if prev_value is None:
			# register never displayed before
			value_color = get_color_status(reg_val)
		elif reg_val == prev_value:
			value_color = get_color_status(reg_val)
		else:
			value_color = COLOR_REGVAL_MODIFIED

	value_text = '0x%.016lX' % (reg_val)
	segs = [('  ', ''),
			(register_name.upper().ljust(4, ' ') + ': ', COLOR_REGNAME),
			(value_text, value_color)]

	# visible length without the color codes so the columns stay aligned
	plain_len = 2 + 4 + 2 + len(value_text)

	ann = get_reg_annotation_pwn(register_name, reg_val, map_infos, context_changed)
	if ann:
		segs.append(('  ' + ann, "DIM"))
		plain_len += 2 + len(ann)

	return segs, plain_len

def flush_reg_row_pwn(row: List[Tuple[List[Tuple[str, str]], int]], append_newline: bool = True) -> None:
	'''render one grid row of prebuilt cells, pad by visible length so the 2 columns align'''
	if not row:
		return

	for i, (segs, plain_len) in enumerate(row):
		for text, col in segs:
			if col:
				color(col)

			output(text)

		color("RESET")
		if i < len(row) - 1:
			output(' ' * (REG_COL_WIDTH - plain_len))

	if append_newline:
		output('\n')

def dump_cpsr_row_pwn(cpsr_val: int) -> None:
	'''render the cpsr flag bits row, same styling as the classic display'''
	output('  ')
	color("BOLD")
	color("UNDERLINE")
	color(COLOR_CPUFLAGS)
	dump_cpsr(cpsr_val)
	color("RESET")

def print_cpu_registers_pwn(register_names: List[str]):
	'''2 column annotated register display, the region snapshot is reused across
	   stops and only reloaded when a register fails to resolve against it'''
	registers = get_gp_registers()

	# capture the previous stop values once, so the modified-highlight stays
	# correct even when the annotation pass runs twice (stale snapshot retry)
	prev_register = dict(old_register)

	map_infos = get_reg_snapshot()

	# the annotation cache is valid while the register value, the region
	# snapshot and the symbol source all stay the same
	global REG_ANN_CONTEXT, REG_SNAPSHOT_RELOAD
	reg_context = (
		tuple((m.start, m.end, m.perm, m.map_type) for m in map_infos),
		get_symbols_generation(),
	)
	context_changed = reg_context != REG_ANN_CONTEXT
	REG_ANN_CONTEXT = reg_context

	reg_flag_val = -1
	cells: List[Tuple[List[Tuple[str, str]], int]] = []

	# the annotation pass can run twice: when a register does not resolve
	# against the held snapshot it is stale (fresh mmap), reload once and
	# re-annotate everything against the fresh regions
	reloaded = False
	for _ in range(2):
		REG_SNAPSHOT_RELOAD = False
		cells = []
		reg_flag_val = -1

		for register_name in register_names:
			try:
				reg_val = registers[register_name]
			except KeyError:
				if register_name == 'x29':
					try:
						reg_val = registers['fp']
					except KeyError:
						reg_val = -1
				elif register_name == 'x30':
					try:
						reg_val = registers['lr']
					except KeyError:
						reg_val = -1
				else:
					# registers missing from the general set are skipped
					reg_val = -1

			if register_name in flag_regs:
				# the cpsr flags join the last grid line, in the second column
				reg_flag_val = reg_val
				continue

			if reg_val == -1:
				continue

			cells.append(render_reg_cell_pwn(register_name, reg_val, map_infos, context_changed, prev_register.get(register_name)))
			old_register[register_name] = reg_val

		# one reload per stop max: a failure that survives the fresh snapshot
		# (unmapped address, region gap) is genuine, do not chase it again
		if not REG_SNAPSHOT_RELOAD or reloaded:
			REG_SNAPSHOT_RELOAD = False
			break

		reloaded = True
		map_infos = get_reg_snapshot(reload = True)
		reg_context = (
			tuple((m.start, m.end, m.perm, m.map_type) for m in map_infos),
			get_symbols_generation(),
		)
		context_changed = True
		REG_ANN_CONTEXT = reg_context

	# render the buffered grid, cpsr flags opposite the trailing cell
	for i in range(0, len(cells), 2):
		pair = cells[i:i + 2]
		is_last = i + len(pair) >= len(cells)
		keep_line = is_last and reg_flag_val != -1

		flush_reg_row_pwn(pair, append_newline = not keep_line)
		if keep_line:
			output(' ' * (REG_COL_WIDTH - pair[-1][1]))
			dump_cpsr_row_pwn(reg_flag_val)
			output('\n')

	# jump hints share the last row line like the classic display,
	# dump_jump emits color codes even without a hint so only keep
	# the render when something visible was produced
	out_len = len(GlobalListOutput)
	if is_aarch64():
		dump_jump_arm64(reg_flag_val)

	if any(re.sub(r'\x1b\[[0-9;]*m', '', entry).strip() for entry in GlobalListOutput[out_len:]):
		output('\n')
	else:
		del GlobalListOutput[out_len:]

def dump_eflags(eflags: int):
	# the registers are printed by inverse order of bit field
	# no idea where this comes from :-]
	# masks = { "CF":0, "PF":2, "AF":4, "ZF":6, "SF":7, "TF":8, "IF":9, "DF":10, "OF":11 }
	# printTuples = sorted(masks.items() , reverse=True, key=lambda x: x[1])
	eflagsTuples = [('OF', 11), ('DF', 10), ('IF', 9), ('TF', 8), ('SF', 7), ('ZF', 6), ('AF', 4), ('PF', 2), ('CF', 0)]
	# use the first character of each register key to output, lowercase if bit not set
	for flag, bitfield in eflagsTuples :
		if bool(eflags & (1 << bitfield)) == True:
			output(flag[0] + " ")
		else:
			output(flag[0].lower() + " ")

# function to dump the conditional jumps results
def dump_jumpx86(eflags: int):
	# masks and flags from https://github.com/ant4g0nist/lisa.py
	masks = { "CF":0, "PF":2, "AF":4, "ZF":6, "SF":7, "TF":8, "IF":9, "DF":10, "OF":11 }
	flags = { key: bool(eflags & (1 << value)) for key, value in masks.items() }

	if is_i386():
		pc_addr = get_gp_register("eip")
	elif is_x64():
		pc_addr = get_gp_register("rip")
	else:
		print("[-] dump_jumpx86() error: wrong architecture.")
		return

	mnemonic = get_mnemonic(pc_addr)
	color("RED")
	output_string=""
	## opcode 0x77: JA, JNBE (jump if CF=0 and ZF=0)
	## opcode 0x0F87: JNBE, JA
	if "ja" == mnemonic or "jnbe" == mnemonic:
		if flags["CF"] == False and flags["ZF"] == False:
			output_string="Jump is taken (c = 0 and z = 0)"
		else:
			output_string="Jump is NOT taken (c = 0 and z = 0)"
	## opcode 0x73: JAE, JNB, JNC (jump if CF=0)
	## opcode 0x0F83: JNC, JNB, JAE (jump if CF=0)
	elif "jae" == mnemonic or "jnb" == mnemonic or "jnc" == mnemonic:
		if flags["CF"] == False:
			output_string="Jump is taken (c = 0)"
		else:
			output_string="Jump is NOT taken (c != 0)"
	## opcode 0x72: JB, JC, JNAE (jump if CF=1)
	## opcode 0x0F82: JNAE, JB, JC
	elif "jb" == mnemonic or "jc" == mnemonic or "jnae" == mnemonic:
		if flags["CF"] == True:
			output_string="Jump is taken (c = 1)"
		else:
			output_string="Jump is NOT taken (c != 1)"
	## opcode 0x76: JBE, JNA (jump if CF=1 or ZF=1)
	## opcode 0x0F86: JBE, JNA
	elif "jbe" == mnemonic or "jna" == mnemonic:
		if flags["CF"] == True or flags["ZF"] == 1:
			output_string="Jump is taken (c = 1 or z = 1)"
		else:
			output_string="Jump is NOT taken (c != 1 or z != 1)"
	## opcode 0xE3: JCXZ, JECXZ, JRCXZ (jump if CX=0 or ECX=0 or RCX=0)
	# XXX: we just need cx output...
	elif "jcxz" == mnemonic or "jecxz" == mnemonic or "jrcxz" == mnemonic:
		rcx = get_gp_register("rcx")
		ecx = get_gp_register("ecx")
		cx = get_gp_register("cx")
		if ecx == 0 or cx == 0 or rcx == 0:
			output_string="Jump is taken (cx = 0 or ecx = 0 or rcx = 0)"
		else:
			output_string="Jump is NOT taken (cx != 0 or ecx != 0 or rcx != 0)"
	## opcode 0x74: JE, JZ (jump if ZF=1)
	## opcode 0x0F84: JZ, JE, JZ (jump if ZF=1)
	elif "je" == mnemonic or "jz" == mnemonic:
		if flags["ZF"] == 1:
			output_string="Jump is taken (z = 1)"
		else:
			output_string="Jump is NOT taken (z != 1)"
	## opcode 0x7F: JG, JNLE (jump if ZF=0 and SF=OF)
	## opcode 0x0F8F: JNLE, JG (jump if ZF=0 and SF=OF)
	elif "jg" == mnemonic or "jnle" == mnemonic:
		if flags["ZF"] == 0 and flags["SF"] == flags["OF"]:
			output_string="Jump is taken (z = 0 and s = o)"
		else:
			output_string="Jump is NOT taken (z != 0 or s != o)"
	## opcode 0x7D: JGE, JNL (jump if SF=OF)
	## opcode 0x0F8D: JNL, JGE (jump if SF=OF)
	elif "jge" == mnemonic or "jnl" == mnemonic:
		if flags["SF"] == flags["OF"]:
			output_string="Jump is taken (s = o)"
		else:
			output_string="Jump is NOT taken (s != o)"
	## opcode: 0x7C: JL, JNGE (jump if SF != OF)
	## opcode: 0x0F8C: JNGE, JL (jump if SF != OF)
	elif "jl" == mnemonic or "jnge" == mnemonic:
		if flags["SF"] != flags["OF"]:
			output_string="Jump is taken (s != o)"
		else:
			output_string="Jump is NOT taken (s = o)"
	## opcode 0x7E: JLE, JNG (jump if ZF = 1 or SF != OF)
	## opcode 0x0F8E: JNG, JLE (jump if ZF = 1 or SF != OF)
	elif "jle" == mnemonic or "jng" == mnemonic:
		if flags["ZF"] == 1 or flags["SF"] != flags["OF"]:
			output_string="Jump is taken (z = 1 or s != o)"
		else:
			output_string="Jump is NOT taken (z != 1 or s = o)"
	## opcode 0x75: JNE, JNZ (jump if ZF = 0)
	## opcode 0x0F85: JNE, JNZ (jump if ZF = 0)
	elif "jne" == mnemonic or "jnz" == mnemonic:
		if flags["ZF"] == 0:
			output_string="Jump is taken (z = 0)"
		else:
			output_string="Jump is NOT taken (z != 0)"
	## opcode 0x71: JNO (OF = 0)
	## opcode 0x0F81: JNO (OF = 0)
	elif "jno" == mnemonic:
		if flags["OF"] == 0:
			output_string="Jump is taken (o = 0)"
		else:
			output_string="Jump is NOT taken (o != 0)"
	## opcode 0x7B: JNP, JPO (jump if PF = 0)
	## opcode 0x0F8B: JPO (jump if PF = 0)
	elif "jnp" == mnemonic or "jpo" == mnemonic:
		if flags["PF"] == 0:
			output_string="Jump is NOT taken (p = 0)"
		else:
			output_string="Jump is taken (p != 0)"
	## opcode 0x79: JNS (jump if SF = 0)
	## opcode 0x0F89: JNS (jump if SF = 0)
	elif "jns" == mnemonic:
		if flags["SF"] == 0:
			output_string="Jump is taken (s = 0)"
		else:
			output_string="Jump is NOT taken (s != 0)"
	## opcode 0x70: JO (jump if OF=1)
	## opcode 0x0F80: JO (jump if OF=1)
	elif "jo" == mnemonic:
		if flags["OF"] == 1:
			output_string="Jump is taken (o = 1)"
		else:
			output_string="Jump is NOT taken (o != 1)"
	## opcode 0x7A: JP, JPE (jump if PF=1)
	## opcode 0x0F8A: JP, JPE (jump if PF=1)
	elif "jp" == mnemonic or "jpe" == mnemonic:
		if flags["PF"] == 1:
			output_string="Jump is taken (p = 1)"
		else:
			output_string="Jump is NOT taken (p != 1)"
	## opcode 0x78: JS (jump if SF=1)
	## opcode 0x0F88: JS (jump if SF=1)
	elif "js" == mnemonic:
		if flags["SF"] == 1:
			output_string="Jump is taken (s = 1)"
		else:
			output_string="Jump is NOT taken (s != 1)"

	if output_string:
		if is_i386():
			output(" " + output_string)
		elif is_x64():
			output(" "*46 + output_string)
		else:
			output(output_string)

	color("RESET")

def dump_cpsr(cpsr: int):
	# XXX: some fields reserved in recent ARM specs so we should revise and set to latest?
	cpsrTuples = [ ('N', 31), ('Z', 30), ('C', 29), ('V', 28), ('Q', 27), ('J', 24), 
				   ('E', 9), ('A', 8), ('I', 7), ('F', 6), ('T', 5) ]
	# use the first character of each register key to output, lowercase if bit not set
	for flag, bitfield in cpsrTuples :
		if bool(cpsr & (1 << bitfield)) == True:
			output(flag + " ")
		else:
			output(flag.lower() + " ")

def dump_jump_arm64(cpsr: int):
	masks = { 'N': 31, 'Z':30, 'C':29, 'V': 28, 'Q':27, 'J':24, 'E':9, 'A':8, 'I':7, 'F':6, 'T':5}
	flags = { key: bool(cpsr & (1 << value)) for key, value in masks.items() }

	if is_aarch64():
		pc_addr = get_gp_register("pc")
	else:
		print("[-] dump_jump_arm64() error: wrong architecture.")
		return

	mnemonic = get_mnemonic(pc_addr)
	color("RED")
	output_string=''

	if mnemonic == 'cbnz' or mnemonic == 'tbnz':
		if not flags['Z']:
			output_string = "Jump is taken (Z = 0)"
		else:
			output_string = "Jump is NOT taken (Z = 1)"
	
	elif mnemonic == 'cbz' or mnemonic == 'tbz':
		if flags['Z']:
			output_string = "Jump is taken (Z = 1)"
		else:
			output_string = "Jump is NOT taken (Z = 0)"
	
	elif mnemonic == 'b.eq':
		if flags['Z']:
			output_string = "Jump is taken (Z = 1)"
		else:
			output_string = "Jump is NOT taken (Z = 0)"
	
	elif mnemonic == 'b.ne':
		if not flags['Z']:
			output_string = "Jump is taken (Z = 0)"
		else:
			output_string = "Jump is NOT taken (Z = 1)"
	
	elif mnemonic == 'b.cs' or mnemonic == 'b.hs':
		if flags['C']:
			output_string = "Jump is taken (C = 1)"
		else:
			output_string = "Jump is NOT taken (C = 0)"
	
	elif mnemonic == 'b.cc' or mnemonic == 'b.lo':
		if not flags['C']:
			output_string = "Jump is taken (C = 0)"
		else:
			output_string = "Jump is NOT taken (C = 1)"
	
	elif mnemonic == 'b.mi':
		if flags['N']:
			output_string = "Jump is taken (N = 1)"
		else:
			output_string = "Jump is NOT taken (N = 0)"
	
	elif mnemonic in ('csel', 'csinc', 'csinv', 'csneg'):
		operands = get_operands(pc_addr)
		if flags['Z']:
			output_string = mnemonic + " => " + operands.split(',')[1]
		else:
			output_string = mnemonic + " => " + operands.split(',')[2]
	
	elif mnemonic in ('cset', 'csetm'):
		operands = get_operands(pc_addr)

		if flags['Z']:
			result = 1 if mnemonic == 'cset' else -1
		else:
			result = 0
		output_string = "{0} => {1} = {2}".format(mnemonic, operands.split(',')[0], result)
	
	if output_string:
		output(' '*40 + output_string)
	
	color("RESET")

def print_registers():
	if is_i386(): 
		register_format = x86_registers
	elif is_x64():
		register_format = x86_64_registers
	elif is_arm():
		register_format = arm_32_registers
	elif is_aarch64():
		register_format = aarch64_registers
		if CONFIG_REGISTER_PWN_STYLE:
			print_cpu_registers_pwn(register_format)
			return
	else:
		raise OSError('Unsupported Architecture')

	print_cpu_registers(register_format)
