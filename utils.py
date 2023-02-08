'''
	lldbinit core functions
	Author : peternguyen
'''
from typing import List, Dict, Union, Optional, Type, Set, Any, Generic, TypeVar, Tuple, Iterator
import typing
from typing_extensions import Self
from lldb import SBDebugger, SBFrame, SBProcess, SBThread, SBTarget, SBAddress, \
				SBValue, SBSymbol, SBError, SBType, SBValueList, SBInstructionList, \
				SBInstruction, SBModule, SBModuleSpecList, SBCommandInterpreter, \
				SBCommandReturnObject, SBSection, SBBreakpoint
import ctypes
import lldb
import re
from subprocess import Popen, PIPE, check_call, CalledProcessError
from pathlib import Path
from struct import pack, unpack
from dataclasses import dataclass
import struct
import platform
import time

# default colors - modify as you wish
COLOR_REGVAL           = "WHITE"
COLOR_REGNAME          = "GREEN"
COLOR_CPUFLAGS         = "RED"
COLOR_SEPARATOR        = "BLUE"
COLOR_HIGHLIGHT_LINE   = "RED"
COLOR_REGVAL_MODIFIED  = "YELLOW"
COLOR_SYMBOL_NAME      = "BLUE"
COLOR_CURRENT_PC       = "RED"

#
# Don't mess after here unless you know what you are doing!
#

COLORS = {
	"BLACK":     "\033[30m",
	"RED":       "\033[31m",
	"GREEN":     "\033[32m",
	"YELLOW":    "\033[33m",
	"BLUE":      "\033[34m",
	"MAGENTA":   "\033[35m",
	"CYAN":      "\033[36m",
	"WHITE":     "\033[37m",
	"RESET":     "\033[0m",
	"BOLD":      "\033[1m",
	"UNDERLINE": "\033[4m"
}

# ----------------------------------------------------------
# Packing and Unpacking functions
# ----------------------------------------------------------

def p32(value: int) -> bytes:
	return pack('<I', value)

def p64(value: int) -> bytes:
	return pack('<Q', value)

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

	module_map = resolve_mem_map(target, addr)
	if module_map.section_name.startswith('__TEXT'):
		# address is excutable page
		return "RED"
	elif module_map.section_name.startswith('__DATA'):
		return "MAGENTA"

	return "WHITE" if not readable(addr) else "CYAN"

# ----------------------------------------------------------
# Functions to extract internal and process lldb information
# ----------------------------------------------------------

class LLDBTargetNotFound(Exception):
	# This exception will raise error when frame is None
	def __init__(self, *args: object) -> None:
		super().__init__(*args)

class LLDBFrameNotFound(Exception):
	def __init__(self, *args: object) -> None:
		super().__init__(*args)

def get_selected_frame(debugger: SBDebugger) -> Optional[SBFrame]:
	process = debugger.GetSelectedTarget().GetProcess()
	thread = process.GetSelectedThread()
	frame = thread.GetSelectedFrame()
	return frame

def get_debugger() -> SBDebugger:
	debugger: Optional[SBDebugger] = lldb.debugger
	assert debugger != None, 'lldb.debugger == None'
	return debugger

def get_target() -> SBTarget:
	# try to get current target
	debugger = get_debugger()
	target = debugger.GetSelectedTarget()

	if not target:
		raise LLDBTargetNotFound("[-] error: no target available. please add a target to lldb.")

	return target

def get_arch() -> str:
	arch: str = get_target().triple
	return arch.split('-')[0]

def get_process() -> SBProcess:
	'''
		A read only property that returns an lldb object
		that represents the process (lldb.SBProcess)that this target owns.
	'''
	return get_target().process

def get_frame() -> SBFrame:
	frame = None

	# SBProcess supports thread iteration -> SBThread
	for thread_i in get_process():
		thread: SBThread = thread_i
		if thread.GetStopReason() != lldb.eStopReasonInvalid:
			frame = thread.GetFrameAtIndex(0)
			break

	# this will generate a false positive when we start the target the first time because there's no context yet.
	if not frame:
		raise LLDBFrameNotFound("[-] warning: get_frame() failed. Is the target binary started?")

	return frame

def get_thread() -> Optional[SBThread]:
	thread = None

	# SBProcess supports thread iteration -> SBThread
	for thread_i in get_process():
		thread_i: SBThread = thread_i
		if thread_i.GetStopReason() != lldb.eStopReasonInvalid:
			thread = thread_i
	
	if not thread:
		print("[-] warning: get_thread() failed. Is the target binary started?")

	return thread

def parse_number(str_num: str) -> int:
	num = -1
	if not str_num:
		return -1

	try:
		if str_num.startswith('0x') or str_num.startswith('0X'):
			# parse hex number
			num = int(str_num, 16)
		else:
			# parse number
			num = int(str_num)
	except ValueError:
		try:
			# parse hex number without prefix
			num = int(str_num, 16)
		except ValueError:
			return -1

	return num

# evaluate an expression and return the value it represents
def get_c_array_addr(value: SBValue) -> int:
	var_type_name = value.GetTypeName()
	if not var_type_name:
		return 0
	
	if 'char [' in var_type_name or 'unsigned char [' in var_type_name:
		return value.GetLoadAddress()
	
	if 'int [' in var_type_name or 'unsigned int [' in var_type_name:
		return value.GetLoadAddress()

	return 0

def evaluate(command: str) -> int:
	'''
		Trying to parse command in str format into address
		Assume type of command are:
		- LLDB command -> execute this command and try to get int value
		- Variable name -> this variable hold address of not ??
		                -> if not get address of this variable (&var)
		- hex string -> convert to int
		- int string -> convert to int
	'''

	# assume command is lldb command
	some_express = ESBValue.init_with_expression(command)
	if some_express.is_valid:
		return some_express.int_value

	# assume command is variable
	try:
		some_var = ESBValue(command)
		if not some_var.is_valid:
			# this command is not variable name, try to convert to int
			return parse_number(command)
		
		if some_var.value == None:
			# this variable name doesn't hold address, get address of this some_var instead
			return some_var.addr_of()

		return some_var.int_value

	except ESBValueException:
		# this command is not variable name, try to convert to int
		return parse_number(command)

def is_i386() -> bool:
	arch = get_arch()
	return arch[0:1] == "i"

def is_x64() -> bool:
	arch = get_arch()
	return arch.startswith("x86_64")

def is_arm() -> bool:
	arch = get_arch()
	return arch == "armv7"

def is_aarch64() -> bool:
	arch = get_arch()
	return arch == 'aarch64' or arch.startswith('arm64')

def is_supported_arch() -> bool:
	return is_i386() or is_x64() or is_arm() or is_aarch64()

def get_pointer_size() -> int:
	poisz = evaluate("sizeof(long)")
	return poisz

# from https://github.com/facebook/chisel/blob/master/fblldbobjcruntimehelpers.py
def get_instance_object() -> str:
	instanceObject = ''
	if is_i386():
		instanceObject = '*(id*)($esp+4)'
	elif is_x64():
		instanceObject = '(id)$rdi'
	elif is_aarch64():
		instanceObject = '(id)$x0'
	# not supported yet
	elif is_arm():
		instanceObject = '(id)$r0'
	return instanceObject

# -------------------------
# Register related commands
# -------------------------

# return the int value of a general purpose register
def get_gp_register(reg_name: str) -> int:
	if reg_name.lower() == 'x30':
		reg_name = 'lr'

	regs = get_registers("general")
	for reg in regs:
		reg: SBValue = reg
		if reg_name == reg.GetName():
			return reg.unsigned

	return 0

def get_gp_registers() -> Dict[str, int]:
	regs = get_registers("general")
	
	registers = {}
	for reg in regs:
		reg_name = reg.GetName()
		registers[reg_name] = reg.unsigned

	return registers

def get_registers_by_frame(frame: SBFrame, kind: str) -> SBValue:
	registerSets: SBValueList = frame.GetRegisters()
	
	for registerSet in registerSets:
		registerSet: SBValue = registerSet
		registerName: str = registerSet.GetName()
		if kind.lower() in registerName.lower():
			return registerSet
	
	raise OSError(f'Unable to find register {kind}')
		
def get_registers(kind) -> SBValue:
	"""Returns the registers given the frame and the kind of registers desired.

	Returns None if there's no such kind.
	"""
	return get_registers_by_frame(get_frame(), kind)

# retrieve current instruction pointer via platform independent $pc register
def get_current_pc() -> int:
	try:
		frame = get_frame()
	except LLDBFrameNotFound:
		return 0

	return frame.pc

# retrieve current stack pointer via registers information
# XXX: add ARM
def get_current_sp() -> int:
	if is_i386():
		sp_addr = get_gp_register("esp")
	elif is_x64():
		sp_addr = get_gp_register("rsp")
	elif is_aarch64():
		sp_addr = get_gp_register("sp")
	else:
		print("[-] get_current_sp() error: wrong architecture.")
		return 0
	return sp_addr

def get_module_name_from(address: int) -> str:
	target = get_target()
	sb_addr = SBAddress(address, target)

	module: SBModule = sb_addr.module
	return typing.cast(str, module.file.fullpath)

def read_instructions(start: int, count: int) -> SBInstructionList:
	target = get_target()
	sb_start = SBAddress(start, target)
	return target.ReadInstructions(sb_start, count, 'intel')

def get_instruction_count(start: int, end: int, max_inst: int) -> int:
	'''
		Return how many instructions from start address to end address
	'''

	target = get_target()
	sb_start = SBAddress(start, target)
	sb_end = SBAddress(end, target)

	instructions = read_instructions(start, max_inst)
	return instructions.GetInstructionsCount(sb_start, sb_end, False)

# ----------------------------------------------------------
# LLDB Module functions
# ----------------------------------------------------------

def objc_get_classname(objc: str) -> str:
	classname_command = '(const char *)object_getClassName((id){})'.format(objc)
	class_name = ESBValue.init_with_expression(classname_command)
	if not class_name.is_valid:
		return ''
	
	return class_name.str_value

def find_module_by_name(target: SBTarget, module_name: str):
	for module in target.modules:
		module: SBModule = module
		if module.file.basename == module_name:
			return module

	return None

def get_text_section(module: SBModule) -> SBSection:
	return module.FindSection('__TEXT')

def resolve_symbol_name(address: int) -> str:
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

@dataclass
class ModuleInfo:
	module_name: str = ''
	section_name: str = ''
	perms: int = 0
	offset: int = -1
	abs_offset: int = -1

def resolve_mem_map(target: SBTarget, addr: int) -> ModuleInfo:
	module_info = ModuleInfo()

	# found in load image
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

	return module_info

@dataclass
class MapInfo(object):
	map_type: str
	start: int
	end: int
	perm: str
	shm: str
	region: str

	def __hash__(self) -> int:
		pack_fields = f'{self.map_type}_{self.start}_{self.end}'
		pack_fields+= f'_{self.perm}_{self.shm}_{self.region}'
		return hash(pack_fields)

class MacOSVMMapCache(object):
	caches: Set[MapInfo]
	is_loaded: bool

	def __init__(self: Self) -> None:
		self.caches = set()
		self.is_loaded = False
		if platform.system() != 'Darwin':
			print(f'[!] Command vmmap was not supported on {platform.system()}')
	
	def get_vmmap_info(self: Self) -> str:
		process = get_process()
		if not process:
			return ''

		process_info = process.GetProcessInfo()
		if not process_info.IsValid():
			return ''

		cmd = ['vmmap', str(process_info.GetProcessID()), "-interleaved"]
		proc = Popen(cmd, stdout = PIPE)
		out, _ = proc.communicate()

		return out.decode('utf-8')
	
	def parse_vmmap_info(self: Self) -> Optional[Set[MapInfo]]:
		vmmap_info = self.get_vmmap_info()

		if self.is_loaded:
			# no need to reload vmmap again
			return self.caches

		if not len(self.caches):
			self.is_loaded = True

		if not vmmap_info:
			return None

		match_map = re.findall(
			r'([\x20-\x7F]+)\s+([0-9a-f]+)\-([0-9a-f]+)\s+\[[0-9KMG\.\s]+\]\s+([rwx\-\/]+)\s+([A-Za-z=]+)([\x20-\x7F]+)?',
			vmmap_info
		)
		max_name_len = max([len(line[0].strip()) for line in match_map])

		if not match_map:
			return None

		for m in match_map:
			# add map_info to caches
			o_map_info = MapInfo(m[0].strip().ljust(max_name_len, " "),
								int(m[1], 16),
								int(m[2], 16),
								m[3],
								m[4],
								m[5].strip())

			self.caches.add(o_map_info)

		return self.caches
	
	def query_vmmap(self: Self, address: int) -> Optional[MapInfo]:
		# search it in caches
		for map_info in self.caches:
			if map_info.start <= address < map_info.end:
				return map_info

		# if a new vmmap record hasn't found in caches, try to parse it from vmmap
		process = get_process()
		process_info = process.GetProcessInfo()
		if not process_info.IsValid():
			return None

		cmd = ['vmmap', str(process_info.GetProcessID()), hex(address)]
		proc = Popen(cmd, stdout = PIPE)
		out, err = proc.communicate()
		out = out.decode('utf-8')

		m = re.search(
			r'\-\-\->\s+([\x20-\x7F]+)\s+([0-9a-f]+)\-([0-9a-f]+)\s+\[[0-9KMG\.\s]+\]\s+([rwx\-/]+)\s+([A-Za-z=]+)\s+([\x20-\x7F]+)',
			out
		)
		if not m:
			return None

		map_info = MapInfo(m[1], int(m[2], 16), int(m[3], 16), m[4], m[5], m[6])
		self.caches.add(map_info)

		return map_info

# ----------------------------------------------------------
# Memory Read/Write Support
# ----------------------------------------------------------
class LLDBMemoryException(Exception):
	def __init__(self, *args: object) -> None:
		super().__init__(*args)

def read_mem(addr: int, size: int) -> bytes:
	err = SBError()
	process = get_process()
	if process == None:
		raise LLDBMemoryException('get_process() return None')

	mem_data = process.ReadMemory(addr, size, err)
	if mem_data == None:
		mem_data = b''

	return mem_data

def readable(addr: int) -> bool:
	try:
		mem = read_mem(addr, 1)
	except LLDBMemoryException:
		return False
	return True if len(mem) == 1 else False

def read_pointer_from(addr: int, pointer_size: int) -> int:
	membuf = read_mem(addr, pointer_size)
	if not membuf:
		raise LLDBMemoryException(f'Unable to read pointer from {hex(addr)}')
	
	return int.from_bytes(membuf, byteorder='little')

def read_u8(addr: int) -> int:
	arr = read_mem(addr, 1)
	if not len(arr):
		raise LLDBMemoryException(f'Unable to read mem at {hex(addr)}')
	
	return unpack('<B', arr)[0]

def read_u16(addr: int) -> int:
	arr = read_mem(addr, 2)
	if not len(arr):
		raise LLDBMemoryException(f'Unable to read mem at {hex(addr)}')
	
	return unpack('<H', arr)[0]

def read_u32(addr: int) -> int:
	arr = read_mem(addr, 4)
	if not len(arr):
		raise LLDBMemoryException(f'Unable to read mem at {hex(addr)}')
	
	return unpack('<I', arr)[0]

def read_u64(addr: int) -> int:
	arr = read_mem(addr, 8)
	if not len(arr):
		raise LLDBMemoryException(f'Unable to read mem at {hex(addr)}')
	
	return unpack('<Q', arr)[0]

def read_cstr(addr: int, max_size: int=1024) -> bytes:
	c_str = bytearray()
	i = 0
	
	while i < max_size:
		try:
			ch = read_u8(addr + i)
			if ch == 0x00:
				break
			c_str.append(ch)
			i+=1
		except LLDBMemoryException:
			break

	return bytes(c_str)

def write_mem(addr: int, data: bytes) -> int:
	err = SBError()
	process = get_process()
	if process == None:
		raise LLDBMemoryException('get_process() return None')

	sz_write = process.WriteMemory(addr, data, err)
	if not err.Success():
		sz_write = 0

	return sz_write

def size_of(struct_name: str) -> int:
	res = lldb.SBCommandReturnObject()
	ci: SBCommandInterpreter = get_debugger().GetCommandInterpreter()
	ci.HandleCommand(f"p sizeof({struct_name})", res)
	if res.GetError():
		# struct is not exists
		return -1
	
	m = re.search(r'\(unsigned long\) \$\d+ = (\d+)\n', res.GetOutput())
	if m:
		return int(m.group(1))
	
	return -1

SIGN_MASK = 1 << 55
INT64_MAX = 18446744073709551616

def stripPAC(pointer: int , type_size: int) -> int:
	ptr_mask = (1 << (64 - type_size)) - 1
	pac_mask = ~ptr_mask
	sign = pointer & SIGN_MASK

	if sign:
		return (pointer | pac_mask) + INT64_MAX
	else:
		return pointer & ptr_mask

def strip_kernelPAC(pointer: int) -> int:
	if get_arch() != 'arm64e':
		return pointer
	
	T1Sz = ESBValue('gT1Sz')
	return stripPAC(pointer, T1Sz.int_value)

def strip_kernel_or_userPAC(pointer: int) -> int:
	try:
		T1Sz = ESBValue('gT1Sz')
		return stripPAC(pointer, T1Sz.int_value)
	except ESBValueException:
		return stripPAC(pointer, 24) # last 3 bytes is PAC signature in user-mode

TYPE_NAME_CACHE = {}
ENUM_NAME_CACHE = {}

def get_type(type_name: str) -> SBType:
	'''
		Borrow this from XNU debug script
	'''
	global TYPE_NAME_CACHE

	target_type = str(type_name).strip()
	
	if target_type in TYPE_NAME_CACHE:
		# use cache to speedup
		return TYPE_NAME_CACHE[target_type]
	
	requested_type_is_struct = False
	m = re.match(r'\s*struct\s*(.*)$', target_type)
	if m:
		requested_type_is_struct = True
		target_type = m.group(1)
	
	tmp_type = None
	requested_type_is_pointer = False
	if target_type.endswith('*') :
		requested_type_is_pointer = True
	
	search_type = target_type.rstrip('*').strip()
	type_arr = [t for t in get_target().FindTypes(search_type)]
	if requested_type_is_struct:
		type_arr = [t for t in type_arr if t.type == lldb.eTypeClassStruct]
	
	 # After the sort, the struct type with more fields will be at index [0].
	# This hueristic helps selecting struct type with more fields compared to ones with "opaque" members
	type_arr.sort(reverse=True, key=lambda x: x.GetNumberOfFields())
	if len(type_arr) > 0:
		tmp_type = type_arr[0]
	else:
		raise NameError(f'Unable to find type {target_type}')

	if not tmp_type.IsValid():
		raise NameError(f'Unable to Cast to type {target_type}')

	if requested_type_is_pointer:
		tmp_type = tmp_type.GetPointerType()
	TYPE_NAME_CACHE[target_type] = tmp_type

	return TYPE_NAME_CACHE[target_type]

def get_enum_name(enum_name, _key, prefix = ''):
	'''
		Borrow this from XNU debug script
	'''
	global ENUM_NAME_CACHE

	ty = get_type(enum_name)
	
	if enum_name not in ENUM_NAME_CACHE:
		ty_dict  = {}

		for e in ty.get_enum_members_array():
			if ty.GetTypeFlags() & lldb.eTypeIsSigned:
				ty_dict[e.GetValueAsSigned()] = e.GetName()
			else:
				ty_dict[e.GetValueAsUnsigned()] = e.GetName()

		ENUM_NAME_CACHE[enum_name] = ty_dict
	else:
		ty_dict = ENUM_NAME_CACHE[enum_name]

	if ty.GetTypeFlags() & lldb.eTypeIsSigned:
		key = ctypes.c_long(_key).value
	else:
		key = _key

	name = ty_dict.get(key, "UNKNOWN({:d})".format(key))
	if name.startswith(prefix):
		return name[len(prefix):]
	return name

# overwrites SBValue for easier to access struct member
def find_global_variable(name: str) -> Optional[SBValue]:
	target = get_target()

	sbvar_list: SBValueList = target.FindGlobalVariables(name, 1)
	sbvar: SBValue = sbvar_list.GetValueAtIndex(0)
	if not sbvar.IsValid():
		return None
		
	return sbvar

class ESBValueException(Exception):
	# handle exception while using sb_value
	def __init__(self, *args: object) -> None:
		super().__init__(*args)

class ESBValue(object):
	'''
		Wrapper of lldb.SBValue make it easier to use to load debug variable from binary
	'''

	sb_var_name: str
	sb_value: SBValue
	is_expression: bool
	# store metadata for ESBValue
	sb_attributes: Dict[str, Any]

	def __init__(self: Self, var_name: str, var_type: str = ''):
		super().__init__()
		self.sb_var_name = ''
		# store metadata
		self.sb_attributes = {}
		self.is_expression = False

		if var_name == 'classcall':
			# skip initialize for classcall
			return

		# find this variable in global context
		g_sb_value = find_global_variable(var_name)
		if not g_sb_value:
			# find this variable in local context
			sb_value: SBValue = get_frame().FindVariable(var_name)
			if not sb_value.IsValid():
				raise ESBValueException(f'Unable to find variable {var_name} in this context.')
			
			self.sb_value = sb_value
		
		else:
			self.sb_value = g_sb_value

		if var_type and self.sb_value:
			address = int(self.sb_value.GetValue(), 16)
			target = get_target()
			self.sb_value = target.CreateValueFromExpression('var_name', f'({var_type}){address}')
			self.sb_var_name = 'var_name'
	
	@classmethod
	def init_with_SBValue(cls: Type['ESBValue'], sb_value: SBValue):
		new_esbvalue = cls('classcall')
		new_esbvalue.sb_value = sb_value
		new_esbvalue.sb_var_name = sb_value.GetName()
		return new_esbvalue
	
	@classmethod
	def init_with_address(cls: Type['ESBValue'], address: int, var_type: str):
		target = get_target()
		new_esbvalue = cls('classcall')
		new_esbvalue.sb_value = target.CreateValueFromExpression('var_name', f'({var_type}){address}')
		new_esbvalue.sb_var_name = 'var_name'
		return new_esbvalue
	
	@classmethod
	def init_with_expression(cls: Type['ESBValue'], expression: str):
		frame = get_frame()
		if frame != None:
			exp_sbvalue: SBValue = frame.EvaluateExpression(expression)
		else:
			target = get_target()
			exp_sbvalue: SBValue = target.EvaluateExpression(expression)
		
		new_esbvalue = cls('classcall')
		new_esbvalue.sb_value = exp_sbvalue
		new_esbvalue.is_expression = True
		return new_esbvalue
	
	@classmethod
	def init_null(cls: Type['ESBValue'], var_type: str):
		return cls.init_with_address(0, var_type=var_type)

	# save metadata for this ESBValue
	def set_attribute(self: Self, attr_name: str, value: Any):
		self.sb_attributes[attr_name] = value
	
	def get_attribute(self, attr_name: str) -> Optional[Any]:
		try:
			return self.sb_attributes[attr_name]
		except KeyError:
			return None
	
	def get(self: Self, attr_name: str) -> 'ESBValue':
		'''
			Get child member of a struct.

			Developer can pass 'ips_wqset.wqset_q' directly to attr_name to get wqset_q
			rather than esb_value.get('ips_wqset').get('wqset_q')
		'''

		if '.' in attr_name:
			attr_names = attr_name.split('.')
		else:
			attr_names = [attr_name]
		
		sb_value = self.sb_value

		# automatically get the last child in `attr_name`
		for attr_name in attr_names:
			sb_value: SBValue = sb_value.GetChildMemberWithName(attr_name)
			if not sb_value.IsValid():
				raise ESBValueException(f'member attribute {attr_name} didn\'t exists.')
			
		return ESBValue.init_with_SBValue(sb_value)
	
	def has_member(self: Self, attr_name: str) -> bool:
		'''
			check attr_name exists or not
		'''
		try:
			self.get(attr_name)
			return True
		except ESBValueException:
			return False

	def addr_of(self: Self) -> int:
		'''
			return address of variable
			allproc = ESBValue('allproc')
			allproc.add_of() is equal to &allproc in C-lang
		'''
		return self.sb_value.GetLoadAddress()
	
	@property
	def is_valid(self: Self) -> bool:
		return self.sb_value.IsValid()

	@property
	def is_null(self: Self) -> bool:
		return self.int_value == 0
	
	@property
	def is_not_null(self: Self) -> bool:
		return not self.is_null
	
	@property
	def value_type(self: Self) -> str:
		'''
			return type name of sb_value
		'''
		return self.sb_value.GetTypeName()
	
	@property
	def value(self: Self) -> str:
		''' extract content of sb_value'''
		return self.sb_value.GetValue()
	
	@property
	def int_value(self: Self) -> int:
		''' extract content of sb_value in integer '''
		content = self.value
		type_name = self.value_type

		if content == None:
			return 0

		if type_name.startswith('uint8_t') or type_name.startswith('int8_t') or \
				type_name.startswith('char'):
			# trying to cast value to int in Python
			content = content.strip("'\\x")
			return int(content, 16)

		return parse_number(content)
	
	@property
	def str_value(self: Self, max_length: int = 1024) -> str:
		if self.is_expression:
			summary:str = self.sb_value.GetSummary()
			return summary.strip('"')

		return read_cstr(self.addr_of(), max_length).decode('utf-8')
	
	@property
	def var_name(self: Self) -> str:
		if self.var_name:
			return self.var_name
		
		return self.sb_value.GetName()
	
	@property
	def var_type_name(self: Self) -> str:
		return self.sb_value.GetTypeName()
	
	@property
	def summary(self: Self) -> str:
		return self.sb_value.GetSummary()
	
	def dereference(self: Self) -> 'ESBValue':
		'''
			dereference a pointer
		'''
		return ESBValue.init_with_SBValue(self.sb_value.Dereference())
	
	def get_SBAddress(self: Self) -> SBAddress:
		return self.sb_value.GetAddress()
	
	def cast_to(self: Self, var_type: str) -> 'ESBValue':
		return ESBValue.init_with_address(self.int_value, var_type)
	
	def cast_ref(self: Self, var_type: str) -> 'ESBValue':
		return ESBValue.init_with_address(self.addr_of(), var_type)

	def __getitem__(self: Self, idx) -> 'ESBValue':
		return ESBValue.init_with_SBValue(self.sb_value.GetChildAtIndex(idx))

# ----------------------------------------------------------
# Cyclic algorithm to find offset on memory
# ----------------------------------------------------------

def de_bruijn(charset: bytes, n: int = 4, maxlen: int = 0x10000) -> bytearray:
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
def cyclic(length: int = 0, n: int = 4) -> bytearray:
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

def cyclic_find(subseq: Union[int, bytes], length: int = 0x10000) -> int:
	# finding subseq in generator then return pos of this subseq
	# if it doens't find then return -1
	generator = cyclic(length)

	if isinstance(subseq, int): # subseq might be a number or hex value
		try:
			subseq = p32(subseq)
		except struct.error: # struct.error
			try:
				subseq = p64(subseq)
			except struct.error: # struct.error
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

def hexdump(addr: int, chars: bytes, sep: str, width: int, lines=0xFFFFFFF) -> str:
	l = []
	line_count = 0
	
	while chars:
		if line_count >= lines:
			break
		line = chars[:width]
		chars = chars[width:]
		line = line.ljust(width, b'\x00' )
		if get_pointer_size() == 4:
			szaddr = "0x%.08X" % addr
		else:
			szaddr = "0x%.016lX" % addr
		
		l.append("\033[1m%s :\033[0m %s%s \033[1m%s\033[0m" % \
				(szaddr, sep.join( "%02X" % c for c in line ), sep, quotechars( line )))
		
		addr += 0x10
		line_count = line_count + 1

	return "\n".join(l)

def quotechars(chars: bytes) -> str:
	data = ""
	for x in bytearray(chars):
		if x >= 0x20 and x <= 126:
			data += chr(x)
		else:       
			data += "."
	return data

def get_uuid_summary(uuid_bytes: bytes) -> str:

	assert len(uuid_bytes) == 16, 'UUID bytes must be 16 in length'
	data = list(uuid_bytes)
	return "{a[0]:02X}{a[1]:02X}{a[2]:02X}{a[3]:02X}-{a[4]:02X}{a[5]:02X}-{a[6]:02X}{a[7]:02X}-{a[8]:02X}{a[9]:02X}-{a[10]:02X}{a[11]:02X}{a[12]:02X}{a[13]:02X}{a[14]:02X}{a[15]:02X}".format(a=data)

def get_connection_protocol() -> str:
	""" Returns a string representing what kind of connection is used for debugging the target.
		params: None
		returns:
			str - connection type. One of ("core","kdp","gdb", "unknown")
	"""
	target = get_target()
	retval = "unknown"

	if target == None:
		return retval

	sb_process: lldb.SBProcess = target.GetProcess()
	process_plugin_name:str = sb_process.GetPluginName()
	process_plugin_name = process_plugin_name.lower()

	if "kdp" in process_plugin_name:
		retval = "kdp"
	
	elif "gdb" in process_plugin_name:
		retval = "gdb"
	
	elif "mach-o" in process_plugin_name and "core" in process_plugin_name:
		retval = "core"

	return retval

def address_of(target: SBTarget, sb_value: SBValue) -> int:
	try:
		sb_address: SBAddress = sb_value.GetAddress()
		if sb_address.IsValid():
			return sb_address.GetLoadAddress(target)
		return 0xffffffffffffffff
	except AttributeError:
		return 0xffffffffffffffff

def cast_address_as_pointer_type(
		target: SBTarget,
		var_name: str,
		address: int,
		type_name: str) -> Optional[SBValue]:

	sb_type: SBType = target.FindFirstType(type_name)
	pointer_type: SBType = sb_type.GetPointerType()
	
	if pointer_type.IsValid():
		my_var = target.CreateValueFromExpression(var_name, f'({pointer_type.name}){hex(address)}')
		return my_var

	return None

def dyld_arm64_resolve_dispatch(target: SBTarget, target_address: int) -> int:
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

	instructions: SBInstructionList = target.ReadInstructions(SBAddress(target_address, target), 3, 'intel')
	if instructions.GetSize() == 0:
		return 0
	
	instruction_0: SBInstruction = instructions.GetInstructionAtIndex(0)
	instruction_1: SBInstruction = instructions.GetInstructionAtIndex(1)
	instruction_2: SBInstruction = instructions.GetInstructionAtIndex(2)

	if instruction_0.GetMnemonic(target) != 'adrp' or instruction_1.GetMnemonic(target) != 'add' or \
		(instruction_2.GetMnemonic(target) != 'br' and instruction_2.GetOperands(target).startswith('x')):
		return 0
	
	page_shift = int(instruction_0.GetOperands(target).split(',')[1])
	target_page = (target_address + page_shift * 0x1000) & 0xFFFFFFFFFFFFF000
	call_offset = int(instruction_1.GetOperands(target).split(',')[2].strip(' #'), 16)
	call_func_ptr = target_page + call_offset 

	return call_func_ptr

## --------- END --------- ##
# VMware fusion bridge to take snapshots, restore and create new snapshot in lldb
# this feature support debug XNU kernel easier and faster in lldb
def vmfusion_check() -> bool:
	vmrun = Path('/Applications/VMware Fusion.app/Contents/Public/vmrun')
	return True if vmrun.exists() else False

def argument_validate(arg: str) -> str:
	if ' ' in arg:
		return f'"{arg}"'

	return arg

def get_all_running_vm() -> Dict[str, str]:
	vms = {}

	proc = Popen(['vmrun', 'list'], stdout=PIPE)
	out, err = proc.communicate()
	
	lines = out.split(b'\n')[1:]
	for line in lines:
		if not line:
			continue

		vm_path = Path(line.decode('utf-8'))
		vm_name = vm_path.stem.replace(' ','-')

		vms[vm_name] = vm_path

	return vms

def take_vm_snapshot(target_vm: str, snapshot_name: str) -> None:
	try:
		check_call(['vmrun', 'snapshot', target_vm, argument_validate(snapshot_name)])
	except CalledProcessError as err:
		pass

def revert_vm_snapshot(target_vm: str, snapshot_name: str) -> str:
	error = ''
	try:
		# revert back to specific snapshot
		check_call(['vmrun', 'revertToSnapshot', target_vm, argument_validate(snapshot_name)])
		time.sleep(2)
		# start target vm
		check_call(['vmrun', 'start', target_vm])
	except CalledProcessError as err:
		error = str(err)
	return error

def delete_vm_snapshot(target_vm: str, snapshot_name: str) -> str:
	try:
		check_call(['vmrun', 'deleteSnapshot', target_vm, argument_validate(snapshot_name)])
		return ''
	except CalledProcessError as err:
		return str(err)

def list_vm_snapshot(target_vm: str) -> List[str]:
	proc = Popen(['vmrun', 'listSnapshots', target_vm], stdout=PIPE)
	out, _ = proc.communicate()

	snapshots = []

	lines = out.split(b'\n')[1:]
	for line in lines:
		if not line:
			continue
		snapshot_name = line.decode('utf-8')
		snapshots.append(snapshot_name)

	return snapshots