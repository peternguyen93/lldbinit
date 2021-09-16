'''
LLDB utils functions
Author : peternguyen
'''
import lldb
import re
from subprocess import Popen, PIPE, check_call, CalledProcessError
from pathlib import Path
from struct import *
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

def p32(value):
	return pack('<I', value)

def p64(value):
	return pack('<Q', value)

# ----------------------------------------------------------
# Color Related Functions
# ----------------------------------------------------------

def get_color_status(addr):
	target = get_target()
	process = get_process()
	xinfo = resolve_mem_map(target, addr)

	if xinfo['section_name'] == '__TEXT':
		# address is excutable page
		return "RED"
	elif xinfo['section_name'] == '__DATA':
		return "MAGENTA"

	error = lldb.SBError()
	process.ReadMemory(addr, 1, error)
	if error.Success():
		# memory is readable
		return "CYAN"

	return "WHITE"

# ----------------------------------------------------------
# Functions to extract internal and process lldb information
# ----------------------------------------------------------

def get_selected_frame(debugger):
	process = debugger.GetSelectedTarget().GetProcess()
	thread = process.GetSelectedThread()
	frame = thread.GetSelectedFrame()
	return frame

def get_arch():
	return lldb.debugger.GetSelectedTarget().triple.split('-')[0]

def get_process():
	'''
		A read only property that returns an lldb object
		that represents the process (lldb.SBProcess)that this target owns.
	'''
	return get_target().process

def get_frame():
	frame = None
	# SBProcess supports thread iteration -> SBThread
	for thread in get_process():
		if (thread.GetStopReason() != lldb.eStopReasonNone) and (thread.GetStopReason() != lldb.eStopReasonInvalid):
			frame = thread.GetFrameAtIndex(0)
			break
	# this will generate a false positive when we start the target the first time because there's no context yet.
	if not frame:
		print("[-] warning: get_frame() failed. Is the target binary started?")
	return frame

def get_thread():
	thread = None
	# SBProcess supports thread iteration -> SBThread
	for _thread in get_process():
		if (_thread.GetStopReason() != lldb.eStopReasonNone) and (_thread.GetStopReason() != lldb.eStopReasonInvalid):
			thread = _thread
	
	if not thread:
		print("[-] warning: get_thread() failed. Is the target binary started?")

	return thread

def get_target():
	target = lldb.debugger.GetSelectedTarget()
	if not target:
		print("[-] error: no target available. please add a target to lldb.")
		return None
	return target

def try_convert_str_to_int(num_str):
	try:
		return int(num_str, base=10)
	except ValueError:
		try:
			return int(num_str, base=16)
		except ValueError as e:
			print("Exception on evaluate: " + str(e))
			return 0

# evaluate an expression and return the value it represents
def evaluate(command):
	frame = get_frame()
	if frame:
		value = frame.EvaluateExpression(command)
		if not value.IsValid():
			return 0
		
		if value.GetValue() == None:
			return try_convert_str_to_int(command)
		
		return try_convert_str_to_int(value.GetValue())
	# use the target version - if no target exists we can't do anything about it
	else:
		target = get_target()
		if target == None:
			return 0
		value = target.EvaluateExpression(command)
		if not value.IsValid():
			return 0
		
		if value.GetValue() == None:
			return try_convert_str_to_int(command)
		
		return try_convert_str_to_int(value.GetValue())

def is_i386():
	arch = get_arch()
	return arch[0:1] == "i"

def is_x64():
	arch = get_arch()
	return arch.startswith("x86_64")

def is_arm():
	arch = get_arch()
	return arch == "armv7"

def is_aarch64():
	arch = get_arch()
	return arch == 'aarch64' or arch.startswith('arm64')

def get_pointer_size():
	poisz = evaluate("sizeof(long)")
	return poisz

# from https://github.com/facebook/chisel/blob/master/fblldbobjcruntimehelpers.py
def get_instance_object():
	instanceObject = None
	if is_i386():
		instanceObject = '*(id*)($esp+4)'
	elif is_x64():
		instanceObject = '(id)$rdi'
	elif is_aarch64():
		instanceObject = '(id)$x0'
	# not supported yet
	elif is_arm():
		instanceObject = None
	return instanceObject

# -------------------------
# Register related commands
# -------------------------

# return the int value of a general purpose register
def get_gp_register(reg_name):
	regs = get_registers("general")
	if regs == None:
		return 0
	for reg in regs:
		if reg_name == reg.GetName():
			#return int(reg.GetValue(), 16)
			return reg.unsigned
	return 0

def get_gp_registers():
	regs = get_registers("general")
	if regs == None:
		return 0
	
	registers = {}
	for reg in regs:
		reg_name = reg.GetName()
		registers[reg_name] = reg.unsigned
	return registers

def get_registers_by_frame(frame, kind):
	if not frame:
		return None
	registerSets = frame.GetRegisters() # Return type of SBValueList.
	for registerSet in registerSets:
		if kind.lower() in registerSet.GetName().lower():
			return registerSet
	return None
		
def get_registers(kind):
	"""Returns the registers given the frame and the kind of registers desired.

	Returns None if there's no such kind.
	"""
	frame = get_frame()
	return get_registers_by_frame(frame, kind)

# retrieve current instruction pointer via platform independent $pc register
def get_current_pc():
	frame = get_frame()
	if not frame:
		return 0

	return frame.pc

# retrieve current stack pointer via registers information
# XXX: add ARM
def get_current_sp():
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

# helper function that updates given register
def update_register(register, command):
	help = """
Update given register with a new value.

Syntax: register_name <value>

Where value can be a single value or an expression.
"""

	cmd = command.split()
	if len(cmd) == 0:
		print("[-] error: command requires arguments.")
		print("")
		print(help)
		return

	if cmd[0] == "help":
		print(help)
		return

	value = evaluate(command)
	if value == None:
		print("[-] error: invalid input value.")
		print("")
		print(help)
		return

	# we need to format because hex() will return string with an L and that will fail to update register
	get_frame().reg[register].value = format(value, '#x')

# ----------------------------------------------------------
# LLDB Module functions
# ----------------------------------------------------------

def objc_get_classname(objc):
	classname_command = '(const char *)object_getClassName((id){})'.format(objc)
	classname_value = get_frame().EvaluateExpression(classname_command)
	if classname_value.IsValid() == False:
		return ''
	
	return classname_value.GetSummary().strip('"')

def find_module_by_name(target, module_name):
	for module in target.modules:
		if module.file.basename == module_name:
			return module
	return None

def get_text_section(module):
	return module.FindSection('__TEXT')

def resolve_symbol_name(address):
	target = get_target()
	sb_addr = lldb.SBAddress(address, target)
	addr_sym = sb_addr.GetSymbol()
	if addr_sym.IsValid():
		return addr_sym.GetName()
	return ''

def resolve_mem_map(target, addr):
	found = False

	xinfo = {
		'module_name' : '',
		'section_name' : '',
		'perms' : 0,
		'offset' : -1,
		'abs_offset' : -1
	}

	# found in load image
	for module in target.modules:
		absolute_offset = 0
		for section in module.sections:
			if section.GetLoadAddress(target) == 0xffffffffffffffff:
				continue

			start_addr = section.GetLoadAddress(target)
			end_addr = start_addr + section.GetFileByteSize()
			if start_addr <= addr <= end_addr:
				xinfo['module_name'] = module.file.basename
				xinfo['section_name'] = section.GetName()
				xinfo['perms'] = section.GetPermissions()
				xinfo['offset'] = addr - start_addr
				xinfo['abs_offset'] = absolute_offset + xinfo['offset']
				return xinfo

			absolute_offset += section.GetFileByteSize()

	return xinfo

## String operations ##

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

vmmap_caches = []

class MapInfo(object):
	def __init__(self, _type, start, end, perm, shm, region):
		self.type  = _type
		self.start = start
		self.end   = end
		self.perm  = perm
		self.shm   = shm
		self.region= region

	def __hash__(self):
		s = self.type
		s+= str(self.start)
		s+= str(self.end)
		s+= self.perm
		s+= self.shm
		s+= self.region
		return hash(s)

	def __eq__(self, other):
		return hash(self) == hash(other)

	def __ne__(self, other):
		return hash(self) != hash(other)

	def __lt__(self, other):
		return hash(self) < hash(other)

	def __le__(self, other):
		return hash(self) <= hash(other)

	def __gt__(self, other):
		return hash(self) > hash(other)

	def __ge__(self, other):
		return hash(self) >= hash(other)

def get_vmmap_info():
	if platform.system() != 'Darwin':
		print('[!] This feature only support on macOS')
		return ''

	process = get_process()
	if not process:
		return ''

	process_info = process.GetProcessInfo()
	if not process_info.IsValid():
		return ''

	cmd = ['vmmap', str(process_info.GetProcessID())]
	proc = Popen(cmd, stdout = PIPE)
	out, err = proc.communicate()

	return out.decode('utf-8')

def parse_vmmap_info():
	vmmap_info = get_vmmap_info()

	if not vmmap_info:
		return

	match_map = re.findall(
		r'([\x20-\x7F]+)\s+([0-9a-f]+)\-([0-9a-f]+)\s+\[[0-9KMG\.\s]+\]\s+([rwx\-/]+)\s+([A-Za-z=]+)\s+([\x20-\x7F]+)',
		vmmap_info
	)

	if not match_map:
		print('[-] Vmmap parse error')
		print(vmmap_info)
		return

	for m in match_map:
		o_map_info = MapInfo(m[0], int(m[1], 16), int(m[2], 16), m[3], m[4], m[5])
		if o_map_info not in vmmap_caches:
			# add to caches
			vmmap_caches.append(o_map_info)

	return vmmap_caches

def query_vmmap(address):
	global vmmap_caches

	if platform.system() != 'Darwin':
		print('[!] This feature only support on macOS')
		return None

	for map_info in vmmap_caches:
		if map_info.start <= address < map_info.end:
			return map_info

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
	if map_info not in vmmap_caches:
		# save this query map into caches
		vmmap_caches.append(map_info)

	return map_info

# ----------------------------------------------------------
# Memory Read/Write Support
# ----------------------------------------------------------

def read_mem(addr, size):
	err = lldb.SBError()
	process = get_process()

	mem_data = process.ReadMemory(addr, size, err)
	if not err.Success():
		mem_data = b''

	return mem_data

def read_str(addr, size):
	err = lldb.SBError()
	process = get_process()

	c_str = b''
	for i in range(size):
		c = process.ReadMemory(addr + i, 1, err)
		if not err.Success():
			c_str = b''
			break
		
		if c == b'\x00':
			break
		
		c_str += c
			
	return c_str

def write_mem(addr, data):
	err = lldb.SBError()
	process = get_process()

	sz_write = process.WriteMemory(addr, data, err)
	if not err.Success():
		sz_write = 0

	return sz_write

def try_read_mem(addr, size):
	err = lldb.SBError()
	process = get_process()
	mem_data = b''

	while size != 0:
		mem_data = process.ReadMemory(addr, size, err)
		if err.Success():
			break

		size -= 1

	return mem_data

def size_of(struct_name):
	res = lldb.SBCommandReturnObject()
	lldb.debugger.GetCommandInterpreter().HandleCommand(f"p sizeof({struct_name})", res)
	if res.GetError():
		# struct is not exists
		return -1
	
	m = re.search(r'\(unsigned long\) \$\d+ = (\d+)\n', res.GetOutput())
	if m:
		return int(m.group(1))
	
	return -1

# overwrites SBValue for easier to access struct member

def findGlobalVariable(name):
	target = get_target()
	sbvar = target.FindGlobalVariables(name, 1).GetValueAtIndex(0)
	if not sbvar.IsValid():
		return None
	return sbvar

class ESBValue(object):
	def __init__(self, var_name, var_type=''):
		super().__init__()
		if var_name == 'classcall':
			self.sb_value = None
		else:
			# find this variable in global context
			self.sb_value = findGlobalVariable(var_name)
			if not self.sb_value:
				# find this variable in local context
				self.sb_value = lldb.frame.FindVariable(var_name)
				if not self.sb_value.IsValid():
					self.sb_value = None

		if var_type and self.sb_value:
			address = int(self.sb_value.GetValue(), 16)
			# self.sb_value = cast_address_to(get_target(), 'new_var', address, var_type)
			target = get_target()
			self.sb_value = target.CreateValueFromExpression('var_name', f'({var_type}){address}')
	
	@classmethod
	def initWithSBValue(cls, sb_value):
		new_esbvalue = cls('classcall')
		new_esbvalue.sb_value = sb_value
		return new_esbvalue
	
	@classmethod
	def initWithAddressType(cls, address, var_type):
		target = get_target()
		new_esbvalue = cls('classcall')
		new_esbvalue.sb_value = target.CreateValueFromExpression('var_name', f'({var_type}){address}')
		return new_esbvalue
	
	def __getattr__(self, name):
		if name == 'sb_value':
			return self.sb_value

		if self.sb_value == None:
			return None
		
		return ESBValue.initWithSBValue(self.GetChildMemberWithName(name))
	
	def GetValue(self):
		if not self.sb_value:
			return None
		return self.sb_value.GetValue()
	
	def GetSummary(self):
		if not self.sb_value:
			return None
		return self.sb_value.GetSummary()
	
	def GetIntValue(self):
		value = self.GetValue()
		if not value:
			return 0
		if value.startswith('0x'):
			return int(value, 16)
		return int(value)
	
	def Dereference(self):
		if not self.sb_value:
			return None
		return ESBValue.initWithSBValue(self.sb_value.Dereference())
	
	def GetBoolValue(self):
		if not self.sb_value:
			return False
		return True if self.GetValue() == 'true' else False
	
	def GetStrValue(self):
		summary = self.GetSummary()
		if summary and 'no value available' not in summary:
			return summary[1:-1] # skip double quote in "data"
		return ''
	
	def GetLoadAddress(self):
		if not self.sb_value:
			return 0
		return self.sb_value.GetLoadAddress()
	
	def GetAddress(self):
		if not self.sb_value:
			return 0
		return self.sb_value.GetAddress()
	
	def GetChildMemberWithName(self, child_name):
		if not self.sb_value:
			return None
		return self.sb_value.GetChildMemberWithName(child_name)
	
	def GetChildAtIndex(self, idx):
		if not self.sb_value:
			return None
		return self.sb_value.GetChildAtIndex(idx)
	
	def IsValid(self):
		if not self.sb_value:
			return False
		return self.sb_value.IsValid()
	
	def __getitem__(self, idx):
		if not self.sb_value:
			return None
		return ESBValue.initWithSBValue(self.GetChildAtIndex(idx))
	
	def CastTo(self, var_type, use_load_addr = False):
		if use_load_addr:
			address = self.GetLoadAddress()
		else:
			address = self.GetIntValue()
		
		target = get_target()
		new_sb = target.CreateValueFromExpression('new_var', f'({var_type}){address}')
		self.sb_value = new_sb
		return self

# ----------------------------------------------------------
# Cyclic algorithm to find offset on memory
# ----------------------------------------------------------

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

def hexdump(addr, chars, sep, width, lines=0xFFFFFFF):
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
		l.append("\033[1m%s :\033[0m %s%s \033[1m%s\033[0m" % (szaddr, sep.join( "%02X" % c for c in line ), sep, quotechars( line )))
		addr += 0x10
		line_count = line_count + 1
	return "\n".join(l)

def quotechars( chars ):
	data = ""
	for x in bytearray(chars):
		if x >= 0x20 and x <= 126:
			data += chr(x)
		else:       
			data += "."
	return data

def GetUUIDSummary(uuid_bytes : bytes):

	assert len(uuid_bytes) == 16, 'UUID bytes must be 16 in length'
	data = list(uuid_bytes)
	return "{a[0]:02X}{a[1]:02X}{a[2]:02X}{a[3]:02X}-{a[4]:02X}{a[5]:02X}-{a[6]:02X}{a[7]:02X}-{a[8]:02X}{a[9]:02X}-{a[10]:02X}{a[11]:02X}{a[12]:02X}{a[13]:02X}{a[14]:02X}{a[15]:02X}".format(a=data)

def GetConnectionProtocol():
	""" Returns a string representing what kind of connection is used for debugging the target.
		params: None
		returns:
			str - connection type. One of ("core","kdp","gdb", "unknown")
	"""
	target = get_target()

	retval = "unknown"
	process_plugin_name = target.GetProcess().GetPluginName().lower()
	if "kdp" in process_plugin_name:
		retval = "kdp"
	elif "gdb" in process_plugin_name:
		retval = "gdb"
	elif "mach-o" in process_plugin_name and "core" in process_plugin_name:
		retval = "core"
	return retval

def address_of(target, sb_value):
	try:
		return sb_value.GetAddress().GetLoadAddress(target)
	except AttributeError:
		return 0xffffffffffffffff

def cast_address_as_pointer_type(target, var_name, address, type_name):
	pointer = target.FindFirstType(type_name).GetPointerType()
	if pointer.IsValid():
		my_var = target.CreateValueFromExpression(var_name, f'({pointer.name}){hex(address)}')
		return my_var
	return None

## --------- END --------- ##
# VMware fusion bridge to take snapshots, restore and create new snapshot in lldb
# this feature support debug XNU kernel easier and faster in lldb
def vmfusion_check():
	vmrun = Path('/Applications/VMware Fusion.app/Contents/Public/vmrun')
	return True if vmrun.exists() else False

def argument_validate(arg):
	if ' ' in arg:
		return f'"{arg}"'

	return arg

def get_all_running_vm():
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

def take_vm_snapshot(target_vm, snapshot_name):
	try:
		check_call(['vmrun', 'snapshot', target_vm, argument_validate(snapshot_name)])
		return None
	except CalledProcessError as err:
		return None

def revert_vm_snapshot(target_vm, snapshot_name):
	error = None
	try:
		# revert back to specific snapshot
		check_call(['vmrun', 'revertToSnapshot', target_vm, argument_validate(snapshot_name)])
		time.sleep(2)
		# start target vm
		check_call(['vmrun', 'start', target_vm])
	except CalledProcessError as err:
		error = err
	return error

def delete_vm_snapshot(target_vm, snapshot_name):
	try:
		check_call(['vmrun', 'deleteSnapshot', target_vm, argument_validate(snapshot_name)])
		return None
	except CalledProcessError as err:
		return err

def list_vm_snapshot(target_vm):
	proc = Popen(['vmrun', 'listSnapshots', target_vm], stdout=PIPE)
	out, err = proc.communicate()

	snapshots = []

	lines = out.split(b'\n')[1:]
	for line in lines:
		if not line:
			continue
		snapshot_name = line.decode('utf-8')
		snapshots.append(snapshot_name)

	return snapshots

def dyld_arm64_resolve_dispatch(target, target_address):
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

	instructions = target.ReadInstructions(lldb.SBAddress(target_address, target), 3, 'intel')
	if instructions.GetSize() == 0:
		return 0
	
	if instructions[0].GetMnemonic(target) != 'adrp' or instructions[1].GetMnemonic(target) != 'add' or \
		(instructions[2].GetMnemonic(target) != 'br' and instructions[2].GetOperands(target).startswith('x')):
		return 0
	
	page_shift = int(instructions[0].GetOperands(target).split(',')[1])
	target_page = (target_address + page_shift * 0x1000) & 0xFFFFFFFFFFFFF000
	call_offset = int(instructions[1].GetOperands(target).split(',')[2].strip(' #'), 16)
	call_func_ptr = target_page + call_offset 

	return call_func_ptr