'''
Small script support xnu kernel debugging
Author : peternguyen
'''

from utils import *
from ctypes import *
import re

kobject_types = [
	'', 'THREAD_CONTROL', 'TASK_CONTROL', 'HOST', 'HOST_PRIV', 'PROCESSOR',
	'PSET', 'PSET_NAME', 'TIMER', 'PAGER_REQ', 'DEVICE', 'XMM_OBJECT',
	'XMM_PAGER', 'XMM_KERNEL', 'XMM_REPLY', 'NOTDEF 15', 'NOTDEF 16', 'HOST_SEC',
	'LEDGER', 'MASTER_DEV', 'TASK_NAME', 'SUBSYTEM', 'IO_DONE_QUE', 'SEMAPHORE',
	'LOCK_SET', 'CLOCK', 'CLOCK_CTRL' , 'IOKIT_SPARE', 'NAMED_MEM', 'IOKIT_CON',
	'IOKIT_OBJ', 'UPL', 'MEM_OBJ_CONTROL', 'AU_SESSIONPORT', 'FILEPORT', 'LABELH',
	'TASK_RESUME', 'VOUCHER', 'VOUCHER_ATTR_CONTROL', 'WORK_INTERVAL', 'UX_HANDLER',
	'UEXT_OBJECT', 'ARCADE_REG', 'TASK_INSPECT', 'TASK_READ', 'THREAD_INSPECT', 'THREAD_READ'
]

EMBEDDED_PANIC_MAGIC = 0x46554E4B
EMBEDDED_PANIC_STACKSHOT_SUCCEEDED_FLAG = 0x02

MACOS_PANIC_MAGIC = 0x44454544
MACOS_PANIC_STACKSHOT_SUCCEEDED_FLAG = 0x04

AURR_PANIC_MAGIC = 0x41555252
AURR_PANIC_VERSION = 1

## main functions ##
@dataclass
class KextInfo:
	kext_file_name: str = ''
	name: str = ''
	address: int = 0
	size: int = 0
	uuid: str = ''

# save up cpu cost by create a cache for kext information
KEXT_INFO_DICTIONARY: Dict[str, KextInfo] = {}

def xnu_get_all_kexts():
	global KEXT_INFO_DICTIONARY

	try:
		g_load_kext_summaries = ESBValue('gLoadedKextSummaries')
	except ESBValueException:
		print(f'[!] Unable to find symbol gLoadedKextSummaries in this kernel')
		return

	base_address = g_load_kext_summaries.int_value
	entry_size = g_load_kext_summaries.get('entry_size').int_value
	kext_summaries_ptr = base_address + size_of('OSKextLoadedKextSummaryHeader')

	num_summaries = g_load_kext_summaries.get('numSummaries').int_value
	for _ in range(num_summaries):
		kext_summary = ESBValue.init_with_address(kext_summaries_ptr, 'OSKextLoadedKextSummary *')
		
		# fix remove null padding character while dumping kext_name
		kext_name = kext_summary.get('name').str_value
		kext_address = kext_summary.get('address').int_value
		kext_size = kext_summary.get('size').int_value
		kext_uuid_addr = kext_summary.get('uuid').addr_of()
		kext_uuid = get_uuid_summary(read_mem(kext_uuid_addr, size_of('uuid_t')))

		# kext_name format : com.apple.<type of kext>.<kext bin name>
		kext_file_name = kext_name.split('.')[-1]
		KEXT_INFO_DICTIONARY[kext_file_name] = KextInfo(kext_file_name, kext_name, \
														kext_address, kext_size, kext_uuid)
		kext_summaries_ptr += entry_size	

def xnu_showallkexts():
	
	xnu_get_all_kexts()

	longest_kext_name = len(max(KEXT_INFO_DICTIONARY, key=lambda kext_name: len(kext_name)))
	
	print('-- Loaded kexts:')
	for kext_bin_name in KEXT_INFO_DICTIONARY:
		kext_uuid    = KEXT_INFO_DICTIONARY[kext_bin_name].uuid
		kext_address = KEXT_INFO_DICTIONARY[kext_bin_name].address
		kext_size    = KEXT_INFO_DICTIONARY[kext_bin_name].size
		kext_name    = KEXT_INFO_DICTIONARY[kext_bin_name].name
		print(f'+ {kext_name:{longest_kext_name}}\t{kext_uuid}\t\t0x{kext_address:X}\t{kext_size}')

def xnu_write_task_kdp_pmap(task: ESBValue) -> bool:
	try:
		kdp_pmap = ESBValue('kdp_pmap')
	except ESBValueException:
		print('Unable to find "kdp_pmap" symbol in this kernel')
		return False
	
	task = task.cast_to('task *')
	kdp_pmap_addr = kdp_pmap.addr_of()
	pmap = task.get('map').get('pmap')

	if not write_mem(kdp_pmap_addr, pack('<Q', pmap.int_value)):
		print(f'[!] Overwrite kdp_pmap with task->map->pmap failed.')
		return False

	return True

def xnu_reset_kdp_pmap() -> bool:
	try:
		kdp_pmap = ESBValue('kdp_pmap')
	except ESBValueException:
		print('Unable to find "kdp_pmap" symbol in this kernel')
		return False
	
	kdp_pmap_addr = kdp_pmap.addr_of()

	if not write_mem(kdp_pmap_addr, pack('<Q', 0)):
		print(f'[!] Overwrite kdp_pmap with task->map->pmap failed.')
		return False

	return True

def xnu_read_user_address(target: SBTarget, task: ESBValue, address: int, size: int) -> bytes:
	out = ''

	if get_connection_protocol() != 'kdp':
		print('[!] xnu_read_user_address() only works on kdp-remote')
		return b''

	if not xnu_write_task_kdp_pmap(task):
		return b''

	out = read_mem(address, size)

	if not xnu_reset_kdp_pmap():
		print(f'[!] Reset kdp_pmap failed')
		return b''

	return out

def xnu_write_user_address(target: SBTarget, task: ESBValue, address: int, value: int) -> bool:
	if get_connection_protocol() != 'kdp':
		print('[!] xnu_read_user_address() only works on kdp-remote')
		return False

	if xnu_write_task_kdp_pmap(task):
		return False

	if not write_mem(address, value.to_bytes(byteorder='little', length=4)):
		return False

	if not xnu_reset_kdp_pmap():
		print(f'[!] Reset kdp_pmap failed')
		return False

	return True

def xnu_find_process_by_name(proc_name: str) -> Optional[ESBValue]:
	try:
		allproc = ESBValue('allproc')
	except ESBValueException:
		print('Unable to find "allproc" symbol in this kernel')
		return None
	
	allproc_ptr = allproc.get('lh_first')

	match_proc = None
	while not allproc_ptr.is_null:
		p_name = allproc_ptr.get('p_name').str_value
		if p_name == proc_name:
			match_proc = allproc_ptr 
			break

		allproc_ptr = allproc_ptr.get('p_list').get('le_next')

	return match_proc

def xnu_list_all_process():
	try:
		allproc = ESBValue('allproc')
	except ESBValueException:
		print('Unable to find "allproc" symbol in this kernel')
		return None

	allproc_ptr = allproc.get('lh_first')

	while not allproc_ptr.is_null:
		p_name = allproc_ptr.get('p_name').str_value
		p_pid = allproc_ptr.get('p_pid').int_value
		print(f'+ {p_pid} - {p_name} - {allproc_ptr.int_value}')

		allproc_ptr = allproc_ptr.get('p_list').get('le_next')

def xnu_showbootargs() -> str:
	try:
		pe_state = ESBValue('PE_state')
	except ESBValueException:
		print('Unable to find "PE_state" symbol in this kernel')
		return ''

	boot_args = pe_state.get('bootArgs').cast_to('boot_args *')
	commandline = boot_args.get('CommandLine')
	return commandline.str_value

def xnu_panic_log() -> bytes:
	try:
		panic_info = ESBValue('panic_info')
		debug_buf_ptr = ESBValue('debug_buf_ptr')
	except ESBValueException:
		print('Unable to find "panic_info" and "debug_buf_ptr" symbol in this kernel')
		return b''

	mph_magic = panic_info.get('mph_magic')
	if mph_magic.int_value != MACOS_PANIC_MAGIC:
		print('[!] Currently support parse MACOS_PANIC')
		return b''
	
	panic_buf = panic_info.int_value

	panic_log_begin_offset = panic_info.get('mph_panic_log_offset').int_value
	panic_log_len = panic_info.get('panic_log_len').int_value
	other_log_begin_offset = panic_info.get('mph_other_log_offset').int_value
	other_log_len = panic_info.get('mph_other_log_len').int_value

	cur_debug_buf_ptr_offset = debug_buf_ptr.int_value - panic_buf
	if other_log_begin_offset != 0 and (other_log_len == 0 or other_log_len < (cur_debug_buf_ptr_offset - other_log_begin_offset)):
		other_log_len = cur_debug_buf_ptr_offset - other_log_begin_offset
	
	# skip ProcessPanicStackshot
	out_str = b''
	out_str += read_mem(panic_buf + panic_log_begin_offset, panic_log_len)
	if other_log_begin_offset != 0:
		out_str += read_mem(panic_buf + other_log_begin_offset, other_log_len)
	
	return out_str

### XNU MACH IPC PORT ###

LTABLE_ID_GEN_SHIFT = 0
LTABLE_ID_GEN_BITS  = 46
LTABLE_ID_GEN_MASK  = 0x00003fffffffffff
LTABLE_ID_IDX_SHIFT = LTABLE_ID_GEN_BITS
LTABLE_ID_IDX_BITS  = 18
LTABLE_ID_IDX_MASK  = 0xffffc00000000000

def waitq_table_idx_from_id(_id: ESBValue) -> int:
	return int((_id.int_value & LTABLE_ID_IDX_MASK) >> LTABLE_ID_IDX_SHIFT)

def waitq_table_gen_from_id(_id: ESBValue) -> int:
	return (_id.int_value & LTABLE_ID_GEN_MASK) >> LTABLE_ID_GEN_SHIFT

def get_waitq_set_id_string(setid: ESBValue) -> str:
	idx = waitq_table_idx_from_id(setid)
	gen = waitq_table_gen_from_id(setid)
	return "{:>7d}/{:<#14x}".format(idx, gen)

def get_ipc_space_table(ipc_space: ESBValue) -> Tuple[ESBValue, int]:
	""" Return the tuple of (entries, size) of the table for a space
	"""
	table = ipc_space.get('is_table.__hazard_ptr')
	if table.is_valid:
		# macOS 12 structure
		return (table, table.get('ie_size').int_value)
	
	else:
		# macOS 11 structure
		table = ipc_space.get('is_table')
		return (table, ipc_space.get('is_table_size').int_value)

def get_ipc_task(proc: ESBValue) -> ESBValue:
	return proc.get('task').cast_to('task *')

def get_proc_from_task(task: ESBValue) -> ESBValue:
	return task.get('bsd_info').cast_to('proc *')

def get_destination_proc_from_port(port : ESBValue) -> ESBValue:
	dest_space = port.get('ip_receiver')
	if not dest_space.is_valid:
		dest_space = port.get('data.receiver')

	task = dest_space.get('is_task')
	proc = get_proc_from_task(task)
	return proc
	
def get_ipc_port_name(ie_bits : int, ipc_idx : int) -> int:
	'''
		osfmk/ipc/ipc_entry.c
		```c
		ipc_entry_t
		ipc_entry_lookup(
			ipc_space_t             space,
			mach_port_name_t        name)
		{
			...
			index = MACH_PORT_INDEX(name);
			if (index < space->is_table_size) {
				entry = &space->is_table[index];
				if (IE_BITS_GEN(entry->ie_bits) != MACH_PORT_GEN(name) ||
					IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE) {
					entry = IE_NULL;
				}
			....
		}
		```
		mach_port_name = index | (entry->ie_bits & 0xFF000000) >> 24
	'''
	return ((ie_bits & 0xFF000000) >> 24) | (ipc_idx << 8)

def get_waitq_sets(wqset_q: ESBValue) -> List[str]:
	sets = []

	if wqset_q.is_null:
		return sets

	ref = wqset_q.get('waitq_set_id')
	if ref.is_valid:
		return sets

	wqr_value = ref.get('wqr_value')
	while not wqr_value.is_null:
		if wqr_value.int_value & 1:
			sets.append(get_waitq_set_id_string(wqr_value))
			break

		link = wqr_value.cast_to('struct waitq_link *')
		sets.append(get_waitq_set_id_string(link.get('wql_node')))
		ref  = link.get('wql_next')

	return sets

def get_iokit_object_type_str(kobject: ESBValue) -> str:
	# get iokit object type
	vtable_ptr = kobject.cast_to('uintptr_t *').dereference()
	vtable_func_ptr = ESBValue.init_with_address(vtable_ptr.int_value + 2 * size_of('uintptr_t'), 'uintptr_t *')
	first_vtable_func = vtable_func_ptr[0].int_value
	func_desc = resolve_symbol_name(first_vtable_func)
	m = re.match(r'(\w*)::(\w*)', func_desc)
	if not m:
		return '<unknow>'
	
	return m[1]

def get_kobject_from_port(portval: ESBValue) -> str:
	""" Get Kobject description from the port.
		params: portval - core.value representation of 'ipc_port *' object
		returns: str - string of kobject information
	"""
	io_bits = portval.get('ip_object.io_bits').int_value
	if not io_bits & 0x800:
		return ''

	kobject_val = portval.get('ip_kobject')
	if not kobject_val.is_valid:
		kobject_val = portval.get('kdata.kobject') # use old way

	kobject_str = "{0: <#020x}".format(kobject_val.int_value)
	objtype_index = io_bits & 0x3ff
	try:
		objtype_str   = get_enum_name('ipc_kotype_t', objtype_index, "IKOT_")
	except NameError:
		try:
			objtype_str = kobject_types[objtype_index]
		except IndexError:
			objtype_str = 'UNKNOW'

	if objtype_str == 'IOKIT_OBJECT' or objtype_str == 'IOKIT_OBJ':
		iokit_classnm = get_iokit_object_type_str(kobject_val)
		desc_str = "kobject({:s}:{:s})".format(objtype_str, iokit_classnm)
	else:
		desc_str = "kobject({0:s})".format(objtype_str)
		if objtype_str[:5] == 'TASK_':
			proc_val = get_proc_from_task(kobject_val.cast_to('task *'))
			desc_str += " " + proc_val.get('p_name').str_value
	return kobject_str + " " + desc_str

def get_port_destination_summary(port: ESBValue) -> str:
	out_str = ''
	destination_str = ''
	destname_str = get_kobject_from_port(port)
	if not destname_str or "kobject(TIMER)" in destname_str:
		# check port is active
		if port.get('ip_object.io_bits').int_value & 0x80000000:
			imq_receiver_name = port.get('ip_messages.imq_receiver_name')
			destname_str = "{0: <#020x}".format(imq_receiver_name.int_value)
			desc_proc = get_destination_proc_from_port(port)
			if not desc_proc.is_null:
				proc_name = desc_proc.get('p_name').str_value
				proc_pid = desc_proc.get('p_pid').int_value
				destination_str = "{0:s}({1:d})".format(proc_name, proc_pid)
			else:
				destination_str = 'task()'
		else:
			destname_str = "{0: <#020x}".format(port.int_value)
			destination_str = "inactive-port"

	out_str += "{0: <20s} {1: <20s}".format(destname_str, destination_str)
	return out_str

def get_ipc_entry_summary(entry : ESBValue, ipc_name = 0, rights_filter = ''):
	""" 
		Borrow from XNU source
		Get summary of a ipc entry.
		params:
			entry - core.value representing ipc_entry_t in the kernel
			ipc_name - str of format '0x0123' for display in summary.  
		returns:
			str - string of ipc entry related information

		types of rights:
			'Dead'  : Dead name
			'Set'   : Port set
			'S'     : Send right
			'R'     : Receive right
			'O'     : Send-once right
			'm'     : Immovable send port
			'i'     : Immovable receive port
			'g'     : No grant port
		types of notifications:
			'd'     : Dead-Name notification requested
			's'     : Send-Possible notification armed
			'r'     : Send-Possible notification requested
			'n'     : No-Senders notification requested
			'x'     : Port-destroy notification requested
	"""
	ipc_entry_info = {
		"object" : 0,
		"right" : '', "urefs" : 0,
		"nsets" : 0, "nmsgs" : 0,
		"destname" : '', "destination" : ''
	}

	ie_object = entry.get('ie_object')
	ie_bits = entry.get('ie_bits').int_value

	if (ie_bits & 0x001f0000) == 0:
		# entry is freed
		return None

	io_bits = ie_object.get('io_bits').int_value
	ipc_entry_info['urefs'] = ie_bits & 0xffff
	ipc_entry_info['object'] = ie_object.int_value

	if ie_bits & 0x00100000:
		ipc_entry_info['right'] = 'Dead'
	elif ie_bits & 0x00080000:
		ipc_entry_info['right'] = 'Set'
		psetval = ie_object.cast_to('ipc_pset *')

		wqset_q = psetval.get('ips_wqset.wqset_q')
		if not wqset_q.is_valid:
			wqset_q = psetval.get('ips_messages.data.pset.setq.wqset_q')
		
		set_str = get_waitq_sets(wqset_q)

		ipc_entry_info['nsets'] = len(set_str)
		ipc_entry_info['nmsgs'] = 0
	else:
		if ie_bits & 0x00010000:
			if ie_bits & 0x00020000:
				# SEND + RECV
				ipc_entry_info['right'] = 'SR'
			else:
				# SEND only
				ipc_entry_info['right'] = 'S'
		elif ie_bits & 0x00020000:
			# RECV only
			ipc_entry_info['right'] = 'R'
		elif ie_bits & 0x00040000 :
			# SEND_ONCE
			ipc_entry_info['right'] = 'O'
		portval = ie_object.cast_to('ipc_port_t')

		ie_request = entry.get('ie_request').int_value
		if ie_request:
			ip_requests_addr = portval.get('ip_requests').int_value
			requestsval = ESBValue.init_with_address(
								ip_requests_addr + ie_request * size_of('struct ipc_port_request'),
								'struct ipc_port_request *'
							)
			sorightval = requestsval.get('notify.port')
			soright_ptr = sorightval.int_value
			if soright_ptr != 0:
				# dead-name notification requested
				ipc_entry_info['right'] += 'd'
				# send-possible armed
				if soright_ptr & 0x1:
					ipc_entry_info['right'] += 's'
				# send-possible requested
				if soright_ptr & 0x2:
					ipc_entry_info['right'] += 'r'
		
		# No-senders notification requested
		if portval.get('ip_nsrequest').int_value != 0 or portval.get('ip_kobject_nsrequest').int_value:
			ipc_entry_info['right'] += 'n'
		
		# port-destroy notification requested
		if portval.get('ip_pdrequest').int_value != 0:
			ipc_entry_info['right'] += 'x'
		
		# Immovable receive rights
		if portval.get('ip_immovable_receive').int_value != 0:
			ipc_entry_info['right'] += 'i'
		
		# Immovable send rights
		if portval.get('ip_immovable_send').int_value != 0:
			ipc_entry_info['right'] += 'm'

		# No-grant Port
		if portval.get('ip_no_grant').int_value != 0:
			ipc_entry_info['right'] += 'g'

		# Port with SB filtering on
		if io_bits & 0x00001000 != 0:
			ipc_entry_info['right'] += 'f'

		# early-out if the rights-filter doesn't match
		if rights_filter != '' and rights_filter != ipc_entry_info['right']:
			return None

		# # now show the port destination part
		ipc_entry_info['destname'] = get_port_destination_summary(ie_object.cast_to('ipc_port_t'))

		# Get the number of sets to which this port belongs
		set_str = get_waitq_sets(portval.get('ip_waitq'))
		ipc_entry_info['nsets'] = len(set_str)
		ipc_entry_info['nmsgs'] = portval.get('ip_messages.imq_msgcount').int_value

	if rights_filter == '' or rights_filter == ipc_entry_info['right']:
		return ipc_entry_info
	
	return None

def print_ipc_information(ipc_space: ESBValue):
	entry_table, num_entries = get_ipc_space_table(ipc_space)
	if entry_table == None:
		print('[!] Unable to retrieve entry_table')
		return

	entry_table_address = entry_table.int_value

	print("{0: <20s} {1: <20s} {2: <20s} {3: <8s} {4: <10s} {5: <18s} {6: >8s} {7: <8s}".format(
		'ipc_space', 'is_task', 'is_table', 'flags', 'ports', 'table_next', 'low_mod', 'high_mod'
	))

	flags = ''
	if entry_table_address:
		flags += 'A'
	else:
		flags += ' '
	if ipc_space.get('is_grower').int_value:
		flags += 'G'

	print("{0: <#020x} {1: <#020x} {2: <#020x} {3: <8s} {4: <10d} {5: <#18x} {6: >8d} {7: <8d}".format(
			ipc_space.int_value,
			ipc_space.get('is_task').int_value,
			entry_table.int_value,
			flags,
			num_entries,
			ipc_space.get('is_table_next').int_value,
			ipc_space.get('is_low_mod').int_value,
			ipc_space.get('is_high_mod').int_value)
		)

	print("{: <20s} {: <12s} {: <8s} {: <8s} {: <8s} {: <8s} {: <20s} {: <20s}".format(
		"object", "name", "rights", "urefs", "nsets", "nmsgs", "destname", "destination"))
	
	for idx in range(1, num_entries):
		ipc_entry = ESBValue.init_with_address(entry_table_address + idx * size_of('struct ipc_entry'), 'ipc_entry_t')
		ipc_entry_info = get_ipc_entry_summary(ipc_entry)
		if ipc_entry_info == None:
			continue
		
		print("{: <#020x} {: <12s} {: <8s} {: <8d} {: <8d} {: <8d} {: <20s} {: <20s}".format(
			ipc_entry_info['object'],
			str(hex(get_ipc_port_name(ipc_entry.get('ie_bits').int_value, idx))),
			ipc_entry_info['right'],
			ipc_entry_info['urefs'],
			ipc_entry_info['nsets'],
			ipc_entry_info['nmsgs'],
			ipc_entry_info['destname'],
			ipc_entry_info['destination']
		))


### XNU ZONES TRACKING ###

class ZoneMetaOld(object):
	"""
		Helper class that helpers walking metadata
	"""
	pagesize: int
	zone_map_min: int
	zone_map_max: int
	zone_meta_min: int
	zone_meta_max: int
	zone_array: 'XNUZones'
	zp_nopoison_cookie: int
	meta: ESBValue

	def _looksForeign(self: Self, addr: int) -> bool:
		if addr & (self.pagesize - 1):
			return False

		meta = ESBValue.init_with_address(addr, "struct zone_page_metadata *")
		if meta.is_null:
			return False

		return meta.get('zm_foreign_cookie')[0] == 0x123456789abcdef

	def __init__(self: Self, zone_array: 'XNUZones', addr: int, isPageIndex: bool = False):
		zone_info = ESBValue('zone_info')

		self.pagesize = ESBValue('page_size').int_value
		self.zone_map_min   = zone_info.get('zi_map_range.min_address').int_value
		self.zone_map_max   = zone_info.get('zi_map_range.max_address').int_value
		self.zone_meta_min  = zone_info.get('zi_meta_range.min_address').int_value
		self.zone_meta_max  = zone_info.get('zi_meta_range.max_address').int_value
		self.zone_array     = zone_array
		self.zp_nopoison_cookie = ESBValue('zp_nopoison_cookie').int_value

		if isPageIndex:
			# sign extend
			addr = c_uint64(c_int32(addr).value * self.pagesize).value

		self.address = addr

		if self.zone_meta_min <= addr and addr < self.zone_meta_max:
			self.kind = 'Metadata'
			addr -= (addr - self.zone_meta_min) % size_of('struct zone_page_metadata')
			self.meta_addr = addr
			self.meta = ESBValue.init_with_address(addr, 'struct zone_page_metadata *')

			self.page_addr = self.zone_map_min + ((addr - self.zone_meta_min) // size_of('struct zone_page_metadata') * self.pagesize)
			self.first_offset = 0
		
		elif self.zone_map_min <= addr and addr < self.zone_map_max:
			addr &= ~(self.pagesize - 1)
			page_idx = (addr - self.zone_map_min) // self.pagesize

			self.kind = 'Element'
			self.page_addr = addr
			self.meta_addr = self.zone_meta_min + page_idx * size_of('struct zone_page_metadata')
			self.meta = ESBValue.init_with_address(self.meta_addr, "struct zone_page_metadata *")
			self.first_offset = 0
		
		elif self._looksForeign(addr):
			self.kind = 'Element (F)'
			addr &= ~(self.pagesize - 1)
			self.page_addr = addr
			self.meta_addr = addr
			self.meta = ESBValue.init_with_address(addr, "struct zone_page_metadata *")
			self.first_offset = 32 # ZONE_FOREIGN_PAGE_FIRST_OFFSET in zalloc.c
		
		else:
			self.kind = 'Unknown'
			self.meta = ESBValue.init_with_address(0, "struct zone_page_metadata *")
			self.page_addr = 0
			self.meta_addr = 0
			self.first_offset = 0
	
	def __str__(self: Self) -> str:
		return f'ZoneMetaOld(kind="{self.kind}", meta_addr="{self.meta_addr}", page_addr="{self.page_addr}")'
			
	def isSecondaryPage(self: Self) -> int:
		return self.meta.is_not_null and self.meta.get('zm_secondary_page').is_not_null

	def getPageCount(self: Self) -> int:
		if self.meta.is_not_null and self.meta.get('zm_page_count').is_not_null:
			return self.meta.get('zm_page_count').int_value
		return 0

	def getAllocCount(self: Self) -> int:
		if self.meta.is_not_null and self.meta.get('zm_alloc_count').is_not_null:
			return self.meta.get('zm_page_count').int_value
		return 0

	def getReal(self: Self) -> 'ZoneMetaOld':
		if self.isSecondaryPage():
			return ZoneMetaOld(self.zone_array, self.meta.int_value - self.meta.get('zm_page_count').int_value)

		return self

	def getFreeList(self: Self) -> ESBValue:
		if self.meta.is_null:
			return ESBValue.init_with_address(0, 'vm_offset_t *')

		zm_freelist_offs = self.meta.get('zm_freelist_offs').int_value
		vm_offset_addr = 0
		if self.meta.is_not_null and (zm_freelist_offs != 0xffff):
			vm_offset_addr = self.page_addr + zm_freelist_offs
		
		return ESBValue.init_with_address(vm_offset_addr, 'vm_offset_t *')
	
	def isInFreeList(self: Self, element_addr: int) -> bool:
		cur = self.getFreeList()
		if cur == None:
			return False
		
		while cur.is_not_null:
			if cur.int_value == element_addr:
				return True
			
			cur = cur.dereference()
			next_addr = cur.int_value ^ self.zp_nopoison_cookie
			cur = ESBValue.init_with_address(next_addr, 'vm_offset_t *')
		
		return False
	
	def isInAllocationList(self: Self, element_addr: int) -> bool:
		zone = self.zone_array[self.meta.get('zm_index').int_value]
		if not zone:
			return False

		esize = zone.get('z_elem_size').int_value
		offs  = self.first_offset
		end   = self.pagesize
		if not self.meta.get('zm_percpu').int_value:
			end *= self.meta.get('zm_page_count').int_value

		while offs + esize <= end:
			if (self.page_addr + offs) == element_addr:
				return True
			
			offs += esize
		
		return False

	def iterateFreeList(self: Self) -> Iterator[ESBValue]:
		cur = self.getFreeList()
		if cur != None:
			while cur.is_not_null:
				yield cur

				cur = cur.dereference()
				next_addr = cur.int_value ^ self.zp_nopoison_cookie
				cur = ESBValue.init_with_address(next_addr, 'vm_offset_t *')

	def iterateElements(self: Self) -> Iterator[int]:
		if self.meta is None:
			return

		zone = self.zone_array[self.meta.get('zm_index').int_value]
		if not zone:
			return

		esize = zone.get('z_elem_size').int_value
		offs  = self.first_offset
		end   = self.pagesize
		if not self.meta.get('zm_percpu').int_value:
			end *= self.meta.get('zm_page_count').int_value

		while offs + esize <= end:
			yield self.page_addr + offs
			offs += esize

ZONE_ADDR_FOREIGN = 0
ZONE_ADDR_NATIVE  = 1

class ZoneMetaNew(object):
	"""
	Helper class that helpers walking metadata
	"""
	zone: ESBValue

	def __init__(self: Self, zone_array: 'XNUZones', addr: int, isPageIndex: bool = False):
		self.pagesize  = ESBValue('page_size').int_value
		self.zone_info = ESBValue('zone_info')
		self.zone_array = zone_array

		def load_range(var: ESBValue) -> Tuple[int, int]:
			return (var.get('min_address').int_value, var.get('max_address').int_value)

		def in_range(x: int, r: Tuple[int, int]) -> bool:
			return x >= r[0] and x <= r[1]

		self.meta_range = load_range(self.zone_info.get('zi_meta_range'))
		self.native_range = load_range(self.zone_info.get('zi_map_range')[ZONE_ADDR_NATIVE])
		self.foreign_range = load_range(self.zone_info.get('zi_map_range')[ZONE_ADDR_FOREIGN])
		self.addr_base = min(self.foreign_range[0], self.native_range[0])

		if isPageIndex:
			# sign extend
			addr = c_uint64(c_int32(addr).value * self.pagesize).value

		self.address = addr

		if in_range(addr, self.meta_range):
			self.kind = 'Metadata'
			addr -= addr % size_of('struct zone_page_metadata')
			self.meta_addr = addr
			self.meta = ESBValue.init_with_address(addr, "struct zone_page_metadata *")

			self.page_addr = self.addr_base + ((addr - self.meta_range[0]) // size_of('struct zone_page_metadata') * self.pagesize)
		elif in_range(addr, self.native_range) or in_range(addr, self.foreign_range):
			addr &= ~(self.pagesize - 1)
			page_idx = (addr - self.addr_base) // self.pagesize

			self.kind = 'Element'
			self.page_addr = addr
			self.meta_addr = self.meta_range[0] + page_idx * size_of('struct zone_page_metadata')
			self.meta = ESBValue.init_with_address(self.meta_addr, "struct zone_page_metadata *")
		else:
			self.kind = 'Unknown'
			self.meta = ESBValue.init_with_address(0, "struct zone_page_metadata *")
			self.page_addr = 0
			self.meta_addr = 0

		if self.meta.is_not_null:
			zone = self.zone_array[self.meta.get('zm_index').int_value]
			if zone == None:
				self.zone = ESBValue.init_null('struct zone *')
			else:
				self.zone = zone
		else:
			self.zone = ESBValue.init_null('struct zone *')
	
	def __str__(self: Self) -> str:
		return f'ZoneMetaNew(kind="{self.kind}", meta_addr="{self.meta_addr}", page_addr="{self.page_addr}")'

	@property
	def isSecondaryPage(self: Self) -> bool:
		return self.meta and self.meta.get('zm_chunk_len').int_value >= 0xe

	def getPageCount(self: Self):
		n = self.meta and self.meta.get('zm_chunk_len').int_value or 0
		if self.zone and self.zone.get('z_percpu').int_value:
			n *= ESBValue('zpercpu_early_count').int_value
		return n

	def getAllocAvail(self: Self):
		if not self.meta: return 0
		chunk_len = self.meta.get('zm_chunk_len').int_value
		return chunk_len * self.pagesize // self.zone.get('z_elem_size').int_value

	def getAllocCount(self: Self):
		if not self.meta: return 0
		return self.meta.get('zm_alloc_size').int_value // self.zone.get('z_elem_size').int_value

	def getReal(self: Self) -> 'ZoneMetaNew':
		if self.isSecondaryPage:
			# return ZoneMeta()
			addr = self.meta.int_value - size_of('struct zone_page_metadata') * self.meta.get('zm_page_index').int_value
			return ZoneMetaNew(self.zone_array, addr)

		return self

	def getElementAddress(self: Self, addr: int) -> int:
		meta  = self.getReal()
		esize = meta.zone.get('z_elem_size').int_value
		start = meta.page_addr

		if esize == 0:
			return 0

		estart = addr - start
		return start + estart - (estart % esize)

	def getInlineBitmapChunkLength(self: Self):
		if self.zone.get('z_percpu').is_not_null:
			return self.zone.get('z_chunk_pages').int_value
		return self.meta.get('zm_chunk_len').int_value

	def getBitmapSize(self: Self) -> int:
		if self.zone.is_null:
			return 0

		if not self.meta or self.zone.get('z_permanent').int_value or not self.meta.get('zm_chunk_len').int_value:
			return 0

		if self.meta.get('zm_inline_bitmap').is_not_null:
			return -4 * self.getInlineBitmapChunkLength()
		
		return 8 << (self.meta.get('zm_bitmap').int_value & 0x7)

	def getBitmap(self: Self) -> int:
		if self.zone.is_null:
			return 0

		if not self.meta or self.zone.get('z_permanent').int_value or not self.meta.get('zm_chunk_len').int_value:
			return 0
		
		if self.meta.get('zm_inline_bitmap').is_valid:
			return self.meta.get('zm_bitmap').addr_of()
		
		bbase = self.zone_info.get('zi_bits_range.min_address').int_value
		index = self.meta.get('zm_bitmap').int_value & ~0x7
		return bbase + index

	def getFreeCountSlow(self: Self) -> int:
		if self.zone.is_null:
			return 0

		if not self.meta or self.zone.get('z_permanent').int_value or not self.meta.get('zm_chunk_len').int_value:
			return self.getAllocAvail() - self.getAllocCount()

		n = 0
		if self.meta.get('zm_inline_bitmap').is_not_null:
			for i in range(0, self.getInlineBitmapChunkLength()):
				m = ESBValue.init_with_address(self.meta_addr + i * 16, 'struct zone_page_metadata *');
				bits = m.get('zm_bitmap').int_value
				while bits:
					n += 1
					bits &= bits - 1
		else:
			bitmap = ESBValue.init_with_address(self.getBitmap(), 'uint64_t *')
			for i in range(0, 1 << (self.meta.get('zm_bitmap').int_value & 0x7)):
				bits = bitmap[i].int_value
				while bits:
					n += 1
					bits &= bits - 1
		
		return n

	def isElementFree(self: Self, addr: int) -> bool:
		meta = self.meta
		if self.zone.is_null:
			return False

		if meta.is_not_null or self.zone.get('z_permanent').int_value or not meta.get('zm_chunk_len').int_value:
			return True
		
		start = self.page_addr
		esize = self.zone.get('z_elem_size').int_value
		eidx  = (addr - start) // esize
		if meta.get('zm_inline_bitmap').is_not_null:
			idx = (eidx // 32)
			meta = ESBValue.init_with_address(meta.int_value + idx, 'struct zone_page_metadata *')
			bits = meta.get('zm_bitmap').int_value
			return bits & (1 << (eidx % 32)) != 0
		else:
			bitmap = ESBValue.init_with_address(self.getBitmap(), 'uint64_t *')
			bits = bitmap[eidx // 64].int_value
			return (bits & (1 << (eidx % 64))) != 0
	
	def isInFreeList(self: Self, addr: int) -> bool:
		return self.isElementFree(addr)

	def iterateElements(self: Self) -> Iterator[int]:
		if self.meta.is_null or self.zone.is_null:
			return
			
		esize = self.zone.get('z_elem_size').int_value
		start = 0
		end   = self.pagesize * self.meta.get('zm_chunk_len').int_value
		end  -= end % esize

		for offs in range(start, end, esize):
			yield self.page_addr + offs

gkalloc_heap_names: List[str] = []

class XNUZones:
	zones_access_cache: Dict[str, ESBValue]
	logged_zones: Dict[str, ESBValue]
	pointer_size: int
	is_zone_meta_old: bool

	def __init__(self):
		# get all zones symbols
		self.kalloc_heap_names = []
		self.zones_access_cache = {}
		self.logged_zones = {}
		self.zone_index_array = []
		self.pointer_size = 8
		# self.zone_security_array = None
		self.zone_struct_size = 0
		self.zone_array_address = 0
		self.is_zone_meta_old = False
	
	@property
	def is_loaded(self: Self) -> bool:
		return False if not len(self.kalloc_heap_names) else True

	def load_from_kernel(self: Self, target: SBTarget) -> bool:
		global gkalloc_heap_names

		self.pointer_size = get_pointer_size()
		self.target = target

		try:
			self.zone_security_array = ESBValue('zone_security_array')
			self.zone_struct_size = size_of('zone')
			zone_array = ESBValue('zone_array')
			num_zones = ESBValue('num_zones')
		except ESBValueException:
			print(f'[!] Unable to find zone_array/num_zones/zone_security_array/zone symbol in this kernel')
			return False
		
		num_zones = num_zones.int_value
		
		self.zone_array_address = zone_array.addr_of() # save zone_array base address for later used
		if len(gkalloc_heap_names) < 4:
			kalloc_heap_names = ESBValue('kalloc_heap_names')
			for i in range(4):
				kalloc_heap_name = kalloc_heap_names[i].cast_to('char *')
				gkalloc_heap_names.append(kalloc_heap_name.str_value)

		for idx in range(num_zones):
			zone_name = self._extract_zone_name(zone_array[idx])
			zone = zone_array[idx]
			zone.set_attribute('zone_name', zone_name)
			zone.set_attribute('zone_idx', idx)

			self.zones_access_cache[zone_name] = zone
			self.zone_index_array.append(zone_name)

			if self.is_zone_logging(zone):
				# cache logged zone for lookup
				self.logged_zones[zone_name] = zone
		
		try:
			_ = ESBValue('zp_nopoison_cookie')
			self.is_zone_meta_old = True
		except ESBValueException:
			self.is_zone_meta_old = False
		
		return True
	
	def is_zone_logging(self: Self, zone: ESBValue) -> bool:
		return not zone.get('zlog_btlog').is_null
	
	def _extract_zone_name(self: Self, zone: ESBValue) -> str:
		z_name = zone.get('z_name').str_value
			
		if zone.get('kalloc_heap').is_valid:
			heap_name_idx = zone.get('kalloc_heap').int_value
		else:
			# macOS 12 will change how we retrieve kalloc heap name checkout zone_heap_name
			zone_idx = (zone.addr_of() - self.zone_array_address) // self.zone_struct_size
			heap_name_idx = self.zone_security_array[zone_idx].get('z_kheap_id').int_value

		if heap_name_idx < 4:
			return gkalloc_heap_names[heap_name_idx] + z_name

		return z_name

	def __len__(self: Self) -> int:
		return len(self.zones_access_cache)
	
	def __iter__(self: Self):
		for zone_name in self.zones_access_cache:
			yield self.zones_access_cache[zone_name]

	def __getitem__(self: Self, idx: int) -> Optional[ESBValue]:
		if idx >= len(self.zone_index_array):
			return None
		
		zone_name = self.zone_index_array[idx]
		return self.zones_access_cache[zone_name]
	
	def has_zone_name(self: Self, zone_name: str) -> bool:
		return False if zone_name not in self.zones_access_cache else True
	
	def iter_zone_name(self: Self):
		for zone_name in self.zones_access_cache:
			yield zone_name
	
	def get_zone_by_name(self: Self, zone_name: str) -> Optional[ESBValue]:
		if zone_name in self.zones_access_cache:
			return self.zones_access_cache[zone_name]
		
		return None
	
	def get_zone_id_by_name(self: Self, zone_name: str) -> int:
		return self.zone_index_array.index(zone_name)
	
	def get_zones_by_regex(self: Self, zone_name_regex: str) -> list:
		zones = []

		if self.zones_access_cache:
			for zone_name in self.zones_access_cache:
				if re.match(zone_name_regex, zone_name):
					zones.append(self.zones_access_cache[zone_name])

		return zones
	
	def show_zone_being_logged(self: Self):
		if not self.logged_zones:
			return
		
		for logged_zone_name in self.logged_zones:
			zone = self.logged_zones[logged_zone_name]
			zone_name = zone.get_attribute('zone_name')
			logged_zone_idx = zone.get_attribute('zone_idx')
			zlog_btlog = zone.get('zlog_btlog')
			if not zlog_btlog.is_null:
				print(f'- zone_array[{logged_zone_idx}]: {zone_name} log at {zlog_btlog.value}')
	
	def get_logged_zone_index_by_name(self: Self, zone_name: str) -> int:
		try:
			return typing.cast(int, self.logged_zones[zone_name].get_attribute('zone_idx'))
		except KeyError:
			return -1
	
	def zone_find_stack_elem(self: Self, zone_name: str, target_element: int, action: int):
		""" Zone corruption debugging: search the zone log and print out the stack traces for all log entries that
			refer to the given zone element.
			Usage: zstack_findelem <btlog addr> <elem addr>

			When the kernel panics due to a corrupted zone element, get the
			element address and use this command.  This will show you the stack traces of all logged zalloc and
			zfree operations which tells you who touched the element in the recent past.  This also makes
			double-frees readily apparent.
		"""
		try:
			log_records = ESBValue('log_records')
			corruption_debug_flag = ESBValue('corruption_debug_flag')
		except ESBValueException:
			print(f'[!] Unable to find log_records/corruption_debug_flag in this kernel')
			return

		if not log_records.int_value or not corruption_debug_flag.int_value:
			print("[!] Zone logging with corruption detection not enabled. Add '-zc zlog=<zone name>' to boot-args.")
			return False
		
		zone = self.get_zone_by_name(zone_name)
		if zone == None:
			print(f'[!] Unable to find this zone {zone_name}')
			return
		
		if not self.is_zone_logging(zone):
			print(f'[!] Unable to track this zone {zone_name}, please add this zone into boot-args')
			return
		
		btlog_ptr = zone.get('zlog_btlog').cast_to('btlog_t *')
		
		btrecord_size = btlog_ptr.get('btrecord_size').int_value
		btrecords = btlog_ptr.get('btrecords').int_value
		depth = btlog_ptr.get('btrecord_btdepth').int_value

		prev_operation = -1
		scan_items = 0

		element_hash_queue = btlog_ptr.get('elem_linkage_un').get('element_hash_queue')
		hashelem = element_hash_queue.get('tqh_first').cast_to('btlog_element_t *')

		if (target_element >> 32) != 0:
			target_element = target_element ^ 0xFFFFFFFFFFFFFFFF
		else:
			target_element = target_element ^ 0xFFFFFFFF

		'''
			Loop through element_hash_queue linked list to find record information of our target_element
		'''
		while not hashelem.is_null:
			hashelem_value = hashelem.get('elem').int_value
			if hashelem_value == target_element:
				# found record information of target_element

				recindex = hashelem.get('recindex').int_value

				recoffset = recindex * btrecord_size
				record = ESBValue.init_with_address(btrecords + recoffset, 'btlog_record_t *')
				# extract action for this chunk address and see if this chunk was freed or allocated
				record_operation = record.get('operation').int_value

				if action == 0:
					out_str = ('-' * 8)
					if record_operation == 1:
						out_str += "OP: ALLOC. "
					else:
						out_str += "OP: FREE.  "

					out_str += "Stack Index {0: <d} {1: <s}\n".format(recindex, ('-' * 8))

					print(out_str)
					print(self.get_btlog_backtrace(depth, record))
					print(' \n')

					if record_operation == prev_operation:
						if prev_operation == 0:
							print("{0: <s} DOUBLE FREE! {1: <s}".format(('*' * 8), ('*' * 8)))
						else:
							print("{0: <s} DOUBLE OP! {1: <s}".format(('*' * 8), ('*' * 8)))
						return True

				elif action == 1 and not record_operation:
					# show free only
					out_str = ('-' * 8)
					out_str += "OP: FREE.  "
					out_str += "Stack Index {0: <d} {1: <s}\n".format(recindex, ('-' * 8))
					print(out_str)
					print(self.get_btlog_backtrace(depth, record))
					print(' \n')
				elif action == 2 and record_operation:
					# show allocation only
					out_str = ('-' * 8)
					out_str += "OP: ALLOC.  "
					out_str += "Stack Index {0: <d} {1: <s}\n".format(recindex, ('-' * 8))
					print(out_str)
					print(self.get_btlog_backtrace(depth, record))
					print(' \n')
				
				prev_operation = record_operation
				scan_items = 0

			hashelem = hashelem.get('element_hash_link').get('tqe_next')
			hashelem = hashelem.cast_to('btlog_element_t *')

			scan_items += 1
			if scan_items % 100 == 0:
				print("Scanning is ongoing. {0: <d} items scanned since last check." .format(scan_items))
	
	def get_btlog_backtrace(self: Self, depth: int, zstack_record: ESBValue) -> str:
		""" Helper routine for getting a BT Log record backtrace stack.
			params:
				depth:int - The depth of the zstack record
				zstack_record:btlog_record_t * - A BTLog record
			returns:
				str - string with backtrace in it.
		"""

		out_str = ''
		frame = 0
		if not zstack_record:
			return "Zstack record none!"
		
		zstack_record_bt = zstack_record.get('bt')
		pc_array = read_mem(zstack_record_bt.addr_of(), depth * self.pointer_size)

		while frame < depth:
			frame_pc = unpack('<Q', pc_array[frame*self.pointer_size : (frame + 1) * self.pointer_size])[0]
			if not frame_pc:
				break
			
			sb_addr = get_target().ResolveLoadAddress(frame_pc)
			if sb_addr:
				symbol_str = str(sb_addr)
			else:
				symbol_str = ''
			out_str += "{0: <#0X} <{1: <s}>\n".format(frame_pc, symbol_str)
			frame += 1

		return out_str
	
	def zone_iterate_queue(self: Self, page: ESBValue):
		cur_page_addr = page.get('packed_address')#.GetIntValue()
		while not cur_page_addr.is_null:
			if self.is_zone_meta_old:
				meta = ZoneMetaOld(self, cur_page_addr.int_value, isPageIndex=True)
			else:
				meta = ZoneMetaNew(self, cur_page_addr.int_value, isPageIndex=True)

			yield meta
			page = meta.meta.get('zm_page_next')
			cur_page_addr = cur_page_addr.get('packed_address')
	
	def iter_chunks_at_zone(self: Self, zone: ESBValue):
		if zone.get('z_self').is_null or zone.get('permanent').int_value:
			yield 'None', 0
		
		if self.is_zone_meta_old:
			iteration_list = [zone.get('pages_any_free_foreign'), zone.get('pages_all_used_foreign'),
					zone.get('pages_intermediate'), zone.get('pages_all_used')]
		else:
			iteration_list = [zone.get('z_pageq_full'), zone.get('z_pageq_partial'), zone.get('z_pageq_empty'), zone.get('z_pageq_va')]

		for head in iteration_list:
			for meta in self.zone_iterate_queue(head):
				for elem in meta.iterateElements():
					status = 'Allocated'
					if meta.isInFreeList(elem):
						status = 'Freed'
					
					yield status, elem
	
	def get_chunk_info_at_zone(self: Self, zone: ESBValue, chunk_addr: int) -> str:
		for status, elem in self.iter_chunks_at_zone(zone):
			if status == 'None':
				break

			if elem == chunk_addr:
				return status
		
		return 'None'
			
	def get_chunk_info_at_zone_name(self: Self, zone_name: str, chunk_addr: int) -> str:
		if not self.has_zone_name(zone_name):
			return 'None'
		
		zone = self.zones_access_cache[zone_name]
		return self.get_chunk_info_at_zone(zone, chunk_addr)
	
	def get_info_chunks_at_range(self: Self, from_zone_idx: int, to_zone_idx: int, chunk_addr: int):
		# assert (from_zone_idx >=0 and to_zone_idx < len(self)) and (from_zone_idx < to_zone_idx), \
		# 				'from_zone_idx or to_zone_idx is out of bound'

		# for i in range(from_zone_idx, to_zone_idx):
		# 	zone = self[i]
		# 	ret = self.get_chunk_info_at_zone(i, chunk_addr)
		# 	if ret != 'None':
		# 		info = {
		# 			'zone_name': zone.get_attribute('zone_name'),
		# 			'zone_idx': i,
		# 			'status': ret 
		# 		}
		# 		return info
		
		return None
	
	def find_chunk_info(self, chunk_addr : int):
		'''
			Walk through the hold zone in zone_array, this method could take time
		'''

		for zone_name in self.zones_access_cache:
			zone = self.zones_access_cache[zone_name]
			ret = self.get_chunk_info_at_zone_name(zone_name, chunk_addr)
			if ret != 'None':
				info = {
					'zone_name':zone.get_attribute('zone_name'),
					'zone_idx': zone.get_attribute('zone_idx'),
					'status': ret 
				}
				return info
		
		return None

	def inspect_zone_name(self: Self, zone_name: str):
		'''
			List all chunks and their status for a zone
		'''

		zone = self.get_zone_by_name(zone_name)
		if zone == None:
			print(f'[!] zone: {zone_name} does not exists.')
			return

		print('Zone: ', COLORS['YELLOW'], zone.get_attribute('zone_name'), COLORS['RESET'])
		print(COLORS['BOLD'], end='')
		print("{:>5s}  {:<20s} {:<10s}".format("#", "Element", "Status"))
		print(COLORS['RESET'], end='')

		num = 0
		for status, elem in self.iter_chunks_at_zone(zone):
			if status == 'None':
				break

			color = COLORS["GREEN"]
			if status == 'Freed':
				color = COLORS["RED"]
			
			print(color, end='')
			print("{:5d}  0x{:<20X} {:<10s}".format(num, elem, status))
			print(COLORS['RESET'], end='')
			num+=1
	
	def get_allocated_elems(self: Self, zone_name: str) -> list:
		elems = []

		zone = self.get_zone_by_name(zone_name)
		if zone == None:
			return elems
		
		for status, elem in self.iter_chunks_at_zone(zone):
			if status == 'Allocated':
				elems.append(elem)
		
		return elems
	
	def get_freed_elems(self: Self, zone_name: str) -> list:
		elems = []

		zone = self.get_zone_by_name(zone_name)
		if zone == None:
			return elems
		
		for status, elem in self.iter_chunks_at_zone(zone):
			if status == 'Freed':
				elems.append(elem)
		
		return elems

# --- IOKit stuffs --- #
IOKIT_OBJECTS = (
	'OSArray', 'OSDictionary', 'OSData', 'OSString', 'OSSymbol',
	'OSBoolean', 'OSOrderedSet', 'OSNumber', 'OSSet'
)

def iokit_get_type(object_address: int) -> str:
	vtable = read_u64(object_address)
	if not vtable:
		return ''

	sym_name = resolve_symbol_name(vtable)
	m = re.match(r'vtable for (\w*)', sym_name)
	if not m:
		return ''
	
	if m[1] not in IOKIT_OBJECTS:
		return ''

	return m[1]

def iokit_print(object_address : int, level = 0):
	iokit_type = iokit_get_type(object_address)
	if not iokit_type:
		print(f'[!] Unable to detect iokit object at address {hex(object_address)}')
		return

	# cast this address to sepecific IOKit class
	iokit_object = ESBValue.init_with_address(object_address, iokit_type + ' *')

	if level == 0:
		print(f'({iokit_type} *){hex(object_address)} : ', end='')

	if iokit_type == 'OSDictionary':
		# loop through this OSDictionary
		print(' '*level + '{')
		dict_count = iokit_object.get('count').int_value
		dict_ptr = iokit_object.get('dictionary').int_value

		for i in range(dict_count):
			key_ptr = read_u64(dict_ptr)
			value_ptr = read_u64(dict_ptr + 8)

			print(' '*(level + 1), end='')
			iokit_print(key_ptr, level=level+1)
			print(' : ', end='')
			iokit_print(value_ptr, level=level+1)
			print('')

			dict_ptr += 0x10
		
		print(' '*level + '}', end='')

	elif iokit_type == 'OSArray':
		print(' '*level + '[')
		array_count = iokit_object.get('count').int_value
		array_ptr   = iokit_object.get('array').int_value

		for _ in range(array_count):
			value_addr = read_u64(array_ptr)
			print(' '*(level + 1))
			iokit_print(value_addr, level=level+1)
			print(',')
			array_ptr += 8

	elif iokit_type == 'OSSet':
		# unimplemented
		print(f'OSSet({hex(object_address)})', end='')
	
	elif iokit_type == 'OSOrderedSet':
		# unimplemented
		print(f'OSOrderedSet({hex(object_address)})', end='')

	elif iokit_type == 'OSString' or iokit_type == 'OSSymbol':
		string_value = iokit_object.get('string').str_value
		if iokit_type == 'OSSymbol':
			print(string_value, end='')
		else:
			print(f'"{string_value}"', end='')
	
	elif iokit_type == 'OSNumber':
		number_value = iokit_object.get('value').int_value
		print(number_value, end='')
	
	elif iokit_type == 'OSData':
		# unimplemented
		print(f'OSData({hex(object_address)})', end='')
	
	elif iokit_type == 'OSBoolean':
		boolean_value = iokit_object.get('value').int_value
		if boolean_value:
			print('true', end='')
		else:
			print('false', end='')
	
	if level == 0:
		print("") # add newline
