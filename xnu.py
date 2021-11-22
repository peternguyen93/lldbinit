'''
Small script support xnu kernel debugging
Author : peternguyen
'''

import lldb
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

def xnu_esbvalue_check(esbvar : ESBValue) -> bool:
	esb_var_name = esbvar.GetName()
	if not esbvar.IsValid():
		print(f'[!] Unable to find "{esb_var_name}", please boot xnu with development kernel Or \
load binary has debug infos')
		return False
	return True

# save up cpu cost by create a cache for kext information
gKextInfos = {} 

def xnu_get_all_kexts() -> dict:
	kexts = {}

	g_load_kext_summaries = ESBValue('gLoadedKextSummaries')
	if not xnu_esbvalue_check(g_load_kext_summaries):
		return kexts

	base_address = g_load_kext_summaries.GetIntValue()
	entry_size = g_load_kext_summaries.entry_size.GetIntValue()
	kext_summaries_ptr = base_address + size_of('OSKextLoadedKextSummaryHeader')

	for i in range(g_load_kext_summaries.numSummaries.GetIntValue()):
		kext_summary_at = ESBValue.initWithAddressType(kext_summaries_ptr, 'OSKextLoadedKextSummary *')
		
		kext_name = kext_summary_at.name.GetStrValue()
		kext_address = kext_summary_at.address.GetIntValue()
		kext_size = kext_summary_at.size.GetValue()
		kext_uuid_addr = kext_summary_at.uuid.GetLoadAddress()
		kext_uuid = GetUUIDSummary(read_mem(kext_uuid_addr, size_of('uuid_t')))

		# kext_name format : com.apple.<type of kext>.<kext bin name>
		kext_file_name = kext_name.split('.')[-1]
		kexts[kext_file_name] = {
			'name' : kext_name, # original kext name
			'uuid' : kext_uuid,
			'address' : kext_address,
			'size' : kext_size
		}
		kext_summaries_ptr += entry_size
	
	return kexts

def xnu_load_kextinfo():
	global gKextInfos
	if not gKextInfos:
		gKextInfos = xnu_get_all_kexts()

def xnu_get_kext_base_address(kext_name : str) -> int:
	global gKextInfos
	
	xnu_load_kextinfo()

	try:
		return gKextInfos[kext_name]['address']
	except KeyError:
		return -1

def xnu_showallkexts():
	global gKextInfos
	
	xnu_load_kextinfo()

	longest_kext_name = len(max(gKextInfos, key=lambda kext_name: len(kext_name)))
	
	print('-- Loaded kexts:')
	for kext_bin_name in gKextInfos:
		kext_uuid    = gKextInfos[kext_bin_name]['uuid']
		kext_address = gKextInfos[kext_bin_name]['address']
		kext_size    = gKextInfos[kext_bin_name]['size']
		kext_name    = gKextInfos[kext_bin_name]['name']
		print(f'+ {kext_name:{longest_kext_name}}\t{kext_uuid}\t\t0x{kext_address:X}\t{kext_size}')

def xnu_write_task_kdp_pmap(task : ESBValue) -> bool:
	kdp_pmap = ESBValue('kdp_pmap')
	if not xnu_esbvalue_check(kdp_pmap):
		return False

	task = task.CastTo('task *')
	kdp_pmap_addr = kdp_pmap.GetLoadAddress()
	pmap = task.map.pmap

	if not write_mem(kdp_pmap_addr, pack('<Q', pmap.GetIntValue())):
		print(f'[!] Overwrite kdp_pmap with task->map->pmap failed.')
		return False

	return True

def xnu_reset_kdp_pmap() -> bool:
	kdp_pmap = ESBValue('kdp_pmap')
	if not xnu_esbvalue_check(kdp_pmap):
		return False
	
	kdp_pmap_addr = kdp_pmap.GetLoadAddress()

	if not write_mem(kdp_pmap_addr, pack('<Q', 0)):
		print(f'[!] Overwrite kdp_pmap with task->map->pmap failed.')
		return False

	return True

def xnu_read_user_address(target : lldb.SBTarget, task : ESBValue, address : int, size : int) -> bytes:
	out = ''

	if GetConnectionProtocol() != 'kdp':
		print('[!] xnu_read_user_address() only works on kdp-remote')
		return b''

	if not xnu_write_task_kdp_pmap(target, task):
		return b''

	out = read_mem(address, size)

	if not xnu_reset_kdp_pmap(target):
		print(f'[!] Reset kdp_pmap failed')
		return b''

	return out

def xnu_write_user_address(target : lldb.SBTarget, task : ESBValue, address : int, value : int) -> bool:
	if GetConnectionProtocol() != 'kdp':
		print('[!] xnu_read_user_address() only works on kdp-remote')
		return False

	if xnu_write_task_kdp_pmap(target, task):
		return False

	if not write_mem(address, value):
		return False

	if not xnu_reset_kdp_pmap(target):
		print(f'[!] Reset kdp_pmap failed')
		return False

	return True

def xnu_find_process_by_name(search_proc_name : str) -> ESBValue:
	allproc = ESBValue('allproc')
	if not allproc.IsValid():
		return None

	allproc_ptr = allproc.lh_first

	match_proc = None
	while allproc_ptr.GetIntValue():
		if allproc_ptr.p_name.GetStrValue() == search_proc_name:
			match_proc = allproc_ptr 
			break

		allproc_ptr = allproc_ptr.p_list.le_next

	return match_proc

def xnu_list_all_process():
	allproc = ESBValue('allproc')
	if not allproc.IsValid():
		return None

	allproc_ptr = allproc.lh_first

	while allproc_ptr.GetIntValue():
		proc_name = allproc_ptr.p_name.GetStrValue()
		p_pid = allproc_ptr.p_pid.GetIntValue()
		print(f'+ {p_pid} - {proc_name} - {allproc_ptr.GetValue()}')
		allproc_ptr = allproc_ptr.p_list.le_next

def xnu_showbootargs() -> str:
	pe_state = ESBValue('PE_state')
	if not xnu_esbvalue_check(pe_state):
		return ''

	boot_args = pe_state.bootArgs.CastTo('boot_args *')
	commandline = boot_args.CommandLine
	return read_str(commandline.GetLoadAddress(), 1024).decode('utf-8')

def xnu_panic_log() -> str:
	panic_info = ESBValue('panic_info')
	if not xnu_esbvalue_check(panic_info):
		return b''

	mph_magic = panic_info.mph_magic
	if not mph_magic.IsValid():
		print('[!] Unable to find mph_magic in panic_info')
		return b''
	
	if mph_magic.GetIntValue() != MACOS_PANIC_MAGIC:
		print('[!] Currently support parse MACOS_PANIC')
		return b''
	
	panic_buf = panic_info.GetIntValue()

	panic_log_begin_offset = panic_info.mph_panic_log_offset.GetIntValue()
	panic_log_len = panic_info.mph_panic_log_len.GetIntValue()
	other_log_begin_offset = panic_info.mph_other_log_offset.GetIntValue()
	other_log_len = panic_info.mph_other_log_len.GetIntValue()

	debug_buf_ptr = ESBValue('debug_buf_ptr')

	cur_debug_buf_ptr_offset = debug_buf_ptr.GetIntValue() - panic_buf
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

def waitq_table_idx_from_id(_id : ESBValue) -> int:
	return int((_id.GetIntValue() & LTABLE_ID_IDX_MASK) >> LTABLE_ID_IDX_SHIFT)

def waitq_table_gen_from_id(_id : ESBValue) -> int:
	return (_id.GetIntValue() & LTABLE_ID_GEN_MASK) >> LTABLE_ID_GEN_SHIFT

def get_waitq_set_id_string(setid : ESBValue) -> str:
	idx = waitq_table_idx_from_id(setid)
	gen = waitq_table_gen_from_id(setid)
	return "{:>7d}/{:<#14x}".format(idx, gen)

def get_ipc_space_table(ipc_space : ESBValue) -> tuple:
	""" Return the tuple of (entries, size) of the table for a space
	"""
	table = ipc_space.is_table.__hazard_ptr
	if table.IsValid():
		# macOS 12 structure
		if table.GetIntValue():
			return (table, table.ie_size.GetIntValue())
	else:
		# macOS 11 structure
		table = ipc_space.is_table
		if table.GetIntValue():
			return (table, ipc_space.is_table_size.GetIntValue())
	return (None, 0)

def get_ipc_task(proc : ESBValue) -> ESBValue:
	return proc.task.CastTo('task *')

def get_proc_from_task(task : ESBValue) -> ESBValue:
	return task.bsd_info.CastTo('proc *')

def get_destination_proc_from_port(port : ESBValue) -> ESBValue:
	dest_space = port.ip_receiver
	if not dest_space.IsValid():
		dest_space = port.data.receiver

	task = dest_space.is_task
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

def get_waitq_sets(wqset_q : ESBValue) -> list:
	sets = []

	if wqset_q.IsValid() or wqset_q.IsNull():
		return sets

	ref = wqset_q.waitq_set_id
	if ref.IsValid():
		return sets

	while not ref.wqr_value.IsNull():
		if ref.wqr_value.GetIntValue() & 1:
			sets.append(get_waitq_set_id_string(ref.wqr_value))
			break

		link = ref.wqr_value.CastTo('struct waitq_link *')
		sets.append(get_waitq_set_id_string(link.wql_node))
		ref  = link.wql_next

	return sets

def get_iokit_object_type_str(kobject : ESBValue) -> str:
	# get iokit object type
	vtable_ptr = kobject.CastTo('uintptr_t *').Dereference()
	vtable_func_ptr = ESBValue.initWithAddressType(vtable_ptr.GetIntValue() + 2 * size_of('uintptr_t'), 'uintptr_t *')
	first_vtable_func = vtable_func_ptr[0].GetIntValue()
	func_desc = resolve_symbol_name(first_vtable_func)
	m = re.match(r'(\w*)::(\w*)', func_desc)
	if not m:
		return '<unknow>'
	
	return m[1]

def get_kobject_from_port(portval : ESBValue) -> str:
	""" Get Kobject description from the port.
		params: portval - core.value representation of 'ipc_port *' object
		returns: str - string of kobject information
	"""
	io_bits = portval.ip_object.io_bits.GetIntValue()
	if not io_bits & 0x800:
		return ''

	kobject_val = portval.ip_kobject
	if not kobject_val.IsValid():
		kobject_val = portval.kdata.kobject # use old way

	kobject_str = "{0: <#020x}".format(kobject_val.GetIntValue())
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
			proc_val = get_proc_from_task(kobject_val.CastTo('task *'))
			desc_str += " " + proc_val.p_name.GetStrValue()
	return kobject_str + " " + desc_str

def get_port_destination_summary(port : ESBValue) -> str:
	out_str = ''
	destination_str = ''
	destname_str = get_kobject_from_port(port)
	if not destname_str or "kobject(TIMER)" in destname_str:
		# check port is active
		if port.ip_object.io_bits.GetIntValue() & 0x80000000:
			destname_str = "{0: <#020x}".format(port.ip_messages.imq_receiver_name.GetIntValue())
			desc_proc = get_destination_proc_from_port(port)
			if not desc_proc.IsNull():
				destination_str = "{0:s}({1:d})".format(desc_proc.p_name.GetStrValue(), desc_proc.p_pid.GetIntValue())
			else:
				destination_str = 'task()'
		else:
			destname_str = "{0: <#020x}".format(port.GetIntValue())
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

	ie_object = entry.ie_object
	ie_bits = entry.ie_bits.GetIntValue()

	if (ie_bits & 0x001f0000) == 0:
		# entry is freed
		return None

	io_bits = ie_object.io_bits.GetIntValue()
	ipc_entry_info['urefs'] = ie_bits & 0xffff
	ipc_entry_info['object'] = entry.ie_object.GetIntValue()

	if ie_bits & 0x00100000:
		ipc_entry_info['right'] = 'Dead'
	elif ie_bits & 0x00080000:
		ipc_entry_info['right'] = 'Set'
		psetval = ie_object.CastTo('ipc_pset *')
		try:
			set_str = get_waitq_sets(psetval.ips_wqset.wqset_q)
		except AttributeError:
			set_str = get_waitq_sets(psetval.ips_messages.data.pset.setq.wqset_q)
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
		portval = ie_object.CastTo('ipc_port_t')

		ie_request = entry.ie_request.GetIntValue()
		if ie_request:
			ip_requests_addr = portval.ip_requests.GetIntValue()
			requestsval = ESBValue.initWithAddressType(
								ip_requests_addr + ie_request * size_of('struct ipc_port_request'),
								'struct ipc_port_request *'
							)
			sorightval = requestsval.notify.port
			soright_ptr = sorightval.GetIntValue()
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
		if portval.ip_nsrequest.GetIntValue() != 0 or portval.ip_kobject_nsrequest.GetIntValue():
			ipc_entry_info['right'] += 'n'
		
		# port-destroy notification requested
		if portval.ip_pdrequest.GetIntValue() != 0:
			ipc_entry_info['right'] += 'x'
		
		# Immovable receive rights
		if portval.ip_immovable_receive.GetIntValue() != 0:
			ipc_entry_info['right'] += 'i'
		
		# Immovable send rights
		if portval.ip_immovable_send.GetIntValue() != 0:
			ipc_entry_info['right'] += 'm'

		# No-grant Port
		if portval.ip_no_grant.GetIntValue() != 0:
			ipc_entry_info['right'] += 'g'

		# Port with SB filtering on
		if io_bits & 0x00001000 != 0:
			ipc_entry_info['right'] += 'f'

		# early-out if the rights-filter doesn't match
		if rights_filter != '' and rights_filter != ipc_entry_info['right']:
			return None

		# # now show the port destination part
		ipc_entry_info['destname'] = get_port_destination_summary(ie_object.CastTo('ipc_port_t'))

		# Get the number of sets to which this port belongs
		set_str = get_waitq_sets(portval.ip_waitq)
		ipc_entry_info['nsets'] = len(set_str)
		ipc_entry_info['nmsgs'] = portval.ip_messages.imq_msgcount.GetIntValue()

	if rights_filter == '' or rights_filter == ipc_entry_info['right']:
		return ipc_entry_info
	
	return None

def print_ipc_information(ipc_space : ESBValue):
	entry_table, num_entries = get_ipc_space_table(ipc_space)
	if entry_table == None:
		print('[!] Unable to retrieve entry_table')
		return

	entry_table_address = entry_table.GetIntValue()

	print("{0: <20s} {1: <20s} {2: <20s} {3: <8s} {4: <10s} {5: <18s} {6: >8s} {7: <8s}".format(
		'ipc_space', 'is_task', 'is_table', 'flags', 'ports', 'table_next', 'low_mod', 'high_mod'
	))

	flags = ''
	if entry_table_address:
		flags += 'A'
	else:
		flags += ' '
	if ipc_space.is_grower.GetIntValue():
		flags += 'G'

	print("{0: <#020x} {1: <#020x} {2: <#020x} {3: <8s} {4: <10d} {5: <#18x} {6: >8d} {7: <8d}".format(
			ipc_space.GetIntValue(),
			ipc_space.is_task.GetIntValue(),
			entry_table.GetIntValue(),
			flags,
			num_entries,
			ipc_space.is_table_next.GetIntValue(),
			ipc_space.is_low_mod.GetIntValue(),
			ipc_space.is_high_mod.GetIntValue())
		)

	print("{: <20s} {: <12s} {: <8s} {: <8s} {: <8s} {: <8s} {: <20s} {: <20s}".format(
		"object", "name", "rights", "urefs", "nsets", "nmsgs", "destname", "destination"))
	
	for idx in range(1, num_entries):
		ipc_entry = ESBValue.initWithAddressType(entry_table_address + idx * size_of('struct ipc_entry'), 'ipc_entry_t')
		ipc_entry_info = get_ipc_entry_summary(ipc_entry)
		if ipc_entry_info == None:
			continue
		
		print("{: <#020x} {: <12s} {: <8s} {: <8d} {: <8d} {: <8d} {: <20s} {: <20s}".format(
			ipc_entry_info['object'],
			str(hex(get_ipc_port_name(ipc_entry.ie_bits.GetIntValue(), idx))),
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

	def _looksForeign(self, addr):
		if addr & (self.pagesize - 1):
			return False

		meta = ESBValue.initWithAddressType(addr, "struct zone_page_metadata *")
		if not meta.IsValid():
			return False

		return meta.zm_foreign_cookie[0] == 0x123456789abcdef

	def __init__(self, zone_array, addr, isPageIndex = False):
		zone_info = ESBValue('zone_info')

		self.pagesize = ESBValue('page_size').GetIntValue()
		self.zone_map_min   = zone_info.zi_map_range.min_address.GetIntValue()
		self.zone_map_max   = zone_info.zi_map_range.max_address.GetIntValue()
		self.zone_meta_min  = zone_info.zi_meta_range.min_address.GetIntValue()
		self.zone_meta_max  = zone_info.zi_meta_range.max_address.GetIntValue()
		self.zone_array     = zone_array
		self.zp_nopoison_cookie = ESBValue('zp_nopoison_cookie').GetIntValue()

		if isPageIndex:
			# sign extend
			addr = c_uint64(c_int32(addr).value * self.pagesize).value

		self.address = addr

		if self.zone_meta_min <= addr and addr < self.zone_meta_max:
			self.kind = 'Metadata'
			addr -= (addr - self.zone_meta_min) % size_of('struct zone_page_metadata')
			self.meta_addr = addr
			self.meta = ESBValue.initWithAddressType(addr, 'struct zone_page_metadata *')

			self.page_addr = self.zone_map_min + ((addr - self.zone_meta_min) / size_of('struct zone_page_metadata') * self.pagesize)
			self.first_offset = 0
		elif self.zone_map_min <= addr and addr < self.zone_map_max:
			addr &= ~(self.pagesize - 1)
			page_idx = (addr - self.zone_map_min) // self.pagesize

			self.kind = 'Element'
			self.page_addr = addr
			self.meta_addr = self.zone_meta_min + page_idx * size_of('struct zone_page_metadata')
			self.meta = ESBValue.initWithAddressType(self.meta_addr, "struct zone_page_metadata *")
			self.first_offset = 0
		elif self._looksForeign(addr):
			self.kind = 'Element (F)'
			addr &= ~(self.pagesize - 1)
			self.page_addr = addr
			self.meta_addr = addr
			self.meta = ESBValue.initWithAddressType(addr, "struct zone_page_metadata *")
			self.first_offset = 32 # ZONE_FOREIGN_PAGE_FIRST_OFFSET in zalloc.c
		else:
			self.kind = 'Unknown'
			self.meta = None
			self.page_addr = 0
			self.meta_addr = 0
			self.first_offset = 0
	
	def __str__(self) -> str:
		return f'ZoneMetaOld(kind="{self.kind}", meta_addr="{self.meta_addr}", page_addr="{self.page_addr}")'
			
	def isSecondaryPage(self):
		return self.meta and self.meta.zm_secondary_page

	def getPageCount(self):
		return self.meta and self.meta.zm_page_count or 0

	def getAllocCount(self):
		return self.meta and self.meta.zm_alloc_count or 0

	def getReal(self):
		if self.isSecondaryPage():
			return ZoneMeta(self.meta.GetIntValue() - self.meta.zm_page_count.GetIntValue())

		return self

	def getFreeList(self):
		if not self.meta:
			return None
		zm_freelist_offs = self.meta.zm_freelist_offs.GetIntValue()
		if (self.meta != None) and (zm_freelist_offs != 0xffff):
			return ESBValue.initWithAddressType(self.page_addr + zm_freelist_offs, 'vm_offset_t *')
		return None
	
	def isInFreeList(self, element_addr):
		cur = self.getFreeList()
		if cur == None:
			return False
		
		while cur.GetIntValue():
			if cur.GetIntValue() == element_addr:
				return True
			
			cur = cur.Dereference()
			next_addr = cur.GetIntValue() ^ self.zp_nopoison_cookie
			cur = ESBValue.initWithAddressType(next_addr, 'vm_offset_t *')
		
		return False
	
	def isInAllocationList(self, element_addr):
		esize = self.zone_array[self.meta.zm_index.GetIntValue()].z_elem_size.GetIntValue()
		offs  = self.first_offset
		end   = self.pagesize
		if not self.meta.zm_percpu.GetIntValue():
			end *= self.meta.zm_page_count.GetIntValue()

		while offs + esize <= end:
			if (self.page_addr + offs) == element_addr:
				return True
			
			offs += esize
		
		return False

	def iterateFreeList(self):
		cur = self.getFreeList()
		if cur != None:
			while cur.GetIntValue():
				yield cur

				cur = cur.Dereference()
				next_addr = cur.GetIntValue() ^ self.zp_nopoison_cookie
				cur = ESBValue.initWithAddressType(next_addr, 'vm_offset_t *')

	def iterateElements(self):
		if self.meta is None:
			return

		esize = self.zone_array[self.meta.zm_index.GetIntValue()].z_elem_size.GetIntValue()
		offs  = self.first_offset
		end   = self.pagesize
		if not self.meta.zm_percpu.GetIntValue():
			end *= self.meta.zm_page_count.GetIntValue()

		while offs + esize <= end:
			yield self.page_addr + offs
			offs += esize

ZONE_ADDR_FOREIGN = 0
ZONE_ADDR_NATIVE  = 1

class ZoneMetaNew(object):
	"""
	Helper class that helpers walking metadata
	"""

	def __init__(self, zone_array, addr, isPageIndex = False):
		self.pagesize  = ESBValue('page_size').GetIntValue()
		self.zone_info = ESBValue('zone_info')
		self.zone_array = zone_array

		def load_range(var):
			return (var.min_address.GetIntValue(), var.max_address.GetIntValue())

		def in_range(x, r):
			return x >= r[0] and x <= r[1]

		self.meta_range = load_range(self.zone_info.zi_meta_range)
		self.native_range = load_range(self.zone_info.zi_map_range[ZONE_ADDR_NATIVE])
		self.foreign_range = load_range(self.zone_info.zi_map_range[ZONE_ADDR_FOREIGN])
		self.addr_base = min(self.foreign_range[0], self.native_range[0])

		if isPageIndex:
			# sign extend
			addr = c_uint64(c_int32(addr).value * self.pagesize).value

		self.address = addr

		if in_range(addr, self.meta_range):
			self.kind = 'Metadata'
			addr -= addr % size_of('struct zone_page_metadata')
			self.meta_addr = addr
			self.meta = ESBValue.initWithAddressType(addr, "struct zone_page_metadata *")

			self.page_addr = self.addr_base + ((addr - self.meta_range[0]) // size_of('struct zone_page_metadata') * self.pagesize)
		elif in_range(addr, self.native_range) or in_range(addr, self.foreign_range):
			addr &= ~(self.pagesize - 1)
			page_idx = (addr - self.addr_base) // self.pagesize

			self.kind = 'Element'
			self.page_addr = addr
			self.meta_addr = self.meta_range[0] + page_idx * size_of('struct zone_page_metadata')
			self.meta = ESBValue.initWithAddressType(self.meta_addr, "struct zone_page_metadata *")
		else:
			self.kind = 'Unknown'
			self.meta = None
			self.page_addr = 0
			self.meta_addr = 0

		if self.meta:
			self.zone = self.zone_array[self.meta.zm_index.GetIntValue()]
		else:
			self.zone = None
	
	def __str__(self) -> str:
		return f'ZoneMetaNew(kind="{self.kind}", meta_addr="{self.meta_addr}", page_addr="{self.page_addr}")'

	def isSecondaryPage(self):
		return self.meta and self.meta.zm_chunk_len.GetIntValue() >= 0xe

	def getPageCount(self):
		n = self.meta and self.meta.zm_chunk_len.GetIntValue() or 0
		if self.zone and self.zone.z_percpu.GetIntValue():
			n *= ESBValue('zpercpu_early_count').GetIntValue()
		return n

	def getAllocAvail(self):
		if not self.meta: return 0
		chunk_len = self.meta.zm_chunk_len.GetIntValue()
		return chunk_len * self.pagesize // self.zone.z_elem_size.GetIntValue()

	def getAllocCount(self):
		if not self.meta: return 0
		return self.meta.zm_alloc_size.GetIntValue() // self.zone.z_elem_size.GetIntValue()

	def getReal(self):
		if self.isSecondaryPage():
			return ZoneMeta(self.meta.GetIntValue() - size_of('struct zone_page_metadata') * self.meta.zm_page_index.GetIntValue())

		return self

	def getElementAddress(self, addr):
		meta  = self.getReal()
		esize = meta.zone.z_elem_size.GetIntValue()
		start = meta.page_addr

		if esize == 0:
			return None

		estart = addr - start
		return start + estart - (estart % esize)

	def getInlineBitmapChunkLength(self):
		if self.zone.z_percpu:
			return self.zone.z_chunk_pages.GetIntValue()
		return self.meta.zm_chunk_len.GetIntValue()

	def getBitmapSize(self):
		if not self.meta or self.zone.z_permanent.GetIntValue() or not self.meta.zm_chunk_len.GetIntValue():
			return 0
		if self.meta.zm_inline_bitmap:
			return -4 * self.getInlineBitmapChunkLength()
		return 8 << (self.meta.zm_bitmap.GetIntValue() & 0x7)

	def getBitmap(self):
		if not self.meta or self.zone.z_permanent.GetIntValue() or not self.meta.zm_chunk_len.GetIntValue():
			return 0
		if self.meta.zm_inline_bitmap:
			return self.meta.zm_bitmap.GetLoadAddress()
		bbase = self.zone_info.zi_bits_range.min_address.GetIntValue()
		index = self.meta.zm_bitmap.GetIntValue() & ~0x7
		return bbase + index

	def getFreeCountSlow(self):
		if not self.meta or self.zone.z_permanent.GetIntValue() or not self.meta.zm_chunk_len.GetIntValue():
			return self.getAllocAvail() - self.getAllocCount()

		n = 0
		if self.meta.zm_inline_bitmap.GetIntValue():
			for i in range(0, self.getInlineBitmapChunkLength()):
				m = ESBValue.initWithAddressType(self.meta_addr + i * 16, 'struct zone_page_metadata *');
				bits = m.zm_bitmap.GetIntValue()
				while bits:
					n += 1
					bits &= bits - 1
		else:
			bitmap = ESBValue.initWithAddressType(self.getBitmap(), 'uint64_t *')
			for i in range(0, 1 << (self.meta.zm_bitmap.GetIntValue() & 0x7)):
				bits = bitmap[i].GetIntValue()
				while bits:
					n += 1
					bits &= bits - 1
		return n

	def isElementFree(self, addr):
		meta = self.meta

		if not meta or self.zone.z_permanent.GetIntValue() or not meta.zm_chunk_len.GetIntValue():
			return True
		
		start = self.page_addr
		esize = self.zone.z_elem_size.GetIntValue()
		eidx  = (addr - start) // esize
		if meta.zm_inline_bitmap.GetIntValue():
			idx = (eidx // 32)
			bits = ESBValue.initWithAddressType(meta.GetIntValue() + idx, 'struct zone_page_metadata *').zm_bitmap.GetIntValue()
			return bits & (1 << (eidx % 32)) != 0
		else:
			bitmap = ESBValue.initWithAddressType(self.getBitmap(), 'uint64_t *')
			bits = bitmap[eidx // 64].GetIntValue()
			return (bits & (1 << (eidx % 64))) != 0
	
	def isInFreeList(self, addr):
		return self.isElementFree(addr)

	def iterateElements(self):
		if self.meta is None:
			return
		esize = self.zone.z_elem_size.GetIntValue()
		start = 0
		end   = self.pagesize * self.meta.zm_chunk_len.GetIntValue()
		end  -= end % esize

		for offs in range(start, end, esize):
			yield self.page_addr + offs

ZoneMeta = None
gkalloc_heap_names = []

class XNUZones:
	def __init__(self, target):
		global ZoneMeta
		global gkalloc_heap_names
		# get all zones symbols
		self.zone_list = []
		self.target = target
		self.kalloc_heap_names = []
		self.zone_access_cache = {}
		self.logged_zones = {}
		self.pointer_size = get_pointer_size()

		zone_array = ESBValue('zone_array')
		if not xnu_esbvalue_check(zone_array):
			return
		
		num_zones = ESBValue('num_zones')
		if not xnu_esbvalue_check(num_zones):
			return
		
		if len(gkalloc_heap_names) < 4:
			kalloc_heap_names = ESBValue('kalloc_heap_names')
			for i in range(4):
				kalloc_heap_name = kalloc_heap_names[i].CastTo('char *')
				gkalloc_heap_names.append(kalloc_heap_name.GetStrValue())

		for i in range(num_zones.GetIntValue()):
			self.zone_list.append(zone_array[i].GetLoadAddress())
			self.zone_access_cache[self.getZoneName(zone_array[i])] = i
		
		# parse boot-args to findout zlog
		boot_args = xnu_showbootargs()
		zlog_array = re.findall(r'(zlog|zlog(\d+))=([a-z0-9\.]+)', boot_args)
		if zlog_array:
			for zlog in zlog_array:
				self.logged_zones[zlog[2]] = self.zone_access_cache[zlog[2]]
				if zlog[0] == 'zlog':
					break
		
		if ESBValue('zp_nopoison_cookie').IsValid():
			ZoneMeta = ZoneMetaOld
		else:
			ZoneMeta = ZoneMetaNew

	def __len__(self):
		return len(self.zone_list)
	
	def __iter__(self):
		for zone_addr in self.zone_list:
			yield ESBValue.initWithAddressType(zone_addr, 'zone *')

	def __getitem__(self, idx):
		if idx >= len(self.zone_list):
			return None
		
		# cast to 'zone *'
		return ESBValue.initWithAddressType(self.zone_list[idx], 'zone *')
	
	@classmethod
	def getZoneName(cls, zone):
		z_name = zone.z_name.GetStrValue()
		heap_name_idx = zone.kalloc_heap.GetIntValue()
		if heap_name_idx < 4:
			return gkalloc_heap_names[heap_name_idx] + z_name
		return z_name

	def getallzones_name(self):
		zone_names = []
		for i in range(len(self)):
			zone_names.append(self.getZoneName(self[i]))
		
		return zone_names
	
	def getZoneByName(self, zone_name):
		if zone_name in self.zone_access_cache:
			return self[self.zone_access_cache[zone_name]]

		for i in range(len(self)):
			zone = self[i]
			if self.getZoneName(zone) == zone_name:
				return zone
		
		return None
	
	def getZoneIdxbyName(self, zone_name):
		if zone_name in self.zone_access_cache:
			return self.zone_access_cache[zone_name]

		for i in range(len(self)):
			if self.getZoneName(self[i]) == zone_name:
				return i

		return -1
	
	def getZonebyRegex(self, zone_name_regex):
		zone_idxs = []

		if self.zone_access_cache:
			for zone_name in self.zone_access_cache:
				if re.match(zone_name_regex, zone_name):
					zone_idxs.append(self.zone_access_cache[zone_name])

		else:
			for i in range(len(self)):
				z_name = self.getZoneName(self[i])
				if re.match(zone_name_regex, z_name):
					zone_idxs.append(i)

		return zone_idxs
	
	def findzone_by_names(self, name):
		zones = []

		if self.zone_access_cache:
			for zone_name in self.zone_access_cache:
				if zone_name == name:
					idx = self.zone_access_cache[zone_name]
					zones.append((idx, self[idx]))
		else:

			for i in range(len(self)):
				zone = self[i]
				z_name = self.getZoneName(zone)
				if z_name == name:
					zones.append((i, zone))
				
		return zones
	
	def is_zonelogging(self, zone_idx):
		return self[zone_idx].zlog_btlog.GetIntValue() != 0
	
	def show_zone_being_logged(self):

		if not self.logged_zones:
			return
		
		for logged_zone_name in self.logged_zones:
			logged_zone_idx = self.logged_zones[logged_zone_name]
			zone = self[logged_zone_idx]
			zlog_btlog = zone.zlog_btlog
			zone_name = self.getZoneName(zone)
			if zlog_btlog.GetIntValue() != 0:
				print(f'- zone_array[{logged_zone_idx}]: {zone_name} log at {zlog_btlog.GetValue()}')
	
	def getLoggedZoneIdxByName(self, zone_name):
		try:
			return self.logged_zones[zone_name]
		except KeyError:
			return -1
	
	def zone_find_stack_elem(self, zone_idx, target_element, action=0):
		""" Zone corruption debugging: search the zone log and print out the stack traces for all log entries that
			refer to the given zone element.
			Usage: zstack_findelem <btlog addr> <elem addr>

			When the kernel panics due to a corrupted zone element, get the
			element address and use this command.  This will show you the stack traces of all logged zalloc and
			zfree operations which tells you who touched the element in the recent past.  This also makes
			double-frees readily apparent.
		"""

		log_records = ESBValue('log_records')
		corruption_debug_flag = ESBValue('corruption_debug_flag')

		if not log_records.GetIntValue() or not corruption_debug_flag.GetBoolValue():
			print("[!] Zone logging with corruption detection not enabled. Add '-zc zlog=<zone name>' to boot-args.")
			return False
		
		zone = self[zone_idx]
		btlog_ptr = zone.zlog_btlog.CastTo('btlog_t *')
		
		btrecord_size = btlog_ptr.btrecord_size.GetIntValue()
		btrecords = btlog_ptr.btrecords.GetIntValue()
		depth = btlog_ptr.btrecord_btdepth.GetIntValue()

		prev_operation = -1
		scan_items = 0

		element_hash_queue = btlog_ptr.elem_linkage_un.element_hash_queue
		hashelem = element_hash_queue.tqh_first
		hashelem = hashelem.CastTo('btlog_element_t *')

		if (target_element >> 32) != 0:
			target_element = target_element ^ 0xFFFFFFFFFFFFFFFF
		else:
			target_element = target_element ^ 0xFFFFFFFF

		while hashelem.GetIntValue() != 0:
			if hashelem.elem.GetIntValue() == target_element:
				recindex = hashelem.recindex.GetIntValue()

				recoffset = recindex * btrecord_size
				record = ESBValue.initWithAddressType(btrecords + recoffset, 'btlog_record_t *')
				record_operation = record.operation.GetIntValue()

				if not action:
					out_str = ('-' * 8)
					if record_operation == 1:
						out_str += "OP: ALLOC. "
					else:
						out_str += "OP: FREE.  "

					out_str += "Stack Index {0: <d} {1: <s}\n".format(recindex, ('-' * 8))

					print(out_str)
					print(self.GetBtlogBacktrace(depth, record))
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
					print(self.GetBtlogBacktrace(depth, record))
					print(' \n')
				elif action == 2 and record_operation:
					# show free only
					out_str = ('-' * 8)
					out_str += "OP: ALLOC.  "
					out_str += "Stack Index {0: <d} {1: <s}\n".format(recindex, ('-' * 8))
					print(out_str)
					print(self.GetBtlogBacktrace(depth, record))
					print(' \n')
				
				prev_operation = record_operation
				scan_items = 0

			hashelem = hashelem.element_hash_link.tqe_next
			hashelem = hashelem.CastTo('btlog_element_t *')

			scan_items += 1
			if scan_items % 100 == 0:
				print("Scanning is ongoing. {0: <d} items scanned since last check." .format(scan_items))
	
	def GetBtlogBacktrace(self, depth, zstack_record):
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
		
		# zstack_record_bt = zstack_record.GetChildMemberWithName('bt')
		zstack_record_bt = zstack_record.bt
		pc_array = read_mem(zstack_record_bt.GetLoadAddress(), depth * self.pointer_size)

		while frame < depth:
			frame_pc = unpack('<Q', pc_array[frame*self.pointer_size : (frame + 1) * self.pointer_size])[0]
			if not frame_pc:
				break
			
			sb_addr = self.target.ResolveLoadAddress(frame_pc)
			if sb_addr:
				symbol_str = str(sb_addr)
			else:
				symbol_str = ''
			out_str += "{0: <#0X} <{1: <s}>\n".format(frame_pc, symbol_str)
			frame += 1

		return out_str
	
	def ZoneIteratePageQueue(self, page):
		cur_page_addr = page.packed_address.GetIntValue()
		while cur_page_addr:
			meta = ZoneMeta(self, cur_page_addr, isPageIndex=True)
			# print(meta)
			yield meta
			page = meta.meta.zm_page_next
			cur_page_addr = page.packed_address.GetIntValue()
	
	def IterateAllChunkAt(self, zone_idx):
		zone = self[zone_idx]

		if not zone.z_self.GetIntValue() or zone.permanent.GetIntValue():
			yield 'None', 0
		
		if ZoneMeta == ZoneMetaOld:
			iteration_list = [zone.pages_any_free_foreign, zone.pages_all_used_foreign,
					zone.pages_intermediate, zone.pages_all_used]
		else:
			iteration_list = [zone.z_pageq_full, zone.z_pageq_partial, zone.z_pageq_empty, zone.z_pageq_va]

		for head in iteration_list:
			for meta in self.ZoneIteratePageQueue(head):
				for elem in meta.iterateElements():
					status = 'Allocated'
					if meta.isInFreeList(elem):
						status = 'Freed'
					
					yield status, elem
			
	def GetChunkInfoAtZone(self, zone_idx, chunk_addr):
		for status, elem in self.IterateAllChunkAt(zone_idx):
			if status == 'None':
				break

			if elem == chunk_addr:
				return status
		
		return 'None'
	
	def GetChunkInfoWithRange(self, from_zone_idx, to_zone_idx, chunk_addr):
		assert (from_zone_idx >=0 and to_zone_idx < len(self)) and (from_zone_idx < to_zone_idx), \
						'from_zone_idx or to_zone_idx is out of bound'

		for i in range(from_zone_idx, to_zone_idx):
			zone = self[i]
			ret = self.GetChunkInfoAtZone(i, chunk_addr)
			if ret != 'None':
				info = {
					'zone_name':self.getZoneName(zone),
					'zone_idx': i,
					'status': ret 
				}
				return info
		
		return None
	
	def FindChunkInfo(self, chunk_addr):
		
		for i in range(len(self)):
			zone = self[i]
			ret = self.GetChunkInfoAtZone(i, chunk_addr)
			if ret != 'None':
				info = {
					'zone_name':self.getZoneName(zone),
					'zone_idx': i,
					'status': ret 
				}
				return info
		
		return None

	def InspectZone(self, zone_idx):
		zone = self[zone_idx]
		print('Zone: ', COLORS['YELLOW'], self.getZoneName(zone), COLORS['RESET'])
		print(COLORS['BOLD'], end='')
		print("{:>5s}  {:<20s} {:<10s}".format("#", "Element", "State"))
		print(COLORS['RESET'], end='')

		num = 0
		for status, elem in self.IterateAllChunkAt(zone_idx):
			if status == 'None':
				break

			color = COLORS["GREEN"]
			if status == 'Freed':
				color = COLORS["RED"]
			
			print(color, end='')
			print("{:5d}  0x{:<20X} {:10s}".format(num, elem, status))
			print(COLORS['RESET'], end='')
			num+=1