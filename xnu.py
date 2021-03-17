'''
Small script support xnu kernel debugging
Author : peternguyen
'''

import lldb
from utils import *
from xnu_structures import *

EMBEDDED_PANIC_MAGIC = 0x46554E4B
EMBEDDED_PANIC_STACKSHOT_SUCCEEDED_FLAG = 0x02

MACOS_PANIC_MAGIC = 0x44454544
MACOS_PANIC_STACKSHOT_SUCCEEDED_FLAG = 0x04

AURR_PANIC_MAGIC = 0x41555252
AURR_PANIC_VERSION = 1

## lldb cmd functions ##

def xnu_print_all_kexts():
	kext_infos = xnu_get_all_kexts()

	for kext_info in kext_infos:
		kext_name = bytes(kext_info.name).strip(b'\x00').decode('utf-8')
		uuid_str = GetUUIDSummary(bytes(kext_info.uuid))
		base_address = hex(kext_info.address)

		print(f'+ {kext_name}\t{uuid_str}\t\t{base_address}')

## main functions ##
def xnu_get_all_kexts():
	target = get_target()

	# get linked list of loaded kexts
	kext_summaries = target.FindGlobalVariables('gLoadedKextSummaries', 1).GetValueAtIndex(0)
	if not kext_summaries.IsValid():
		print('[!] This command only support for XNU kernel debugging.')
		return []

	base_address = int(kext_summaries.GetValue(), 16)

	raw_data = read_mem(base_address, sizeof(OSKextLoadedKextSummaryHeader))
	if len(raw_data) < sizeof(OSKextLoadedKextSummaryHeader):
		print('[!] Read OSKextLoadedKextSummaryHeader error.')
		return []

	kext_summary_header = OSKextLoadedKextSummaryHeader.from_buffer_copy(raw_data)

	entry_size = kext_summary_header.entry_size
	kextInfos = []
	for i in range(kext_summary_header.numSummaries):
		raw_data = read_mem(base_address + 0x10 + i * entry_size, entry_size)
		if len(raw_data) < entry_size:
			print('[!] Read OSKextLoadedKextSummary error.')
			return []

		kextinfo = OSKextLoadedKextSummary.from_buffer_copy(raw_data)
		kextInfos.append(kextinfo)

	return kextInfos

def xnu_get_kext_base_address(kext_name):
	kext_infos = xnu_get_all_kexts()
	if not kext_infos:
		return 0

	for kext_info in kext_infos:
		mod_kext_name = bytes(kext_info.name).strip(b'\x00').decode('utf-8')
		if kext_name in mod_kext_name:
			return kext_info.address

	return 0

def xnu_get_kdp_pmap_addr(target):
	kdp_pmap_var = target.FindGlobalVariables('kdp_pmap', 1).GetValueAtIndex(0)
	return address_of(target, kdp_pmap_var)

def xnu_write_task_kdp_pmap(target, task):
	kdp_pmap_addr = xnu_get_kdp_pmap_addr(target)
	if kdp_pmap_addr == 0xffffffffffffffff:
		print('[!] kdp_pmap not found')
		return False

	my_task = cast_address_to(target, 'my_task', task, 'task')
	if my_task == None:
		print(f'[!] Invalid task address {hex(task)}')
		return False

	# write target pmap address to kdp_pmap to resolve userspace address
	pmap = my_task.GetChildMemberWithName('map').GetChildMemberWithName('pmap').GetValue()
	pmap = int(pmap, 16)

	if not write_mem(kdp_pmap_addr, pack('<Q', pmap)):
		print(f'[!] Overwrite kdp_pmap with task->map->pmap failed.')
		return False

	return True

def xnu_reset_kdp_pmap(target):
	kdp_pmap_addr = xnu_get_kdp_pmap_addr(target)
	if kdp_pmap_addr == 0xffffffffffffffff:
		print('[!] kdp_pmap not found')
		return False

	if not write_mem(kdp_pmap_addr, pack('<Q', 0)):
		print(f'[!] Overwrite kdp_pmap with task->map->pmap failed.')
		return False

	return True


def xnu_read_user_address(target, task, address, size):
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

def xnu_write_user_address(target, task, address, value):
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

def xnu_search_process_by_name(search_proc_name):
	target = get_target()
	allproc = target.FindGlobalVariables('allproc', 1).GetValueAtIndex(0)

	if not allproc.IsValid():
		print('[!] This command only support for XNU kernel debugging.')
		return None

	allproc_ptr = allproc.GetChildMemberWithName('lh_first')
	error = lldb.SBError()

	match_proc = None
	while int(allproc_ptr.GetValue(), 16):
		proc_name = allproc_ptr.GetChildMemberWithName('p_name')
		cstr_proc_name = proc_name.GetData().GetString(error, 0)
		if cstr_proc_name == search_proc_name:
			match_proc = allproc_ptr 
			break

		allproc_ptr = allproc_ptr.GetChildMemberWithName('p_list').GetChildMemberWithName('le_next')

	return match_proc

def xnu_list_all_process():
	target = get_target()
	allproc = target.FindGlobalVariables('allproc', 1).GetValueAtIndex(0)

	if not allproc.IsValid():
		print('[!] This command only support for XNU kernel debugging.')
		return None

	allproc_ptr = allproc.GetChildMemberWithName('lh_first')
	error = lldb.SBError()

	while int(allproc_ptr.GetValue(), 16):
		proc_name = allproc_ptr.GetChildMemberWithName('p_name')
		cstr_proc_name = proc_name.GetData().GetString(error, 0)
		p_pid = allproc_ptr.GetChildMemberWithName('p_pid').GetValue()

		print(f'+ {p_pid} - {cstr_proc_name} - {allproc_ptr.GetValue()}')

		allproc_ptr = allproc_ptr.GetChildMemberWithName('p_list').GetChildMemberWithName('le_next')

def xnu_showbootargs(target):
	pe_state = findGlobalVariable('PE_state')
	if not pe_state:
		return ''

	boot_args = pe_state.GetChildMemberWithName('bootArgs')
	boot_args = cast_address_to(target, 'my_boot_args', int(boot_args.GetValue(), 16), 'boot_args')
	commandline = boot_args.GetChildMemberWithName('CommandLine')
	
	return read_str(commandline.load_addr, 1024).decode('utf-8')

def xnu_panic_log(target):
	panic_info = findGlobalVariable('panic_info')
	if not panic_info:
		return b''

	mph_magic = panic_info.GetChildMemberWithName('mph_magic')
	if not mph_magic.IsValid():
		print('[!] Unable to find mph_magic in panic_info')
		return b''
	
	mph_magic = int(mph_magic.GetValue())
	if mph_magic != MACOS_PANIC_MAGIC:
		print('[!] Currently support parse MACOS_PANIC')
		return b''
	
	panic_buf = int(panic_info.GetValue(), 16)

	panic_log_begin_offset = panic_info.GetChildMemberWithName('mph_panic_log_offset')
	panic_log_begin_offset = int(panic_log_begin_offset.GetValue())
	panic_log_len = panic_info.GetChildMemberWithName('mph_panic_log_len')
	panic_log_len = int(panic_log_len.GetValue())
	other_log_begin_offset = panic_info.GetChildMemberWithName('mph_other_log_offset')
	other_log_begin_offset = int(other_log_begin_offset.GetValue())
	other_log_len = panic_info.GetChildMemberWithName('mph_other_log_len')
	other_log_len = int(other_log_len.GetValue())

	debug_buf_ptr = findGlobalVariable('debug_buf_ptr')
	if not debug_buf_ptr:
		return b''

	cur_debug_buf_ptr_offset = int(debug_buf_ptr.GetValue(), 16) - panic_buf
	if other_log_begin_offset != 0 and (other_log_len == 0 or other_log_len < (cur_debug_buf_ptr_offset - other_log_begin_offset)):
		other_log_len = cur_debug_buf_ptr_offset - other_log_begin_offset
	
	# skip ProcessPanicStackshot

	out_str = b''
	out_str += read_mem(panic_buf + panic_log_begin_offset, panic_log_len)
	if other_log_begin_offset != 0:
		out_str += read_mem(panic_buf + other_log_begin_offset, other_log_len)
	
	return out_str

### XNU ZONES TRACKING ###

class XNUZones:
	def __init__(self, target):
		# get all zones symbols
		self.zone_list = []
		self.target = target

		zone_array = findGlobalVariable('zone_array')
		if not zone_array:
			return
		
		num_zones = findGlobalVariable('num_zones')
		if not num_zones:
			return

		for i in range(int(num_zones.GetValue())):
			self.zone_list.append(zone_array.GetChildAtIndex(i).load_addr)
		
		self.pointer_size = get_pointer_size()
	
	def __len__(self):
		return len(self.zone_list)
	
	def __iter__(self):
		for zone in self.zone_list:
			yield zone

	def __getitem__(self, idx):
		# return 0 if idx >= len(self.zone_list) else self.zone_list[idx]
		if idx >= len(self.zone_list):
			return None
		
		# cast to 'zone *'
		return cast_address_to(self.target, 'my_boot_args', self.zone_list[idx], 'zone')
	
	def getZoneName(self, zone):
		try:
			z_name = zone.GetChildMemberWithName('z_name')
			return z_name.GetSummary()
		except AttributeError:
			return ''
	
	def getZoneBTLog(self, zone):
		try:
			zlog_btlog = zone.GetChildMemberWithName('zlog_btlog')
			return zlog_btlog
		except AttributeError:
			return ''

	def showallzones_name(self):
		zone_names = []
		for i in range(len(self)):
			zone = self[i]
			z_name = zone.GetChildMemberWithName('z_name')
			zone_names.append(z_name.GetSummary())
		
		return zone_names
	
	def findzone_by_name(self, name):
		for i in range(len(self)):
			zone = self[i]
			z_name = zone.GetChildMemberWithName('z_name')
			if z_name == name:
				return zone
		
		return None
	
	def findzone_by_names(self, name):
		zones = []
		for i in range(len(self)):
			zone = self[i]
			z_name = zone.GetChildMemberWithName('z_name')
			if z_name == name:
				zones.append((i, zone))
		return zones
	
	def is_zonelogging(self, zone_idx):
		zone = self[zone_idx]
		zone_logging = zone.GetChildMemberWithName('zlog_btlog')
		return bool(int(zone_logging.GetValue(), 16) != 0)
	
	def show_zone_being_logged(self):
		for i in range(len(self)):
			zone = self[i]
			zlog_btlog = zone.GetChildMemberWithName('zlog_btlog')
			zone_name = self.getZoneName(zone)
			if int(zlog_btlog.GetValue(), 16) != 0:
				print(f'- zone_array[{i}]: {zone_name} log at {zlog_btlog}')
	
	def find_logged_zone_by_name(self, name):
		for i in range(len(self)):
			zone = self[i]
			zlog_btlog = zone.GetChildMemberWithName('zlog_btlog')
			zlog_btlog = int(zlog_btlog.GetValue(), 16)
			zone_name = self.getZoneName(zone)

			if zone_name == name and zlog_btlog:
				return zone
		
		return None
	
	def zone_find_stack_elem(self, zone_idx, elem):
		""" Zone corruption debugging: search the zone log and print out the stack traces for all log entries that
			refer to the given zone element.
			Usage: zstack_findelem <btlog addr> <elem addr>

			When the kernel panics due to a corrupted zone element, get the
			element address and use this command.  This will show you the stack traces of all logged zalloc and
			zfree operations which tells you who touched the element in the recent past.  This also makes
			double-frees readily apparent.
		"""

		log_records = findGlobalVariable('log_records')
		log_records = int(log_records.GetValue())
		corruption_debug_flag = findGlobalVariable('corruption_debug_flag')
		if corruption_debug_flag.GetValue() == 'true':
			corruption_debug_flag = 1
		else:
			corruption_debug_flag = 0 

		if not log_records or not corruption_debug_flag:
			print("[!] Zone logging with corruption detection not enabled. Add '-zc zlog=<zone name>' to boot-args.")
			return False
		
		btlog_ptr = cast_address_to(self.target, 'blog_ptr', int(self.getZoneBTLog(self[zone_idx]).GetValue(), 16), 'btlog_t')
		target_element = elem

		btrecord_size = btlog_ptr.GetChildMemberWithName('btrecord_size')
		btrecord_size = int(btrecord_size.GetValue())

		btrecords = btlog_ptr.GetChildMemberWithName('btrecords')
		btrecords = int(btrecords.GetValue())

		depth = btlog_ptr.GetChildMemberWithName('btrecord_btdepth')
		depth = int(depth.GetValue())

		prev_op = -1
		scan_items = 0

		elem_linkage_un = btlog_ptr.GetChildMemberWithName('elem_linkage_un')
		element_hash_queue = elem_linkage_un.GetChildMemberWithName('element_hash_queue')
		hashelem = element_hash_queue.GetChildMemberWithName('tqh_first')
		hashelem = cast_address_to(self.target, 'hashelem', int(hashelem.GetValue(), 16), 'btlog_element_t')

		if (target_element >> 32) != 0:
			target_element = target_element ^ 0xFFFFFFFFFFFFFFFF
		else:
			target_element = target_element ^ 0xFFFFFFFF

		while int(hashelem.GetValue(), 16) != 0:
			s_elem = hashelem.GetChildMemberWithName('elem')
			s_elem = int(s_elem.GetValue())

			if s_elem == target_element:
				recindex = hashelem.GetChildMemberWithName('recindex')
				recindex = int(recindex.GetValue())

				recoffset = recindex * btrecord_size
				record = cast_address_to(self.target, 'record', btrecords + recoffset, 'btlog_record_t')
				record_operation = int(record.GetChildMemberWithName('operation').GetValue())

				out_str = ('-' * 8)
				if record_operation == 1:
					out_str += "OP: ALLOC. "
				else:
					out_str += "OP: FREE.  "

				out_str += "Stack Index {0: <d} {1: <s}\n".format(recindex, ('-' * 8))

				print(out_str)
				print(self.GetBtlogBacktrace(depth, record))
				print(' \n')

				if int(record_operation) == prev_op:
					print("{0: <s} DOUBLE OP! {1: <s}".format(('*' * 8), ('*' * 8)))
					return True
				prev_op = record_operation
				scan_items = 0

			element_hash_link = hashelem.GetChildMemberWithName('element_hash_link')
			hashelem = element_hash_link.GetChildMemberWithName('tqe_next')
			hashelem = cast_address_to(self.target, 'hashelem', int(hashelem.GetValue(), 16), 'btlog_element_t')

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
		
		zstack_record_bt = zstack_record.GetChildMemberWithName('bt')
		pc_array = read_mem(zstack_record_bt.load_addr, depth * self.pointer_size)

		while frame < depth:
			frame_pc = unpack('<Q', pc_array[frame*8 : (frame + 1) * 8])[0]
			if not frame_pc:
				break
			
			sb_addr = self.target.ResolveLoadAddress(frame_pc)
			if sb_addr:
				symbol_str = str(sb_addr)
			else:
				symbol_str = ''
			out_str += "{0: <#0x} <{1: <s}>\n".format(frame_pc, symbol_str)
			frame += 1

		return out_str