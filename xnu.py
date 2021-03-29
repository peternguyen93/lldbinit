'''
Small script support xnu kernel debugging
Author : peternguyen
'''

import lldb
from utils import *

EMBEDDED_PANIC_MAGIC = 0x46554E4B
EMBEDDED_PANIC_STACKSHOT_SUCCEEDED_FLAG = 0x02

MACOS_PANIC_MAGIC = 0x44454544
MACOS_PANIC_STACKSHOT_SUCCEEDED_FLAG = 0x04

AURR_PANIC_MAGIC = 0x41555252
AURR_PANIC_VERSION = 1

## main functions ##

def xnu_get_all_kexts():
	g_load_kext_summaries = ESBValue('gLoadedKextSummaries')
	base_address = g_load_kext_summaries.GetIntValue()
	entry_size = g_load_kext_summaries.entry_size.GetIntValue()
	kext_summaries_ptr = base_address + size_of('OSKextLoadedKextSummaryHeader')

	kexts = []
	
	for i in range(g_load_kext_summaries.numSummaries.GetIntValue()):
		kext_summary_at = ESBValue.initWithAddressType(kext_summaries_ptr, 'OSKextLoadedKextSummary *')
		
		kext_name = kext_summary_at.name.GetSummary()
		kext_address = kext_summary_at.address.GetIntValue()
		kext_size = kext_summary_at.size.GetValue()
		kext_uuid_addr = kext_summary_at.uuid.GetLoadAddress()
		kext_uuid = GetUUIDSummary(read_mem(kext_uuid_addr, size_of('uuid_t')))

		kexts.append((kext_name, kext_uuid, kext_address, kext_size))
		kext_summaries_ptr += entry_size
	
	return kexts

def xnu_get_kext_base_address(kext_name):
	kext_infos = xnu_get_all_kexts()
	if not kext_infos:
		return 0

	for kext_info in kext_infos:
		mod_kext_name = bytes(kext_info[0]).strip(b'\x00').decode('utf-8')
		if kext_name in mod_kext_name:
			return kext_info.address[2]

	return 0

def xnu_get_kdp_pmap_addr(target):
	kdp_pmap_var = target.FindGlobalVariables('kdp_pmap', 1).GetValueAtIndex(0)
	return address_of(target, kdp_pmap_var)

def xnu_write_task_kdp_pmap(target, task):
	kdp_pmap = ESBValue('kdp_pmap')
	if not kdp_pmap.IsValid():
		print('[!] kdp_pmap not found')
		return False

	task = task.CastTo('task *')
	kdp_pmap_addr = kdp_pmap.GetLoadAddress()
	pmap = task.map.pmap

	if not write_mem(kdp_pmap_addr, pack('<Q', pmap.GetIntValue())):
		print(f'[!] Overwrite kdp_pmap with task->map->pmap failed.')
		return False

	return True

def xnu_reset_kdp_pmap(target):
	kdp_pmap = ESBValue('kdp_pmap')
	if not kdp_pmap.IsValid():
		print('[!] kdp_pmap not found')
		return False
	
	kdp_pmap_addr = kdp_pmap.GetLoadAddress()

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
	allproc = ESBValue('allproc')

	if not allproc.IsValid():
		print('[!] This command only support for XNU kernel debugging.')
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
		print('[!] This command only support for XNU kernel debugging.')
		return None

	allproc_ptr = allproc.lh_first

	while allproc_ptr.GetIntValue():
		proc_name = allproc_ptr.p_name.GetStrValue()
		p_pid = allproc_ptr.p_pid.GetIntValue()
		print(f'+ {p_pid} - {proc_name} - {allproc_ptr.GetValue()}')
		allproc_ptr = allproc_ptr.p_list.le_next

def xnu_showbootargs(target):
	pe_state = ESBValue('PE_state')
	boot_args = pe_state.bootArgs.CastTo('boot_args *')
	commandline = boot_args.CommandLine
	return read_str(commandline.GetLoadAddress(), 1024).decode('utf-8')

def xnu_panic_log(target):
	panic_info = ESBValue('panic_info')
	if not panic_info.IsValid():
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

	# panic_log_begin_offset = panic_info.GetChildMemberWithName('mph_panic_log_offset')
	# panic_log_begin_offset = int(panic_log_begin_offset.GetValue())
	# panic_log_len = panic_info.GetChildMemberWithName('mph_panic_log_len')
	# panic_log_len = int(panic_log_len.GetValue())
	# other_log_begin_offset = panic_info.GetChildMemberWithName('mph_other_log_offset')
	# other_log_begin_offset = int(other_log_begin_offset.GetValue())
	# other_log_len = panic_info.GetChildMemberWithName('mph_other_log_len')
	# other_log_len = int(other_log_len.GetValue())

	# debug_buf_ptr = findGlobalVariable('debug_buf_ptr')
	# if not debug_buf_ptr:
	# 	return b''
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

### XNU ZONES TRACKING ###

class XNUZones:
	def __init__(self, target):
		# get all zones symbols
		self.zone_list = []
		self.target = target

		zone_array = ESBValue('zone_array')
		if not zone_array.IsValid():
			return
		
		num_zones = ESBValue('num_zones')
		if not num_zones.IsValid():
			return

		for i in range(num_zones.GetIntValue()):
			self.zone_list.append(zone_array[i].GetLoadAddress())
		
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
		return ESBValue.initWithAddressType(self.zone_list[idx], 'zone *')
	
	def getZoneBTLog(self, zone):
		try:
			# zlog_btlog = zone.GetChildMemberWithName('zlog_btlog')
			# return zlog_btlog
			return zone.zlog_btlog
		except AttributeError:
			return ''

	def showallzones_name(self):
		zone_names = []
		for i in range(len(self)):
			# zone = self[i]
			# z_name = zone.GetChildMemberWithName('z_name')
			zone_names.append(self[i].z_name.GetSummary())
		
		return zone_names
	
	def findzone_by_name(self, name):
		for i in range(len(self)):
			zone = self[i]
			# z_name = zone.GetChildMemberWithName('z_name')
			z_name = zone.z_name
			if z_name == name:
				return zone
		
		return None
	
	def findzone_by_names(self, name):
		zones = []
		for i in range(len(self)):
			zone = self[i]
			# z_name = zone.GetChildMemberWithName('z_name')
			z_name = zone.z_name
			if z_name == name:
				zones.append((i, zone))
		return zones
	
	def is_zonelogging(self, zone_idx):
		zone = self[zone_idx]
		# zone_logging = zone.GetChildMemberWithName('zlog_btlog')
		# zone_logging = zone.zlog_btlog
		return zone.zlog_btlog.GetIntValue() != 0
	
	def show_zone_being_logged(self):
		for i in range(len(self)):
			zone = self[i]
			# zlog_btlog = zone.GetChildMemberWithName('zlog_btlog')
			zlog_btlog = zone.zlog_btlog
			zone_name = zone.z_name.GetSummary()
			if zlog_btlog.GetIntValue() != 0:
				print(f'- zone_array[{i}]: {zone_name} log at {zlog_btlog.GetValue()}')
	
	def find_logged_zone_by_name(self, name):
		for i in range(len(self)):
			zone = self[i]
			# zlog_btlog = zone.GetChildMemberWithName('zlog_btlog')
			zlog_btlog = zone.zlog_btlog
			zone_name = zone.z_name.GetSummary()

			if zone_name == name and zlog_btlog.GetIntValue():
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

		log_records = ESBValue('log_records')
		corruption_debug_flag = ESBValue('corruption_debug_flag')

		if not log_records.GetIntValue() or not corruption_debug_flag.GetBoolValue():
			print("[!] Zone logging with corruption detection not enabled. Add '-zc zlog=<zone name>' to boot-args.")
			return False
		
		zone = self[zone_idx]
		btlog_ptr = zone.zlog_btlog.CastTo('btlog_t *')
		
		target_element = elem

		btrecord_size = btlog_ptr.btrecord_size.GetIntValue()
		btrecords = btlog_ptr.btrecords.GetIntValue()
		depth = btlog_ptr.btrecord_btdepth.GetIntValue()

		prev_op = -1
		scan_items = 0

		element_hash_queue = btlog_ptr.elem_linkage_un.element_hash_queue
		hashelem = element_hash_queue.tqh_first
		hashelem = hashelem.CastTo('btlog_element_t *')

		if (target_element >> 32) != 0:
			target_element = target_element ^ 0xFFFFFFFFFFFFFFFF
		else:
			target_element = target_element ^ 0xFFFFFFFF

		while hashelem.GetIntValue() != 0:
			# s_elem = hashelem.GetChildMemberWithName('elem')
			# s_elem = int(s_elem.GetValue())
			if hashelem.elem.GetIntValue() == target_element:
				# recindex = hashelem.GetChildMemberWithName('recindex')
				# recindex = int(recindex.GetValue())
				recindex = hashelem.recindex.GetIntValue()

				recoffset = recindex * btrecord_size
				record = ESBValue.initWithAddressType(btrecords + recoffset, 'btlog_record_t *')
				record_operation = record.operation.GetIntValue()

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

			# element_hash_link = hashelem.GetChildMemberWithName('element_hash_link')
			# hashelem = element_hash_link.GetChildMemberWithName('tqe_next')
			# hashelem = cast_address_to(self.target, 'hashelem', int(hashelem.GetValue(), 16), 'btlog_element_t')
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