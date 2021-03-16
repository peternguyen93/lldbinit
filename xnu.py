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
				print(f'- Zone: {zone_name} log at {zlog_btlog}')
	
	def find_logged_zone_by_name(self, name):
		for i in range(len(self)):
			zone = self[i]
			zlog_btlog = zone.GetChildMemberWithName('zlog_btlog')
			zlog_btlog = int(zlog_btlog.GetValue(), 16)
			zone_name = self.getZoneName(zone)

			if zone_name == name and zlog_btlog:
				return zone
		
		return None