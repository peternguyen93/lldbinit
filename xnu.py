'''
Small script support xnu kernel debugging
Author : peternguyen
'''

import lldb
from utils import *
from xnu_structures import *

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

	assert kext_summary_header.entry_size == sizeof(OSKextLoadedKextSummary), 'Difference size of OSKextLoadedKextSummary'

	kexts_info = []
	for i in range(kext_summary_header.numSummaries):
		raw_data = read_mem(base_address + 0x10 + i * sizeof(OSKextLoadedKextSummary), sizeof(OSKextLoadedKextSummary))
		if len(raw_data) < sizeof(OSKextLoadedKextSummary):
			print('[!] Read OSKextLoadedKextSummary error.')
			return []

		kext_info = OSKextLoadedKextSummary.from_buffer_copy(raw_data)
		kexts_info.append(kext_info)

	return kexts_info

def xnu_get_kext_base_address(kext_name):
	kext_infos = xnu_get_all_kexts()
	if not kext_infos:
		return 0

	for kext_info in kext_infos:
		mod_kext_name = bytes(kext_info.name).strip(b'\x00').decode('utf-8')
		if kext_name in mod_kext_name:
			return kext_info.address

	return 0

def xnu_get_all_tasks():
	task_queue = target.FindGlobalVariables('tasks', 1).GetValueAtIndex(0)

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

	if xnu_write_task_kdp_pmap(target, task):
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
