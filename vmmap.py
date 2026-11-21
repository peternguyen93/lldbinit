'''
	lldbinit vmmap backends
	Author : peternguyen
'''
from typing import List, Optional, Type, Callable
from typing_extensions import Self
from dataclasses import dataclass
from subprocess import Popen, PIPE
from bisect_local import bisect_left
from utils import get_process, get_target
import lldb
import platform
import re

@dataclass
class MapInfo(object):
	map_type: str
	start: int
	end: int
	perm: str
	shm: str
	region: str

def is_api_backend() -> bool:
	'''
		return True when the debug session is not backed by a local userspace
		process - remote debugging (remote-ios / remote-macosx platform) or
		kernel debugging - where the vmmap binary cannot inspect the target
	'''
	if get_target().GetPlatform().GetName().startswith('remote'):
		return True

	process_info = get_process().GetProcessInfo()
	return not process_info.IsValid() or process_info.GetProcessID() == 1

def thread_stack_addrs() -> List[int]:
	'''
		collect the stack pointer of each thread to identify stack regions
	'''
	stack_addrs = []
	for thread in get_process():
		frame = thread.GetFrameAtIndex(0)
		if frame.IsValid():
			stack_addrs.append(frame.GetSP())

	return stack_addrs

def resolve_region_name(region: lldb.SBMemoryRegionInfo, stack_addrs: List[int]) -> str:
	'''
		resolve region name for remote/kernel sessions - debugserver does
		not send region names so fall back to the module/section backing
		the region (needs the matching binary as target), the region that
		holds a thread stack is named STACK
	'''
	name = region.GetName()
	if name:
		return name

	region_base = region.GetRegionBase()
	region_end = region.GetRegionEnd()
	for sp in stack_addrs:
		if region_base <= sp < region_end:
			return 'STACK'

	sbaddr = lldb.SBAddress(region_base, get_target())
	section = sbaddr.GetSection()
	if section and section.IsValid():
		module = sbaddr.GetModule()
		module_name = module.file.basename if module and module.IsValid() else ''
		if module_name:
			return f'{module_name}`{section.name}'

		return section.name

	return ''

def region_to_map_info(region: lldb.SBMemoryRegionInfo, stack_addrs: Optional[List[int]] = None) -> MapInfo:
	'''
		convert lldb.SBMemoryRegionInfo to MapInfo
	'''
	perm = ''.join(c for c, is_set in (
					('r', region.IsReadable()),
					('w', region.IsWritable()),
					('x', region.IsExecutable()),
				) if is_set)

	if stack_addrs is None:
		stack_addrs = thread_stack_addrs()

	return MapInfo(resolve_region_name(region, stack_addrs) or 'unknown',
					region.GetRegionBase(),
					region.GetRegionEnd(),
					perm, '', '')

class VMMapCacheBase(object):
	'''
		common vmmap interface, use VMMapCacheBase.get_cache() to get the
		backend matching the current debug session
	'''
	_instance: Optional['VMMapCacheBase'] = None

	def __init__(self: Self) -> None:
		self.caches: List[MapInfo] = [] # sorted MapInfo list by start address
		self.is_loaded = False

	@classmethod
	def instance(cls: Type['VMMapCacheBase']) -> 'VMMapCacheBase':
		''' return the singleton backend for each subclass '''
		if cls._instance is None:
			cls._instance = cls()

		return cls._instance

	@classmethod
	def get_cache(cls) -> 'VMMapCacheBase':
		''' dispatcher: pick the backend based on the current debug session '''
		if is_api_backend():
			return VMMapRegionCache.instance()

		return MacOSVMMapCache.instance()

	def query_vmmap(self: Self, address: int) -> Optional[MapInfo]:
		''' find the MapInfo containing the address '''
		raise NotImplementedError

	def get_map_infos(self: Self) -> List[MapInfo]:
		''' return all MapInfo of the current process '''
		raise NotImplementedError

	def get_map_infos_by(self: Self, filter_cb: Callable[[MapInfo], bool]) -> List[MapInfo]:
		result = []
		for map_info in self.get_map_infos():
			if filter_cb(map_info):
				result.append(map_info)

		return result

class MacOSVMMapCache(VMMapCacheBase):
	'''
		backend which parses the output from the vmmap binary,
		only works for local macOS userspace debugging
	'''
	def __init__(self: Self) -> None:
		super().__init__()
		if platform.system() != 'Darwin':
			print(f'[!] Command vmmap was not supported on {platform.system()}')

	def get_vmmap_info(self: Self) -> str:
		process = get_process()
		if not process:
			return ''

		process_info = process.GetProcessInfo()
		if not process_info.IsValid():
			return ''

		process_id = process_info.GetProcessID()
		if process_id == 1:
			return ''

		cmd = ['vmmap', str(process_id), "-interleaved"]
		proc = Popen(cmd, stdout = PIPE, stderr = PIPE)
		out, _ = proc.communicate()

		return out.decode('utf-8')

	def load_vmmap_info(self: Self):
		# force update all MapInfo in self.caches
		vmmap_info = self.get_vmmap_info()
		if not vmmap_info:
			return

		self.caches.clear()
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
			self.caches.append(o_map_info)

		# sort caches MapInfo by start address
		sorted(self.caches, key=lambda mapinfo: mapinfo.start)

	def cache_load(self: Self, force_reload: bool = False):
		if not len(self.caches):
			self.load_vmmap_info()

		if force_reload:
			self.load_vmmap_info()

	def query_vmmap(self: Self, address: int) -> Optional[MapInfo]:
		if not len(self.caches):
			self.cache_load()

		# search it in caches
		tmp_map_info = MapInfo(start=address, end=0, perm='', shm='', region='', map_type='')
		idx = bisect_left(self.caches, tmp_map_info, key=lambda o: o.start)

		if  0 <= idx < len(self.caches):
			# make sure index in current caches range
			# if not use vmmap command line to search and update into cache
			map_info = self.caches[idx]
			if map_info.start <= address < map_info.end:
				return self.caches[idx]

		# if a new vmmap record hasn't found in caches, try to parse it from vmmap
		process = get_process()
		process_info = process.GetProcessInfo()
		if not process_info.IsValid():
			return None

		process_id = process_info.GetProcessID()
		if process_id == 1:
			return None

		cmd = ['vmmap', str(process_id), hex(address)]
		proc = Popen(cmd, stdout = PIPE, stderr=PIPE)
		out, _ = proc.communicate()
		out = out.decode('utf-8')

		m = re.search(
			r'\-\-\->\s+([\x20-\x7F]+)\s+([0-9a-f]+)\-([0-9a-f]+)\s+\[[0-9KMG\.\s]+\]\s+([rwx\-/]+)\s+([A-Za-z=]+)\s+([\x20-\x7F]+)',
			out
		)
		if not m:
			return None

		# update new MapInfo into cache
		map_info = MapInfo(m[1], int(m[2], 16), int(m[3], 16), m[4], m[5], m[6])
		# idx return from bisect_left is the index to insert value to keep the order
		idx = bisect_left(self.caches, map_info, key=lambda o: o.start)
		if idx >= len(self.caches):
			self.caches.append(map_info)
		else:
			self.caches.insert(idx, map_info)

		return map_info

	def get_map_infos(self: Self) -> List[MapInfo]:
		self.cache_load()
		return self.caches

class VMMapRegionCache(VMMapCacheBase):
	'''
		backend which wraps the lldb SBMemoryRegionInfo API, works for
		kernel debugging and remote sessions where the vmmap binary
		cannot inspect the target process. no cache, every call talks
		to the debug session directly
	'''
	def query_vmmap(self: Self, address: int) -> Optional[MapInfo]:
		region = lldb.SBMemoryRegionInfo()
		get_process().GetMemoryRegionInfo(address, region)
		if not region.IsMapped():
			return None

		return region_to_map_info(region)

	def get_map_infos(self: Self) -> List[MapInfo]:
		regions = get_process().GetMemoryRegions()
		stack_addrs = thread_stack_addrs()
		map_infos = []
		region = lldb.SBMemoryRegionInfo()
		for i in range(regions.GetSize()):
			regions.GetMemoryRegionAtIndex(i, region)
			map_infos.append(region_to_map_info(region, stack_addrs))

		return map_infos
