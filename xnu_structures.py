from ctypes import *

class OSKextLoadedKextSummaryHeader(Structure):
	_fields_  = [
		("version", c_uint32),
		("entry_size", c_uint32),
		("numSummaries", c_uint32),
		("reserved", c_uint32)
	]

class OSKextLoadedKextSummary(Structure):
	_fields_ = [
		("name", c_byte * 64),
		("uuid", c_byte * 16),
		("address", c_uint64),
		("size", c_uint64),
		("version", c_uint64),
		("loadTag", c_uint32),
		("flags", c_uint32),
		("reference_list", c_uint64)
	]