'''
.____    .____     ________ __________.__ _______  ._____________
|    |   |    |    \______ \\______   \__|\      \ |__\__    ___/
|    |   |    |     |    |  \|    |  _/  |/   |   \|  | |    |   
|    |___|    |___  |    `   \    |   \  /    |    \  | |    |   
|_______ \_______ \/_______  /______  /__\____|__  /__| |____|   
		\/       \/        \/       \/           \/              LLDBINIT v2.0

A gdbinit clone for LLDB aka how to make LLDB a bit more useful and less crappy

(c) Deroko 2014, 2015, 2016
(c) fG! 2017-2019 - reverser@put.as - https://reverse.put.as
(c) Peternguyen 2020

Available at https://github.com/gdbinit/lldbinit

No original license by Deroko so I guess this is do whatever you want with this
as long you keep original credits and sources references.

Original lldbinit code by Deroko @ https://github.com/deroko/lldbinit
gdbinit available @ https://github.com/gdbinit/Gdbinit

Huge thanks to Deroko for his original effort!

To list all implemented commands use 'lldbinitcmds' command.

How to install it:
------------------

$ cp lldbinit.py ~
$ echo "command script import  ~/lldbinit.py" >>$HOME/.lldbinit

or

$ cp lldbinit.py /Library/Python/2.7/site-packages
$ echo "command script import lldbinit" >> $HOME/.lldbinit

or

just copy it somewhere and use "command script import path_to_script" when you want to load it.

BUGS:
-----

LLDB design:
------------
lldb -> debugger -> target -> process -> thread -> frame(s)
									  -> thread -> frame(s)
'''
from __future__ import print_function 

if __name__ == "__main__":
	print("Run only as script from LLDB... Not as standalone program!")

import sys
import re
import os
import time
import argparse
import subprocess
import tempfile

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from utils import *
from symbols import get_symbol_from_address, arm64_resolve_dispatch_function_name,\
					get_inst_size, get_mnemonic, get_operands, get_instruction_count, \
					read_instructions, get_module_name, load_custom_symbols, \
					custom_sym_backtrace, get_module_info_from_address, \
					get_current_pc_inst, get_indirect_address_from, get_indirect_flow_address, \
					get_indirect_flow_dest, CUSTOM_SYMBOLS, \
					get_active_symbols, set_active_symbols, RemoteSymbols, \
					get_symbols_generation
from xnu import *
from vmmap import *
import gui
from gui import *

try:
	from keystone import *
	CONFIG_KEYSTONE_AVAILABLE = 1
except ImportError:
	CONFIG_KEYSTONE_AVAILABLE = 0

VERSION = "3.0"

#
# User configurable options
#
CONFIG_DISPLAY_DISASSEMBLY_BYTES = 1
CONFIG_DISASSEMBLY_LINE_COUNT = 8
CONFIG_USE_CUSTOM_DISASSEMBLY_FORMAT = 1
CONFIG_DISPLAY_STACK_WINDOW = 0
CONFIG_DISPLAY_FLOW_WINDOW = 0
CONFIG_ENABLE_REGISTER_SHORTCUTS = 1
CONFIG_DISPLAY_DATA_WINDOW = 0

# setup the logging level, which is a bitmask of any of the following possible values (don't use spaces, doesn't seem to work)
#
# LOG_VERBOSE LOG_PROCESS LOG_THREAD LOG_EXCEPTIONS LOG_SHLIB LOG_MEMORY LOG_MEMORY_DATA_SHORT LOG_MEMORY_DATA_LONG LOG_MEMORY_PROTECTIONS LOG_BREAKPOINTS LOG_EVENTS LOG_WATCHPOINTS
# LOG_STEP LOG_TASK LOG_ALL LOG_DEFAULT LOG_NONE LOG_RNB_MINIMAL LOG_RNB_MEDIUM LOG_RNB_MAX LOG_RNB_COMM  LOG_RNB_REMOTE LOG_RNB_EVENTS LOG_RNB_PROC LOG_RNB_PACKETS LOG_RNB_ALL LOG_RNB_DEFAULT
# LOG_DARWIN_LOG LOG_RNB_NONE
#
# to see log (at least in macOS)
# $ log stream --process debugserver --style compact
# (or whatever style you like)
CONFIG_LOG_LEVEL = "LOG_NONE"

# removes the offsets and modifies the module name position
# reference: https://lldb.llvm.org/formats.html
CUSTOM_DISASSEMBLY_FORMAT = "\"{${function.initial-function}{${function.name-without-args}} @ {${module.file.basename}}:\n}{${function.changed}\n{${function.name-without-args}} @ {${module.file.basename}}:\n}{${current-pc-arrow} }${addr-file-or-load}: \""
# POINTER_SIZE = 8 # assume architecture is 64 bits

arm_type = "thumbv7-apple-ios"

Int3Dictionary: Dict[int, int] = {}

XNU_ZONES = XNUZones()
SelectedVM = ''

def is_in_Xcode() -> bool:
	path_env = os.getenv('PATH')
	if not path_env:
		# PATH didn't exists.
		return False

	return True if path_env.startswith('/Applications/Xcode') else False

def __lldb_init_module(debugger: SBDebugger, internal_dict: Dict):
	''' we can execute commands using debugger.HandleCommand which makes all output to default
	lldb console. With GetCommandinterpreter().HandleCommand() we can consume all output
	with SBCommandReturnObject and parse data before we send it to output (eg. modify it);
	'''

	# don't load if we are in Xcode since it is not compatible and will block Xcode
	if is_in_Xcode():
		return

	'''
	If I'm running from $HOME where .lldbinit is located, seems like lldb will load 
	.lldbinit 2 times, thus this dirty hack is here to prevent doulbe loading...
	if somebody knows better way, would be great to know :)
	''' 
	var: lldb.SBStringList = debugger.GetInternalVariableValue(\
								"stop-disassembly-count", debugger.GetInstanceName())
	if var.IsValid():
		var = var.GetStringAtIndex(0)
		if var == "0":
			return
	
	res = lldb.SBCommandReturnObject()
	ci: SBCommandInterpreter = debugger.GetCommandInterpreter()

	# settings
	ci.HandleCommand("settings set target.x86-disassembly-flavor intel", res)
	ci.HandleCommand("settings set prompt \"(lldbinit) \"", res)
	ci.HandleCommand("settings set stop-disassembly-count 0", res)
	# set the log level - must be done on startup?
	ci.HandleCommand("settings set target.process.extra-startup-command QSetLogging:bitmask=" + CONFIG_LOG_LEVEL + ";", res)
	if CONFIG_USE_CUSTOM_DISASSEMBLY_FORMAT == 1:
		ci.HandleCommand("settings set disassembly-format " + CUSTOM_DISASSEMBLY_FORMAT, res)

	# the hook that makes everything possible :-)
	ci.HandleCommand("command script add -f lldbinit.HandleHookStopOnTarget HandleHookStopOnTarget", res)
	ci.HandleCommand("command script add -f lldbinit.HandleHookStopOnTarget ctx", res)
	ci.HandleCommand("command script add -f lldbinit.HandleHookStopOnTarget context", res)
	# commands
	ci.HandleCommand("command script add -f lldbinit.cmd_lldbinitcmds lldbinitcmds", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_IphoneConnect iphone", res)
	#
	# dump memory commands
	#
	ci.HandleCommand("command script add -f lldbinit.cmd_db db", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_dw dw", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_dd dd", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_dq dq", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_DumpInstructions u", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_findmem findmem", res)
	#
	# ObjectiveC commands
	#
	ci.HandleCommand("command script add -f lldbinit.cmd_objc objc", res)
	#
	# Image commands
	#
	ci.HandleCommand("command script add -f lldbinit.cmd_xinfo xinfo", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_telescope tele", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_vmmap vmmap", res)
	#
	# Exploitation Helper commands
	#
	ci.HandleCommand("command script add -f lldbinit.cmd_pattern_create pattern_create", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_pattern_offset pattern_offset", res)
	#
	# Settings related commands
	#
	ci.HandleCommand("command script add -f lldbinit.cmd_enable enable", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_disable disable", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_contextcodesize contextcodesize", res)
	# a few settings aliases
	ci.HandleCommand("command alias enablesolib enable solib", res)
	ci.HandleCommand("command alias disablesolib disable solib", res)
	ci.HandleCommand("command alias enableaslr enable aslr", res)
	ci.HandleCommand("command alias disableaslr disable aslr", res)
	#
	# Breakpoint related commands
	#
	ci.HandleCommand("command script add -f lldbinit.cmd_m_bp mbp", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_to_ida_addr toida", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_bhb bhb", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_bht bht", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_bpt bpt", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_bpn bpn", res)
	# disable a breakpoint or all
	ci.HandleCommand("command script add -f lldbinit.cmd_bpd bpd", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_bpda bpda", res)
	# clear a breakpoint or all
	ci.HandleCommand("command script add -f lldbinit.cmd_bpc bpc", res)
	ci.HandleCommand("command alias bpca breakpoint delete", res)
	# enable a breakpoint or all
	ci.HandleCommand("command script add -f lldbinit.cmd_bpe bpe", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_bpea bpea", res)
	# commands to set temporary int3 patches and restore original bytes
	ci.HandleCommand("command script add -f lldbinit.cmd_int3 int3", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_rint3 rint3", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_listint3 listint3", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_nop nop", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_null null", res)
	# change eflags commands
	ci.HandleCommand("command script add -f lldbinit.cmd_cfa cfa", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_cfc cfc", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_cfd cfd", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_cfi cfi", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_cfo cfo", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_cfp cfp", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_cfs cfs", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_cft cft", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_cfz cfz", res)
	# skip/step current instruction commands
	ci.HandleCommand("command script add -f lldbinit.cmd_skip skip", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_stepo stepo", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_si si", res)
	# load breakpoints from file
	ci.HandleCommand("command script add -f lldbinit.cmd_LoadBreakPoints lb", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_LoadBreakPointsRva lbrva", res)
	
	# alias for existing breakpoint commands
	# list all breakpoints
	ci.HandleCommand("command alias bpl breakpoint list", res)
	# alias "bp" command that exists in gdbinit - lldb also has alias for "b"
	ci.HandleCommand("command alias bp _regexp-break", res)
	# to set breakpoint commands - I hate typing too much
	ci.HandleCommand("command alias bcmd breakpoint command add", res)
	# launch process and stop at entrypoint (not exactly as gdb command that just inserts breakpoint)
	# usually it will be inside dyld and not the target main()
	ci.HandleCommand("command alias break_entrypoint process launch --stop-at-entry", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_show_loadcmds show_loadcmds", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_show_header show_header", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_datawin datawin", res)
	
	if CONFIG_KEYSTONE_AVAILABLE == 1:
		ci.HandleCommand("command script add -f lldbinit.cmd_asm32 asm32", res)
		ci.HandleCommand("command script add -f lldbinit.cmd_asm64 asm64", res)
		ci.HandleCommand("command script add -f lldbinit.cmd_arm32 arm32", res)
		ci.HandleCommand("command script add -f lldbinit.cmd_arm64 arm64", res)
		ci.HandleCommand("command script add -f lldbinit.cmd_armthumb armthumb", res)

	# custom symbol commands
	# merge sym_load and sym_bt into sym <sub command> <args>
	ci.HandleCommand("command script add -f lldbinit.cmd_custom_sym sym", res)

	# aarch64 register display style
	ci.HandleCommand("command script add -f lldbinit.cmd_regstyle regstyle", res)

	# xnu kernel debug commands
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_showallkexts showallkexts", res)
	# ci.HandleCommand("command script add -f lldbinit.cmd_xnu_breakpoint kbp", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_to_offset ktooff", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_list_all_process showallproc", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_find_process_by_name showproc", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_read_usr_addr readuseraddr", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_set_kdp_pmap setkdp", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_reset_kdp_pmap resetkdp", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_kdp_reboot kdp-reboot", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_show_bootargs showbootargs", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_panic_log panic_log", res)

	# xnu zone commands
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_list_zone zone_list", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_zshow_logged_zone zone_show_logged_zone", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_zone_triage zone_triage", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_inspect_zone zone_inspect", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_show_chunk_at zone_show_chunk_at", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_show_chunk_with_regex zone_find_chunk_with_regex", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_find_chunk zone_find_chunk", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_zone_backtrace_at zone_backtrace_at", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_xnu_zone_reload zone_reload", res)

	# # xnu port commands
	# ci.HandleCommand("command script add -f lldbinit.cmd_xnu_show_ipc_task_port showtaskipc", res)
	# ci.HandleCommand("command script add -f lldbinit.cmd_xnu_show_ports showports", res)

	# xnu iokit commands
	ci.HandleCommand("command script add -f lldbinit.cmd_iokit_print iokit_print", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_iokit_type iokit_type", res)

	# xnu load kext
	ci.HandleCommand("command script add -f lldbinit.cmd_addkext addkext", res)

	ci.HandleCommand("command script add -f lldbinit.cmd_strip_pac strip_pac", res)

	# VMware/Virtualbox support
	ci.HandleCommand("command script add -f lldbinit.cmd_vm_take_snapshot vmsnapshot", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_vm_reverse_snapshot vmrevert", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_vm_delete_snapshot vmdelsnap", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_vm_list_snapshot vmshowsnap", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_vm_show_vm vmlist", res)
	ci.HandleCommand("command script add -f lldbinit.cmd_vm_select_vm vmselect", res)

	# add the hook - we don't need to wait for a target to be loaded
	ci.HandleCommand("target stop-hook add -o \"HandleHookStopOnTarget\"", res)
	ci.HandleCommand("command script add --function lldbinit.cmd_banner banner", res)
	debugger.HandleCommand("banner")
	return

def cmd_banner(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):    
	print(COLORS["RED"] + "[+] Loaded lldbinit version: " + VERSION + COLORS["RESET"])

def cmd_lldbinitcmds(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Display all available lldbinit commands.'''

	help_table = [
		[ "lldbinitcmds", "this command" ],
		[ "enable", "configure lldb and lldbinit options" ],
		[ "disable", "configure lldb and lldbinit options" ],
		[ "contextcodesize", "set number of instruction lines in code window" ],
		[ "b", "breakpoint address" ],
		[ "bpt", "set a temporary software breakpoint" ],
		[ "bhb", "set an hardware breakpoint" ],
		[ "bpc", "clear breakpoint" ],
		[ "bpca", "clear all breakpoints" ],
		[ "bpd", "disable breakpoint" ],
		[ "bpda", "disable all breakpoints" ],
		[ "bpe", "enable a breakpoint" ],
		[ "bpea", "enable all breakpoints" ],
		[ "bcmd", "alias to breakpoint command add"],
		[ "bpl", "list all breakpoints"],
		[ "bpn", "temporarly breakpoint next instruction" ],
		[ "break_entrypoint", "launch target and stop at entrypoint" ],
		[ "skip", "skip current instruction" ],
		[ "int3", "patch memory address with INT3" ],
		[ "rint3", "restore original byte at address patched with INT3" ],
		[ "listint3", "list all INT3 patched addresses" ],
		[ "nop", "patch memory address with NOP" ],
		[ "null", "patch memory address with NULL" ],
		[ "stepo", "step over calls and loop instructions" ],
		[ "lb", "load breakpoints from file and apply them (currently only func names are applied)" ],
		[ "lbrva", "load breakpoints from file and apply to main executable, only RVA in this case" ],
		[ "db/dw/dd/dq", "memory hex dump in different formats" ],
		[ "findmem", "search memory" ],
		[ "cfa/cfc/cfd/cfi/cfo/cfp/cfs/cft/cfz", "change CPU flags" ],
		[ "u", "dump instructions" ],
		[ "iphone", "connect to debugserver running on iPhone" ],
		[ "ctx/context", "show current instruction pointer CPU context" ],
		[ "show_loadcmds", "show otool output of Mach-O load commands" ],
		[ "show_header", "show otool output of Mach-O header" ],
		[ "enablesolib/disablesolib", "enable/disable the stop on library load events" ],
		[ "enableaslr/disableaslr", "enable/disable process ASLR" ],
		[ "datawin", "set start address to display on data window" ],
		[ "asm32/asm64", "x86/x64 assembler using keystone" ],
		[ "arm32/arm64/armthumb", "ARM assembler using keystone" ],
		[ 'tele', 'view memory page'],
		[ 'xinfo', 'find address belong to image'],
		[ 'pattern_create', 'create cyclic string'],
		[ 'pattern_offset', 'find offset in cyclic string'],
		
		[ 'addkext', 'add an existed kext into kernel debug session'],
		[ 'showallkexts', 'show all loaded kexts (only for xnu kernel debug)'],
		[ 'kbp', 'set breakpoint at offset for specific kext (only for xnu kernel debug)'],
		[ 'ktooff', 'convert current address to offset from basse address of kext (only for xnu kernel debug)'],
		[ 'showallproc', 'show all running process (only for xnu kernel debug)'],
		[ 'showproc', 'show specific process information of target process (only for xnu kernel debug)'],
		[ 'readuseraddr', 'read userspace address (only for xnu kernel debug with kdp-remote)'],
		[ 'setkdp', 'set kdp_pmap (only for xnu kernel debug with kdp-remote)'],
		[ 'resetkdp', 'reset kdp_pmap (only for xnu kernel debug with kdp-remote)'],
		[ 'showbootargs', 'show boot-args of macOS'],
		[ 'kdp-reboot', 'reboot the remote machine'],
		[ 'panic_log', 'show panic log'],
		[ 'zone_list', 'list xnu zones name'],
		[ 'zone_find_zones_index', 'list index of matching zone'],
		[ 'zone_show_logged_zone', 'show all logged zones enable by "-zlog=<zone_name>'],
		[ 'zone_triage', 'detect and print trace log for use after free/double free'],
		[ 'zone_inspect', 'list all chunk in specific zone with their status'],
		[ 'zone_show_chunk_at', 'find chunk address is freed or not'],
		[ 'zone_find_chunk', 'find location of chunk address'],
		[ 'zone_show_chunk_with_regex', 'find location of chunk address by using regex'],
		[ 'zone_backtrace_at', 'list callstack of chunk if btlog is enabled'],
		[ 'zone_reload', 'reload zone if network connection is failed'],
		[ 'showports', 'Show all ports of given process name'],
		[ 'iokit_print', 'Display readable iokit object of given address'],
		[ 'iokit_type', 'Get type of iokit object of given address'],

		['strip_pac', 'Strip PAC Pointer in ARM64e'],
		['regstyle', 'toggle the aarch64 register display style (classic/annotated)'],

		['vmsnapshot', 'take snapshot for running virtual machine'],
		['vmrevert', 'reverse snapshot for running virtual machine'],
		['vmdelsnap', 'delete snapshot of running virtual machine'],
		['vmshowsnap', 'show all snapshot of running virtual machine'],
		['vmlist', 'list running virtual machine'],
		['vmselect', 'select running virtual machine']
	]

	print("lldbinit available commands:")

	for row in help_table:
		print(" {: <20} - {: <30}".format(*row))

	print("\nUse \'cmdname help\' for extended command help.")

# -------------------------
# Settings related commands
# -------------------------

def cmd_enable(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Enable certain lldb and lldbinit options. Use \'enable help\' for more information.'''
	help = """
Enable certain lldb and lldbinit configuration options.

Syntax: enable <setting>

Available settings:
 color: enable color mode.
 solib: enable stop on library events trick.
 aslr: enable process aslr.
 stackwin: enable stack window in context display.
 datawin: enable data window in context display, configure address with datawin.
 flow: call targets and objective-c class/methods.
 frameformat: enable backtrace frame format to include file address.
 """

	global CONFIG_ENABLE_COLOR
	global CONFIG_DISPLAY_STACK_WINDOW
	global CONFIG_DISPLAY_FLOW_WINDOW
	global CONFIG_DISPLAY_DATA_WINDOW

	cmd = command.split()
	if len(cmd) == 0:
		print("[-] error: command requires arguments.")
		print("")
		print(help)
		return

	if cmd[0] == "color":
		gui.CONFIG_ENABLE_COLOR = 1
		print("[+] Enabled color mode.")
	elif cmd[0] == "solib":
		debugger.HandleCommand("settings set target.process.stop-on-sharedlibrary-events true")
		print("[+] Enabled stop on library events trick.")
	elif cmd[0] == "aslr":
		debugger.HandleCommand("settings set target.disable-aslr false")
		print("[+] Enabled ASLR.")
	elif cmd[0] == "stackwin":
		CONFIG_DISPLAY_STACK_WINDOW = 1
		print("[+] Enabled stack window in context display.")
	elif cmd[0] == "flow":
		CONFIG_DISPLAY_FLOW_WINDOW = 1
		print("[+] Enabled indirect control flow window in context display.")
	elif cmd[0] == "datawin":
		CONFIG_DISPLAY_DATA_WINDOW = 1
		print("[+] Enabled data window in context display. Configure address with \'datawin\' cmd.")
	elif cmd[0] == "frameformat":
		# upddate backtrace frame format to include file address
		debugger.HandleCommand("settings set frame-format \"frame #${frame.index}: {${ansi.fg.cyan}${frame.pc}${ansi.normal} (0x${ansi.fg.yellow}${script.frame:gui.frame_file_pc}${ansi.normal}) }{${module.file.basename}{\`}}{${function.name-with-args}{${frame.no-debug}${function.pc-offset}}}{ at ${ansi.fg.cyan}${line.file.basename}${ansi.normal}:${ansi.fg.yellow}${line.number}${ansi.normal}{:${ansi.fg.yellow}${line.column}${ansi.normal}}}${frame.kind}{${function.is-optimized} [opt]}{${function.is-inlined} [inlined]}{${frame.is-artificial} [artificial]}\n\"", res)
		print("[+] Enabled backtrace frame format to include file address.")
	
	elif cmd[0] == "help":
		print(help)
	else:
		print("[-] error: unrecognized command.")
		print(help)

	return

def cmd_disable(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Disable certain lldb and lldbinit options. Use \'disable help\' for more information.'''
	help = """
Disable certain lldb and lldbinit configuration options.

Syntax: disable <setting>

Available settings:
 color: disable color mode.
 solib: disable stop on library events trick.
 aslr: disable process aslr.
 stackwin: disable stack window in context display.
 datawin: enable data window in context display.
 flow: call targets and objective-c class/methods.
 """

	global CONFIG_ENABLE_COLOR
	global CONFIG_DISPLAY_STACK_WINDOW
	global CONFIG_DISPLAY_FLOW_WINDOW
	global CONFIG_DISPLAY_DATA_WINDOW

	cmd = command.split()
	if len(cmd) == 0:
		print("[-] error: command requires arguments.")
		print("")
		print(help)
		return

	if cmd[0] == "color":
		gui.CONFIG_ENABLE_COLOR = 0
		print("[+] Disabled color mode.")
	elif cmd[0] == "solib":
		debugger.HandleCommand("settings set target.process.stop-on-sharedlibrary-events false")
		print("[+] Disabled stop on library events trick.")
	elif cmd[0] == "aslr":
		debugger.HandleCommand("settings set target.disable-aslr true")
		print("[+] Disabled ASLR.")
	elif cmd[0] == "stackwin":
		CONFIG_DISPLAY_STACK_WINDOW = 0
		print("[+] Disabled stack window in context display.")
	elif cmd[0] == "flow":
		CONFIG_DISPLAY_FLOW_WINDOW = 0
		print("[+] Disabled indirect control flow window in context display.")
	elif cmd[0] == "datawin":
		CONFIG_DISPLAY_DATA_WINDOW = 0
		print("[+] Disabled data window in context display.")
	elif cmd[0] == "frameformat":
		debugger.HandleCommand("settings set frame-format \"frame #${frame.index}: {${ansi.fg.cyan}${frame.pc}${ansi.normal} }{${module.file.basename}{\`}}{${function.name-with-args}{${frame.no-debug}${function.pc-offset}}}{ at ${ansi.fg.cyan}${line.file.basename}${ansi.normal}:${ansi.fg.yellow}${line.number}${ansi.normal}{:${ansi.fg.yellow}${line.column}${ansi.normal}}}${frame.kind}{${function.is-optimized} [opt]}{${function.is-inlined} [inlined]}{${frame.is-artificial} [artificial]}\n\"", res)
		print("[+] Disabled backtrace frame format to include file address.")
	
	elif cmd[0] == "help":
		print(help)
	else:
		print("[-] error: unrecognized command.")
		print(help)

	return

def cmd_contextcodesize(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict): 
	'''Set the number of disassembly lines in code window.
		Use \'contextcodesize help\' for more information.'''
	
	help = """
Configures the number of disassembly lines displayed in code window.

Syntax: contextcodesize <line_count>

Note: expressions supported, do not use spaces between operators.
"""

	global CONFIG_DISASSEMBLY_LINE_COUNT

	cmd = command.split()
	if len(cmd) != 1:
		print("[-] error: please insert the number of disassembly lines to display.")
		print("")
		print(help)
		return
	if cmd[0] == "help":
		print(help)
		print("\nCurrent configuration value is: {:d}".format(CONFIG_DISASSEMBLY_LINE_COUNT))
		return
	
	value = evaluate(cmd[0])
	if value == None:
		print("[-] error: invalid input value.")
		print("")
		print(help)
		return

	CONFIG_DISASSEMBLY_LINE_COUNT = value

	return

def cmd_regstyle(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Switch the aarch64 register display style. Use \'regstyle help\' for more information.'''

	help = """
Switch the aarch64 register display between the classic grid and the
annotated grid (2 columns with pwndbg style region/symbol annotations).

Syntax: regstyle [old|new]

Without arguments it toggles between the two displays.
 a old: classic 4 column grid.
 a new: annotated 2 column grid, each pointer is annotated with its
        memory region or function (PAC stripped, [pac] tagged).
"""

	global CONFIG_REGISTER_PWN_STYLE

	cmd = command.split()
	if cmd and cmd[0] == "help":
		print(help)
		return

	if not cmd:
		gui.CONFIG_REGISTER_PWN_STYLE = 0 if gui.CONFIG_REGISTER_PWN_STYLE else 1
	elif cmd[0] in ("old", "classic"):
		gui.CONFIG_REGISTER_PWN_STYLE = 0
	elif cmd[0] in ("new", "pwn"):
		gui.CONFIG_REGISTER_PWN_STYLE = 1
	else:
		print("[-] error: unrecognized argument.")
		print("")
		print(help)
		return

	print("[+] Register display style: {0}".format(
		"annotated (pwn)" if gui.CONFIG_REGISTER_PWN_STYLE else "classic"))

	return

# ---------------------------
# Breakpoint related commands
# ---------------------------

# create breakpoint base on module name and offset
def cmd_m_bp(debugger: SBDebugger, command: str, result: SBCommandReturnObject, _dict: Dict):
	args = command.split(' ')
	if len(args) < 2:
		print('mbp <module_name> <ida default mapped address>')
		return

	module_name = args[0]
	ida_mapped_addr = evaluate(args[1])

	cur_target: SBTarget = debugger.GetSelectedTarget()
	target_module = find_module_by_name(cur_target, module_name)
	if not target_module:
		result.PutCString('Module {0} is not found'.format(module_name))
		return

	text_section = get_text_section(target_module)
	file_base_addr = text_section.file_addr # get default address of module in file
	offset = ida_mapped_addr - file_base_addr

	base_addr = text_section.GetLoadAddress(cur_target) # get ASLR address when module is loaded
	target_addr = base_addr + offset

	cur_target.BreakpointCreateByAddress(target_addr)

	result.PutCString('Done')

def cmd_to_ida_addr(debugger: SBDebugger, command: str, result: SBCommandReturnObject, _dict: Dict):
	args = command.split(' ')
	if len(args) < 2:
		print('toida <module_name> <ida default mapped address>')
		print('Convert lldb ASLR address of specific module to ida mapped address')
		return

	module_name = args[0]
	aslr_mapped_addr = evaluate(args[1])

	cur_target = debugger.GetSelectedTarget()
	target_module = find_module_by_name(cur_target, module_name)
	if not target_module:
		result.PutCString('Module {0} is not found'.format(module_name))
		return
	
	text_section = get_text_section(target_module)

	aslr_base_addr = text_section.GetLoadAddress(cur_target) # get ASLR address when module is loaded
	offset = aslr_mapped_addr - aslr_base_addr
	
	ida_base_addr = text_section.file_addr # get default address of module in file
	ida_mapped_addr = ida_base_addr + offset

	result.PutCString('[+] Ida mapped address of {0} : {1}'.format(module_name, hex(ida_mapped_addr)))

# temporary software breakpoint
def cmd_bpt(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Set a temporary software breakpoint. Use \'bpt help\' for more information.'''
	help = """
Set a temporary software breakpoint.

Syntax: bpt <address>

Note: expressions supported, do not use spaces between operators.
"""

	cmd = command.split()
	if len(cmd) != 1:
		print("[-] error: please insert a breakpoint address.")
		print("")
		print(help)
		return
	if cmd[0] == "help":
		print(help)
		return
	
	value = evaluate(cmd[0])
	if not value:
		print("[-] error: invalid input value.")
		print("")
		print(help)
		return
	
	target = get_target()
	breakpoint: lldb.SBBreakpoint = target.BreakpointCreateByAddress(value)
	breakpoint.SetOneShot(True)
	breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())

	print("[+] Set temporary breakpoint at 0x{:x}".format(value))
	
# hardware breakpoint
def cmd_bhb(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Set an hardware breakpoint'''
	help = """
Set an hardware breakpoint.

Syntax: bhb <address>

Note: expressions supported, do not use spaces between operators.
"""

	cmd = command.split()
	if len(cmd) != 1:
		print("[-] error: please insert a breakpoint address.")
		print("")
		print(help)
		return
	if cmd[0] == "help":
		print(help)
		return
	
	value = evaluate(cmd[0])
	if not value:
		print("[-] error: invalid input value.")
		print("")
		print(help)
		return

	# the python API doesn't seem to support hardware breakpoints
	# so we set it via command line interpreter
	res = lldb.SBCommandReturnObject()
	ci: SBCommandInterpreter = debugger.GetCommandInterpreter()
	ci.HandleCommand("breakpoint set -H -a " + hex(value), res)

	print("[+] Set hardware breakpoint at 0x{:x}".format(value))
	return

# temporary hardware breakpoint
def cmd_bht(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Set a temporary hardware breakpoint'''
	print("[-] error: lldb has no x86/x64 temporary hardware breakpoints implementation.")
	return

# clear breakpoint number
def cmd_bpc(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Clear a breakpoint. Use \'bpc help\' for more information.'''
	res = lldb.SBCommandReturnObject()
	ci: SBCommandInterpreter = debugger.GetCommandInterpreter()
	ci.HandleCommand(f"breakpoint delete {command}", res)
	print(res.GetOutput())

# disable breakpoint number
def cmd_bpd(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	res = lldb.SBCommandReturnObject()
	ci: SBCommandInterpreter = debugger.GetCommandInterpreter()
	ci.HandleCommand("breakpoint disable " + command, res)
	print(res.GetOutput())

# disable all breakpoints
def cmd_bpda(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Disable all breakpoints. Use \'bpda help\' for more information.'''
	help = """
Disable all breakpoints.

Syntax: bpda
"""
		
	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return

	target = get_target()

	if target.DisableAllBreakpoints() == False:
		print("[-] error: failed to disable all breakpoints.")

	print("[+] Disabled all breakpoints.")

# enable breakpoint number
def cmd_bpe(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	res = lldb.SBCommandReturnObject()
	ci: SBCommandInterpreter = debugger.GetCommandInterpreter()
	ci.HandleCommand("breakpoint enable " + command, res)
	print(res.GetOutput())

# enable all breakpoints
def cmd_bpea(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Enable all breakpoints. Use \'bpea help\' for more information.'''
	help = """
Enable all breakpoints.

Syntax: bpea
"""
		
	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return

	target = get_target()

	if target.EnableAllBreakpoints() == False:
		print("[-] error: failed to enable all breakpoints.")

	print("[+] Enabled all breakpoints.")

# Temporarily breakpoint next instruction - this is useful to skip loops (don't want to use stepo for this purpose)
def cmd_bpn(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Temporarily breakpoint instruction at next address. Use \'bpn help\' for more information.'''
	help = """
Temporarily breakpoint instruction at next address

Syntax: bpn

Note: control flow is not respected, it breakpoints next instruction in memory.
"""

	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return

	target = get_target()
	start_addr = get_current_pc()
	next_addr = start_addr + get_inst_size(start_addr)
	
	breakpoint: SBBreakpoint = target.BreakpointCreateByAddress(next_addr)
	breakpoint.SetOneShot(True)
	breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())

	print("[+] Set temporary breakpoint at 0x{:x}".format(next_addr))

# skip current instruction - just advances PC to next instruction but doesn't execute it
def cmd_skip(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Advance PC to instruction at next address. Use \'skip help\' for more information.'''
	help = """
Advance current instruction pointer to next instruction.

Syntax: skip

Note: control flow is not respected, it advances to next instruction in memory.
"""

	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return

	start_addr = get_current_pc()
	next_addr = start_addr + get_inst_size(start_addr)
	
	if is_x64():
		get_frame().reg["rip"].value = format(next_addr, '#x')
	elif is_i386():
		get_frame().reg["eip"].value = format(next_addr, '#x')
	# show the updated context
	debugger.HandleCommand("context")

# XXX: ARM breakpoint
def cmd_int3(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Patch byte at address to an INT3 (0xCC) instruction. Use \'int3 help\' for more information.'''
	help = """
Patch process memory with an INT3 byte at given address.

Syntax: int3 [<address>]

Note: useful in cases where the debugger breakpoints aren't respected but an INT3 will always trigger the debugger.
Note: ARM not yet supported.
Note: expressions supported, do not use spaces between operators.
"""

	global Int3Dictionary

	cmd = command.split()
	# if empty insert a int3 at current PC
	if len(cmd) == 0:
		int3_addr = get_current_pc()
		if int3_addr == 0:
			print("[-] error: invalid current address.")
			return
	elif len(cmd) == 1:
		if cmd[0] == "help":
			print(help)
			return
		
		int3_addr = evaluate(cmd[0])
		if not int3_addr:
			print("[-] error: invalid input address value.")
			print("")
			print(help)
			return
	else:
		print("[-] error: please insert a breakpoint address.")
		print("")
		print(help)
		return
	
	bytes_string = read_mem(int3_addr, 1)
	if not len(bytes_string):
		print("[-] error: Failed to read memory at 0x{:x}.".format(int3_addr))
		return

	bytes_read = bytearray(bytes_string)
	
	patch_byte = b'\xCC'
	if write_mem(int3_addr, patch_byte) == 0:
		print("[-] error: Failed to write memory at 0x{:x}.".format(int3_addr))
		return

	# save original bytes for later restore
	Int3Dictionary[int3_addr] = bytes_read[0]

	print("[+] Patched INT3 at 0x{:x}".format(int3_addr))

def cmd_rint3(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Restore byte at address from a previously patched INT3 (0xCC) instruction. Use \'rint3 help\' for more information.'''
	help = """
Restore the original byte at a previously patched address using \'int3\' command.

Syntax: rint3 [<address>]

Note: expressions supported, do not use spaces between operators.
"""

	global Int3Dictionary
	
	cmd = command.split()
	# if empty insert a int3 at current PC
	if len(cmd) == 0:
		int3_addr = get_current_pc()
		if int3_addr == 0:
			print("[-] error: invalid current address.")
			return
	elif len(cmd) == 1:
		if cmd[0] == "help":
			print(help)
			return
		int3_addr = evaluate(cmd[0])
		if not int3_addr:
			print("[-] error: invalid input address value.")
			print("")
			print(help)
			return        
	else:
		print("[-] error: please insert a INT3 patched address.")
		print("")
		print(help)
		return

	if len(Int3Dictionary) == 0:
		print("[-] error: No INT3 patched addresses to restore available.")
		return
	
	bytes_string = read_mem(int3_addr, 1)
	if not len(bytes_string):
		print("[-] error: Failed to read memory at 0x{:x}.".format(int3_addr))
		return
		
	bytes_read = bytearray(bytes_string)

	if bytes_read[0] == 0xCC:
		#print("Found byte patched byte at 0x{:x}".format(int3_addr))
		
		try:
			original_byte = Int3Dictionary[int3_addr]
		except:
			print("[-] error: Original byte for address 0x{:x} not found.".format(int3_addr))
			return

		if write_mem(int3_addr, bytearray([original_byte])) == 0:
			print("[-] error: Failed to write memory at 0x{:x}.".format(int3_addr))
			return
		# remove element from original bytes list
		del Int3Dictionary[int3_addr]
	else:
		print("[-] error: No INT3 patch found at 0x{:x}.".format(int3_addr))


def cmd_listint3(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''List all patched INT3 (0xCC) instructions. Use \'listint3 help\' for more information.'''
	help = """
List all addresses patched with \'int3\' command.

Syntax: listint3
"""

	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return

	if len(Int3Dictionary) == 0:
		print("[-] No INT3 patched addresses available.")
		return

	print("Current INT3 patched addresses:")
	for address in Int3Dictionary:
		print("[*] {:s}".format(hex(address)))

# XXX: ARM NOPs
def cmd_nop(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''NOP byte(s) at address. Use \'nop help\' for more information.'''
	help = """
Patch process memory with NOP (0x90) byte(s) at given address.

Syntax: nop <address> [<size>]

Note: default size is one byte if size not specified.
Note: ARM not yet supported.
Note: expressions supported, do not use spaces between operators.
"""

	cmd = command.split()
	if len(cmd) == 1:
		if cmd[0] == "help":
			print(help)
			return
		
		nop_addr = evaluate(cmd[0])
		patch_size = 1
		if not nop_addr:
			print("[-] error: invalid address value.")
			print("")
			print(help)
			return
	elif len(cmd) == 2:
		nop_addr = evaluate(cmd[0])
		if not nop_addr:
			print("[-] error: invalid address value.")
			print("")
			print(help)
			return
		
		patch_size = evaluate(cmd[1])
		if not patch_size:
			print("[-] error: invalid size value.")
			print("")
			print(help)
			return
	else:
		print("[-] error: please insert a breakpoint address.")
		print("")
		print(help)
		return

	current_patch_addr = nop_addr
	patch_byte = b'\x90'
	# can we do better here? WriteMemory takes an input string... weird
	for _ in range(patch_size):
		if write_mem(current_patch_addr, patch_byte) == 0:
			print("[-] error: Failed to write memory at 0x{:x}.".format(current_patch_addr))
			return
			
		current_patch_addr += 1

def cmd_null(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Patch byte(s) at address to NULL (0x00). Use \'null help\' for more information.'''
	help = """
Patch process memory with NULL (0x00) byte(s) at given address.

Syntax: null <address> [<size>]

Note: default size is one byte if size not specified.
Note: expressions supported, do not use spaces between operators.
"""
	cmd = command.split()
	if len(cmd) == 1:
		if cmd[0] == "help":
			print(help)
			return        
		null_addr = evaluate(cmd[0])
		patch_size = 1
		if null_addr == None:
			print("[-] error: invalid address value.")
			print("")
			print(help)
			return
	elif len(cmd) == 2:
		null_addr = evaluate(cmd[0])
		if null_addr == None:
			print("[-] error: invalid address value.")
			print("")
			print(help)
			return
		patch_size = evaluate(cmd[1])
		if patch_size == None:
			print("[-] error: invalid size value.")
			print("")
			print(help)
			return
	else:
		print("[-] error: please insert a breakpoint address.")
		print("")
		print(help)
		return

	current_patch_addr = null_addr
	# format for WriteMemory()
	# can we do better here? WriteMemory takes an input string... weird
	for _ in range(patch_size):
		if write_mem(current_patch_addr, b'\x00') == 0:
			print("[-] error: Failed to write memory at 0x{:x}.".format(current_patch_addr))
			return

		current_patch_addr += 1

'''
	Implements stepover instruction.    
'''
def cmd_stepo(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Step over calls and some other instructions so we don't need to step into them. Use \'stepo help\' for more information.'''
	help = """
Step over calls and loops that we want executed but not step into.
Affected instructions: call, movs, stos, cmps, loop.

Syntax: stepo
"""

	cmd = command.split()
	if len(cmd) != 0 and cmd[0] == "help":
		print(help)
		return

	global arm_type
	debugger.SetAsync(True)			
	target = get_target()
		
	if is_arm():
		cpsr = get_gp_register("cpsr")
		t = (cpsr >> 5) & 1
		if t:
			#it's thumb
			arm_type = "thumbv7-apple-ios"
		else:
			arm_type = "armv7-apple-ios"

	# compute the next address where to breakpoint
	pc_addr = get_current_pc()
	if pc_addr == 0:
		print("[-] error: invalid current address.")
		return

	next_addr = pc_addr + get_inst_size(pc_addr)
	# much easier to use the mnemonic output instead of disassembling via cmd line and parse
	mnemonic = get_mnemonic(pc_addr)

	if is_arm():
		if "blx" == mnemonic or "bl" == mnemonic:
			breakpoint: SBBreakpoint = target.BreakpointCreateByAddress(next_addr)
			breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())
			breakpoint.SetOneShot(True)
			breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())
			target.GetProcess().Continue()
			return
		else:
			selected_thread: SBThread = get_process().selected_thread
			selected_thread.StepInstruction(False)
			return
	# XXX: make the other instructions besides call user configurable?
	# calls can be call, callq, so use wider matching for those
	if mnemonic == "call" or mnemonic == "callq" or "movs" == mnemonic or "stos" == mnemonic or "loop" == mnemonic or "cmps" == mnemonic:
		breakpoint: SBBreakpoint = target.BreakpointCreateByAddress(next_addr)
		breakpoint.SetOneShot(True)
		breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())
		target.GetProcess().Continue()
	
	else:
		selected_thread: SBThread = get_process().selected_thread
		selected_thread.StepInstruction(False)

# XXX: help
def cmd_LoadBreakPointsRva(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	global  GlobalOutputList
	GlobalOutputList = []
	'''
	frame = get_frame();
		target = lldb.debugger.GetSelectedTarget();

		nummods = target.GetNumModules();
		#for x in range (0, nummods):
		#       mod = target.GetModuleAtIndex(x);
		#       #print(dir(mod));
		#       print(target.GetModuleAtIndex(x));              
		#       for sec in mod.section_iter():
		#               addr = sec.GetLoadAddress(target);
		#               name = sec.GetName();
		#               print(hex(addr));

		#1st module is executable
		mod = target.GetModuleAtIndex(0);
		sec = mod.GetSectionAtIndex(0);
		loadaddr = sec.GetLoadAddress(target);
		if loadaddr == lldb.LLDB_INVALID_ADDRESS:
				sec = mod.GetSectionAtIndex(1);
				loadaddr = sec.GetLoadAddress(target);
		print(hex(loadaddr));
	'''

	target = get_target()
	mod: SBModule = target.GetModuleAtIndex(0)
	sec: SBSection = mod.GetSectionAtIndex(0)
	loadaddr = sec.GetLoadAddress(target)
	if loadaddr == lldb.LLDB_INVALID_ADDRESS:
		sec = mod.GetSectionAtIndex(1)
		loadaddr = sec.GetLoadAddress(target)
	try:
		f = open(command, "r")
	except:
		output("[-] Failed to load file : " + command)
		result.PutCString("".join(GlobalListOutput))
		return
	while True:
		line = f.readline()
		if not line: 
			break
		line = line.rstrip()
		if not line: 
			break
		debugger.HandleCommand("breakpoint set -a " + hex(loadaddr + int(line, 16)))
	f.close()

# XXX: help
def cmd_LoadBreakPoints(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	global GlobalOutputList
	GlobalOutputList = []

	try:
		f = open(command, "r")
	except:
		output("[-] Failed to load file : " + command)
		result.PutCString("".join(GlobalListOutput))
		return
	while True:
		line = f.readline()
		if not line:
			break
		line = line.rstrip()
		if not line:
			break
		debugger.HandleCommand("breakpoint set --name " + line)
	f.close()

# -----------------------
# Memory related commands
# -----------------------

'''
	Output nice memory hexdumps...
'''
# display byte values and ASCII characters
def cmd_db(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Display hex dump in byte values and ASCII characters. Use \'db help\' for more information.'''
	help = """
Display memory hex dump in byte length and ASCII representation.

Syntax: db [<address>]

Note: if no address specified it will dump current instruction pointer address.
Note: expressions supported, do not use spaces between operators.
"""

	global GlobalListOutput
	GlobalListOutput.clear()

	'''
		Parse argument of db, for example, argument pass into command is
		"struct->x + struct->length" result will be : "struct->x + struct->length"
	'''	
	
	if not len(command):
		dump_addr = get_current_pc()
		if not dump_addr:
			print("[-] error: invalid current address.")
			return
	else:
		if command == "help":
			print(help)
			return
		dump_addr = evaluate(command)
		if not dump_addr:
			print("[-] error: invalid input address value.")
			print("")
			print(help)
			return

	membuff = read_mem(dump_addr, 0x100) # avoid overhead when trying to read unreadable address
	if not len(membuff):
		print('[-] error: Your {0} address is not readable'.format(hex(dump_addr)))
		return
	membuff = membuff.ljust(0x100, b'\x00')

	color("BLUE")
	if POINTER_SIZE == 4:
		output("[0x0000:0x%.08X]" % dump_addr)
		output("------------------------------------------------------")
	else:
		output("[0x0000:0x%.016lX]" % dump_addr)
		output("------------------------------------------------------")
	color("BOLD")
	output("[data]")
	color("RESET")
	output("\n")
	#output(hexdump(dump_addr, membuff, " ", 16));
	index = 0
	while index < 0x100:
		data = unpack(b"B"*16, membuff[index:index+0x10])
		if POINTER_SIZE == 4:
			szaddr = "0x%.08X" % dump_addr
		else:
			szaddr = "0x%.016lX" % dump_addr
		fmtnice = "%.02X %.02X %.02X %.02X %.02X %.02X %.02X %.02X"
		fmtnice = fmtnice + " - " + fmtnice
		output("\033[1m%s :\033[0m %.02X %.02X %.02X %.02X %.02X %.02X %.02X %.02X - %.02X %.02X %.02X %.02X %.02X %.02X %.02X %.02X \033[1m%s\033[0m" % 
			(szaddr, 
			data[0], 
			data[1], 
			data[2], 
			data[3], 
			data[4], 
			data[5], 
			data[6], 
			data[7], 
			data[8], 
			data[9], 
			data[10], 
			data[11], 
			data[12], 
			data[13], 
			data[14], 
			data[15], 
			quotechars(membuff[index:index+0x10])));
		if index + 0x10 != 0x100:
			output("\n")
		index += 0x10
		dump_addr += 0x10
	color("RESET")
	#last element of the list has all data output...
	#so we remove last \n
	result.PutCString("".join(GlobalListOutput))
	result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# display word values and ASCII characters
def cmd_dw(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	''' Display hex dump in word values and ASCII characters. Use \'dw help\' for more information.'''
	help = """
Display memory hex dump in word length and ASCII representation.

Syntax: dw [<address>]

Note: if no address specified it will dump current instruction pointer address.
Note: expressions supported, do not use spaces between operators.
"""

	global GlobalListOutput
	GlobalListOutput.clear()

	'''
		Parse argument of db, for example, argument pass into command is
		"struct->x + struct->length" result will be : "struct->x + struct->length"
	'''	

	if not len(command):
		dump_addr = get_current_pc()
		if not dump_addr:
			print("[-] error: invalid current address.")
			return
	else:
		if command == "help":
			print(help)
			return
		dump_addr = evaluate(command)
		if not dump_addr:
			print("[-] error: invalid input address value.")
			print("")
			print(help)
			return

	membuff = read_mem(dump_addr, 0x100) # avoid overhead when trying to read unreadable address
	if not len(membuff): # confuse with membuff contains all NULL byte and length of membuff
		print('[-] error: Your {0} address is not readable'.format(hex(dump_addr)))
		return
	membuff = membuff.ljust(0x100, b'\x00')

	color("BLUE")
	if POINTER_SIZE == 4: #is_i386() or is_arm():
		output("[0x0000:0x%.08X]" % dump_addr)
		output("--------------------------------------------")
	else: #is_x64():
		output("[0x0000:0x%.016lX]" % dump_addr)
		output("--------------------------------------------")
	color("BOLD")
	output("[data]")
	color("RESET")
	output("\n")
	index = 0
	while index < 0x100:
		data = unpack("HHHHHHHH", membuff[index:index+0x10])
		if POINTER_SIZE == 4:
			szaddr = "0x%.08X" % dump_addr
		else:
			szaddr = "0x%.016lX" % dump_addr
		output("\033[1m%s :\033[0m %.04X %.04X %.04X %.04X %.04X %.04X %.04X %.04X \033[1m%s\033[0m" % (szaddr, 
			data[0],
			data[1],
			data[2],
			data[3],
			data[4],
			data[5],
			data[6],
			data[7],
			quotechars(membuff[index:index+0x10])));
		if index + 0x10 != 0x100:
			output("\n")
		index += 0x10
		dump_addr += 0x10
	color("RESET")
	result.PutCString("".join(GlobalListOutput))
	result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# display dword values and ASCII characters
def cmd_dd(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	''' Display hex dump in double word values and ASCII characters. Use \'dd help\' for more information.'''
	help = """
Display memory hex dump in double word length and ASCII representation.

Syntax: dd [<address>]

Note: if no address specified it will dump current instruction pointer address.
Note: expressions supported, do not use spaces between operators.
"""

	global GlobalListOutput
	GlobalListOutput.clear()

	'''
		Parse argument of db, for example, argument pass into command is
		"struct->x + struct->length" result will be : "struct->x + struct->length"
	'''	

	if not len(command):
		dump_addr = get_current_pc()
		if not dump_addr:
			print("[-] error: invalid current address.")
			return
	else:
		if command == "help":
			print(help)
			return
		dump_addr = evaluate(command)
		if not dump_addr:
			print("[-] error: invalid input address value.")
			print("")
			print(help)
			return

	membuff = read_mem(dump_addr, 0x100) # avoid overhead when trying to read unreadable address
	if not len(membuff):
		print('[-] error: Your {0} address is not readable'.format(hex(dump_addr)))
		return
	membuff = membuff.ljust(0x100, b'\x00')

	color("BLUE")
	if POINTER_SIZE == 4:
		output("[0x0000:0x%.08X]" % dump_addr)
		output("----------------------------------------")
	else: #is_x64():
		output("[0x0000:0x%.016lX]" % dump_addr)
		output("----------------------------------------")
	color("BOLD")
	output("[data]")
	color("RESET")
	output("\n")
	index = 0
	while index < 0x100:
		(mem0, mem1, mem2, mem3) = unpack("IIII", membuff[index:index+0x10])
		if POINTER_SIZE == 4:
			szaddr = "0x%.08X" % dump_addr
		else:
			szaddr = "0x%.016lX" % dump_addr
		output("\033[1m%s :\033[0m %.08X %.08X %.08X %.08X \033[1m%s\033[0m" % (szaddr, 
											mem0, 
											mem1, 
											mem2, 
											mem3, 
											quotechars(membuff[index:index+0x10])));
		if index + 0x10 != 0x100:
			output("\n")
		index += 0x10
		dump_addr += 0x10
	color("RESET")
	result.PutCString("".join(GlobalListOutput))
	result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# display quad values
def cmd_dq(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	''' Display hex dump in quad values. Use \'dq help\' for more information.'''
	help = """
Display memory hex dump in quad word length.

Syntax: dq [<address>]

Note: if no address specified it will dump current instruction pointer address.
Note: expressions supported, do not use spaces between operators.
"""

	global GlobalListOutput
	GlobalListOutput.clear()

	'''
		Parse argument of db, for example, argument pass into command is
		"struct->x + struct->length" result will be : "struct->x + struct->length"
	'''	

	if not len(command):
		dump_addr = get_current_pc()
		if not dump_addr:
			print("[-] error: invalid current address.")
			return
	else:
		if command == "help":
			print(help)
			return
		dump_addr = evaluate(command)
		if not dump_addr:
			print("[-] error: invalid input address value.")
			print("")
			print(help)
			return

	membuff = read_mem(dump_addr, 0x100) # avoid overhead when trying to read unreadable address
	if not len(membuff):
		print('[-] error: Your {0} address is not readable'.format(hex(dump_addr)))
		return

	membuff = membuff.ljust(0x100, b'\x00')

	color("BLUE")
	if POINTER_SIZE == 4:
		output("[0x0000:0x%.08X]" % dump_addr)
		output("-------------------------------------------------------")
	else:
		output("[0x0000:0x%.016lX]" % dump_addr)
		output("-------------------------------------------------------")
	color("BOLD")
	output("[data]")
	color("RESET")
	output("\n")   
	index = 0
	while index < 0x100:
		(mem0, mem1, mem2, mem3) = unpack("QQQQ", membuff[index:index+0x20])
		if POINTER_SIZE == 4:
			szaddr = "0x%.08X" % dump_addr
		else:
			szaddr = "0x%.016lX" % dump_addr
		output("\033[1m%s :\033[0m %.016lX %.016lX %.016lX %.016lX" % (szaddr, mem0, mem1, mem2, mem3))
		if index + 0x20 != 0x100:
			output("\n")
		index += 0x20
		dump_addr += 0x20
	color("RESET")
	result.PutCString("".join(GlobalListOutput))
	result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

def cmd_strip_pac(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):	
	if not len(command):
		print('strip_pac <addr>')
		return
	
	pac_addr = evaluate(command)
	unpac_addr = strip_kernel_or_userPAC(pac_addr)
	print(f'[+] PACed pointer 0x{pac_addr:X} -> 0x{unpac_addr:X}')

# XXX: help
def cmd_findmem(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Search memory'''

	global GlobalListOutput
	GlobalListOutput.clear()

	arg = str(command)
	parser = argparse.ArgumentParser(prog="lldb")
	parser.add_argument("-s", "--string",  help="Search string")
	parser.add_argument("-u", "--unicode", help="Search unicode string")
	parser.add_argument("-b", "--binary",  help="Serach binary string (eg. -b 4142434445 will find ABCDE anywhere in mem)")
	parser.add_argument("-d", "--dword",   help="Find dword (native packing) (eg. -d 0x41414141)")
	parser.add_argument("-q", "--qword",   help="Find qword (native packing) (eg. -d 0x4141414141414141)")
	parser.add_argument("-f", "--file" ,   help="Load find pattern from file")
	parser.add_argument("-c", "--count",   help="How many occurances to find, default is all")

	parser = parser.parse_args(arg.split())
	
	if parser.string != None:
		search_string = parser.string.encode('utf-8')
	elif parser.unicode != None:
		search_string  = parser.unicode
	elif parser.binary != None:
		search_string = parser.binary.decode("hex")
	elif parser.dword != None:
		dword = evaluate(parser.dword)
		if not dword:
			print("[-] Error evaluating : " + parser.dword)
			return
		search_string = p32(dword & 0xffffffff)
	elif parser.qword != None:
		qword = evaluate(parser.qword)
		if not qword:
			print("[-] Error evaluating : " + parser.qword)
			return
		search_string = p64(qword & 0xffffffffffffffff)
	elif parser.file != None:
		f = 0
		try:
			f = open(parser.file, "rb")
		except:
			print("[-] Failed to open file : " + parser.file)
			return
		search_string = f.read()
		f.close()
	else:
		print("[-] Wrong option... use findmem --help")
		return
	
	count = -1
	if parser.count != None:
		count = evaluate(parser.count)
		if not count:
			print("[-] Error evaluating count : " + parser.count)
			return
	
	process = get_process()
	pid = process.GetProcessID()
	output_data = subprocess.check_output(["/usr/bin/vmmap", "%d" % pid])
	output_data = output_data.decode('utf-8')
	lines = output_data.split("\n")
	#print(lines);
	#this relies on output from /usr/bin/vmmap so code is dependant on that 
	#only reason why it's used is for better description of regions, which is
	#nice to have. If they change vmmap in the future, I'll use my version 
	#and that output is much easier to parse...
	newlines = []
	for x in lines:
		p = re.compile(r"([\S\s]+)\s([\da-fA-F]{16}-[\da-fA-F]{16}|[\da-fA-F]{8}-[\da-fA-F]{8})")
		m = p.search(x)
		if not m: continue
		tmp = []
		mem_name  = m.group(1)
		mem_range = m.group(2)
		#0x000000-0x000000
		mem_start = int(mem_range.split("-")[0], 16)
		mem_end   = int(mem_range.split("-")[1], 16)
		tmp.append(mem_name)
		tmp.append(mem_start)
		tmp.append(mem_end)
		newlines.append(tmp)
	
	lines = sorted(newlines, key=lambda sortnewlines: sortnewlines[1])
	#move line extraction a bit up, thus we can latter sort it, as vmmap gives
	#readable pages only, and then writable pages, so it looks ugly a bit :)
	newlines = []
	for x in lines:
		mem_name = x[0]
		mem_start= x[1]
		mem_end  = x[2]
		mem_size = mem_end - mem_start
	
		membuff = read_mem(mem_start, mem_size)
		if not len(membuff):
			continue

		off = 0
		base_displayed = 0

		while True:
			if count == 0: 
				return
			idx = membuff.find(search_string)
			if idx == -1: 
				break
			if count != -1:
				count = count - 1
			off += idx
	
			GlobalListOutput.clear()
			
			if POINTER_SIZE == 4:
				ptrformat = "%.08X"
			else:
				ptrformat = "%.016lX"

			color("RESET")
			output("Found at : ")
			color("GREEN")
			output(ptrformat % (mem_start + off))
			color("RESET")
			if base_displayed == 0:
				output(" base : ")
				color("YELLOW")
				output(ptrformat % mem_start)
				color("RESET")
				base_displayed = 1
			else:
				output("        ")
				if POINTER_SIZE == 4:
					output(" " * 8)
				else:
					output(" " * 16)
			#well if somebody allocated 4GB of course offset will be to small to fit here
			#but who cares...
			output(" off : %.08X %s" % (off, mem_name))
			print("".join(GlobalListOutput))
			membuff = membuff[idx+len(search_string):]
			off += len(search_string)
	return

def cmd_datawin(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Configure address to display in data window. Use \'datawin help\' for more information.'''
	help = """
Configure address to display in data window.

Syntax: datawin <address>

The data window display will be fixed to the address you set. Useful to observe strings being decrypted, etc.
Note: expressions supported, do not use spaces between operators.
"""

	global DATA_WINDOW_ADDRESS

	cmd = command.split()
	if len(cmd) == 0:
		print("[-] error: please insert an address.")
		print("")
		print(help)
		return

	if cmd[0] == "help":
		print(help)
		return        

	dump_addr = evaluate(cmd[0])
	if not dump_addr:
		print("[-] error: invalid address value.")
		print("")
		print(help)
		gui.DATA_WINDOW_ADDRESS = 0
		return
	gui.DATA_WINDOW_ADDRESS = dump_addr

# xinfo command
def cmd_xinfo(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):

	args = command.split(' ')
	if len(args) != 1 or args[0] == '':
		output('Usage : xinfo <address>')
		return

	address = evaluate(args[0])
	if not address:
		print(f'{COLORS["RED"]} Invalid address {COLORS["RESET"]}')
		return

	cur_target = debugger.GetSelectedTarget()
	module_map = get_module_info_from_address(cur_target, address)
	base_address = 0
	if not module_map.module_name:
		map_info = VMMapCacheBase.get_cache().query_vmmap(address)
		if not map_info:
			print(f'{COLORS["RED"]} Your address is not match any image map {COLORS["RESET"]}')
			return

		module_name = map_info.map_type
		offset = address - map_info.start
		base_address = map_info.start

	else:
		module_name = f'{module_map.module_name}.{module_map.section_name}'
		base_address = module_map.start_address
		if module_map.abs_offset < 0:
			offset = module_map.offset
		else:
			offset = module_map.abs_offset

	symbol_name = get_symbol_from_address(address)
	print(f'{COLORS["YELLOW"]} - {module_name}(0x{base_address:X}) : 0x{offset:X} : {symbol_name} {COLORS["RESET"]}')

def cmd_telescope(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	args = command.split(' ')

	if len(args) > 2 or len(args) == 0:
		print('tele/telescope <address / $register> <length (multiply by 8 for x64 and 4 for x86)>')
		return
	
	address = evaluate(args[0])
	
	try:
		n_field = evaluate(args[1]) // POINTER_SIZE
		if n_field == 0:
			n_field = 8

	except IndexError:
		n_field = 8

	reset = COLORS['RESET']
	red = COLORS['RED']
	yellow = COLORS['YELLOW']
	cyan = COLORS['CYAN']
	magenta = COLORS['MAGENTA']
	bold = COLORS['BOLD']

	print(f'{red}CODE{reset} | ', end='')
	print(f'{yellow}STACK{reset} | ', end='')
	print(f'{cyan}HEAP{reset} | ', end='')
	print(f'{magenta}DATA{reset}')

	cur_target: SBTarget = debugger.GetSelectedTarget()

	memory = read_mem(address, n_field * POINTER_SIZE)
	if not len(memory):
		return
	
	# print telescope memory
	for i in range(n_field):
		ptr_value = unpack('<Q', memory[i*POINTER_SIZE:(i + 1)*POINTER_SIZE])[0]
		unpack_ptr = ptr_value
		
		if is_paced_addr(ptr_value):
			# this pointer could be PAC, try to unpack it
			unpack_ptr = strip_kernel_or_userPAC(unpack_ptr)

		print(f'{cyan}0x{(address + i*8):X}{reset}: ', end='')

		if unpack_ptr:
			module_map = get_module_info_from_address(cur_target, unpack_ptr)

			offset = module_map.offset
			module_name = f'{module_map.module_name}.{module_map.section_name}'

			if offset > -1:
				symbol_name = get_symbol_from_address(unpack_ptr)
				if module_map.section_name == '__TEXT':
					# this address is executable
					select_color = red
				else:
					select_color = magenta

				if symbol_name:
					print(f'{select_color}0x{unpack_ptr:X}{reset} -> {bold}"{symbol_name}"{reset}')
				else:
					print(f'{select_color}0x{unpack_ptr:X}{reset} -> {bold}{module_name}:0x{module_map.abs_offset:X}{reset}')

			elif readable(unpack_ptr):
				# check this readable address is on heap or stack or mapped address
				map_info = VMMapCacheBase.get_cache().query_vmmap(unpack_ptr)
				possible_cstr = read_cstr2(unpack_ptr, max_size=1024)
				select_color = cyan

				if map_info:
					if map_info.map_type.startswith('Stack'):
						# is stack address
						select_color = yellow
					elif map_info.map_type.startswith('MALLOC'):
						# heap
						select_color = cyan
					else:
						# mapped address
						select_color = magenta
			
				print(f'{select_color}0x{unpack_ptr:X}{reset}', end='')
				if possible_cstr:
					out_str = possible_cstr.decode('utf-8')
					print(f' -> "{out_str}"')
				else:
					print('')
				
			else:
				print(f'0x{ptr_value:X}')
		
		else:
			print(f'0x{ptr_value:X}')

def cmd_vmmap(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''
		vmmap like in Linux
	'''
	if platform.system() == 'Linux':
		# cat /proc/pid/maps
		proc = get_process()
		proc_id = proc.GetProcessID()

		with open('/proc/{0}/maps'.format(proc_id), 'r') as f:
			map_info = f.read()
			print(map_info)

		return

	if platform.system() != 'Darwin':
		print('[!] This command only works in macOS')
		return

	addr = evaluate(command)
	if not addr:
		# add color or sth like in this text
		map_infos = VMMapCacheBase.get_cache().get_map_infos()
		if not map_infos:
			print('[-] Target debug does not support memory region info (qMemoryRegionInfo unsupported)')
			return

		for map_info in map_infos:
			display_map_info(map_info)

		return

	map_info = VMMapCacheBase.get_cache().query_vmmap(addr)
	if not map_info:
		print('[-] Unable to find your address {0}'.format(hex(addr)))
		return

	display_map_info(map_info)

def cmd_objc(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''
		Return class name of objectiveC object
	'''
	
	objc_addr = evaluate(command)
	if not objc_addr:
		print('objc <register/address> => return class name of objectiveC object')
		return
	
	class_name = objc_get_classname(objc_addr)
	# print content or structure of this objc object
	res = lldb.SBCommandReturnObject()
	ci: SBCommandInterpreter = debugger.GetCommandInterpreter()
	ci.HandleCommand(f'p *(({class_name} *){hex(objc_addr)})', res)
	if res.Succeeded():
		print(res.GetOutput())

def cmd_cf_obj(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''
		Return CoreFoundation object name, information, and more for debugging
	'''

	objc_addr = evaluate(command)
	if not objc_addr:
		print('cf_obj <register/address> => return CoreFoundation object name, information, and more for debugging')
		return

	# evaluate_expression = evaluate(f'((CFTypeRef)0x{objc_addr:X})')

def cmd_pattern_create(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	pattern_length = parse_number(command) 

	if pattern_length <= 0:
		print('Invalid pattern_length')
		return

	print(cyclic(pattern_length).decode('utf-8'))

def cmd_pattern_offset(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	args = command.split(' ')

	if len(args) != 2:
		print('pattern_offset <value / $register> <length (multiply by 8 for x64 and 4 for x86)>')
		return

	value = evaluate(args[0])
	if value == 0:
		print(f'Your value "{args[0]}" is invalid')
		return

	length = parse_number(args[1])

	pos = cyclic_find(value, length)
	print('Value {0}{1}{2} locate at offset {3}{4}{5}'.format(
		COLORS['YELLOW'], hex(value), COLORS['RESET'], COLORS['YELLOW'], hex(pos), COLORS['RESET'])
	)

# -----------------------------
# modify eflags/rflags commands
# -----------------------------

def modify_eflags(flag: str):
	# read the current value so we can modify it
	if is_x64():
		eflags = get_gp_register("rflags")
	elif is_i386():
		eflags = get_gp_register("eflags")
	else:
		print("[-] error: unsupported architecture.")
		return

	masks = { "CF":0, "PF":2, "AF":4, "ZF":6, "SF":7, "TF":8, "IF":9, "DF":10, "OF":11 }
	if flag not in masks.keys():
		print("[-] error: requested flag not available")
		return
	# we invert whatever value is set
	if bool(eflags & (1 << masks[flag])) == True:
		eflags = eflags & ~(1 << masks[flag])
	else:
		eflags = eflags | (1 << masks[flag])

	# finally update the value
	if is_x64():
		get_frame().reg["rflags"].value = format(eflags, '#x')
	elif is_i386():
		get_frame().reg["eflags"].value = format(eflags, '#x')

def cmd_cfa(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Change adjust flag. Use \'cfa help\' for more information.'''
	help = """
Flip current adjust flag.

Syntax: cfa
"""
	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return
	modify_eflags("AF")

def cmd_cfc(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Change carry flag. Use \'cfc help\' for more information.'''
	help = """
Flip current carry flag.

Syntax: cfc
"""
	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return
	modify_eflags("CF")

def cmd_cfd(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Change direction flag. Use \'cfd help\' for more information.'''
	help = """
Flip current direction flag.

Syntax: cfd
"""
	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return
	modify_eflags("DF")

def cmd_cfi(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Change interrupt flag. Use \'cfi help\' for more information.'''
	help = """
Flip current interrupt flag.

Syntax: cfi
"""
	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return
	modify_eflags("IF")

def cmd_cfo(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Change overflow flag. Use \'cfo help\' for more information.'''
	help = """
Flip current overflow flag.

Syntax: cfo
"""
	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return
	modify_eflags("OF")

def cmd_cfp(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Change parity flag. Use \'cfp help\' for more information.'''
	help = """
Flip current parity flag.

Syntax: cfp
"""
	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return
	modify_eflags("PF")

def cmd_cfs(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Change sign flag. Use \'cfs help\' for more information.'''
	help = """
Flip current sign flag.

Syntax: cfs
"""
	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return
	modify_eflags("SF")

def cmd_cft(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Change trap flag. Use \'cft help\' for more information.'''
	help = """
Flip current trap flag.

Syntax: cft
"""
	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return
	modify_eflags("TF")

def cmd_cfz(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Change zero flag. Use \'cfz help\' for more information.'''
	help = """
Flip current zero flag.

Syntax: cfz
""" 
	cmd = command.split()
	if len(cmd) != 0:
		if cmd[0] == "help":
			print(help)
			return
		print("[-] error: command doesn't take any arguments.")
		print("")
		print(help)
		return
	modify_eflags("ZF")

'''
	si, c, r instruction override deault ones to consume their output.
	For example:
		si is thread step-in which by default dumps thread and frame info
		after every step. Consuming output of this instruction allows us
		to nicely display informations in our hook-stop
	Same goes for c and r (continue and run)
'''
def cmd_si(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	debugger.SetAsync(True)
	selected_target: SBTarget = debugger.GetSelectedTarget()
	selected_target.process.selected_thread.StepInstruction(False)
	result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult)

def c(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	debugger.SetAsync(True)
	selected_target: SBTarget = debugger.GetSelectedTarget()
	selected_target.GetProcess().Continue()
	result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult)

# ------------------------------
# Disassembler related functions
# ------------------------------

'''
	Handles 'u' command which displays instructions. Also handles output of
	'disassemble' command ...
'''
# XXX: help
def cmd_DumpInstructions(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Dump instructions at certain address (SoftICE like u command style)'''
	help = """ """

	global GlobalListOutput
	GlobalListOutput.clear()
	
	cmd = command.split()
	if len(cmd) == 0 or len(cmd) > 2:
		disassemble(get_current_pc(), CONFIG_DISASSEMBLY_LINE_COUNT)
	elif len(cmd) == 1:
		address = evaluate(cmd[0])
		if not address:
			return
		disassemble(address, CONFIG_DISASSEMBLY_LINE_COUNT)
	else:
		address = evaluate(cmd[0])
		if not address:
			return
		count = evaluate(cmd[1])
		if not count:
			return
		disassemble(address, count)

	result.PutCString("".join(GlobalListOutput))
	result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# ------------------------------------
# Commands that use external utilities
# ------------------------------------

def cmd_show_loadcmds(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict): 
	'''Show otool output of Mach-O load commands. Use \'show_loadcmds\' for more information.'''
	help = """
Show otool output of Mach-O load commands.

Syntax: show_loadcmds <address>

Where address is start of Mach-O header in memory.
Note: expressions supported, do not use spaces between operators.
"""
	cmd = command.split()
	if len(cmd) == 1:
		if cmd[0] == "help":
			print(help)
			return
		header_addr = evaluate(cmd[0])
		if not header_addr:
			print("[-] error: invalid header address value.")
			print("")
			print(help)
			return        
	else:
		print("[-] error: please insert a valid Mach-O header address.")
		print("")
		print(help)
		return

	if os.path.isfile("/usr/bin/otool") == False:
		print("/usr/bin/otool not found. Please install Xcode or Xcode command line tools.")
		return
	
	data = read_mem(header_addr, 4096*10)
	if not len(data):
		print("[-] error: Failed to read memory at 0x{:x}.".format(header_addr))
		return

	# open a temporary filename and set it to delete on close
	f = tempfile.NamedTemporaryFile(delete=True)
	f.write(data)
	# pass output to otool
	output_data = subprocess.check_output(["/usr/bin/otool", "-l", f.name])
	# show the data
	print(output_data)
	# close file - it will be automatically deleted
	f.close()

	return

def cmd_show_header(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict): 
	'''Show otool output of Mach-O header. Use \'show_header\' for more information.'''
	help = """
Show otool output of Mach-O header.

Syntax: show_header <address>

Where address is start of Mach-O header in memory.
Note: expressions supported, do not use spaces between operators.
"""
	cmd = command.split()
	if len(cmd) == 1:
		if cmd[0] == "help":
			print(help)
			return
		header_addr = evaluate(cmd[0])
		if not header_addr:
			print("[-] error: invalid header address value.")
			print("")
			print(help)
			return        
	else:
		print("[-] error: please insert a valid Mach-O header address.")
		print("")
		print(help)
		return

	if os.path.isfile("/usr/bin/otool") == False:
			print("/usr/bin/otool not found. Please install Xcode or Xcode command line tools.")
			return
	
	# recent otool versions will fail so we need to read a reasonable amount of memory
	# even just for the mach-o header
	data = read_mem(header_addr, 4096*10)
	if not len(data):
		print("[-] error: Failed to read memory at 0x{:x}.".format(header_addr))
		return

	# open a temporary filename and set it to delete on close
	f = tempfile.NamedTemporaryFile(delete=True)
	f.write(data)
	# pass output to otool
	output_data = subprocess.check_output(["/usr/bin/otool", "-hv", f.name])
	# show the data
	print(output_data)
	# close file - it will be automatically deleted
	f.close()

	return

# use keystone-engine.org to assemble
def assemble_keystone(arch, mode, code, syntax=0):
	ks = Ks(arch, mode)
	if syntax != 0:
		ks.syntax = syntax

	print("\nKeystone output:\n----------")
	for inst in code:
		try:
			encoding, count = ks.asm(inst)
			output = []
			output.append(inst)
			output.append('->')
			
			if encoding:
				for i in encoding:
					output.append("{:02x}".format(i))
				print(" ".join(output))

		except KsError as e:
			print("[-] error: keystone failed to assemble: {:s}".format(e))
			return

def cmd_asm32(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''32 bit x86 interactive Keystone based assembler. Use \'asm32 help\' for more information.'''
	help = """
32 bit x86 interactive Keystone based assembler.

Syntax: asm32

Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_X86 and KS_MODE_32.

Requires Keystone and Python bindings from www.keystone-engine.org.
"""
	cmd = command.split()
	if len(cmd) != 0 and cmd[0] == "help":
		print(help)
		return

	if CONFIG_KEYSTONE_AVAILABLE == 0:
		print("[-] error: keystone python bindings not available. please install from www.keystone-engine.org.")
		return
	
	inst_list = []
	while True:
		line = input('Assemble ("stop" or "end" to finish): ')
		if line == 'stop' or line == 'end':
			break
		inst_list.append(line)
	
	assemble_keystone(KS_ARCH_X86, KS_MODE_32, inst_list)

def cmd_asm64(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''64 bit x86 interactive Keystone based assembler. Use \'asm64 help\' for more information.'''
	help = """
64 bit x86 interactive Keystone based assembler

Syntax: asm64

Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_X86 and KS_MODE_64.

Requires Keystone and Python bindings from www.keystone-engine.org.
"""
	cmd = command.split()
	if len(cmd) != 0 and cmd[0] == "help":
		print(help)
		return

	if CONFIG_KEYSTONE_AVAILABLE == 0:
		print("[-] error: keystone python bindings not available. please install from www.keystone-engine.org.")
		return
	
	inst_list = []
	while True:
		line = input('Assemble ("stop" or "end" to finish): ')
		if line == 'stop' or line == 'end':
			break
		inst_list.append(line)
	
	assemble_keystone(KS_ARCH_X86, KS_MODE_64, inst_list)

def cmd_arm32(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''32 bit ARM interactive Keystone based assembler. Use \'arm32 help\' for more information.'''
	help = """
32 bit ARM interactive Keystone based assembler

Syntax: arm32

Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_ARM and KS_MODE_LITTLE_ENDIAN.
	
Requires Keystone and Python bindings from www.keystone-engine.org.
"""
	cmd = command.split()
	if len(cmd) != 0 and cmd[0] == "help":
		print(help)
		return

	if CONFIG_KEYSTONE_AVAILABLE == 0:
		print("[-] error: keystone python bindings not available. please install from www.keystone-engine.org.")
		return
	
	inst_list = []
	while True:
		line = input('Assemble ("stop" or "end" to finish): ')
		if line == 'stop' or line == 'end':
			break
		inst_list.append(line)
	
	assemble_keystone(KS_ARCH_ARM, KS_MODE_LITTLE_ENDIAN, inst_list)

def cmd_armthumb(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''32 bit ARM Thumb interactive Keystone based assembler. Use \'armthumb help\' for more information.'''
	help = """
32 bit ARM Thumb interactive Keystone based assembler

Syntax: armthumb

Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_ARM and KS_MODE_THUMB.

Requires Keystone and Python bindings from www.keystone-engine.org.
"""
	cmd = command.split()
	if len(cmd) != 0 and cmd[0] == "help":
		print(help)
		return

	if CONFIG_KEYSTONE_AVAILABLE == 0:
		print("[-] error: keystone python bindings not available. please install from www.keystone-engine.org.")
		return
	
	inst_list = []
	while True:
		line = input('Assemble ("stop" or "end" to finish): ')
		if line == 'stop' or line == 'end':
			break
		inst_list.append(line)
	
	assemble_keystone(KS_ARCH_ARM, KS_MODE_THUMB, inst_list)

def cmd_arm64(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''64 bit ARM interactive Keystone based assembler. Use \'arm64 help\' for more information.'''
	help = """
64 bit ARM interactive Keystone based assembler

Syntax: arm64

Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_ARM64 and KS_MODE_LITTLE_ENDIAN.

Requires Keystone and Python bindings from www.keystone-engine.org.
"""
	cmd = command.split()
	if len(cmd) != 0 and cmd[0] == "help":
		print(help)
		return

	if CONFIG_KEYSTONE_AVAILABLE == 0:
		print("[-] error: keystone python bindings not available. please install from www.keystone-engine.org.")
		return
	
	inst_list = []
	while True:
		line = input('Assemble ("stop" or "end" to finish): ')
		if line == 'stop' or line == 'end':
			break
		inst_list.append(line)
	
	assemble_keystone(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, inst_list)

# iphone connect to lldb server command
def cmd_IphoneConnect(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict): 
	'''Connect to debugserver running on iPhone'''
	global GlobalListOutput
	GlobalListOutput.clear()
		
	if len(command) == 0 or ":" not in command:
		output("Connect to remote iPhone debug server")
		output("\n")
		output("iphone <ipaddress:port>")
		output("\n")
		output("iphone 192.168.0.2:5555")
		result.PutCString("".join(GlobalListOutput))
		result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
		return

	res = lldb.SBCommandReturnObject()
	ci: SBCommandInterpreter = debugger.GetCommandInterpreter()
	ci.HandleCommand("platform select remote-ios", res)
	if res.Succeeded():
		output(res.GetOutput())
	else:
		output("[-] Error running platform select remote-ios")
		result.PutCString("".join(GlobalListOutput))
		result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
		return
	ci.HandleCommand(f"process connect connect://{command}", res)
	if res.Succeeded():
		output("[+] Connected to iphone at : " + command)
	else:
		output(res.GetOutput())
	result.PutCString("".join(GlobalListOutput))
	result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

def cmd_load_custom_symbols(args: List[str]):
	'''
		valid args should be ['load', '<custom symbol path>.json']
	'''

	if len(args) < 2:
		print('sym load <custom symbol path>.json')
		return False
	
	symbol_path = Path(args[1])
	if not symbol_path.exists():
		print(f'[!] Unable to load symbol path from {symbol_path}')
		return False
	
	if not symbol_path.is_file():
		print(f'[!] {symbol_path} must be JSON file')
		return False
	
	load_custom_symbols(str(symbol_path))
	print('[+] Loaded')
	return True

def cmd_sym_break(debugger: SBDebugger, func_name: str):
	'''
		resolve function name from the active symbol source, apply the
		slide and set breakpoint on the target
	'''
	active_symbols = get_active_symbols()
	if not active_symbols.is_loaded:
		print('[!] Custom symbols did not loaded')
		return

	func_addr = active_symbols.query_func_addr(func_name)
	if func_addr is None:
		print(f'[-] Function {func_name} not found in custom symbol db')
		return

	cur_target: SBTarget = get_target()

	if isinstance(active_symbols, RemoteSymbols):
		# live server: query_func_addr already translated the
		# ida address to runtime via the connect slide
		bp_addr = func_addr
		slide = active_symbols.slide
	else:
		# static db: symbols are dumped with ida default mapped address,
		# match the loaded module they belong to via the first db segment
		sym_module: Optional[SBModule] = None
		if active_symbols.segments:
			db_base = active_symbols.segments[0]['start']
			for module in cur_target.modules:
				module_text = get_text_section(module)
				if module_text and module_text.file_addr == db_base:
					sym_module = module
					break

		if not sym_module:
			# kernel debug: kernelcache is the first module
			sym_module = cur_target.GetModuleAtIndex(0)

		module_text = get_text_section(sym_module)
		load_base = module_text.GetLoadAddress(cur_target)
		if load_base == 0 or load_base == lldb.LLDB_INVALID_ADDRESS:
			print(f'[!] Module {sym_module.file.basename} is not loaded, unable to compute slide')
			return

		# slide between ida mapped address and live loaded address
		slide = load_base - module_text.file_addr
		bp_addr = func_addr + slide

	if is_api_backend():
		# kernel or remote session - target text pages are read-only,
		# the sb api has no hardware breakpoint support so set it
		# via command interpreter like cmd_bhb does
		res = SBCommandReturnObject()
		ci: SBCommandInterpreter = debugger.GetCommandInterpreter()
		ci.HandleCommand('breakpoint set -H -a ' + hex(bp_addr), res)
		if res.Succeeded():
			print(f'[+] Hardware breakpoint set at {hex(bp_addr)} - {func_name} (ida {hex(bp_addr - slide)}, slide {hex(slide)})')
		else:
			print(f'[-] Unable to set hardware breakpoint at {hex(bp_addr)} - {func_name}')
		return

	breakpoint = cur_target.BreakpointCreateByAddress(bp_addr)
	print(f'[+] Breakpoint {breakpoint.GetID()} set at {hex(bp_addr)} - {func_name} (ida {hex(bp_addr - slide)}, slide {hex(slide)})')

SYM_CONNECT_DEFAULT_PORT = 9001

def cmd_sym_connect(args: List[str]):
	'''
		connect to a live symbol server (ida_server.py inside ida)
		usage: sym connect [host:]<port> - default 127.0.0.1:9001
	'''
	endpoint_arg = args[1] if len(args) > 1 else f'127.0.0.1:{SYM_CONNECT_DEFAULT_PORT}'

	# accepts [host:]<port>, host defaults to 127.0.0.1
	if ':' in endpoint_arg:
		host, port_str = endpoint_arg.rsplit(':', 1)
	else:
		host, port_str = '127.0.0.1', endpoint_arg

	try:
		port = int(port_str)
	except ValueError:
		print(f'[!] Invalid port {port_str}')
		return

	remote = RemoteSymbols(f'http://{host}:{port}')
	status = remote.connect()
	if status is None:
		print(f'[-] Unable to reach symbol server at {host}:{port}')
		return

	# slide between the ida image base and the live loaded mach header,
	# the server declares its own base so there is no guessing
	cur_target: SBTarget = get_target()
	sym_module = cur_target.GetModuleAtIndex(0)

	# prefer the module matching the idb file the server runs on
	status_file = status.get('file')
	if status_file:
		for module in cur_target.modules:
			if status_file in module.file.basename:
				sym_module = module
				break

	live_base = sym_module.GetObjectFileHeaderAddress().GetLoadAddress(cur_target)
	if live_base == 0 or live_base == lldb.LLDB_INVALID_ADDRESS:
		print('[!] Module is not loaded, connect after the process started')
		return

	image_base = int(status['image_base'])
	remote.slide = live_base - image_base

	set_active_symbols(remote)
	print(f'[+] Connected to {status.get("tool", "?")} symbol server at {host}:{port}')
	print(f'    idb file       : {status_file}')
	print(f'    ida image base : {hex(image_base)}')
	print(f'    live base      : {hex(live_base)}')
	print(f'    slide          : {hex(remote.slide)}')

def cmd_sym_disconnect():
	'''
		fall back to the static custom symbol db (sym load)
	'''
	set_active_symbols(None)
	print('[+] Disconnected, active symbol source back to static custom symbol db')

SYM_PRINT_ANN_MAX = 40 # max annotation length per field

def sym_print_field_ann(value: int, map_infos: List[MapInfo]) -> str:
	'''heuristic annotation for a struct field value, same chain as the
	   register display (small int skip, PAC strip, region, symbol) but
	   standalone - the register annotation cache must not see field lookups'''
	# values below 64K are plain integers, not pointers
	if value < 0x10000:
		return ''

	stripped = strip_kernel_or_userPAC(value)
	pac_tag = stripped != value

	map_info = find_map_info_pwn(map_infos, stripped)
	if map_info is None:
		# unmapped pointer, or the target does not expose regions (no claim)
		return 'unmapped' if map_infos else ''

	name, base = map_info.map_type.strip(), map_info.start

	# executable regions refine to a function symbol
	if 'x' in map_info.perm:
		sym_ann = get_reg_symbol_pwn(stripped)
		if sym_ann and 0 <= stripped - sym_ann[1] <= 0x10000:
			name, base = sym_ann

	off = stripped - base
	ann = name if off == 0 else '{0}+0x{1:X}'.format(name, off)
	if pac_tag:
		ann = '[pac] ' + ann

	if len(ann) > SYM_PRINT_ANN_MAX:
		ann = ann[:SYM_PRINT_ANN_MAX - 1] + '…'

	return ann

def sym_print_value_color(value: int, map_infos: List[MapInfo]) -> str:
	'''field value color, same legend as the tele command:
	   RED code / MAGENTA data / YELLOW stack / CYAN heap,
	   plain for zero, small integers and unreadable addresses'''
	if value == 0:
		return ''

	stripped = strip_kernel_or_userPAC(value)

	module_map = get_module_info_from_address(get_target(), stripped)
	if module_map.offset > -1:
		# inside a module (or a custom symbol segment)
		return 'RED' if module_map.section_name.startswith('__TEXT') else 'MAGENTA'

	if not readable(stripped):
		return ''

	map_info = find_map_info_pwn(map_infos, stripped)
	if map_info is None:
		# readable but unclassified, same default as tele
		return 'CYAN'

	if map_info.map_type.startswith('Stack'):
		return 'YELLOW'

	if map_info.map_type.startswith('MALLOC'):
		return 'CYAN'

	return 'MAGENTA'

def resolve_sym_print_addr(token: str) -> Optional[int]:
	'''sym print address argument: register name (x0), lldb expression ($x0+8,
	   &global, *(void**)$x0) or a plain integer'''
	registers = get_gp_registers()
	reg_token = token.lower().lstrip('$')
	if reg_token in registers:
		return registers[reg_token]

	# the x29/x30 aliases, same as the register display
	if reg_token == 'x29' and 'fp' in registers:
		return registers['fp']
	if reg_token == 'x30' and 'lr' in registers:
		return registers['lr']

	# lldb expression against the current frame, handles hex, globals, derefs
	try:
		value = get_frame().EvaluateExpression(token)
		if value.GetError().Success():
			return value.GetValueAsUnsigned()
	except Exception:
		pass

	try:
		return int(token, 0)
	except ValueError:
		return None

def cmd_sym_print(struct_name: str, addr_token: str):
	'''
		dump a struct layout from a live symbol server at an address
		usage: sym print <struct_name> <address> - address can be a register
		(x0), an expression ($x0+8) or a plain 0x value
	'''
	symbols = get_active_symbols()
	if not isinstance(symbols, RemoteSymbols):
		print('[-] sym print needs a live symbol server - sym connect first')
		return

	layout = symbols.query_struct(struct_name)
	if not layout:
		print(f'[-] No struct layout for {struct_name} (unknown name or server unreachable)')
		return

	addr = resolve_sym_print_addr(addr_token)
	if addr is None:
		print(f'[-] Unable to resolve address {addr_token!r} (try x0, $x0+8 or a 0x value)')
		return

	fields = layout.get('fields', [])
	size = int(layout.get('size', 0) or 0)

	# one read for the whole struct, fields past the readable bytes mark unknown
	try:
		buf = read_mem(addr, size) if size else b''
	except Exception:
		buf = b''

	target = get_target()
	byte_order = 'big' if target.GetByteOrder() == lldb.eByteOrderBig else 'little'
	pointer_size = target.addr_size

	map_infos = get_reg_snapshot()
	name_width = max([len(field['name']) for field in fields] + [8])

	dim, reset = COLORS['DIM'], COLORS['RESET']

	print(f'[+] {COLORS["YELLOW"]}{struct_name}{reset} at {COLORS["CYAN"]}{hex(addr)}{reset} ({hex(size)} bytes, live symbol server)')
	for field in fields:
		off = field['offset']
		fsize = field['size']
		raw = buf[off:off + fsize] if fsize else b''

		if len(raw) < fsize:
			# unreadable memory (bad address / field crosses the region end)
			print(f'    {dim}+0x{off:04X}{reset}  {COLORS["YELLOW"]}{field["name"]:{name_width}}{reset} : {COLORS["RED"]}?{reset}  {dim}unknown{reset}')
			continue

		off_text = f'    {dim}+0x{off:04X}{reset}  '
		name_text = f'{COLORS["YELLOW"]}{field["name"]:{name_width}}{reset}'

		if fsize > 8:
			# arrays/blobs (char [], uint32 [] ...) render as a hex string
			# instead of one huge integer, wrapped at 8 bytes per line
			chunk_indent = ' ' * (13 + name_width + 3)
			for i in range(0, fsize, 32):
				hex_text = ' '.join('{0:02X}'.format(b) for b in raw[i:i + 32])
				if i == 0:
					print(f'{off_text}{name_text} : {dim}{hex_text}{reset}')
				else:
					print(f'{chunk_indent}{dim}{hex_text}{reset}')
			continue

		value = int.from_bytes(raw, byteorder=byte_order)
		value_text = '0x{0:0{1}X}'.format(value, fsize * 2)

		ann = ''
		if fsize == pointer_size:
			ann = sym_print_field_ann(value, map_infos)

		# value color follows the same legend as the tele command
		value_color = COLORS.get(sym_print_value_color(value, map_infos), '')
		ann_text = f'  {dim}{ann}{reset}' if ann else ''

		print(f'{off_text}{name_text} : {value_color}{value_text}{reset}{ann_text}')

def cmd_custom_sym(
		debugger: SBDebugger,
		command: str,
		result: SBCommandReturnObject,
		dict: Dict):
	
	args = command.split(' ')
	if len(args) < 1 or args[0] == 'help':
		print('- sym load <custom sym>.json: load custom symbol db')
		print('- sym bt: resolve backtrace with the active symbol source (custom db or live server)')
		print('- sym break <function_name>: set breakpoint at function from custom symbol db')
		print('- sym connect [host:]<port>: use a live ida/ghidra symbol server as symbol source (default 127.0.0.1:9001)')
		print('- sym disconnect: fall back to the static custom symbol db')
		print('- sym print <struct_name> <address>: dump a struct layout from a live symbol server at an address (register or expression)')
		return
	
	sub_cmd = args[0]

	if sub_cmd == 'load':
		cmd_load_custom_symbols(args)

	elif sub_cmd == 'bt':
		custom_sym_backtrace(debugger)

	elif sub_cmd == 'break':
		if len(args) < 2:
			print('sym break <function_name>')
			return

		cmd_sym_break(debugger, args[1])

	elif sub_cmd == 'connect':
		cmd_sym_connect(args)

	elif sub_cmd == 'disconnect':
		cmd_sym_disconnect()

	elif sub_cmd == 'print':
		if len(args) < 3:
			print('sym print <struct_name> <address>')
			print('    address can be a register (x0), an expression ($x0+8) or a plain 0x value')
			return

		cmd_sym_print(args[1], args[2])

	else:
		print(f'[!] Unsupported sym command {sub_cmd}')

# xnu kernel debug support command
def cmd_xnu_kdp_reboot(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''
		Restart debuggee vm
	'''
	if get_connection_protocol() != 'kdp':
		print('Target is not connect over kdp')
		return False
	
	print('[+] Reboot the remote machine')
	debugger.HandleCommand('process plugin packet send --command 0x13')
	debugger.HandleCommand('detach')
	return True

def cmd_xnu_show_bootargs(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	boot_args = xnu_showbootargs()
	if not boot_args:
		print('Please use kernel.development to boot macOS')
		return False
	
	print('[+] macOS boot-args:', repr(boot_args))
	return True

def cmd_xnu_panic_log(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):

	args = command.split(' ')
	if len(args) > 1:
		print('panic_log <save path | empty>')
		return False
	
	panic_log = xnu_panic_log()
	
	if len(args) == 1 and args[0]:
		log_file = args[0]
		print(f'[+] Saving panic_log to {log_file}')
		f = open(log_file, 'wb')
		f.write(panic_log)
		f.close()
	else:
		print('---- Panic Log ----')
		print(panic_log.decode('utf-8'))
	return True

# xnu zones command

def cmd_xnu_list_zone(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	global XNU_ZONES
	if not XNU_ZONES.is_loaded:
		XNU_ZONES.load_from_kernel(debugger.GetSelectedTarget())
	
	print('[+] Zones:')
	pad_size = len(str(len(XNU_ZONES)))
	for idx, zone_name in enumerate(XNU_ZONES.iter_zone_name()):
		print(f'- {idx:{pad_size}} | {zone_name}')

def cmd_xnu_zshow_logged_zone(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	global XNU_ZONES
	if not XNU_ZONES.is_loaded:
		XNU_ZONES.load_from_kernel(debugger.GetSelectedTarget())
	
	XNU_ZONES.show_zone_being_logged()

def cmd_xnu_zone_triage(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	global XNU_ZONES
	if not XNU_ZONES.is_loaded:
		XNU_ZONES.load_from_kernel(debugger.GetSelectedTarget())

	args = command.split(' ')
	if len(args) < 2:
		print('zone_triage: <zone_name> <element_ptr>')
		return False
	
	zone_name = args[0]
	elem_ptr = evaluate(args[1])
	XNU_ZONES.zone_find_stack_elem(zone_name, elem_ptr, 0)
	return True

def cmd_xnu_inspect_zone(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	global XNU_ZONES
	if not XNU_ZONES.is_loaded:
		XNU_ZONES.load_from_kernel(debugger.GetSelectedTarget())
	
	if not len(command):
		print('zone_inspect: <zone_name>')
		return False
	
	zone_name = command
	if not XNU_ZONES.has_zone_name(zone_name):
		print(f'[!] Invalid zone name : "{zone_name}"')
		return False

	XNU_ZONES.inspect_zone_name(zone_name)
	return True

def cmd_xnu_show_chunk_at(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	global XNU_ZONES
	if not XNU_ZONES.is_loaded:
		XNU_ZONES.load_from_kernel(debugger.GetSelectedTarget())
	
	args = command.split(' ')
	if len(args) < 2:
		print('zone_show_chunk_at: <zone_name> <chunk_addr>')
		return False
	
	zone_name = args[0]
	chunk_addr = evaluate(args[1])

	status = XNU_ZONES.get_chunk_info_at_zone_name(zone_name, chunk_addr)
	if status != 'None':
		zone_idx = XNU_ZONES.get_zone_id_by_name(zone_name)
		color = COLORS["GREEN"]
		if status == 'Freed':
			color = COLORS["RED"]

		print(f'[+] zone_array[{zone_idx}]({zone_name}) - {COLORS["BOLD"]}0x{chunk_addr:X}{COLORS["RESET"]}{color} ({status})')
		print(COLORS["RESET"], end='')
	else:
		print(f'[+] Your chunk address is not found in zone {zone_name}.')
	
	return True

def cmd_xnu_show_chunk_with_regex(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	global XNU_ZONES
	if not XNU_ZONES.is_loaded:
		XNU_ZONES.load_from_kernel(debugger.GetSelectedTarget())
	
	args = command.split(' ')
	if len(args) < 2:
		print('zone_show_chunk_with_regex: <zone_name_regex> <chunk_addr>')
		return False
	
	zone_name_regex = args[0]
	chunk_addr = evaluate(args[1])

	if zone_name_regex == 'kalloc':
		zone_name_regex = '.*kalloc.*' # quickway to find kalloc zone
	
	zones = XNU_ZONES.get_zones_by_regex(zone_name_regex)
	if not zones:
		print('[!] Unable to find any zone')
		return False

	for zone in zones:
		zone_name = zone.get_attribute('zone_name')
		zone_idx = zone.get_attribute('zone_idx')
		print(f'[+] zone_array[{zone_idx}]({zone_name}) : ', end='')

		status = XNU_ZONES.get_chunk_info_at_zone(zone, chunk_addr)
		if status != 'None':
			color = COLORS["GREEN"]
			if status == 'Freed':
				color = COLORS["RED"]

			print(f'{COLORS["BOLD"]}0x{chunk_addr:X}{COLORS["RESET"]}{color}({status})')
			print(COLORS["RESET"], end='')
			break
	
	return True

def cmd_xnu_zone_backtrace_at(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	global XNU_ZONES
	if not XNU_ZONES.is_loaded:
		XNU_ZONES.load_from_kernel(debugger.GetSelectedTarget())
	
	args = command.split(' ')
	if len(args) < 2:
		print('Usage: zone_backtrace_at <zone_name> <chunk_ptr> <action>')
		print('action: 1 for kfree backtrace only ')
		print('        2 for kmalloc backtrace only ')
		return False

	zone_name = args[0]
	chunk_ptr = evaluate(args[1])

	try:
		action = int(args[2])
	except IndexError:
		action = 1 # get backtrace history of free chunk pointer
	
	XNU_ZONES.zone_find_stack_elem(zone_name, chunk_ptr, action)
	return True
	
def cmd_xnu_find_chunk(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	global XNU_ZONES
	if not XNU_ZONES.is_loaded:
		XNU_ZONES.load_from_kernel(debugger.GetSelectedTarget())
	
	if not len(command):
		print('zone_find_chunk: <chunk_addr>')
		return False
	
	chunk_addr = evaluate(command)
	
	info = XNU_ZONES.find_chunk_info(chunk_addr)
	if info != None:
		zone_name = info['zone_name']
		zone_idx = info['zone_idx']
		status = info['status']
		print(f'[+] zone_array[{zone_idx}] ({zone_name}) - 0x{chunk_addr:X}({status})')
	else:
		print('[+] Your chunk address is not found in any zones.')
	
	return True

def cmd_xnu_zone_reload(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	global XNU_ZONES
	if XNU_ZONES.is_loaded:
		return
	
	print('[+] Reload XNU_ZONES')
	XNU_ZONES.load_from_kernel(debugger.GetSelectedTarget())

# -------------------------------------------------------

def cmd_addkext(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	kext_binary_path = Path(command).expanduser().absolute()

	if not kext_binary_path.exists():
		print('[!] Kext binary is not exists')
		return 1

	res = lldb.SBCommandReturnObject()
	debugger.GetCommandInterpreter().HandleCommand(f"target modules add {str(kext_binary_path)}", res)
	if not res.Succeeded():
		print('[!] "target modules add" error :', res.GetError())

	# find base address of kext module
	try:
		kernel_kext_addr = KEXT_INFO_DICTIONARY[kext_binary_path.stem].address
	except KeyError:
		print(f'[!] Unable to find base address of kext binary {kext_binary_path}')
		return 1
	
	res: SBCommandReturnObject = SBCommandReturnObject()
	debugger.GetCommandInterpreter().HandleCommand(
		f"target modules load --file {str(kext_binary_path)} --slide {hex(kernel_kext_addr)}", res)
	
	if not res.Succeeded():
		print('[!] "target modules load" error :', res.GetError())
		return 1

	print('[+] Done.')
	return 0

def cmd_xnu_showallkexts(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	xnu_showallkexts()

def cmd_xnu_breakpoint(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):	
	args = command.split(' ')
	if len(args) < 2:
		print('kbp <kext_name> <offset>')
		return

	kext_name = args[0]
	offset = int(args[1], 16)

	try:
		kext_info = KEXT_INFO_DICTIONARY[kext_name]
	except KeyError:
		print(f'[!] Couldn\'t found base address of kext {kext_name}')
		return

	base_address = kext_info.address
	target_address = offset + base_address

	target: SBTarget = debugger.GetSelectedTarget()
	target.BreakpointCreateByAddress(target_address)
	print('Done')

def cmd_xnu_to_offset(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	args = command.split(' ')
	if len(args) < 2:
		print('ktooff <kext_name> <address>')
		return

	kext_name = args[0]
	address = evaluate(args[1])

	try:
		kext_info = KEXT_INFO_DICTIONARY[kext_name]
	except KeyError:
		print(f'[!] Couldn\'t found base address of kext {kext_name}')
		return

	offset = address - kext_info.address
	print(f'Offsset from Kext {kext_name} base address : 0x{offset:X}')

def cmd_xnu_list_all_process(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	xnu_list_all_process()

def cmd_xnu_find_process_by_name(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	args = command.split(' ')
	if len(args) < 1:
		print('showproc <process name>')
		return

	proc_name = args[0]
	proc = xnu_find_process_by_name(proc_name)
	if proc == None:
		print(f'[!] Couldn\'t found your process {proc_name}')
		return

	p_name = proc.get('p_name').str_value
	p_pid = proc.get('p_pid').int_value
	task = get_ipc_task(proc)

	print(f'+ {"PID":<5} | {"Proc Name":<40} | {"Proc Address":<20} | {"Task Address":<20}')
	print(f'+ {p_pid:<5} | {p_name:<40} | {proc.int_value:#20x} | {task.int_value:#20x}')

def cmd_xnu_read_usr_addr(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	args = command.split(' ')
	if len(args) < 3:
		print('readusraddr <proc_name> <user space address> <size>')
		return

	process_name = args[0]
	proc = xnu_find_process_by_name(process_name)
	if proc == None:
		print('[!] Process does not found.')
		return
	
	user_space_addr = evaluate(args[1])
	try:
		size = int(args[2])
	except (TypeError, ValueError):
		size = 0x20

	raw_data = xnu_read_user_address(proc.get('task'), user_space_addr, size)
	print(hexdump(user_space_addr, raw_data, " ", 16))

def cmd_xnu_set_kdp_pmap(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	if get_connection_protocol() != 'kdp':
		print('[!] cmd_xnu_set_kdp_pmap() only works on kdp-remote')
		return

	args = command.split(' ')
	if len(args) < 1:
		print('setkdp <process name>')
		return
	
	target_proc = xnu_find_process_by_name(args[0])
	if target_proc == None:
		print(f'[!] Process {args[0]} does not found')
		return
	
	if xnu_write_task_kdp_pmap(target_proc.get('task')):
		print('[+] Set kdp_pmap ok.')
	else:
		print('[!] Set kdp_pmap failed.')

def cmd_xnu_reset_kdp_pmap(ddebugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	if get_connection_protocol() != 'kdp':
		print('[!] cmd_xnu_set_kdp_pmap() only works on kdp-remote')
		return

	if not xnu_reset_kdp_pmap():
		print(f'[!] Reset kdp_pmap failed.')
		return

	print('[+] Reset kdp_pmap ok.')

## ----- IOKit commands ----- ##
def cmd_iokit_print(ddebugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	args = command.split(' ')
	if len(args) < 1:
		print('cmd_iokit_print <address>')
		return
	
	address = evaluate(args[0])
	if not address:
		print(f'[!] Unable to detect iokit object at {address}')
		return
	
	iokit_print(address)
	return

def cmd_iokit_type(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	args = command.split(' ')
	if len(args) < 1:
		print('iokit_type <address>')
		return
	
	address = evaluate(args[0])
	if not address:
		print(f'[!] Unable to detect iokit object at {address}')
		return
	
	iokit_object_type = iokit_get_type(address)
	if not iokit_object_type:
		print(f'[!] Unable to detect iokit object at {hex(address)}')
	else:
		print(f'[+] iokit object at {hex(address)} is {iokit_object_type}')

## VMware / VirtualBox commands

def cmd_vm_show_vm(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	if not vmfusion_check():
		print('[!] This feature only support Vmware Fusion')
		return

	running_vms = get_all_running_vm()

	if not running_vms:
		print('[!] No virtual machine is running.')
		return

	for vm_name in running_vms:
		print(f'- {vm_name} : {running_vms[vm_name]}')

def cmd_vm_select_vm(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	if not vmfusion_check():
		print('[!] This feature only support Vmware Fusion')
		return

	global SelectedVM

	args = command.split('\n')
	if len(args) < 1:
		print('vmselect <vm_name>')
		return

	vm_name = args[0]
	running_vms = get_all_running_vm()
	if vm_name not in running_vms:
		print(f'[!] Couldn found your vm name {vm_name}')
		return

	SelectedVM = running_vms[vm_name]

def cmd_vm_take_snapshot(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	if not vmfusion_check():
		print('[!] This feature only support Vmware Fusion')
		return

	global SelectedVM

	args = command.split('\n')
	if len(args) < 1:
		print('vmsnapshot <snapshot name>')
		return

	if not SelectedVM:
		print('[!] Please run `vmselect` to select your vm')
		return

	take_vm_snapshot(SelectedVM, args[0])
	print('Done.')

def cmd_vm_reverse_snapshot(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	if not vmfusion_check():
		print('[!] This feature only support Vmware Fusion')
		return

	global SelectedVM

	args = command.split('\n')
	if len(args) < 1:
		print('vmreverse <snapshot name>')
		return

	if not SelectedVM:
		print('[!] Please run `vmselect` to select your vm')
		return

	revert_vm_snapshot(SelectedVM, args[0])
	print('Done.')

def cmd_vm_delete_snapshot(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	if not vmfusion_check():
		print('[!] This feature only support Vmware Fusion')
		return

	global SelectedVM

	args = command.split('\n')
	if len(args) < 1:
		print('vmreverse <snapshot name>')
		return

	if not SelectedVM:
		print('[!] Please run `vmselect` to select your vm')
		return

	delete_vm_snapshot(SelectedVM, args[0])
	print('Done.')

def cmd_vm_list_snapshot(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	if not vmfusion_check():
		print('[!] This feature only support Vmware Fusion')
		return

	global SelectedVM
	
	if not SelectedVM:
		print('[!] Please run `vmselect` to select your vm')
		return

	snapshots = list_vm_snapshot(SelectedVM)

	print('Current snapshot:')
	for snapshot in snapshots:
		print('-', snapshot)

# ------------------------------------------------------------
# The heart of lldbinit - when lldb stop this is where we land 
# ------------------------------------------------------------


prev_disas_addr = 0
PREV_INSTRUCTION_NUM = CONFIG_DISASSEMBLY_LINE_COUNT // 2 # number of previous execution instruction to be displayed

def HandleHookStopOnTarget(debugger: SBDebugger, command: str, result: SBCommandReturnObject, dict: Dict):
	'''Display current code context.'''
	# Don't display anything if we're inside Xcode
	if is_in_Xcode():
		return
	
	global GlobalListOutput
	global CONFIG_DISPLAY_STACK_WINDOW
	global CONFIG_DISPLAY_FLOW_WINDOW
	global POINTER_SIZE
	global prev_disas_addr

	debugger.SetAsync(True)

	POINTER_SIZE = get_pointer_size()

	# gui render code reads its own module global, keep it in sync (32-bit targets)
	gui.POINTER_SIZE = POINTER_SIZE

	# when we start the thread is still not valid and get_frame() will always generate a warning
	# this way we avoid displaying it in this particular case
	if get_process().GetNumThreads() == 1:
		thread = get_process().GetThreadAtIndex(0)
		if thread.IsValid() == False:
			return

	while True:
		try:
			frame = get_frame()
		except LLDBFrameNotFound as err:
			print(err)
			return

		thread: SBThread = frame.GetThread()
		if thread.GetStopReason() == lldb.eStopReasonInvalid:
			time.sleep(0.001)
		else:
			break
	
	if not frame.IsValid():
		print('[!] The frame is not valid, Does the process start correctly?')
		return

	GlobalListOutput.clear()
	
	arch = get_arch()
	if not is_supported_arch():
		#this is for ARM probably in the future... when I will need it...
		print("[-] error: Unknown architecture : " + arch)
		return

	color(COLOR_SEPARATOR)
	if is_i386() or is_arm():
		output("---------------------------------------------------------------------------------")
	elif is_x64() or is_aarch64():
		output("-----------------------------------------------------------------------------------------------------------------------")
			
	color("BOLD")
	output("[regs]\n")
	color("RESET")
	print_registers()

	if CONFIG_DISPLAY_STACK_WINDOW == 1:
		color(COLOR_SEPARATOR)
		if is_i386() or is_arm():
			output("--------------------------------------------------------------------------------")
		elif is_x64() or is_aarch64():
			output("----------------------------------------------------------------------------------------------------------------------")
		color("BOLD")
		output("[stack]\n")
		color("RESET")
		display_stack()
		output("\n")

	if CONFIG_DISPLAY_DATA_WINDOW == 1:
		color(COLOR_SEPARATOR)
		if is_i386() or is_arm():
			output("---------------------------------------------------------------------------------")
		elif is_x64() or is_aarch64():
			output("-----------------------------------------------------------------------------------------------------------------------")
		color("BOLD")
		output("[data]\n")
		color("RESET")
		display_data()
		output("\n")

	if CONFIG_DISPLAY_FLOW_WINDOW == 1 and (is_x64() or is_aarch64()):
		color(COLOR_SEPARATOR)
		if is_i386() or is_arm():
			output("---------------------------------------------------------------------------------")
		elif is_x64() or is_aarch64():
			output("-----------------------------------------------------------------------------------------------------------------------")
		color("BOLD")
		output("[flow]\n")
		color("RESET")
		display_indirect_flow()

	color(COLOR_SEPARATOR)
	if is_i386() or is_arm():
		output("---------------------------------------------------------------------------------")
	elif is_x64() or is_aarch64():
		output("-----------------------------------------------------------------------------------------------------------------------")
	color("BOLD")
	output("[code]\n")
	color("RESET")

	if not prev_disas_addr:
		prev_disas_addr = get_current_pc()

	cur_pc = get_current_pc()

	# improve better display disasseble instructions 
	if cur_pc > prev_disas_addr:
		# get number of instructions from prev_disas_addr to cur_pc
		count = get_instruction_count(prev_disas_addr, cur_pc, CONFIG_DISASSEMBLY_LINE_COUNT)

		# update prev_disas_addr with cur_pc when number of previous instruction reach the limit
		if count > PREV_INSTRUCTION_NUM or count == 0:
			prev_disas_addr = cur_pc

	elif cur_pc < prev_disas_addr:
		# in this case cur_pc jump into another location, update prev_disas_addr
		prev_disas_addr = cur_pc

	# disassemble and add its contents to output inside
	disassemble(prev_disas_addr, CONFIG_DISASSEMBLY_LINE_COUNT)
		
	color(COLOR_SEPARATOR)
	if POINTER_SIZE == 4:
		output("---------------------------------------------------------------------------------------")
	elif POINTER_SIZE == 8:
		output("-----------------------------------------------------------------------------------------------------------------------------")
	color("RESET")
	
	# XXX: do we really need to output all data into the array and then print it in a single go? faster to just print directly?
	# was it done this way because previously disassembly was capturing the output and modifying it?
	data = "".join(GlobalListOutput)
	result.PutCString(data)
	result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
	return 0
