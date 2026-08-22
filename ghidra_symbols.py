# ghidra_symbols.py
# Ghidra script equivalent of ida_symbols.py
#
# Exports all functions and named symbols (labels / globals / data) to
# /tmp/custom_syms.json in the schema that lldbinit's `sym load` expects:
#
#   {
#       "functions": { "<int addr>": "<name>", ... },
#       "variables": { "<int addr>": "<name>", ... },
#       "segments":  [ {"name": str, "start": int, "end": int}, ... ]
#   }
#
# Note: Ghidra's MemoryBlock.getEnd() returns the last inclusive byte address.
# We add +1 to match IDA's exclusive end_ea convention used by query_segment().
#
# Usage:
#   In Ghidra:  Window > Script Manager > Run Script  (or bind to a key)
#   Headless:   analyzeHeadless <project> <program> -postScript ghidra_symbols.py
#
# After running, in LLDB:
#   (lldbinit) sym load /tmp/custom_syms.json

# @category lldbinit
# @author   peternguyen

import json

OUTPUT_PATH = '/tmp/custom_syms.json'

def dump_all_symbols():
    results = {
        'functions': {},
        'variables': {},
        'segments':  [],
    }

    # ── Functions ─────────────────────────────────────────────────────────────
    func_manager = currentProgram.getFunctionManager()
    for func in func_manager.getFunctions(True):
        entry_point = func.getEntryPoint().getOffset()
        func_name   = func.getName(True)   # True = include namespace
        results['functions'][entry_point] = func_name

    # ── Named symbols (labels / globals / data) ────────────────────────────────
    symbol_table = currentProgram.getSymbolTable()
    for sym in symbol_table.getAllSymbols(True):
        # Skip DEFAULT / unnamed symbols (Ghidra auto-names like "DAT_", "FUN_")
        if sym.getSource().toString() == 'DEFAULT':
            continue
        addr = sym.getAddress()
        # Skip non-memory / external addresses
        if not addr.isMemoryAddress():
            continue
        results['variables'][addr.getOffset()] = sym.getName(True)

    # ── Memory segments (blocks) ───────────────────────────────────────────────
    # Ghidra has no direct end_ea — getEnd() returns the last inclusive byte,
    # so we calculate the exclusive end ourselves with +1.
    memory = currentProgram.getMemory()
    for block in memory.getBlocks():
        start_ea = block.getStart().getOffset()
        end_ea   = block.getEnd().getOffset() + 1   # exclusive end, like IDA
        perms    = (('r' if block.isRead()    else '-') +
                    ('w' if block.isWrite()   else '-') +
                    ('x' if block.isExecute() else '-'))
        results['segments'].append({
            'name':  block.getName(),
            'start': start_ea,
            'end':   end_ea,
            'perms': perms,
        })

    # ── Write JSON ─────────────────────────────────────────────────────────────
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(results, f, indent=2)

    print('[+] dump_all_symbols() done -> {}'.format(OUTPUT_PATH))
    print('    functions : {}'.format(len(results['functions'])))
    print('    variables : {}'.format(len(results['variables'])))
    print('    segments  : {}'.format(len(results['segments'])))

dump_all_symbols()
