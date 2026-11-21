# ghidra_structs.py
# Import / export dyld shared-cache struct JSON for the current program.
#
# Schema (one JSON list entry, see
#   dyld_shared_cache_<ver>_all_structs.json):
#   {
#     "name": str, "ordinal": int, "kind": "struct"|"union"|"enum",
#     "total_size_bytes": int, "field_count": int,
#     "fields": [ {"name","type","offset_bits","offset_bytes",
#                  "size_bits","size_bytes","is_bitfield"}, ... ],
#     "cdecl": str, "pulled_dep": true (only on dependency-only entries)
#   }
#
# Usage: run once as a Ghidra script - it registers
#   Edit > dyld_structs: import JSON...
#   Edit > dyld_structs: export JSON...
# both pop a file chooser (falls back to a path prompt if askFile is
# unavailable in this Ghidra version).
#
# Types land in the data type manager under /dyld_structs, ordinal order
# (dependencies first), so later entries resolve against earlier ones.

# @category lldbinit
# @author   peternguyen

import json
import re

DEFAULT_JSON_PATH = ('/Users/user/Sources/dyld_share_caches/macOS_26_5_2/'
                     'dyld_shared_cache_arm64e_all_structs.json')
CATEGORY = '/dyld_structs'

# ---------------------------------------------------------------------------
# pure schema helpers (keep in sync with ida_structs.py)
# ---------------------------------------------------------------------------

def sort_entries(entries):
    """stable ascending ordinal order - dependencies sort before users"""
    return sorted(entries, key=lambda e: e['ordinal'])

def _parse_field_type(tstr):
    """split a dyld field type into base name, pointer depth and array length"""
    t = tstr.strip()
    arr = None
    m = re.search(r'\[(\d+)\]\s*$', t)
    if m:
        arr = int(m.group(1))
        t = t[:m.start()].strip()
    ptr = 0
    while t.endswith('*'):
        ptr += 1
        t = t[:-1].strip()
    t = re.sub(r'^(struct|union|enum)\s+', '', t)
    return {'base': t, 'ptr': ptr, 'array': arr}

def cdecl_from_fields(kind, name, fields):
    """rebuild the dyld-style cdecl from fields metadata (struct/union only)"""
    kw = 'struct' if kind == 'struct' else 'union'
    out = ['{0} {1}\n{{\n'.format(kw, name)]
    for f in fields:
        p = _parse_field_type(f['type'])
        stars = '*' * p['ptr']
        suffix = '[{0}]'.format(p['array']) if p['array'] else ''
        out.append('  {0} {1}{2}{3};\n'.format(p['base'], stars, f['name'], suffix))
    out.append('};\n')
    return ''.join(out)

def parse_enum_cdecl(cdecl):
    """parse 'enum Name : __intN { A = 0x0, ... };' -> (name, [(key, value)...])"""
    m = re.search(r'enum\s+(?:__\w+\s+)*(\w+)[^{]*\{(.*)\}', cdecl, re.S)
    if not m:
        raise ValueError('unrecognized enum cdecl: ' + cdecl[:60])
    name, body = m.group(1), m.group(2)
    out = []
    nxt = 0
    for item in body.split(','):
        item = item.strip()
        if not item:
            continue
        if '=' in item:
            key, val = item.split('=', 1)
            # strip C integer suffixes (0x0u, 1UL, ...)
            val = int(re.sub(r'[uUlL]+$', '', val.strip()), 0)
            nxt = val + 1
        else:
            key, val = item, nxt
            nxt += 1
        out.append((key.strip(), val))
    return name, out

def schema_entry(name, kind, total_size_bytes, fields, cdecl, ordinal,
                 pulled_dep=False):
    """emit one entry in the exact dyld JSON schema (pulled_dep only when set)"""
    entry = {
        'name': name,
        'ordinal': ordinal,
        'kind': kind,
        'total_size_bytes': total_size_bytes,
        'field_count': len(fields),
        'fields': fields,
        'cdecl': cdecl,
    }
    if pulled_dep:
        entry['pulled_dep'] = True
    return entry

# ---------------------------------------------------------------------------
# host side (ghidra / pyghidra)
# ---------------------------------------------------------------------------

try:
    import jpype
    from docking.action.builder import ActionBuilder
    _ACTION_MODE = 'pyghidra'
except ImportError:
    _ACTION_MODE = None

if _ACTION_MODE == 'pyghidra':
    @jpype.JImplements('java.util.function.Consumer')
    class _ImportCallback(object):
        """menu callback: pick a json file and import it"""
        @jpype.JOverride
        def accept(self, context):
            import_json()

    @jpype.JImplements('java.util.function.Consumer')
    class _ExportCallback(object):
        """menu callback: pick a json file and export to it"""
        @jpype.JOverride
        def accept(self, context):
            export_json()

    @jpype.JImplements('java.lang.Runnable')
    class _EdtTask(object):
        """Runnable shim: wraps a python callable for ghidra.util.Swing.runNow"""
        def __init__(self, fn):
            self._fn = fn

        @jpype.JOverride
        def run(self):
            self._fn()

    def _run_on_edt(fn):
        """run fn on the swing EDT and wait - ghidra 12 runs scripts on a
           background thread but tool menu mutations must happen on EDT"""
        from ghidra.util import Swing
        Swing.runNow(_EdtTask(fn))

def _pick_path(save):
    """file chooser for import (save=False) / export (save=True)"""
    try:
        picked = askFile('dyld structs JSON', 'Export' if save else 'Import')
        return picked.getAbsolutePath() if picked is not None else None
    except NameError:
        return askString('dyld structs JSON', 'Path:', DEFAULT_JSON_PATH)

def _resolve_datatype(dtm, f):
    """turn a dyld field into a ghidra DataType, undefined fallback keeps layout"""
    from ghidra.program.model.data import ArrayDataType
    from ghidra.program.model.data import PointerDataType
    info = _parse_field_type(f['type'])
    elem = dtm.getDataType(CATEGORY + '/' + info['base'])
    if elem is None:
        elem = dtm.getDataType('/' + info['base'])
    if info['ptr']:
        return PointerDataType(elem, 8)   # arm64e pointers
    if info['array']:
        elem_size = max(1, f['size_bytes'] // info['array'])
        if elem is None:
            elem = _undefined(elem_size)
        return ArrayDataType(elem, info['array'], elem_size)
    if elem is None:
        elem = _undefined(f['size_bytes'])
    return elem

def _undefined(size):
    """ghidra 12: UndefinedDataType is gone - the Undefined factory covers
       sizes 1..8 and returns an undefined1[n] array beyond that"""
    from ghidra.program.model.data import Undefined
    return Undefined.getUndefinedDataType(max(1, size))

def _add_struct(dtm, cat, e):
    from ghidra.program.model.data import DataTypeConflictHandler
    from ghidra.program.model.data import StructureDataType
    s = StructureDataType(cat, e['name'], e['total_size_bytes'])
    for f in e['fields']:
        dt = _resolve_datatype(dtm, f)
        try:
            s.replaceAtOffset(f['offset_bytes'], dt, dt.getLength(),
                              f['name'], None)
        except Exception:
            s.insertAtOffset(f['offset_bytes'], dt, dt.getLength())
    dtm.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER)

def _add_union(dtm, cat, e):
    from ghidra.program.model.data import DataTypeConflictHandler
    from ghidra.program.model.data import UnionDataType
    u = UnionDataType(cat, e['name'])
    for f in e['fields']:
        dt = _resolve_datatype(dtm, f)
        u.add(dt, dt.getLength(), f['name'], None)
    dtm.addDataType(u, DataTypeConflictHandler.DEFAULT_HANDLER)

def _add_enum(dtm, cat, e):
    from ghidra.program.model.data import DataTypeConflictHandler
    from ghidra.program.model.data import EnumDataType
    m = re.search(r':\s*__int(\d+)', e['cdecl'])
    size = int(m.group(1)) // 8 if m else 4
    en = EnumDataType(cat, e['name'], size)
    for key, val in parse_enum_cdecl(e['cdecl'])[1]:
        if val is not None:
            en.add(key, val)
    dtm.addDataType(en, DataTypeConflictHandler.DEFAULT_HANDLER)

def import_json(path=None):
    """import the struct json into the program's data type manager"""
    path = path or _pick_path(save=False)
    if not path:
        return
    with open(path) as fh:
        entries = sort_entries(json.load(fh))
    from ghidra.program.model.data import CategoryPath
    dtm = currentProgram.getDataTypeManager()
    cat = CategoryPath(CATEGORY)
    tx = dtm.startTransaction('dyld_structs import')
    ok, failed = 0, []
    try:
        for e in entries:
            try:
                if e['kind'] == 'enum':
                    _add_enum(dtm, cat, e)
                elif e['kind'] == 'union':
                    _add_union(dtm, cat, e)
                else:
                    _add_struct(dtm, cat, e)
                ok += 1
            except Exception as ex:
                failed.append((e['name'], str(ex)))
    finally:
        dtm.endTransaction(tx, True)
    print('[dyld_structs] imported {0}/{1} from {2}'.format(ok, len(entries), path))
    for name, err in failed[:20]:
        print('[dyld_structs]   failed: {0} - {1}'.format(name, err))
    if len(failed) > 20:
        print('[dyld_structs]   ... {0} more'.format(len(failed) - 20))

def _composite_entry(dt, ordinal):
    """export one ghidra Composite (struct/union) as a dyld schema entry"""
    from ghidra.program.model.data import UnionDataType
    kind = 'union' if isinstance(dt, UnionDataType) else 'struct'
    fields = []
    for c in dt.getComponents():
        try:
            is_bf = bool(c.isBitFieldComponent())
        except Exception:
            is_bf = False
        size_bytes = c.getLength()
        off = c.getOffset()
        fields.append({
            'name': c.getFieldName() or '',
            'type': c.getDataType().getDisplayName(),
            'offset_bits': off * 8,
            'offset_bytes': off,
            'size_bits': size_bytes * 8,
            'size_bytes': size_bytes,
            'is_bitfield': is_bf,
        })
    return schema_entry(dt.getName(), kind, dt.getLength(), fields,
                        cdecl_from_fields(kind, dt.getName(), fields), ordinal)

def _enum_entry(dt, ordinal):
    """export one ghidra Enum as a dyld schema entry (cdecl only, like dyld)"""
    size = dt.getLength()
    lines = ['enum {0} : __int{1}\n{{\n'.format(dt.getName(), size * 8)]
    for name in list(dt.getNames()):
        lines.append('  {0} = {1},\n'.format(name, hex(dt.getValue(name))))
    lines.append('};\n')
    return schema_entry(dt.getName(), 'enum', 0, [], ''.join(lines), ordinal)

def _builtin_archive_type(dtm):
    """archive type marker for built-ins, detected from an undefined1 sentinel"""
    from ghidra.program.model.data import Undefined
    sentinel = Undefined.getUndefinedDataType(1)
    archive = sentinel.getSourceArchive()
    return archive.getArchiveType() if archive is not None else None

def export_json(path=None):
    """export the program's composites/enums as dyld struct json"""
    from ghidra.program.model.data import Composite
    from ghidra.program.model.data import Enum
    path = path or _pick_path(save=True)
    if not path:
        return
    dtm = currentProgram.getDataTypeManager()
    builtin_archive = _builtin_archive_type(dtm)
    entries = []
    for dt in dtm.getAllDataTypes():
        if not (isinstance(dt, Composite) or isinstance(dt, Enum)):
            continue
        archive = dt.getSourceArchive()
        if (builtin_archive is not None and archive is not None and
                archive.getArchiveType().equals(builtin_archive)):
            continue   # resolved built-in, not user content
        try:
            if isinstance(dt, Enum):
                entries.append(_enum_entry(dt, len(entries)))
            else:
                entries.append(_composite_entry(dt, len(entries)))
        except Exception as ex:
            print('[dyld_structs]   export failed: {0} - {1}'.format(
                dt.getName(), ex))
    with open(path, 'w') as fh:
        json.dump(entries, fh)
    print('[dyld_structs] exported {0} types -> {1}'.format(len(entries), path))

_actions = None

def add_menus(tool):
    """register the Edit menu actions (idempotent)"""
    global _actions
    if _ACTION_MODE is None:
        print('[dyld_structs] pyghidra engine unavailable, menu not added')
        return
    if tool is None:
        print('[dyld_structs] no tool bound, menu not added')
        return
    if _actions is not None:
        return
    imp = (ActionBuilder('dyld_structs import json', 'dyld_structs')
           .menuPath('Edit', 'dyld_structs: import JSON...')
           .menuGroup('zzDyldStructs')
           .onAction(_ImportCallback())
           .build())
    exp = (ActionBuilder('dyld_structs export json', 'dyld_structs')
           .menuPath('Edit', 'dyld_structs: export JSON...')
           .menuGroup('zzDyldStructs')
           .onAction(_ExportCallback())
           .build())
    _actions = (imp, exp)
    _run_on_edt(lambda: tool.addAction(imp))
    _run_on_edt(lambda: tool.addAction(exp))
    print('[dyld_structs] menu added: Edit > dyld_structs: import/export JSON...')

# auto register when executed as a ghidra script (currentProgram is
# injected by the script engine); silent when imported as a plain module
try:
    if currentProgram is not None:
        add_menus(state.getTool())
except NameError:
    pass
