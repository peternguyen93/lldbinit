# ida_structs.py
# Import / export dyld shared-cache struct JSON for the current IDB.
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
# Usage: run once via File > Script file... - it registers
#   Edit > dyld_structs: import JSON...
#   Edit > dyld_structs: export JSON...
# both pop a file chooser.
#
# Import feeds each cdecl to parse_decls in ordinal order (dependencies
# first) into the Local Types til; failures are reported per name and
# never abort the run. Export walks the Local Types ordinals.

import json
import re

DEFAULT_JSON_PATH = ('/Users/user/Sources/dyld_share_caches/macOS_26_5_2/'
                     'dyld_shared_cache_arm64e_all_structs.json')

# guarded so the pure schema helpers stay testable outside IDA
try:
    import ida_kernwin
    import ida_typeinf
    _IN_IDA = True
except ImportError:
    _IN_IDA = False

# ---------------------------------------------------------------------------
# pure schema helpers (keep in sync with ghidra_structs.py)
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
# host side (IDA)
# ---------------------------------------------------------------------------

def _pick_path(save):
    return ida_kernwin.ask_file(
        save, DEFAULT_JSON_PATH,
        'Export dyld structs JSON' if save else 'Import dyld structs JSON')

def import_json(path=None):
    """import the struct json into Local Types via the built-in C parser"""
    path = path or _pick_path(False)
    if not path:
        return
    with open(path) as fh:
        entries = sort_entries(json.load(fh))
    til = ida_typeinf.get_idati()
    flags = getattr(ida_typeinf, 'PT_REPLACE', 0)
    ok, failed = 0, []
    for e in entries:
        try:
            r = ida_typeinf.parse_decls(til, e['cdecl'], None, flags)
            if r is None or r < 0:
                raise RuntimeError('parse_decls rejected the declaration')
            ok += 1
        except Exception as ex:
            failed.append((e['name'], str(ex)))
    print('[dyld_structs] imported {0}/{1} from {2}'.format(ok, len(entries), path))
    for name, err in failed[:20]:
        print('[dyld_structs]   failed: {0} - {1}'.format(name, err))
    if len(failed) > 20:
        print('[dyld_structs]   ... {0} more'.format(len(failed) - 20))

def _print_tinfo(tif, name):
    """full C declaration of a local type, dyld cdecl style"""
    try:
        flags = (ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE |
                 ida_typeinf.PRTYPE_SEMI)
        return ida_typeinf.print_tinfo('', 2, '', flags, tif, name, '')
    except Exception:
        return str(tif)

def _enum_entry(tif, ordinal):
    """export one IDA enum as a dyld schema entry (cdecl only, like dyld)"""
    name = tif.get_type_name()
    details = ida_typeinf.enum_details_t()
    tif.get_enum_details(details)
    size = tif.get_size() or 4
    lines = ['enum {0} : __int{1}\n{{\n'.format(name, size * 8)]
    for i in range(len(details)):
        member = details[i]
        lines.append('  {0} = {1},\n'.format(member.name, hex(member.value)))
    lines.append('};\n')
    return schema_entry(name, 'enum', 0, [], ''.join(lines), ordinal)

def _udt_entry(tif, ordinal):
    """export one IDA struct/union as a dyld schema entry"""
    kind = 'union' if tif.is_union() else 'struct'
    name = tif.get_type_name()
    udt = ida_typeinf.udt_member_t()
    if not tif.get_udt_details(udt):
        return None
    fields = []
    for m in udt:
        mt = m.type
        try:
            size_bytes = mt.get_size()
        except Exception:
            size_bytes = 0
        size_bytes = max(0, size_bytes or 0)
        is_bf = bool(m.is_bitfield()) if hasattr(m, 'is_bitfield') else False
        fields.append({
            'name': m.name or '',
            'type': str(mt),
            'offset_bits': m.offset,
            'offset_bytes': m.offset // 8,
            'size_bits': size_bytes * 8,
            'size_bytes': size_bytes,
            'is_bitfield': is_bf,
        })
    return schema_entry(name, kind, tif.get_size() or 0, fields,
                        _print_tinfo(tif, name), ordinal)

def export_json(path=None):
    """export Local Types composites/enums as dyld struct json"""
    path = path or _pick_path(True)
    if not path:
        return
    til = ida_typeinf.get_idati()
    entries = []
    for ordinal in range(1, ida_typeinf.get_ordinal_qty(til)):
        tif = ida_typeinf.tinfo_t()
        try:
            if not tif.get_numbered_type(til, ordinal):
                continue
        except Exception:
            continue
        try:
            if tif.is_enum():
                entry = _enum_entry(tif, len(entries))
            elif tif.is_struct() or tif.is_union():
                entry = _udt_entry(tif, len(entries))
            else:
                continue   # typedefs / function pointers are not in the schema
            if entry is not None:
                entries.append(entry)
        except Exception as ex:
            print('[dyld_structs]   export failed: {0} - {1}'.format(
                tif.get_type_name(), ex))
    with open(path, 'w') as fh:
        json.dump(entries, fh)
    print('[dyld_structs] exported {0} types -> {1}'.format(len(entries), path))

if _IN_IDA:
    class _ImportHandler(ida_kernwin.action_handler_t):
        def activate(self, ctx):
            import_json()
            return 1

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    class _ExportHandler(ida_kernwin.action_handler_t):
        def activate(self, ctx):
            export_json()
            return 1

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    def add_menus():
        """register the Edit menu actions (idempotent per session)"""
        for name, label, handler in (
                ('dyld_structs:import', 'dyld_structs: import JSON...',
                 _ImportHandler),
                ('dyld_structs:export', 'dyld_structs: export JSON...',
                 _ExportHandler)):
            desc = ida_kernwin.action_desc_t(name, label, handler(), None,
                                             label, -1)
            # drop stale registrations from earlier runs of this script
            ida_kernwin.unregister_action(name)
            ida_kernwin.register_action(desc)
            # flags arg is a reserved int - placement comes from the menupath
            ida_kernwin.attach_action_to_menu('Edit/' + label, name)
        print('[dyld_structs] menu added: Edit > '
              'dyld_structs: import/export JSON...')

    try:
        add_menus()
    except Exception as ex:
        print('[dyld_structs] menu registration failed: {0}'.format(ex))
