#
# ida_server.py
# Live read-only symbol server running inside IDA.
# Mirrors the CustomSymbols query interface over http/json - each
# endpoint answers one query computed from the idb on request, nothing
# is cached and the idb is never modified. Server addresses are ida
# default mapped addresses (the same values the json dump contains),
# the debugger client applies the slide.
#
# Usage inside IDA:
#   import ida_server
#   ida_server.start()          # listens on 127.0.0.1:<random port, printed on start>
#   ida_server.stop()
# or just run this file as a script (auto-starts, random port on first load).
# The port can be changed any time from Edit > Plugins > 'ida_server: set port...'
#
# Endpoints (mirror CustomSymbols):
#   GET /status                 -> {'tool', 'file', 'image_base'}
#   GET /query_func_name?addr=  -> {'name': str}
#   GET /query_func_addr?name=  -> {'addr': int or null}
#   GET /query_var_name?addr=   -> {'name': str}
#   GET /query_segment?addr=    -> {'segment': {...} or null}
#   GET /query_struct?name=     -> {'struct': {'name','size','fields'} or null}
#

import json
import random
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import idaapi
import ida_funcs
import ida_kernwin
import ida_segment
import ida_typeinf
import idc

HOST = '127.0.0.1'
PORT_RANGE = (20000, 60000) # random first-load port range

_server = None
_port = None # remembered across stops so restarts reuse the same port

def pick_port():
    """random port for the first load, changes every ida session"""
    return random.randint(PORT_RANGE[0], PORT_RANGE[1])

# ---------------------------
# IDA 8 / 9 compatibility shims (same as ida_symbols.py)
# ---------------------------

HAS_SEGMENT_INFO_API = hasattr(ida_segment, 'get_segment_info_by_num')

def get_segment_by_num(n):
    """return segment info (IDA 9) or segment_t (IDA 8) by number, None if out of range"""
    if HAS_SEGMENT_INFO_API:
        info = ida_segment.segment_info_t()
        if ida_segment.get_segment_info_by_num(info, n):
            return info

        return None

    return ida_segment.getnseg(n)

def get_segment_perm(seg):
    """segment permissions, IDA 9 exposes get_perm(), IDA 8 has .perm"""
    return seg.get_perm() if HAS_SEGMENT_INFO_API else seg.perm

# ---------------------------
# main thread marshaling - ida sdk functions are main thread only
# ("Function can be called from the main thread only"), execute_sync
# is the one thread safe way in from the http worker threads
# ---------------------------

def run_on_main(func, *args):
    """execute an ida sdk call on ida's main thread and return its result"""
    if idaapi.is_main_thread():
        return func(*args)

    box = []
    def runner():
        try:
            box.append((func(*args), None))
        except Exception as e:
            box.append((None, e))
        return 0

    # MFF_READ: acquire an idb read lock, our queries never write
    idaapi.execute_sync(runner, idaapi.MFF_READ)
    value, err = box[0] if box else (None, RuntimeError('main thread call did not run'))
    if err:
        raise err

    return value

# ---------------------------
# CustomSymbols-equivalent queries, computed live from the idb
# ---------------------------

def perm_to_str(perm):
    """format a SEGPERM_* bitmask as the 'rwx' string style of the json dump"""
    return (('r' if perm & ida_segment.SEGPERM_READ else '-') +
            ('w' if perm & ida_segment.SEGPERM_WRITE else '-') +
            ('x' if perm & ida_segment.SEGPERM_EXEC else '-'))

def query_segment(addr):
    """segment containing addr, same dict shape as the json dump"""
    for i in range(ida_segment.get_segm_qty()):
        seg = get_segment_by_num(i)
        if seg and seg.start_ea <= addr < seg.end_ea:
            return {
                'name': idc.get_segm_name(seg.start_ea),
                'start': seg.start_ea,
                'end': seg.end_ea,
                'perms': perm_to_str(get_segment_perm(seg)),
            }

    return None

def query_func_name(addr):
    """function name for addr: exact start, else nearest preceding function"""
    func = ida_funcs.get_func(addr)
    if not func:
        # addr falls in a gap - mirror the bisect behavior of
        # CustomSymbols and use the nearest function before it
        func = ida_funcs.get_prev_func(addr)

    if func:
        return idc.get_func_name(func.start_ea)

    return ''

def query_func_addr(name):
    """reverse lookup: function start ea by exact name, None if not a function"""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        return None

    func = ida_funcs.get_func(ea)
    if func and func.start_ea == ea:
        return ea

    return None

def query_var_name(addr):
    """data name at addr, empty when the address is inside a function"""
    if ida_funcs.get_func(addr):
        return ''

    name = idc.get_name(addr)
    return name if name else ''

def query_struct(name):
    """struct layout from the local types: name, size and field list, None if unknown"""
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), name):
        return None

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        # named type exists but is not a struct/union
        return None

    fields = []
    for m in udt:
        # ida stores member offsets in bits, sizes come back via the
        # member type (BADSIZE for unsized types shows as 0)
        size = m.type.get_size()
        if size > 0x7FFFFFFF:
            size = 0

        fields.append({
            'name': m.name,
            'offset': m.offset // 8,
            'size': size,
            'type': str(m.type),
        })

    total = tif.get_size()
    return {
        'name': name,
        'size': total if total <= 0x7FFFFFFF else 0,
        'fields': fields,
    }

# ---------------------------
# http plumbing
# ---------------------------

class SymbolRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        params = parse_qs(url.query)

        try:
            if url.path == '/status':
                image_base, idb_file = run_on_main(
                    lambda: (idaapi.get_imagebase(), idaapi.get_root_filename()))
                self._send_json({
                    'tool': 'ida',
                    'file': idb_file,
                    'image_base': image_base,
                })

            elif url.path == '/query_func_name':
                addr = int(params['addr'][0], 16)
                self._send_json({'name': run_on_main(query_func_name, addr)})

            elif url.path == '/query_func_addr':
                name = params['name'][0]
                self._send_json({'addr': run_on_main(query_func_addr, name)})

            elif url.path == '/query_var_name':
                addr = int(params['addr'][0], 16)
                self._send_json({'name': run_on_main(query_var_name, addr)})

            elif url.path == '/query_segment':
                addr = int(params['addr'][0], 16)
                self._send_json({'segment': run_on_main(query_segment, addr)})

            elif url.path == '/query_struct':
                name = params['name'][0]
                self._send_json({'struct': run_on_main(query_struct, name)})

            else:
                self._send_json({'error': 'unknown path ' + url.path}, code=404)

        except (KeyError, ValueError) as e:
            self._send_json({'error': str(e)}, code=400)
        except Exception as e:
            self._send_json({'error': str(e)}, code=500)

    def log_message(self, fmt, *args):
        # route access logs to the ida output window
        print('[ida_server] ' + fmt % args)

def start(port=None):
    """start the symbol server (idempotent), port None picks a random one on first load"""
    global _server, _port
    if _server is not None:
        print('[ida_server] already running on {0}:{1}'.format(HOST, _server.server_address[1]))
        return

    if port is None:
        port = _port or pick_port()

    try:
        _server = ThreadingHTTPServer((HOST, port), SymbolRequestHandler)
    except OSError as e:
        _server = None
        print('[ida_server] unable to bind {0}:{1} - {2}'.format(HOST, port, e))
        return

    _port = port
    thread = threading.Thread(target=_server.serve_forever, daemon=True)
    thread.start()
    print('[ida_server] listening on {0}:{1} (http, read-only)'.format(HOST, port))

def stop():
    """stop the symbol server if running"""
    global _server
    if _server is None:
        print('[ida_server] not running')
        return

    _server.shutdown()
    _server.server_close()
    _server = None
    print('[ida_server] stopped')

# ---------------------------
# Edit > Plugins > 'ida_server: set port...'
# ---------------------------

def on_menu_set_port():
    """popup asking for the port, restarts the server when it changes"""
    current = _server.server_address[1] if _server is not None else (_port or pick_port())

    port = ida_kernwin.ask_long(current, 'Symbol server port (randomized on first load):')
    if port is None:
        # dialog cancelled
        return

    if port < 1 or port > 65535:
        print('[ida_server] invalid port {0}'.format(port))
        return

    if _server is not None and _server.server_address[1] == port:
        print('[ida_server] already listening on {0}:{1}'.format(HOST, port))
        return

    stop()
    start(port)

class _set_port_handler_t(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        on_menu_set_port()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

def register_menu():
    """register the action and attach it under Edit > Plugins"""
    desc = ida_kernwin.action_desc_t('ida_server:set_port', 'ida_server: set port...', _set_port_handler_t())
    ida_kernwin.register_action(desc)
    ida_kernwin.attach_action_to_menu('Edit/Plugins/ida_server: set port...', desc, ida_kernwin.SETMENU_APP)
    print('[ida_server] menu added: Edit > Plugins > ida_server: set port...')

# auto start when executed as a script file inside IDA
start()
try:
    register_menu()
except Exception as e:
    # menu registration must never break the server itself
    print('[ida_server] menu registration failed - {0}'.format(e))
