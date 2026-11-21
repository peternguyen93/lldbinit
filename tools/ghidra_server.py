#
# ghidra_server.py
# Live read-only symbol server running inside Ghidra (same contract as
# ida_server.py). Mirrors the CustomSymbols query interface over
# http/json - each endpoint answers one query computed from the program
# on request, nothing is cached and the program is never modified.
# Server addresses are ghidra image addresses (the same values a json
# dump would contain), the debugger client applies the slide.
#
# Usage inside Ghidra (Script Manager - add this dir and run):
#   running the script auto-starts the server on a random first-load port
#   (printed on start), or from another script:
#   import ghidra_server; ghidra_server.start(currentProgram)
#   ghidra_server.stop()
# The port can be changed any time from the tool menu: Edit > 'ghidra_server: set port...'
# Compatible with both script engines: Jython 2.7 and PyGhidra (python3).
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
import socket
import threading

try:
    # python3 (PyGhidra)
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs
except ImportError:
    # jython 2.7
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from SocketServer import ThreadingMixIn
    from urlparse import urlparse, parse_qs

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

HOST = '127.0.0.1'
PORT_RANGE = (20000, 60000) # random first-load port range

# ghidra stores offsets as signed java long, addresses above
# 0x8000000000000000 come back negative - normalize on the way out
MASK64 = 0xFFFFFFFFFFFFFFFF

_program = None
_server = None
_port = None # remembered across stops so restarts reuse the same port

def pick_port():
    """random port for the first load, changes every ghidra session"""
    return random.randint(PORT_RANGE[0], PORT_RANGE[1])

def get_program():
    if _program is None:
        raise RuntimeError('no program bound, run start(currentProgram) first')

    return _program

# ---------------------------
# CustomSymbols-equivalent queries, computed live from the program
# ---------------------------

def query_segment(addr):
    """memory block containing addr, same dict shape as the json dump"""
    program = get_program()
    block = program.getMemory().getBlock(addr)
    if not block:
        return None

    return {
        'name': block.getName(),
        'start': block.getStart().getOffset() & MASK64,
        # ghidra block end is inclusive, the dump end is exclusive
        'end': (block.getEnd().getOffset() + 1) & MASK64,
        'perms': ('r' if block.isRead() else '-') +
                 ('w' if block.isWrite() else '-') +
                 ('x' if block.isExecute() else '-'),
    }

def query_func_name(addr):
    """function name for addr: containing function, else nearest preceding"""
    program = get_program()
    func_mgr = program.getFunctionManager()
    func = func_mgr.getFunctionAt(addr)
    if not func:
        # addr falls in a gap - mirror the bisect behavior of
        # CustomSymbols and use the nearest function before it
        func = func_mgr.getFunctionBefore(addr)

    if func:
        return func.getName()

    return ''

def query_func_addr(name):
    """reverse lookup: function entry offset by exact name, None if not a function"""
    program = get_program()
    matches = program.getFunctionManager().getGlobalFunctions(name)
    if matches:
        return matches[0].getEntryPoint().getOffset() & MASK64

    return None

def query_var_name(addr):
    """data/symbol name at addr, empty when the address is inside a function"""
    program = get_program()
    if program.getFunctionManager().getFunctionContaining(addr):
        return ''

    symbol = program.getSymbolTable().getPrimarySymbol(addr)
    if symbol:
        return symbol.getName()

    return ''

def get_status():
    program = get_program()
    return {
        'tool': 'ghidra',
        'file': program.getName(),
        'image_base': program.getImageBase().getOffset() & MASK64,
    }

def query_struct(name):
    """struct layout from the data type manager: name, size and field list, None if unknown"""
    program = get_program()
    dtm = program.getDataTypeManager()

    # exact category path first, then a plain by-name scan (the type
    # can live in any category)
    dt = dtm.getDataType('/' + name)
    if dt is None:
        it = dtm.getAllDataTypes()
        while it.hasNext():
            candidate = it.next()
            if candidate.getName() == name:
                dt = candidate
                break

    # structures and unions list their components, other kinds have no layout
    if dt is None or not hasattr(dt, 'getDefinedComponents'):
        return None

    fields = []
    for c in dt.getDefinedComponents():
        field_name = c.getFieldName()
        if not field_name:
            field_name = c.getDataType().getName()

        fields.append({
            'name': field_name,
            'offset': c.getOffset(),
            'size': c.getLength(),
            'type': c.getDataType().getName(),
        })

    return {'name': name, 'size': dt.getLength(), 'fields': fields}

# ---------------------------
# http plumbing
# ---------------------------

def parse_addr(program, hex_str):
    """parse a hex address string (0x optional) into a ghidra Address"""
    text = hex_str[2:] if hex_str.lower().startswith('0x') else hex_str
    return program.getAddressFactory().getAddress(text)

class SymbolRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        body = json.dumps(obj)
        if not isinstance(body, bytes):
            # python3 socket wants bytes, python2 str already is
            body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        params = parse_qs(url.query)
        program = get_program()

        try:
            if url.path == '/status':
                self._send_json(get_status())

            elif url.path == '/query_func_name':
                addr = parse_addr(program, params['addr'][0])
                self._send_json({'name': query_func_name(addr)})

            elif url.path == '/query_func_addr':
                name = params['name'][0]
                self._send_json({'addr': query_func_addr(name)})

            elif url.path == '/query_var_name':
                addr = parse_addr(program, params['addr'][0])
                self._send_json({'name': query_var_name(addr)})

            elif url.path == '/query_segment':
                addr = parse_addr(program, params['addr'][0])
                self._send_json({'segment': query_segment(addr)})

            elif url.path == '/query_struct':
                name = params['name'][0]
                self._send_json({'struct': query_struct(name)})

            else:
                self._send_json({'error': 'unknown path ' + url.path}, code=404)

        except (KeyError, ValueError) as e:
            self._send_json({'error': str(e)}, code=400)
        except Exception as e:
            self._send_json({'error': str(e)}, code=500)

    def log_message(self, fmt, *args):
        # route access logs to the ghidra console
        print('[ghidra_server] ' + fmt % args)

def start(program=None, port=None):
    """bind the server to a program and start listening (idempotent),
       port None picks a random one on first load"""
    global _program, _server, _port
    if _server is not None:
        print('[ghidra_server] already running on {0}:{1}'.format(HOST, _server.server_address[1]))
        return

    if program is None:
        print('[ghidra_server] no program bound, use start(currentProgram)')
        return

    if port is None:
        port = _port or pick_port()

    _program = program
    try:
        _server = ThreadingHTTPServer((HOST, port), SymbolRequestHandler)
    except (OSError, socket.error) as e:
        _server = None
        _program = None
        print('[ghidra_server] unable to bind {0}:{1} - {2}'.format(HOST, port, e))
        return

    _port = port
    thread = threading.Thread(target=_server.serve_forever)
    thread.daemon = True
    thread.start()
    print('[ghidra_server] listening on {0}:{1} (http, read-only)'.format(HOST, port))

def stop():
    """stop the symbol server if running"""
    global _server, _program
    if _server is None:
        print('[ghidra_server] not running')
        return

    _server.shutdown()
    _server.server_close()
    _server = None
    _program = None
    print('[ghidra_server] stopped')

# ---------------------------
# Edit > 'ghidra_server: set port...'
# ---------------------------

def set_port(port):
    """stop on the old port (if any) and start on the given one, keeping the program binding"""
    program = None
    try:
        program = get_program()
    except Exception:
        pass

    stop()
    start(program, port)

def ask_port_and_apply():
    """popup asking for the port, restarts the server when it changes"""
    from javax.swing import JOptionPane

    current = _server.server_address[1] if _server is not None else (_port or pick_port())
    text = JOptionPane.showInputDialog(None, 'Symbol server port (randomized on first load):', str(current))
    if text is None:
        # dialog cancelled
        return

    try:
        port = int(str(text).strip())
    except ValueError:
        print('[ghidra_server] invalid port ' + str(text))
        return

    if port < 1 or port > 65535:
        print('[ghidra_server] invalid port ' + str(port))
        return

    if _server is not None and _server.server_address[1] == port:
        print('[ghidra_server] already listening on {0}:{1}'.format(HOST, port))
        return

    set_port(port)

try:
    # pyghidra (python3): java classes cannot be extended here, only java
    # interfaces can be implemented - the action is built by ActionBuilder on
    # the java side and calls back into python through a Consumer implementation
    import jpype
    from docking.action.builder import ActionBuilder
    _ACTION_MODE = 'pyghidra'
except ImportError:
    try:
        # jython 2.7: subclassing java classes works there
        from docking.action import DockingAction, MenuData
        _ACTION_MODE = 'jython'
    except ImportError:
        _ACTION_MODE = None

if _ACTION_MODE == 'pyghidra':
    @jpype.JImplements('java.util.function.Consumer')
    class _SetPortCallback(object):
        """action callback shim for pyghidra: implement the java Consumer
           interface instead of subclassing the DockingAction class"""
        @jpype.JOverride
        def accept(self, context):
            ask_port_and_apply()

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

    def _build_set_port_action():
        """build the Edit menu action, the DockingAction itself lives java side"""
        return (ActionBuilder('ghidra_server set port', 'ghidra_server')
                .menuPath('Edit', 'ghidra_server: set port...')
                .menuGroup('zzGhidraServer')
                .onAction(_SetPortCallback())
                .build())

elif _ACTION_MODE == 'jython':
    class _SetPortAction(DockingAction):
        def __init__(self):
            DockingAction.__init__(self, 'ghidra_server set port', 'ghidra_server')
            self.setMenuBarData(MenuData(['Edit', 'ghidra_server: set port...'], None, 'zzGhidraServer'))

        def actionPerformed(self, context):
            ask_port_and_apply()

    def _build_set_port_action():
        """build the Edit menu action by subclassing, jython supports that"""
        return _SetPortAction()

_menu_action = None

def add_menu(tool):
    """register 'ghidra_server: set port...' under the tool Edit menu (idempotent)"""
    global _menu_action
    if _ACTION_MODE is None:
        print('[ghidra_server] docking classes unavailable, menu not added')
        return

    if tool is None:
        print('[ghidra_server] no tool bound, menu not added')
        return

    if _menu_action is not None:
        return

    _menu_action = _build_set_port_action()
    if _ACTION_MODE == 'pyghidra':
        _run_on_edt(lambda: tool.addAction(_menu_action))
    else:
        tool.addAction(_menu_action)
    print('[ghidra_server] menu added: Edit > ghidra_server: set port...')

# auto start when executed as a ghidra script (currentProgram is
# injected by the script engine)
try:
    if currentProgram is not None:
        start(currentProgram)
        add_menu(state.getTool())
except NameError:
    # imported as a module - call start(currentProgram) manually
    pass
