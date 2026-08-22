import idautils
import ida_segment
import idc
import json

def dum_all_symbols():
    results = {
        'functions' : {},
        'variables' : {},
        'segments' : []
    }

    print('[+] dump_all_symbols()')
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        results['functions'][func_ea] = func_name

    for ea, name in idautils.Names():
        results['variables'][ea] = name

    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg:
            perms = (('r' if seg.perm & ida_segment.SEGPERM_READ  else '-') +
                     ('w' if seg.perm & ida_segment.SEGPERM_WRITE else '-') +
                     ('x' if seg.perm & ida_segment.SEGPERM_EXEC  else '-'))
            results['segments'].append({
                'name' : ida_segment.get_segm_name(seg),
                'start' : seg.start_ea,
                'end' : seg.end_ea,
                'perms' : perms,
            })

    with open('/tmp/custom_syms.json', 'w') as f:
        json.dump(results, f)

dum_all_symbols()