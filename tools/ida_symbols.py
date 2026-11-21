import idautils
import ida_segment
import idc
import json

# IDA 9 deprecated getnseg()/get_segm_name() in favor of
# get_segment_info_by_num(); IDA 8 only ships the old API.
HAS_SEGMENT_INFO_API = (hasattr(ida_segment, 'get_segment_info_by_num') and
                        hasattr(ida_segment, 'segment_info_t'))

def get_segment_by_num(n):
    ''' return segment info (IDA 9) or segment_t (IDA 8) by number, None if out of range '''
    if HAS_SEGMENT_INFO_API:
        info = ida_segment.segment_info_t()
        if ida_segment.get_segment_info_by_num(info, n):
            return info

        return None

    return ida_segment.getnseg(n)

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
        seg = get_segment_by_num(i)
        if seg:
            # IDA 9 segment_info_t exposes get_perm(), IDA 8 segment_t has .perm
            perm = seg.get_perm() if HAS_SEGMENT_INFO_API else seg.perm
            perms = (('r' if perm & ida_segment.SEGPERM_READ  else '-') +
                     ('w' if perm & ida_segment.SEGPERM_WRITE else '-') +
                     ('x' if perm & ida_segment.SEGPERM_EXEC  else '-'))
            results['segments'].append({
                # idc.get_segm_name() works on both IDA 8 and IDA 9 without deprecation
                'name' : idc.get_segm_name(seg.start_ea),
                'start' : seg.start_ea,
                'end' : seg.end_ea,
                'perms' : perms,
            })

    with open('/tmp/custom_syms.json', 'w') as f:
        json.dump(results, f)

dum_all_symbols()