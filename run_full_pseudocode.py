"""
run_full_pseudocode.py -- runs through the WHOLE CFG: splits it into
functions (by addresses that are actually call targets -- cfg.call_targets),
reconstructs conditions for each function separately (with its own FPU
stack state, not mixed with other functions), generates pseudocode, and
structures it via dominators. The result is a single readable file with
all functions found.
"""
import struct
import sys
sys.path.insert(0, '.')
from cfg_builder import CFG
from pseudocode import (detect_string_segment, decode_pstrings, auto_detect_calls,
                         reconstruct_conditions, build_pseudocode)
from structuring import structure_pseudocode


def parse_mz_header(data):
    fields = struct.unpack_from('<14H', data, 2)
    names = ['e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc', 'e_maxalloc',
              'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs', 'e_lfarlc', 'e_ovno']
    h = dict(zip(names, fields[:13]))
    h['header_bytes'] = h['e_cparhdr'] * 16
    return h


def instr_tuple(cfg, a):
    i = cfg.instrs[a]
    near = i.fpu_mem_near if i.kind == 'FPU' else None
    return (a, i.kind, i.mnemonic, i.length, near, a)  # code_start=0 -> off=fa (per-function)


def partition_into_functions(cfg):
    """Splits cfg.instrs into functions by addresses from cfg.call_targets
       (plus the program's own entry point, plus the INT 34h-3Bh handlers
       -- they land in cfg.entry_points bypassing an ordinary call, so
       they aren't in cfg.call_targets, but they must still be split out
       as separate "functions", plus the user-program entry point found
       via emulation). A function is the range of addresses from one
       start point to the next, cut off at the first ret/retf encountered."""
    from cfg_builder import (FPU_HANDLER_SEGMENT, FPU_HANDLER_OFFSETS_WITH_COPROCESSOR,
                              FPU_HANDLER_OFFSETS_EMULATED, USER_PROGRAM_ENTRY_SEGMENT,
                              USER_PROGRAM_ENTRY_OFFSET)
    entry = min(cfg.instrs)
    fpu_handler_addrs = {
        cfg.header_bytes + FPU_HANDLER_SEGMENT * 16 + off
        for off in FPU_HANDLER_OFFSETS_WITH_COPROCESSOR + FPU_HANDLER_OFFSETS_EMULATED
    }
    user_entry_addr = cfg.header_bytes + USER_PROGRAM_ENTRY_SEGMENT * 16 + USER_PROGRAM_ENTRY_OFFSET
    starts = sorted(cfg.call_targets | {entry} | fpu_handler_addrs | {user_entry_addr})
    addrs = sorted(cfg.instrs)
    funcs = {}
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else None
        func_addrs = []
        for a in addrs:
            if a < start:
                continue
            if end is not None and a >= end:
                break
            instr = cfg.instrs[a]
            if instr.kind == 'BAD':
                break
            func_addrs.append(a)
            if instr.kind == 'X86' and instr.mnemonic.startswith('ret'):
                break
        if func_addrs:
            funcs[start] = func_addrs
    return funcs


def main():
    with open('<filename>', 'rb') as f:
        data = f.read()
    header = parse_mz_header(data)
    header_bytes = header['header_bytes']
    entry_addr = header_bytes + header['e_cs'] * 16 + header['e_ip']

    print(f"[+] Building the CFG...")
    cfg = CFG(data, header_bytes)
    cfg.build(entry_addr)
    print(f"[+] Instructions visited: {len(cfg.instrs)}")

    str_seg = detect_string_segment(data, header_bytes, len(data)) or header_bytes
    pstrings = decode_pstrings(data, str_seg, len(data))
    print(f"[+] Strings found: {len(pstrings)}  (string segment: 0x{str_seg:x})")

    all_instrs_flat = [instr_tuple(cfg, a) for a in sorted(cfg.instrs) if cfg.instrs[a].kind != 'BAD']
    print_t, input_t, strcmp_t, floatcmp_t = auto_detect_calls(all_instrs_flat, pstrings, data, str_seg)
    print(f"[+] PRINT_TEXT={print_t}  INPUT_READ={input_t}  STRCMP={strcmp_t}  FLOAT_COMPARE={floatcmp_t}")

    funcs = partition_into_functions(cfg)
    print(f"[+] Functions found: {len(funcs)}")

    out_lines = []
    total_print = total_input = total_formula = total_if = 0
    ok_count = fail_count = 0

    for start in sorted(funcs):
        func_addrs = funcs[start]
        instrs = [instr_tuple(cfg, a) for a in func_addrs]
        conditions = reconstruct_conditions(instrs, data, str_seg, strcmp_t, floatcmp_t)
        lines = build_pseudocode(instrs, pstrings, print_t, input_t, conditions,
                                  data, str_seg, code_start=0)
        if not lines:
            continue

        for l in lines:
            if 'PRINT ' in l: total_print += 1
            elif 'INPUT ->' in l: total_input += 1
            elif 'FORMULA ' in l: total_formula += 1
            elif l.strip().startswith('CODE') and 'IF (' in l: total_if += 1

        out_lines.append(f"\ndef sub_0x{start:x}():  # {len(func_addrs)} instr., address 0x{start:x}")
        try:
            structured = structure_pseudocode(lines)
            body = structured if structured.strip() else "pass"
            for bl in body.splitlines():
                out_lines.append("    " + bl)
            ok_count += 1
        except Exception as e:
            out_lines.append(f"    # STRUCTURING ERROR: {e}")
            for l in lines:
                out_lines.append(f"    # {l}")
            fail_count += 1

    result = "\n".join(out_lines)
    with open('full_pseudocode.py.txt', 'w', encoding='utf-8') as f:
        f.write(result)

    print(f"\n[+] Functions structured without errors: {ok_count}, with errors: {fail_count}")
    print(f"[+] Program totals: PRINT={total_print}  INPUT={total_input}  "
          f"FORMULA={total_formula}  IF={total_if}")
    print(f"[+] Written to full_pseudocode.py.txt ({len(result)} characters, {len(out_lines)} lines)")
    return result


if __name__ == '__main__':
    main()
