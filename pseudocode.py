"""
pseudocode.py -- ports the semantic layer from the linear extractor
(basic_extractor.py) to work on top of the CFG (cfg_builder.py), instead of
a flat disasm_range() range.

PORTING PRINCIPLE: the functions auto_detect_calls / reconstruct_conditions
/ build_pseudocode are copied from basic_extractor.py ALMOST VERBATIM --
this is logic already validated in an earlier session (symbolic emulation
of the FPU stack, voting for PRINT/INPUT/STRCMP/float-compare, IF
reconstruction). The only real change is the data source: it used to be a
flat list from disasm_range(start,end) (linear reading of a byte range),
now it's cfg.ordered_instrs(), i.e. only the instructions the CFG actually
reached via the real flow of execution (call/jmp/jcc) -- which was the
whole point of moving to the CFG engine.

List element format (shared with basic_extractor.py so the code is
portable 1:1): (off, kind, mnem, length, near, fa)
  off    -- address RELATIVE to header_bytes (like code_start in the old script)
  kind   -- 'X86' | 'FPU' | 'BAD' (BAD is skipped by the adapter, just like
            '???' used to be skipped -- they carry no semantics)
  mnem   -- mnemonic string (as produced by decoder.py -- compatible 1:1
            with the old Capstone output, since both versions build the
            string the same way: "{mnemonic} {op_str}")
  length -- instruction length in bytes
  near   -- for FPU: absolute offset of the memory operand (fpu_mem_near),
            for X86: always None (as in the old version)
  fa     -- file address (absolute, kept for backward compatibility)
"""
import re, struct, bisect
import sys
sys.path.insert(0, '.')
from cfg_builder import CFG


# ============================================================================
# ============ String segment (verbatim from basic_extractor.py) ===========
def detect_string_segment(data, search_start, search_end):
    votes = {}
    i = search_start
    while i < search_end - 4:
        if data[i+1] == 0 and 1 <= data[i] <= 250:
            ptr = data[i+2] | (data[i+3] << 8)
            implied_base = i - (ptr - 4)
            if 0 <= implied_base < len(data):
                votes[implied_base] = votes.get(implied_base, 0) + 1
        i += 1
    best = max(votes.items(), key=lambda kv: kv[1]) if votes else None
    return best[0] if best and best[1] >= 3 else None


def decode_pstrings(data, seg_start, seg_end):
    results = {}
    i = seg_start
    while i < seg_end - 4:
        length = data[i]
        flag = data[i+1]
        ptr = data[i+2] | (data[i+3] << 8)
        near_off = i - seg_start
        if flag == 0 and ptr == near_off + 4 and length >= 1:
            text_len = length
            if i+4+text_len <= len(data):
                raw = data[i+4:i+4+text_len]
                try: text = raw.decode('cp866', errors='replace')
                except Exception: text = raw.decode('latin1', errors='replace')
                if text and all(c.isprintable() or c in ' \t' for c in text):
                    results[near_off] = text
                    i += 1 + length
                    continue
        i += 1
    return results


# ============================================================================
# ADAPTER: cfg.instrs (dict: file address -> Instr) -> flat list in
# basic_extractor.py's format, sorted by address.
#
# IMPORTANT: sorting by address is an approximation of execution order (as
# also noted in the README, under "honest if/while structuring via
# dominators" -- we don't do that here yet, that's a separate next step).
# For the purposes of porting the FPU emulation and PRINT/INPUT logic,
# sorting by address is enough: both old functions in fact also read
# strictly in increasing address order (that WAS the linear disasm_range),
# so the adapter behaves equivalently in semantics, just restricted to the
# instructions ACTUALLY reached.
def cfg_to_linear_instrs(cfg):
    out = []
    for fa in sorted(cfg.instrs):
        instr = cfg.instrs[fa]
        if instr.kind == 'BAD':
            continue
        off = fa - cfg.header_bytes
        near = instr.fpu_mem_near if instr.kind == 'FPU' else None
        out.append((off, instr.kind, instr.mnemonic, instr.length, near, fa))
    return out


# ============================================================================
# ================= sym() (verbatim from basic_extractor.py) =================
def sym(operand):
    m = re.match(r"\[0x([0-9a-f]+)\]", operand)
    if m: return f"V_{m.group(1)}"
    m = re.match(r"\[(SI|DI|BX|BP)([+\-]\d+)\]", operand)
    if m: return f"ARR_{m.group(1)}[{m.group(2)}]"
    return operand


# ============================================================================
# ============ auto_detect_calls() (verbatim, same LCALL_RE) ==============
LCALL_RE = re.compile(r"lcall\s+(0x[0-9a-f]+)\s*[:,]\s*(0x[0-9a-f]+)")


def read_short_string_descriptor(data, seg_start, near_off):
    p = seg_start + near_off
    if p + 4 > len(data): return None
    length = data[p] | (data[p+1] << 8)
    ptr = data[p+2] | (data[p+3] << 8)
    if length > 64: return None
    chars = data[seg_start+ptr:seg_start+ptr+length]
    try: return chars.decode('cp866', errors='replace')
    except Exception: return None


def auto_detect_calls(instrs, pstrings, data, str_seg_start):
    push_imm_re = re.compile(r"push ax$")
    mov_ax_re = re.compile(r"mov ax, (0x[0-9a-f]+|\d+)$")
    mov_bx_re = re.compile(r"mov bx, (0x[0-9a-f]+)$")

    last_imm = None
    pushes_since_call = []
    last_mov_bx = None
    print_votes, input_votes, strcmp_votes, floatcmp_votes = {}, {}, {}, {}

    for idx, (off, kind, mnem, length, near, fa) in enumerate(instrs):
        if kind == 'FPU':
            continue

        m_ax = mov_ax_re.match(mnem)
        m_bx = mov_bx_re.match(mnem)
        is_push = push_imm_re.match(mnem)
        mc = LCALL_RE.match(mnem)

        if m_bx:
            last_mov_bx = int(m_bx.group(1), 16)
            continue
        if m_ax:
            last_imm = int(m_ax.group(1), 16) if m_ax.group(1).startswith('0x') else int(m_ax.group(1))
            continue
        if is_push and last_imm is not None:
            pushes_since_call.append(last_imm)
            continue
        if mc:
            seg, off2 = int(mc.group(1), 16), int(mc.group(2), 16)
            tgt = (seg, off2)
            if pushes_since_call and pushes_since_call[-1] in pstrings:
                print_votes[tgt] = print_votes.get(tgt, 0) + 1
            if last_mov_bx is not None:
                input_votes[tgt] = input_votes.get(tgt, 0) + 1
            if len(pushes_since_call) == 2:
                for cand in (pushes_since_call[0], pushes_since_call[1]):
                    d1 = read_short_string_descriptor(data, str_seg_start, cand)
                    if d1 is not None and len(d1) == 1 and d1.isprintable() and d1.isalpha():
                        strcmp_votes[tgt] = strcmp_votes.get(tgt, 0) + 1
                        break
            last_mov_bx = None
            pushes_since_call = []
            last_imm = None
            continue

    for idx in range(2, len(instrs) - 1):
        off, kind, mnem, length, near, fa = instrs[idx]
        if kind == 'X86' and mnem.startswith('int '):
            o1, k1, m1, l1, n1, f1 = instrs[idx+1]
            mc = LCALL_RE.match(m1) if k1 == 'X86' else None
            if mc:
                o2, k2, m2, l2, n2, f2 = instrs[idx-1]
                if k2 == 'FPU' and m2.startswith('FLD'):
                    tgt = (int(mc.group(1), 16), int(mc.group(2), 16))
                    floatcmp_votes[tgt] = floatcmp_votes.get(tgt, 0) + 1

    pick = lambda votes: max(votes.items(), key=lambda kv: kv[1])[0] if votes else None
    return pick(print_votes), pick(input_votes), pick(strcmp_votes), pick(floatcmp_votes)


# ============================================================================
# ============ reconstruct_conditions() (verbatim) ==========================
JCC_MAP = {'je': '==', 'jne': '!=', 'jb': '<', 'jbe': '<=', 'ja': '>', 'jae': '>=',
           'jl': '<', 'jle': '<=', 'jg': '>', 'jge': '>='}
FLOAT_TO_INT_TARGET = (0xf63, 0x3dc)  # found in an earlier session


def parse_cmp_operands(mnem):
    m = re.match(r"cmp\s+(.*),\s*(.*)", mnem)
    if m: return m.group(1), m.group(2), False
    m = re.match(r"test\s+(.*),\s*(.*)", mnem)
    if m: return m.group(1), m.group(2), True
    m = re.match(r"or\s+(.*),\s*(.*)", mnem)
    if m and m.group(1) == m.group(2):
        # the "or X, X" idiom -- a zero-test of X via ZF, semantically
        # identical to "test X, X" (the same register on both sides)
        return m.group(1), m.group(2), True
    return None, None, None


def reconstruct_conditions(instrs, data, str_seg_start, strcmp_target, floatcmp_target):
    call_re = LCALL_RE
    jump_re = re.compile(r"^(j[a-z]+)\s+(0x[0-9a-f]+)$")
    conditions = {}

    stack_fpu = []
    push_imm_hist = []
    last_imm = None
    strcmp_literal_by_idx = {}
    i, n = 0, len(instrs)

    jcxz_re = re.compile(r"^jcxz\s+(0x[0-9a-f]+)$")
    for idx, (off, kind, mnem, length, near, fa) in enumerate(instrs):
        if kind != 'X86': continue
        jm = jcxz_re.match(mnem)
        if jm and idx not in conditions:
            # jcxz -- jumps IF cx==0, doesn't need a preceding cmp/test,
            # this is an unconditionally unambiguous semantic of the
            # instruction itself
            conditions[idx] = "cx == 0"

    while i < n:
        off, kind, mnem, length, near, fa = instrs[i]
        if kind == 'FPU':
            parts = mnem.split(" ", 1); op = parts[0]; rest = parts[1] if len(parts) > 1 else ""
            try:
                if op == "FLD":
                    stack_fpu.insert(0, sym(rest.split(" ", 1)[1].strip()) if ("m32real" in rest or "m64real" in rest) else rest)
                elif op in ("FSTP", "FST"):
                    match = re.search(r"ST\((\d+)\)", rest)
                    if match:
                        k = int(match.group(1))
                        if op == "FSTP":
                            stack_fpu.pop(0)
                        else:
                            stack_fpu[k] = stack_fpu[0]
                    elif op == "FSTP":
                        stack_fpu.pop(0)
                elif op in ("FADD", "FSUB", "FMUL", "FDIV", "FSUBR", "FDIVR"):
                    b = sym(rest.split(" ", 1)[1].strip()) if ("m32real" in rest or "m64real" in rest) else rest
                    a = stack_fpu[0]
                    so = {"FADD": "+", "FSUB": "-", "FMUL": "*", "FDIV": "/", "FSUBR": "-", "FDIVR": "/"}[op]
                    stack_fpu[0] = f"({b} {so} {a})" if op in ("FSUBR", "FDIVR") else f"({a} {so} {b})"
                elif op == "FSQRT": stack_fpu[0] = f"sqrt({stack_fpu[0]})"
                elif op == "FABS": stack_fpu[0] = f"abs({stack_fpu[0]})"
                elif op == "FCHS": stack_fpu[0] = f"(-{stack_fpu[0]})"
                elif op in ("FCOMP", "FUCOMP"): stack_fpu.pop(0)
                elif op == "FCOMPP": stack_fpu.pop(0); stack_fpu.pop(0)
            except Exception:
                pass
            i += 1; continue

        m = re.match(r"mov ax, (0x[0-9a-f]+|\d+)$", mnem)
        if m:
            last_imm = int(m.group(1), 16) if m.group(1).startswith('0x') else int(m.group(1))
            i += 1; continue
        if mnem == "push ax" and last_imm is not None:
            push_imm_hist.append(last_imm); push_imm_hist = push_imm_hist[-2:]
            i += 1; continue

        mc = call_re.match(mnem)
        if mc:
            tgt = (int(mc.group(1), 16), int(mc.group(2), 16))
            if tgt == FLOAT_TO_INT_TARGET:
                if stack_fpu: stack_fpu.pop(0)
                i += 1; continue
            if floatcmp_target and tgt == floatcmp_target:
                try:
                    b = stack_fpu.pop(0); a = stack_fpu.pop(0)
                    j = i + 1
                    while j < n:
                        _, kj, mj, _, _, _ = instrs[j]
                        if kj != 'X86' or not jump_re.match(mj):
                            if kj == 'X86' and not (re.match(r"^(mov|lea|push|pop|nop|xchg)", mj)): break
                            j += 1; continue
                        jm = jump_re.match(mj)
                        if jm and jm.group(1) != 'jmp':
                            opy = JCC_MAP.get(jm.group(1), '?')
                            conditions[j] = f"{a} {opy} {b}"
                        j += 1; break
                except Exception:
                    pass
            elif strcmp_target and tgt == strcmp_target and len(push_imm_hist) == 2:
                lit = None
                for cand in (push_imm_hist[0], push_imm_hist[1]):
                    lit_try = read_short_string_descriptor(data, str_seg_start, cand)
                    if lit_try is not None and len(lit_try) == 1 and lit_try.isprintable() and lit_try.isalpha():
                        lit = lit_try; break
                if lit is not None:
                    j = i + 1
                    while j < n:
                        _, kj, mj, _, _, _ = instrs[j]
                        if kj != 'X86' or not jump_re.match(mj):
                            if kj == 'X86' and not (re.match(r"^(mov|lea|push|pop|nop|xchg)", mj)): break
                            j += 1; continue
                        jm = jump_re.match(mj)
                        if jm and jm.group(1) != 'jmp':
                            opy = JCC_MAP.get(jm.group(1), '?')
                            conditions[j] = f"input_str {opy} {lit!r}"
                            strcmp_literal_by_idx[j] = lit
                            j += 1; continue
                        else:
                            break
                push_imm_hist = []
            i += 1; continue

        if kind == 'X86' and not re.match(r"^(mov|lea|push|pop|nop|xchg|call)", mnem):
            push_imm_hist = []
        i += 1

    for idx in range(3, len(instrs)):
        o0, k0, m0, _, _, _ = instrs[idx-3]
        o1, k1, m1, _, _, _ = instrs[idx-2]
        o2, k2, m2, _, _, _ = instrs[idx-1]
        o3, k3, m3, _, _, _ = instrs[idx]
        if not (k0 == k1 == k2 == k3 == 'X86'): continue
        if m0 != "dec ax": continue
        if not re.match(r"or ax, word ptr \[bp", m1): continue
        if m2 != "and ax, ax": continue
        jump_re2 = re.compile(r"^(j[a-z]+)\s+(0x[0-9a-f]+)$")
        jm = jump_re2.match(m3)
        if not jm or jm.group(1) == 'jmp': continue
        jcc = jm.group(1)
        prior = sorted(k for k in strcmp_literal_by_idx if k < idx-3)
        if len(prior) >= 2:
            lit1 = strcmp_literal_by_idx[prior[-2]]
            lit2 = strcmp_literal_by_idx[prior[-1]]
            if jcc == 'je':
                conditions[idx] = f"input_str != {lit1!r} and input_str != {lit2!r}"
            elif jcc == 'jne':
                conditions[idx] = f"input_str == {lit1!r} or input_str == {lit2!r}"

    def resolve_operand(op_str):
        if op_str is None:
            return None
        if re.match(r'^0x[0-9a-f]+$', op_str):
            return str(int(op_str, 16))
        m = re.match(r'(?:word|dword)\s*ptr\s*\[(0x[0-9a-f]+)\]', op_str)
        if m:
            return f"V_{m.group(1)}"
        m = re.match(r'\[(0x[0-9a-f]+)\]', op_str)
        if m:
            return f"V_{m.group(1)}"
        return sym(op_str)

    jump_re = re.compile(r"^(j[a-z]+)\s+(0x[0-9a-f]+)$")
    for idx in range(1, len(instrs)):
        _, k1, m1, _, _, _ = instrs[idx-1]
        _, k2, m2, _, _, _ = instrs[idx]
        if k1 != 'X86' or k2 != 'X86': continue
        jm = jump_re.match(m2)
        if not jm or jm.group(1) == 'jmp': continue
        if idx in conditions: continue
        left, right, is_test = parse_cmp_operands(m1)
        if left is None: continue
        jcc = jm.group(1)
        opv = JCC_MAP.get(jcc)
        if not opv: continue

        left_sym = resolve_operand(left)
        right_sym = resolve_operand(right)

        if left_sym is not None and right_sym is not None:
            left_is_var = left_sym.startswith("V_") or left_sym.startswith("ARR_")
            right_is_var = right_sym.startswith("V_") or right_sym.startswith("ARR_")
            if not left_is_var and right_is_var:
                left_sym, right_sym = right_sym, left_sym

        if is_test:
            if left_sym == right_sym:
                conditions[idx] = f"{left_sym} {opv} 0"
            else:
                conditions[idx] = f"({left_sym} & {right_sym}) {opv} 0"
        else:
            conditions[idx] = f"{left_sym} {opv} {right_sym}"

    return conditions


# ============================================================================
# ================= build_pseudocode() (verbatim) ============================
def build_pseudocode(instrs, pstrings, print_target, input_target, conditions,
                     data, data_seg_start, print_num_target=None, seg_label="CODE",
                     code_start=0):
    call_re = re.compile(r"lcall (0x[0-9a-f]+), (0x[0-9a-f]+)")
    jump_re = re.compile(r"^(j[a-z]+)\s+(0x[0-9a-f]+)$")
    last_imm = None; last_mov_bx = None; pending_push = None
    lines = []; stack_fpu = []
    suppress_next_0690 = False

    emitted_addrs = []
    _last_imm = None; _last_mov_bx = None; _pending_push = None
    for idx, (off, kind, mnem, length, near, fa) in enumerate(instrs):
        if kind == 'X86':
            m = re.match(r"mov bx, (0x[0-9a-f]+)$", mnem)
            if m: _last_mov_bx = int(m.group(1), 16)
            m = re.match(r"mov (\w+), (0x[0-9a-f]+|\d+)$", mnem)
            if m and m.group(1) in ('ax', 'bx', 'cx', 'dx'):
                _last_imm = int(m.group(2), 16) if m.group(2).startswith('0x') else int(m.group(2))
                continue
            m_push = re.match(r"push word ptr \[(0x[0-9a-f]+)\]", mnem)
            if m_push: _pending_push = int(m_push.group(1), 16); continue
            if mnem.startswith("push ax") and _last_imm is not None:
                _pending_push = _last_imm; continue
            mc = call_re.match(mnem)
            if mc:
                tgt = (int(mc.group(1), 16), int(mc.group(2), 16))
                if tgt == print_target and _pending_push in pstrings:
                    emitted_addrs.append(off); _pending_push = None
                elif tgt == input_target and (_last_mov_bx is not None or _pending_push is not None):
                    emitted_addrs.append(off); _last_mov_bx = None; _pending_push = None
                elif print_num_target is not None and tgt == print_num_target and _pending_push is not None:
                    if _pending_push > 0xF and _pending_push not in pstrings:
                        emitted_addrs.append(off)
                    _pending_push = None
                continue
            if jump_re.match(mnem):
                emitted_addrs.append(off); continue
            if re.match(r"^call (0x[0-9a-f]+)$", mnem):
                emitted_addrs.append(off); continue
            if mnem.startswith("ret"):
                emitted_addrs.append(off); continue
        elif kind == 'FPU':
            parts = mnem.split(" ", 1); op = parts[0]
            if op in ("FSTP", "FST"):
                emitted_addrs.append(off)
    emitted_addrs = sorted(set(emitted_addrs))

    def snap(rel_addr):
        i = bisect.bisect_left(emitted_addrs, rel_addr)
        if i < len(emitted_addrs):
            return emitted_addrs[i]
        return rel_addr

    jump_targets = set()
    for idx, (off, kind, mnem, length, near, fa) in enumerate(instrs):
        if kind != 'X86': continue
        if mnem.startswith('jmp'):
            m = re.match(r"jmp\s+(0x[0-9a-f]+)", mnem)
            if m: jump_targets.add(int(m.group(1), 16))
        mj = jump_re.match(mnem)
        if mj and mj.group(1) != 'jmp':
            target = int(mj.group(2), 16)
            jump_targets.add(target)

    # snap() should also be able to land on addresses where nothing but
    # "; jump target label" was emitted -- otherwise the target gets
    # "snapped" forward to the next MEANINGFUL line after it (e.g. the jcc
    # of the next loop iteration), producing a false self-reference.
    emitted_addrs = sorted(set(emitted_addrs) | jump_targets)

    for idx, (off, kind, mnem, length, near, fa) in enumerate(instrs):
        addr_s = f"{seg_label}:{off:04x}"
        generated = False

        if kind == 'X86':
            m = re.match(r"mov bx, (0x[0-9a-f]+)$", mnem)
            if m: last_mov_bx = int(m.group(1), 16)
            m = re.match(r"mov (\w+), (0x[0-9a-f]+|\d+)$", mnem)
            if m and m.group(1) in ('ax', 'bx', 'cx', 'dx'):
                last_imm = int(m.group(2), 16) if m.group(2).startswith('0x') else int(m.group(2))
                continue
            m_push = re.match(r"push word ptr \[(0x[0-9a-f]+)\]", mnem)
            if m_push:
                pending_push = int(m_push.group(1), 16)
                continue
            if mnem.startswith("push ax") and last_imm is not None:
                pending_push = last_imm; continue
            mc = call_re.match(mnem)
            if mc:
                tgt = (int(mc.group(1), 16), int(mc.group(2), 16))
                if tgt == FLOAT_TO_INT_TARGET:
                    if stack_fpu: stack_fpu.pop(0)
                    continue
                if tgt == print_target and pending_push in pstrings:
                    lines.append(f"{addr_s}: PRINT \"{pstrings[pending_push].strip()}\"")
                    pending_push = None
                    suppress_next_0690 = False
                    generated = True
                elif tgt == input_target and (last_mov_bx is not None or pending_push is not None):
                    val = last_mov_bx if last_mov_bx is not None else pending_push
                    if suppress_next_0690 and val == 0x0690:
                        suppress_next_0690 = False
                        last_mov_bx = None
                        pending_push = None
                        continue
                    lines.append(f"{addr_s}: INPUT -> V_{val:04x}")
                    last_mov_bx = None
                    pending_push = None
                    suppress_next_0690 = False
                    continue
                elif print_num_target is not None and tgt == print_num_target and pending_push is not None:
                    if pending_push > 0xF and pending_push not in pstrings:
                        lines.append(f"{addr_s}: PRINT V_{pending_push:04x}")
                        suppress_next_0690 = False
                    pending_push = None
                continue
            mj = jump_re.match(mnem)
            if mj:
                jcc, target_abs = mj.group(1), int(mj.group(2), 16)
                target_rel = target_abs - code_start
                target_snapped = snap(target_rel)
                target_str = f"0x{target_snapped:04x}" + (f" (raw 0x{target_rel:04x})" if target_snapped != target_rel else "")
                if idx in conditions:
                    cond = conditions[idx]
                    lines.append(f"{addr_s}: IF ({cond}) GOTO {target_str}")
                else:
                    if jcc == 'jmp':
                        lines.append(f"{addr_s}: jmp {target_str}")
                    else:
                        lines.append(f"{addr_s}: {jcc} {target_str}  [condition not recognised]")
                generated = True
                continue
            mcall_near = re.match(r"^call (0x[0-9a-f]+)$", mnem)
            if mcall_near:
                call_target_abs = int(mcall_near.group(1), 16)
                call_target_rel = call_target_abs - code_start
                file_off = code_start + call_target_rel
                base = None
                if file_off + 4 < len(data) and data[file_off:file_off+4] == b'\x58\x05\x0D\x00':
                    window = data[file_off:file_off+0x40]
                    idxw = window.find(b'\xD1\xE0\xD1\xE0')
                    if idxw != -1 and idxw + 5 < len(window) and window[idxw+4:idxw+6] == b'\x81\xC0':
                        base = struct.unpack_from('<H', window, idxw+6)[0]
                if base is not None:
                    lines.append(f"{addr_s}: INPUT -> V_{base:04x}")
                    suppress_next_0690 = True
                    generated = True
                else:
                    lines.append(f"{addr_s}: CALL_SUB 0x{call_target_rel:04x}")
                    generated = True
                continue
            if mnem.startswith("ret"):
                lines.append(f"{addr_s}: RETURN")
                generated = True
        elif kind == 'FPU':
            parts = mnem.split(" ", 1); op = parts[0]; rest = parts[1] if len(parts) > 1 else ""
            try:
                if op == "FLD":
                    arg = sym(rest.split(" ", 1)[1].strip()) if ("m32real" in rest or "m64real" in rest) else rest
                    stack_fpu.insert(0, arg)
                elif op in ("FSTP", "FST"):
                    target = sym(rest.split(" ", 1)[-1].strip())
                    rhs = stack_fpu[0]
                    lines.append(f"{addr_s}: FORMULA {target} = {rhs}")
                    generated = True
                    suppress_next_0690 = False
                    if op == "FSTP": stack_fpu.pop(0)
                elif op in ("FADD", "FSUB", "FMUL", "FDIV", "FSUBR", "FDIVR"):
                    b = sym(rest.split(" ", 1)[1].strip()) if ("m32real" in rest or "m64real" in rest) else rest
                    a = stack_fpu[0]
                    so = {"FADD": "+", "FSUB": "-", "FMUL": "*", "FDIV": "/", "FSUBR": "-", "FDIVR": "/"}[op]
                    stack_fpu[0] = f"({b} {so} {a})" if op in ("FSUBR", "FDIVR") else f"({a} {so} {b})"
                elif op == "FSQRT": stack_fpu[0] = f"sqrt({stack_fpu[0]})"
                elif op == "FABS": stack_fpu[0] = f"abs({stack_fpu[0]})"
                elif op == "FCHS": stack_fpu[0] = f"(-{stack_fpu[0]})"
            except Exception:
                stack_fpu = []
            continue

        if not generated and off in jump_targets:
            lines.append(f"{addr_s}: ; jump target label")
            suppress_next_0690 = False

    def replace_arr(match):
        offset = int(match.group(2))
        return f"V_{offset:04x}"
    lines = [re.sub(r"ARR_(SI|DI|BX|BP)\[(\+\d+)\]", replace_arr, line) for line in lines]

    existing_addrs = set()
    for line in lines:
        m = re.match(r"^CODE:([0-9a-f]+):", line)
        if m:
            existing_addrs.add(f"CODE:{m.group(1)}")
    new_lines = []
    for line in lines:
        m = re.match(r"^(CODE:[0-9a-f]+): jmp (0x[0-9a-f]+)", line)
        if m:
            target_addr = f"CODE:{m.group(2)[2:]}"
            if target_addr not in existing_addrs:
                continue
        new_lines.append(line)
    lines = new_lines

    cleaned = []
    prev_was_print = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(";") or stripped == "":
            cleaned.append(line)
            continue
        is_print = stripped.startswith("PRINT ")
        is_call_sub = re.match(r"^CODE:[0-9a-f]+: CALL_SUB 0x[0-9a-f]+", stripped)
        if is_call_sub and prev_was_print:
            prev_was_print = is_print
            continue
        cleaned.append(line)
        prev_was_print = is_print
    lines = cleaned

    return lines
