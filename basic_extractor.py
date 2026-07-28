#!/usr/bin/env python3
import sys, struct, re, argparse, bisect
from capstone import Cs, CS_ARCH_X86, CS_MODE_16

# ================= 1. MZ header =================
def parse_mz_header(data):
    if data[0:2] != b'MZ': raise ValueError("Not an MZ executable")
    fields = struct.unpack_from('<14H', data, 2)
    names = ['e_cblp','e_cp','e_crlc','e_cparhdr','e_minalloc','e_maxalloc',
             'e_ss','e_sp','e_csum','e_ip','e_cs','e_lfarlc','e_ovno']
    h = dict(zip(names, fields[:13]))
    h['header_bytes'] = h['e_cparhdr'] * 16
    return h

# ================= 2. Строковый сегмент =================
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

def read_short_string_descriptor(data, seg_start, near_off):
    p = seg_start + near_off
    if p+4 > len(data): return None
    length = data[p] | (data[p+1] << 8)
    ptr = data[p+2] | (data[p+3] << 8)
    if length > 64: return None
    chars = data[seg_start+ptr:seg_start+ptr+length]
    try: return chars.decode('cp866', errors='replace')
    except Exception: return None

def read_const_float(data, seg_start, near_off):
    p = seg_start + near_off
    if p+4 > len(data): return None
    try: return struct.unpack('<f', data[p:p+4])[0]
    except Exception: return None

def read_const_uint16(data, seg_start, near_off):
    p = seg_start + near_off
    if p+2 > len(data): return None
    return data[p] | (data[p+1] << 8)

# ================= 3. x87 "ESC-через-INT" =================
def modrm_mem_operand(mod, rm, bytes_at):
    bases = {0:"BX+SI",1:"BX+DI",2:"BP+SI",3:"BP+DI",4:"SI",5:"DI",6:"BP",7:"BX"}
    if mod == 0 and rm == 6:
        disp = struct.unpack_from('<H', bytes_at, 0)[0]; return f"[0x{disp:04x}]", disp, 2
    elif mod == 0: return f"[{bases[rm]}]", None, 0
    elif mod == 1:
        disp = struct.unpack_from('<b', bytes_at, 0)[0]
        return f"[{bases[rm]}{'+' if disp>=0 else ''}{disp}]", None, 1
    elif mod == 2:
        disp = struct.unpack_from('<h', bytes_at, 0)[0]
        return f"[{bases[rm]}{'+' if disp>=0 else ''}{disp}]", None, 2
    return "?", None, 0

D8_MEM=["FADD","FMUL","FCOM","FCOMP","FSUB","FSUBR","FDIV","FDIVR"]
D8_REG=["FADD ST,ST({0})","FMUL ST,ST({0})","FCOM ST({0})","FCOMP ST({0})",
        "FSUB ST,ST({0})","FSUBR ST,ST({0})","FDIV ST,ST({0})","FDIVR ST,ST({0})"]
DA_MEM=["FIADD","FIMUL","FICOM","FICOMP","FISUB","FISUBR","FIDIV","FIDIVR"]
DC_MEM=["FADD","FMUL","FCOM","FCOMP","FSUB","FSUBR","FDIV","FDIVR"]
DC_REG=["FADD ST({0}),ST","FMUL ST({0}),ST",None,None,"FSUBR ST({0}),ST","FSUB ST({0}),ST",
        "FDIVR ST({0}),ST","FDIV ST({0}),ST"]
DE_MEM=["FIADD","FIMUL","FICOM","FICOMP","FISUB","FISUBR","FIDIV","FIDIVR"]
DE_REG=["FADDP ST({0}),ST","FMULP ST({0}),ST",None,"FCOMPP","FSUBRP ST({0}),ST","FSUBP ST({0}),ST",
        "FDIVRP ST({0}),ST","FDIVP ST({0}),ST"]
D9_SPECIAL={(4,0):"FCHS",(4,1):"FABS",(4,4):"FTST",(4,5):"FXAM",
    (5,0):"FLD1",(5,1):"FLDL2T",(5,2):"FLDL2E",(5,3):"FLDPI",(5,4):"FLDLG2",(5,5):"FLDLN2",(5,6):"FLDZ",
    (6,0):"F2XM1",(6,1):"FYL2X",(6,2):"FPTAN",(6,3):"FPATAN",(6,4):"FXTRACT",(6,6):"FDECSTP",(6,7):"FINCSTP",
    (7,0):"FPREM",(7,1):"FYL2XP1",(7,2):"FSQRT",(7,4):"FRNDINT",(7,5):"FSCALE",(2,0):"FNOP",(3,0):"FSTP1"}

def decode_D8(mod,reg,rm,mb):
    if mod==3: return D8_REG[reg].format(rm),0,None
    op,near,c = modrm_mem_operand(mod,rm,mb); return f"{D8_MEM[reg]} m32real {op}",c,near
def decode_D9(mod,reg,rm,mb):
    if mod==3:
        s=D9_SPECIAL.get((reg,rm))
        if s: return s,0,None
        if reg==0: return f"FLD ST({rm})",0,None
        if reg==1: return f"FXCH ST({rm})",0,None
        return f"D9/{reg},{rm}(?)",0,None
    names={0:"FLD",2:"FST",3:"FSTP",4:"FLDENV",5:"FLDCW",6:"FSTENV",7:"FSTCW"}
    op,near,c = modrm_mem_operand(mod,rm,mb)
    suf = "m32real" if reg in (0,2,3) else ""
    return f"{names.get(reg,'D9/?')} {suf} {op}".strip(),c,near
def decode_DA(mod,reg,rm,mb):
    if mod==3:
        if reg==5 and rm==1: return "FUCOMPP",0,None
        return f"DA/{reg},{rm}(?)",0,None
    op,near,c = modrm_mem_operand(mod,rm,mb); return f"{DA_MEM[reg]} m32int {op}",c,near
def decode_DB(mod,reg,rm,mb):
    if mod==3:
        c_ = {(4,2):"FNCLEX",(4,3):"FNINIT"}.get((reg,rm))
        return (c_ or f"DB/{reg},{rm}(?)"),0,None
    names={0:"FILD m32int",2:"FIST m32int",3:"FISTP m32int",5:"FLD m80real",7:"FSTP m80real"}
    op,near,c = modrm_mem_operand(mod,rm,mb); return f"{names.get(reg,f'DB/{reg}(?)')} {op}",c,near
def decode_DC(mod,reg,rm,mb):
    if mod==3:
        s=DC_REG[reg]; return (s.format(rm) if s else f"DC/{reg},{rm}(?)"),0,None
    op,near,c = modrm_mem_operand(mod,rm,mb); return f"{DC_MEM[reg]} m64real {op}",c,near
def decode_DD(mod,reg,rm,mb):
    if mod==3:
        names={0:"FFREE ST({0})",2:"FST ST({0})",3:"FSTP ST({0})",4:"FUCOM ST({0})",5:"FUCOMP ST({0})"}
        s=names.get(reg); return (s.format(rm) if s else f"DD/{reg},{rm}(?)"),0,None
    names={0:"FLD",2:"FST",3:"FSTP",4:"FRSTOR",6:"FSAVE",7:"FSTSW"}
    op,near,c = modrm_mem_operand(mod,rm,mb)
    suf = "m64real" if reg in (0,2,3) else ""
    return f"{names.get(reg,f'DD/{reg}(?)')} {suf} {op}".strip(),c,near
def decode_DE(mod,reg,rm,mb):
    if mod==3:
        s=DE_REG[reg]
        if s: return (s if reg==3 else s.format(rm)),0,None
        return f"DE/{reg},{rm}(?)",0,None
    op,near,c = modrm_mem_operand(mod,rm,mb); return f"{DE_MEM[reg]} m16int {op}",c,near
def decode_DF(mod,reg,rm,mb):
    if mod==3:
        if reg==4 and rm==0: return "FSTSW AX",0,None
        return f"DF/{reg},{rm}(?)",0,None
    names={0:"FILD m16int",2:"FIST m16int",3:"FISTP m16int",4:"FBLD m80bcd",5:"FILD m64int",6:"FBSTP m80bcd",7:"FISTP m64int"}
    op,near,c = modrm_mem_operand(mod,rm,mb); return f"{names.get(reg,f'DF/{reg}(?)')} {op}",c,near

DECODERS = {0x34:decode_D8,0x35:decode_D9,0x36:decode_DA,0x37:decode_DB,
            0x38:decode_DC,0x39:decode_DD,0x3a:decode_DE,0x3b:decode_DF}

# ================= 4. Комбинированный дизассемблер =================
_md = Cs(CS_ARCH_X86, CS_MODE_16)

def disasm_range(data, start, end, label_base=None, stop_on_ret=False):
    if label_base is None: label_base = start
    i = start; out = []
    while i < end:
        if data[i] == 0xCD and i+1 < end and data[i+1] in DECODERS:
            modrm = data[i+2] if i+2 < end else 0
            mod=(modrm>>6)&3; reg=(modrm>>3)&7; rm=modrm&7
            mem_bytes = data[i+3:i+5]
            try: mnem, consumed, near = DECODERS[data[i+1]](mod,reg,rm,mem_bytes)
            except Exception as e: mnem, consumed, near = f"ERR {e}", 0, None
            length = 3+consumed
            out.append((i-label_base,'FPU',mnem,length,near,i)); i += length
        else:
            chunk = data[i:i+16]
            dec = list(_md.disasm(chunk, i, count=1))
            if not dec:
                out.append((i-label_base,'???',f"db 0x{data[i]:02x}",1,None,i)); i += 1; continue
            insn = dec[0]
            mnem_full = f"{insn.mnemonic} {insn.op_str}".strip()
            out.append((i-label_base,'X86', mnem_full, insn.size, None, i))
            i += insn.size
            if stop_on_ret and (insn.mnemonic.startswith('ret')):
                break
    return out

# ================= 5. sym() =================
FLOAT_TO_INT_TARGET = (0xf63, 0x3dc)

def sym(operand):
    m = re.match(r"\[0x([0-9a-f]+)\]", operand)
    if m: return f"V_{m.group(1)}"
    m = re.match(r"\[(SI|DI|BX|BP)([+\-]\d+)\]", operand)
    if m: return f"ARR_{m.group(1)}[{m.group(2)}]"
    return operand

# ================= 6. Авто-детект целей рантайма =================
LCALL_RE = re.compile(r"lcall\s+(0x[0-9a-f]+)\s*[:,]\s*(0x[0-9a-f]+)")

def auto_detect_calls(instrs, pstrings, data, str_seg_start):
    push_imm_re = re.compile(r"push ax$")
    mov_ax_re = re.compile(r"mov ax, (0x[0-9a-f]+|\d+)$")
    mov_bx_re = re.compile(r"mov bx, (0x[0-9a-f]+)$")

    last_imm = None
    pushes_since_call = []
    last_mov_bx = None
    print_votes, input_votes, strcmp_votes, floatcmp_votes = {}, {}, {}, {}

    for idx,(off,kind,mnem,length,near,fa) in enumerate(instrs):
        if kind == 'FPU':
            continue

        m_ax = mov_ax_re.match(mnem)
        m_bx = mov_bx_re.match(mnem)
        is_push = push_imm_re.match(mnem)
        mc = LCALL_RE.match(mnem)
        is_jump = re.match(r"^(jmp|je|jne|jb|jbe|ja|jae|jl|jle|jg|jge|loop|jcxz|call)", mnem)

        if m_bx:
            last_mov_bx = int(m_bx.group(1),16)
            continue
        if m_ax:
            last_imm = int(m_ax.group(1),16) if m_ax.group(1).startswith('0x') else int(m_ax.group(1))
            continue
        if is_push and last_imm is not None:
            pushes_since_call.append(last_imm)
            continue
        if mc:
            seg, off = int(mc.group(1),16), int(mc.group(2),16)
            tgt = (seg, off)
            if pushes_since_call and pushes_since_call[-1] in pstrings:
                print_votes[tgt] = print_votes.get(tgt,0) + 1
            if last_mov_bx is not None:
                input_votes[tgt] = input_votes.get(tgt,0) + 1
            if len(pushes_since_call) == 2:
                for cand in (pushes_since_call[0], pushes_since_call[1]):
                    d1 = read_short_string_descriptor(data, str_seg_start, cand)
                    if d1 is not None and len(d1) == 1 and d1.isprintable() and d1.isalpha():
                        strcmp_votes[tgt] = strcmp_votes.get(tgt,0) + 1
                        break
            last_mov_bx = None
            pushes_since_call = []
            last_imm = None
            continue

        if is_jump:
            continue

    for idx in range(2, len(instrs)-1):
        off,kind,mnem,length,near,fa = instrs[idx]
        if kind=='X86' and mnem.startswith('int '):
            o1,k1,m1,l1,n1,f1 = instrs[idx+1]
            mc = LCALL_RE.match(m1) if k1=='X86' else None
            if mc:
                o2,k2,m2,l2,n2,f2 = instrs[idx-1]
                if k2=='FPU' and m2.startswith('FLD'):
                    tgt = (int(mc.group(1),16), int(mc.group(2),16))
                    floatcmp_votes[tgt] = floatcmp_votes.get(tgt,0) + 1

    pick = lambda votes: max(votes.items(), key=lambda kv: kv[1])[0] if votes else None
    return pick(print_votes), pick(input_votes), pick(strcmp_votes), pick(floatcmp_votes)

# ================= 7. Реконструкция условий =================
JCC_MAP = {'je':'==','jne':'!=','jb':'<','jbe':'<=','ja':'>','jae':'>=','jl':'<','jle':'<=','jg':'>','jge':'>='}

def parse_cmp_operands(mnem):
    m = re.match(r"cmp\s+(.*),\s*(.*)", mnem)
    if m: return m.group(1), m.group(2), False
    m = re.match(r"test\s+(.*),\s*(.*)", mnem)
    if m: return m.group(1), m.group(2), True
    return None, None, None

def reconstruct_conditions(instrs, data, str_seg_start, strcmp_target, floatcmp_target):
    call_re = LCALL_RE
    jump_re = re.compile(r"^(j[a-z]+)\s+(0x[0-9a-f]+)$")
    conditions = {}

    # Float/strcmp
    stack_fpu = []
    push_imm_hist = []
    last_imm = None
    strcmp_literal_by_idx = {}
    i, n = 0, len(instrs)
    while i < n:
        off,kind,mnem,length,near,fa = instrs[i]
        if kind=='FPU':
            parts = mnem.split(" ",1); op=parts[0]; rest=parts[1] if len(parts)>1 else ""
            try:
                if op=="FLD":
                    stack_fpu.insert(0, sym(rest.split(" ",1)[1].strip()) if ("m32real" in rest or "m64real" in rest) else rest)
                elif op in ("FSTP","FST"):
                    match = re.search(r"ST\((\d+)\)", rest)
                    if match:
                        k = int(match.group(1))
                        if op == "FSTP":
                            stack_fpu.pop(0)
                        else:
                            stack_fpu[k] = stack_fpu[0]
                    elif op == "FSTP":
                        stack_fpu.pop(0)
                elif op in ("FADD","FSUB","FMUL","FDIV","FSUBR","FDIVR"):
                    b = sym(rest.split(" ",1)[1].strip()) if ("m32real" in rest or "m64real" in rest) else rest
                    a = stack_fpu[0]
                    so={"FADD":"+","FSUB":"-","FMUL":"*","FDIV":"/","FSUBR":"-","FDIVR":"/"}[op]
                    stack_fpu[0] = f"({b} {so} {a})" if op in ("FSUBR","FDIVR") else f"({a} {so} {b})"
                elif op=="FSQRT": stack_fpu[0]=f"sqrt({stack_fpu[0]})"
                elif op=="FABS": stack_fpu[0]=f"abs({stack_fpu[0]})"
                elif op=="FCHS": stack_fpu[0]=f"(-{stack_fpu[0]})"
                elif op in ("FCOMP","FUCOMP"): stack_fpu.pop(0)
                elif op == "FCOMPP": stack_fpu.pop(0); stack_fpu.pop(0)
            except Exception: pass
            i+=1; continue

        m = re.match(r"mov ax, (0x[0-9a-f]+|\d+)$", mnem)
        if m:
            last_imm = int(m.group(1),16) if m.group(1).startswith('0x') else int(m.group(1))
            i+=1; continue
        if mnem=="push ax" and last_imm is not None:
            push_imm_hist.append(last_imm); push_imm_hist = push_imm_hist[-2:]
            i+=1; continue

        mc = call_re.match(mnem)
        if mc:
            tgt = (int(mc.group(1),16), int(mc.group(2),16))
            if tgt == FLOAT_TO_INT_TARGET:
                if stack_fpu: stack_fpu.pop(0)
                i += 1; continue
            if floatcmp_target and tgt==floatcmp_target:
                try:
                    b = stack_fpu.pop(0); a = stack_fpu.pop(0)
                    j = i+1
                    while j<n:
                        _,kj,mj,_,_,_ = instrs[j]
                        if kj!='X86' or not jump_re.match(mj):
                            if kj=='X86' and not (re.match(r"^(mov|lea|push|pop|nop|xchg)", mj)): break
                            j+=1; continue
                        jm = jump_re.match(mj)
                        if jm and jm.group(1)!='jmp':
                            opy = JCC_MAP.get(jm.group(1),'?')
                            conditions[j] = f"{a} {opy} {b}"
                        j+=1; break
                except Exception: pass
            elif strcmp_target and tgt==strcmp_target and len(push_imm_hist)==2:
                lit = None
                for cand in (push_imm_hist[0], push_imm_hist[1]):
                    lit_try = read_short_string_descriptor(data, str_seg_start, cand)
                    if lit_try is not None and len(lit_try)==1 and lit_try.isprintable() and lit_try.isalpha():
                        lit = lit_try; break
                if lit is not None:
                    j = i+1
                    while j<n:
                        _,kj,mj,_,_,_ = instrs[j]
                        if kj!='X86' or not jump_re.match(mj):
                            if kj=='X86' and not (re.match(r"^(mov|lea|push|pop|nop|xchg)", mj)): break
                            j+=1; continue
                        jm = jump_re.match(mj)
                        if jm and jm.group(1)!='jmp':
                            opy = JCC_MAP.get(jm.group(1),'?')
                            conditions[j] = f"input_str {opy} {lit!r}"
                            strcmp_literal_by_idx[j] = lit
                            j+=1; continue
                        else: break
                push_imm_hist = []
            i+=1; continue

        if kind=='X86' and not re.match(r"^(mov|lea|push|pop|nop|xchg|call)", mnem):
            push_imm_hist = []
        i+=1

    # OR-комбинации strcmp
    for idx in range(3, len(instrs)):
        o0,k0,m0,_,_,_ = instrs[idx-3]
        o1,k1,m1,_,_,_ = instrs[idx-2]
        o2,k2,m2,_,_,_ = instrs[idx-1]
        o3,k3,m3,_,_,_ = instrs[idx]
        if not (k0==k1==k2==k3=='X86'): continue
        if m0 != "dec ax": continue
        if not re.match(r"or ax, word ptr \[bp", m1): continue
        if m2 != "and ax, ax": continue
        jm = jump_re.match(m3)
        if not jm or jm.group(1)=='jmp': continue
        jcc = jm.group(1)
        prior = sorted(k for k in strcmp_literal_by_idx if k < idx-3)
        if len(prior) >= 2:
            lit1 = strcmp_literal_by_idx[prior[-2]]
            lit2 = strcmp_literal_by_idx[prior[-1]]
            if jcc == 'je':
                conditions[idx] = f"input_str != {lit1!r} and input_str != {lit2!r}"
            elif jcc == 'jne':
                conditions[idx] = f"input_str == {lit1!r} or input_str == {lit2!r}"

    # Целочисленные cmp/test с нормализацией
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

    for idx in range(1, len(instrs)):
        _,k1,m1,_,_,_ = instrs[idx-1]
        _,k2,m2,_,_,_ = instrs[idx]
        if k1!='X86' or k2!='X86': continue
        jm = jump_re.match(m2)
        if not jm or jm.group(1)=='jmp': continue
        if idx in conditions: continue
        left, right, is_test = parse_cmp_operands(m1)
        if left is None: continue
        jcc = jm.group(1)
        op = JCC_MAP.get(jcc)
        if not op: continue

        left_sym = resolve_operand(left)
        right_sym = resolve_operand(right)

        if left_sym is not None and right_sym is not None:
            left_is_var = left_sym.startswith("V_") or left_sym.startswith("ARR_")
            right_is_var = right_sym.startswith("V_") or right_sym.startswith("ARR_")
            if not left_is_var and right_is_var:
                left_sym, right_sym = right_sym, left_sym

        if is_test:
            if left_sym == right_sym:
                conditions[idx] = f"{left_sym} {op} 0"
            else:
                conditions[idx] = f"({left_sym} & {right_sym}) {op} 0"
        else:
            conditions[idx] = f"{left_sym} {op} {right_sym}"

    return conditions

# ================= 8. Поиск констант =================
def lookup_var_value(var_name, data, data_seg_start, pstrings):
    m = re.match(r"V_([0-9a-f]+)", var_name)
    if not m: return None
    off = int(m.group(1), 16)
    f = read_const_float(data, data_seg_start, off)
    if f is not None and abs(f) > 1e-6:
        return f"{f:g}"
    return None

# ================= 9. Псевдокод =================
def detect_choice_writes(instrs, input_target, pstrings):
    results = []
    n = len(instrs)
    shl_re = re.compile(r"^shl \w+, ?1$")
    add_re = re.compile(r"^add ax, (0x[0-9a-f]+|\d+)$")
    for i in range(n):
        off, kind, mnem, length, near, fa = instrs[i]
        if kind != 'FPU' or not mnem.startswith('FLD'):
            continue
        j = i + 1
        if j >= n or instrs[j][1] != 'X86': continue
        mc = LCALL_RE.match(instrs[j][2])
        if not mc or (int(mc.group(1),16), int(mc.group(2),16)) != FLOAT_TO_INT_TARGET:
            continue
        j += 1
        shl_count = 0
        while j < n and instrs[j][1]=='X86' and shl_re.match(instrs[j][2]):
            shl_count += 1; j += 1
        if shl_count == 0:
            continue
        if j >= n or instrs[j][1] != 'X86': continue
        m_add = add_re.match(instrs[j][2])
        if not m_add:
            continue
        base = int(m_add.group(1),16) if m_add.group(1).startswith('0x') else int(m_add.group(1))
        j += 1
        if j >= n or instrs[j][1] != 'X86' or instrs[j][2] != 'mov bx, ax':
            continue
        j += 1
        skip_ops = {'push ds','pop es','push es','push bx'}
        seen_ops = set()
        while j < n and instrs[j][1]=='X86' and instrs[j][2] in skip_ops:
            seen_ops.add(instrs[j][2]); j += 1
        if j >= n or instrs[j][1] != 'X86':
            continue
        mc2 = LCALL_RE.match(instrs[j][2])
        if not mc2 or (int(mc2.group(1),16), int(mc2.group(2),16)) != input_target:
            continue
        stride = 2 ** shl_count
        results.append((j, base, stride, i))
    return results

def find_menu_options(instrs, print_target, pstrings, before_idx, max_back=150):
    num_re = re.compile(r"^(\d+)\s+(.+)$")
    options = {}
    last_imm = None
    j = before_idx - 1
    steps = 0
    while j >= 0 and steps < max_back:
        off, kind, mnem, length, near, fa = instrs[j]
        if kind == 'X86':
            mc = LCALL_RE.match(mnem)
            if mc and (int(mc.group(1),16), int(mc.group(2),16)) == print_target:
                if j-1 >= 0 and instrs[j-1][1]=='X86' and instrs[j-1][2]=='push ax' and \
                   j-2 >= 0 and instrs[j-2][1]=='X86':
                    m2 = re.match(r"mov ax, (0x[0-9a-f]+)$", instrs[j-2][2])
                    if m2:
                        straddr = int(m2.group(1),16)
                        txt = pstrings.get(straddr, "")
                        m3 = num_re.match(txt.strip())
                        if m3:
                            options[int(m3.group(1))] = m3.group(2).strip()
            j -= 1; steps += 1; continue
        j -= 1; steps += 1
    return options if len(options) >= 2 else {}

def build_pseudocode(instrs, pstrings, print_target, input_target, conditions,
                     data, data_seg_start, print_num_target=None, seg_label="CODE",
                     code_start=0):
    call_re = re.compile(r"lcall (0x[0-9a-f]+), (0x[0-9a-f]+)")
    jump_re = re.compile(r"^(j[a-z]+)\s+(0x[0-9a-f]+)$")
    last_imm = None; last_mov_bx = None; pending_push = None
    lines = []; stack_fpu = []

    # Флаг для подавления следующего INPUT V_0690 после обёртки ввода
    suppress_next_0690 = False

    emitted_addrs = []
    _last_imm=None; _last_mov_bx=None; _pending_push=None
    for idx,(off,kind,mnem,length,near,fa) in enumerate(instrs):
        if kind=='X86':
            m = re.match(r"mov bx, (0x[0-9a-f]+)$", mnem)
            if m: _last_mov_bx = int(m.group(1),16)
            m = re.match(r"mov (\w+), (0x[0-9a-f]+|\d+)$", mnem)
            if m and m.group(1) in ('ax','bx','cx','dx'):
                _last_imm = int(m.group(2),16) if m.group(2).startswith('0x') else int(m.group(2))
                continue
            m_push = re.match(r"push word ptr \[(0x[0-9a-f]+)\]", mnem)
            if m_push: _pending_push = int(m_push.group(1),16); continue
            if mnem.startswith("push ax") and _last_imm is not None:
                _pending_push = _last_imm; continue
            mc = call_re.match(mnem)
            if mc:
                tgt = (int(mc.group(1),16), int(mc.group(2),16))
                if tgt == print_target and _pending_push in pstrings:
                    emitted_addrs.append(off); _pending_push=None
                elif tgt == input_target and (_last_mov_bx is not None or _pending_push is not None):
                    emitted_addrs.append(off); _last_mov_bx=None; _pending_push=None
                elif print_num_target is not None and tgt == print_num_target and _pending_push is not None:
                    if _pending_push > 0xF and _pending_push not in pstrings:
                        emitted_addrs.append(off)
                    _pending_push=None
                continue
            if jump_re.match(mnem):
                emitted_addrs.append(off); continue
            if re.match(r"^call (0x[0-9a-f]+)$", mnem):
                emitted_addrs.append(off); continue
            if mnem.startswith("ret"):
                emitted_addrs.append(off); continue
        elif kind=='FPU':
            parts = mnem.split(" ",1); op=parts[0]
            if op in ("FSTP","FST"):
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

    for idx,(off,kind,mnem,length,near,fa) in enumerate(instrs):
        addr_s = f"{seg_label}:{off:04x}"
        generated = False

        if kind == 'X86':
            m = re.match(r"mov bx, (0x[0-9a-f]+)$", mnem)
            if m: last_mov_bx = int(m.group(1),16)
            m = re.match(r"mov (\w+), (0x[0-9a-f]+|\d+)$", mnem)
            if m and m.group(1) in ('ax','bx','cx','dx'):
                last_imm = int(m.group(2),16) if m.group(2).startswith('0x') else int(m.group(2))
                continue
            m_push = re.match(r"push word ptr \[(0x[0-9a-f]+)\]", mnem)
            if m_push:
                pending_push = int(m_push.group(1), 16)
                continue
            if mnem.startswith("push ax") and last_imm is not None:
                pending_push = last_imm; continue
            mc = call_re.match(mnem)
            if mc:
                tgt = (int(mc.group(1),16), int(mc.group(2),16))
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
                        # Подавляем дублирующий INPUT
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
                jcc, target_abs = mj.group(1), int(mj.group(2),16)
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
                        lines.append(f"{addr_s}: {jcc} {target_str}  [условие не распознано]")
                generated = True
                # jmp не сбрасывает suppress_next_0690, он сохраняется
                continue
            mcall_near = re.match(r"^call (0x[0-9a-f]+)$", mnem)
            if mcall_near:
                call_target_abs = int(mcall_near.group(1),16)
                call_target_rel = call_target_abs - code_start
                file_off = code_start + call_target_rel
                base = None
                if file_off + 4 < len(data) and data[file_off:file_off+4] == b'\x58\x05\x0D\x00':
                    window = data[file_off:file_off+0x40]
                    idx = window.find(b'\xD1\xE0\xD1\xE0')
                    if idx != -1 and idx + 5 < len(window) and window[idx+4:idx+6] == b'\x81\xC0':
                        base = struct.unpack_from('<H', window, idx+6)[0]
                if base is not None:
                    lines.append(f"{addr_s}: INPUT -> V_{base:04x}")
                    suppress_next_0690 = True   # следующий INPUT 0690 будет подавлен
                    generated = True
                else:
                    lines.append(f"{addr_s}: CALL_SUB 0x{call_target_rel:04x}")
                    generated = True
                continue
            if mnem.startswith("ret"):
                lines.append(f"{addr_s}: RETURN")
                generated = True
        elif kind == 'FPU':
            parts = mnem.split(" ",1); op=parts[0]; rest=parts[1] if len(parts)>1 else ""
            try:
                if op=="FLD":
                    arg = sym(rest.split(" ",1)[1].strip()) if ("m32real" in rest or "m64real" in rest) else rest
                    stack_fpu.insert(0, arg)
                elif op in ("FSTP","FST"):
                    target = sym(rest.split(" ",1)[-1].strip())
                    rhs = stack_fpu[0]
                    lines.append(f"{addr_s}: FORMULA {target} = {rhs}")
                    generated = True
                    suppress_next_0690 = False
                    if op=="FSTP": stack_fpu.pop(0)
                elif op in ("FADD","FSUB","FMUL","FDIV","FSUBR","FDIVR"):
                    b = sym(rest.split(" ",1)[1].strip()) if ("m32real" in rest or "m64real" in rest) else rest
                    a = stack_fpu[0]
                    so={"FADD":"+","FSUB":"-","FMUL":"*","FDIV":"/","FSUBR":"-","FDIVR":"/"}[op]
                    stack_fpu[0] = f"({b} {so} {a})" if op in ("FSUBR","FDIVR") else f"({a} {so} {b})"
                elif op=="FSQRT": stack_fpu[0]=f"sqrt({stack_fpu[0]})"
                elif op=="FABS": stack_fpu[0]=f"abs({stack_fpu[0]})"
                elif op=="FCHS": stack_fpu[0]=f"(-{stack_fpu[0]})"
            except Exception:
                stack_fpu = []
            continue

        if not generated and off in jump_targets:
            lines.append(f"{addr_s}: ; метка перехода")
            suppress_next_0690 = False

    def replace_arr(match):
        offset = int(match.group(2))
        return f"V_{offset:04x}"
    lines = [re.sub(r"ARR_(SI|DI|BX|BP)\[(\+\d+)\]", replace_arr, line) for line in lines]

    # Удаление jmp в никуда
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

    # Удаление CALL_SUB, идущих сразу после PRINT
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

# ================= main =================

# ================= СТРУКТУРИРОВАНИЕ if/while =================

class Stmt:
    __slots__ = ('addr','kind','text','target','cond')
    def __init__(self, addr, kind, text, target=None, cond=None):
        self.addr=addr; self.kind=kind; self.text=text; self.target=target; self.cond=cond
    def __repr__(self):
        return f"<{self.kind} @{self.addr:04x} target={self.target}>"

LINE_RE = re.compile(r"^CODE:([0-9a-f]+): (.+)$")
GOTO_RE = re.compile(r"GOTO (0x[0-9a-f]+)")
JMP_RE  = re.compile(r"^jmp (0x[0-9a-f]+)")
IF_RE   = re.compile(r"^IF \((.+)\) GOTO 0x[0-9a-f]+")

def parse_statements(lines):
    stmts = []
    for line in lines:
        if line.startswith(';') or not line.strip():
            continue
        m = LINE_RE.match(line)
        if not m: continue
        addr = int(m.group(1),16)
        rest = m.group(2)
        if rest.startswith('PRINT '):
            stmts.append(Stmt(addr,'PRINT',rest))
        elif rest.startswith('INPUT -> '):
            stmts.append(Stmt(addr,'INPUT',rest))
        elif rest.startswith('FORMULA '):
            stmts.append(Stmt(addr,'FORMULA',rest))
        elif rest.startswith('CALL_SUB '):
            stmts.append(Stmt(addr,'PRINT',rest))
        elif rest.startswith('IF ('):
            gm = GOTO_RE.search(rest); im = IF_RE.match(rest)
            target = int(gm.group(1),16) if gm else None
            cond = im.group(1) if im else '?'
            stmts.append(Stmt(addr,'IF',rest,target,cond))
        elif rest.startswith('jmp '):
            jm = JMP_RE.match(rest)
            target = int(jm.group(1),16) if jm else None
            stmts.append(Stmt(addr,'JMP',rest,target))
        elif rest.startswith('RETURN'):
            stmts.append(Stmt(addr,'RETURN',rest))
    return stmts

def build_index(stmts):
    return {s.addr: i for i,s in enumerate(stmts)}

def detect_loops(stmts, addr2idx):
    loops = {}
    for i,s in enumerate(stmts):
        if s.target is None: continue
        tgt_idx = addr2idx.get(s.target)
        if tgt_idx is None: continue
        if tgt_idx <= i:
            loops[tgt_idx] = max(loops.get(tgt_idx, tgt_idx), i)
    return loops

def region_is_simple(stmts, lo, hi, addr2idx):
    for i in range(lo, hi):
        s = stmts[i]
        if s.target is None: continue
        tgt_idx = addr2idx.get(s.target)
        if tgt_idx is None: continue
        if tgt_idx < lo or tgt_idx > hi:
            return False
    return True

INDENT = "    "

def detect_ladder(stmts, addr2idx, i):
    conditions = []
    branch_idxs = []
    j = i
    while True:
        if j+1 >= len(stmts) or stmts[j].kind != 'IF' or stmts[j+1].kind != 'JMP':
            return None
        if_stmt, jmp_stmt = stmts[j], stmts[j+1]
        a_idx = addr2idx.get(if_stmt.target)
        jmp_idx = addr2idx.get(jmp_stmt.target)
        if a_idx is None or jmp_idx is None:
            return None
        conditions.append(if_stmt.cond)
        branch_idxs.append(a_idx)
        if jmp_idx == j+2 and j+2 < len(stmts) and stmts[j+2].kind == 'IF':
            j += 2
            continue
        if len(conditions) < 2:
            return None
        return conditions, branch_idxs, jmp_idx, j+2

def render_ladder(stmts, addr2idx, loops, conditions, branch_idxs, else_idx, depth):
    pad = INDENT*depth
    out = []
    all_starts = sorted(set(branch_idxs) | {else_idx})
    def region_end(start_idx, overall_hi):
        for s in all_starts:
            if s > start_idx:
                return s
        return overall_hi
    overall_hi = max(all_starts) + 200 if all_starts else len(stmts)
    overall_hi = min(overall_hi, len(stmts))
    for k, (cond, a_idx) in enumerate(zip(conditions, branch_idxs)):
        kw = "if" if k == 0 else "elif"
        out.append(f"{pad}{kw} {cond}:")
        hi = region_end(a_idx, overall_hi)
        body = render(stmts, addr2idx, loops, a_idx, hi, depth+1)
        out.extend(body if body else [f"{pad}{INDENT}pass"])
    out.append(f"{pad}else:")
    hi = region_end(else_idx, overall_hi)
    body = render(stmts, addr2idx, loops, else_idx, hi, depth+1)
    out.extend(body if body else [f"{pad}{INDENT}pass"])
    return out, max(all_starts)

def render(stmts, addr2idx, loops, lo, hi, depth=0):
    out = []
    pad = INDENT*depth
    i = lo
    while i < hi:
        if i in loops and loops[i] > i:
            back_idx = loops[i]
            out.append(f"{pad}while True:  # CODE:{stmts[i].addr:04x} .. CODE:{stmts[back_idx].addr:04x}")
            out.extend(render_loop_body(stmts, addr2idx, loops, i, back_idx, depth+1))
            i = back_idx + 1
            continue

        s = stmts[i]
        if s.kind in ('PRINT','INPUT','FORMULA'):
            text = s.text
            m = re.match(r"CALL_SUB (0x[0-9a-f]+)", text)
            if m:
                text = f"sub_{m.group(1)}()"
            out.append(f"{pad}{text}")
            i += 1
        elif s.kind == 'RETURN':
            out.append(f"{pad}return")
            i += 1
        elif s.kind == 'JMP':
            tgt_idx = addr2idx.get(s.target)
            if tgt_idx is not None and tgt_idx > i:
                out.append(f"{pad}# --- goto CODE:{s.target:04x} (пропуск блока ниже) ---")
                i = tgt_idx
            else:
                out.append(f"{pad}# GOTO CODE:{s.target:04x}  [нераспознанный переход назад]")
                i += 1
        elif s.kind == 'IF':
            ladder = detect_ladder(stmts, addr2idx, i)
            if ladder is not None:
                conditions, branch_idxs, else_idx, end_idx = ladder
                ladder_lines, max_start = render_ladder(stmts, addr2idx, loops, conditions,
                                                          branch_idxs, else_idx, depth)
                out.extend(ladder_lines)
                i = max(end_idx, max_start)
                continue
            tgt_idx = addr2idx.get(s.target)
            if tgt_idx is not None and tgt_idx == i+1:
                i += 1
            elif tgt_idx is not None and tgt_idx > i and region_is_simple(stmts, i+1, tgt_idx, addr2idx):
                out.append(f"{pad}if not ({s.cond}):")
                inner = render(stmts, addr2idx, loops, i+1, tgt_idx, depth+1)
                out.extend(inner if inner else [f"{pad}{INDENT}pass"])
                i = tgt_idx
            elif tgt_idx is not None and tgt_idx <= i:
                out.append(f"{pad}if {s.cond}:")
                out.append(f"{pad}{INDENT}continue  # переход назад к телу цикла")
                i += 1
            else:
                out.append(f"{pad}if {s.cond}:")
                out.append(f"{pad}{INDENT}pass  # GOTO CODE:{s.target:04x} [сложный переход, не структурирован]")
                i += 1
        else:
            i += 1
    return out

def render_loop_body(stmts, addr2idx, loops, header_idx, back_idx, depth):
    pad = INDENT*depth
    out = []
    i = header_idx
    while i <= back_idx:
        if i != header_idx and i in loops and loops[i] > i and loops[i] <= back_idx:
            inner_back = loops[i]
            out.append(f"{pad}while True:  # CODE:{stmts[i].addr:04x} .. CODE:{stmts[inner_back].addr:04x}")
            out.extend(render_loop_body(stmts, addr2idx, loops, i, inner_back, depth+1))
            i = inner_back + 1
            continue
        s = stmts[i]
        if s.kind in ('PRINT','INPUT','FORMULA'):
            text = s.text
            m = re.match(r"CALL_SUB (0x[0-9a-f]+)", text)
            if m:
                text = f"sub_{m.group(1)}()"
            out.append(f"{pad}{text}"); i += 1
        elif s.kind == 'RETURN':
            out.append(f"{pad}return"); i += 1
        elif s.kind == 'JMP':
            tgt_idx = addr2idx.get(s.target)
            if tgt_idx == header_idx:
                i += 1
            elif tgt_idx is not None and tgt_idx > back_idx:
                out.append(f"{pad}break  # --- goto CODE:{s.target:04x} (выход из цикла) ---")
                i += 1
            elif tgt_idx is not None and tgt_idx > i:
                out.append(f"{pad}# --- goto CODE:{s.target:04x} ---")
                i = tgt_idx
            else:
                out.append(f"{pad}continue  # goto CODE:{s.target:04x}")
                i += 1
        elif s.kind == 'IF':
            tgt_idx = addr2idx.get(s.target)
            if tgt_idx == header_idx:
                out.append(f"{pad}if {s.cond}:")
                out.append(f"{pad}{INDENT}continue")
                i += 1
            elif tgt_idx is not None and tgt_idx > back_idx:
                out.append(f"{pad}if {s.cond}:")
                out.append(f"{pad}{INDENT}break  # --- goto CODE:{s.target:04x} (выход из цикла) ---")
                i += 1
            elif tgt_idx is not None and tgt_idx == i+1:
                i += 1
            elif tgt_idx is not None and tgt_idx > i and region_is_simple(stmts, i+1, tgt_idx, addr2idx):
                out.append(f"{pad}if not ({s.cond}):")
                inner = render(stmts, addr2idx, loops, i+1, tgt_idx, depth+1)
                out.extend(inner if inner else [f"{pad}{INDENT}pass"])
                i = tgt_idx
            else:
                out.append(f"{pad}if {s.cond}:")
                out.append(f"{pad}{INDENT}pass  # GOTO CODE:{s.target:04x} [сложный переход внутри цикла]")
                i += 1
        else:
            i += 1
    return out

def structure_pseudocode(lines):
    stmts = parse_statements(lines)
    addr2idx = build_index(stmts)
    loops = detect_loops(stmts, addr2idx)
    body = render(stmts, addr2idx, loops, 0, len(stmts), depth=0)
    return "\n".join(body)

# ================= РАСПОЗНАВАНИЕ ОБЁРТОК ВВОДА =================
def decode_opaque_input_wrapper(data, file_offset):
    try:
        if data[file_offset:file_offset+11] != b'\x58\x05\x0D\x00\x0E\x50\x9A\x88\x47\xBD\x09':
            return None
        idx = data.find(b'\xD1\xE0\xD1\xE0', file_offset, file_offset+0x40)
        if idx == -1:
            return None
        if data[idx+2:idx+5] == b'\x81\xC0':
            base = struct.unpack_from('<H', data, idx+5)[0]
            return base
    except Exception:
        pass
    return None

def get_pstring_after_call(data, file_offset):
    p = file_offset
    length = data[p]
    if p + 1 + length <= len(data):
        raw = data[p+1:p+1+length]
        try:
            text = raw.decode('cp866', errors='replace')
            if text and all(c.isprintable() or c in ' \t' for c in text):
                return text
        except:
            pass
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--out", default="extracted")
    ap.add_argument("--max-scan", type=lambda x:int(x,0), default=None)
    ap.add_argument("--print-num-seg", type=lambda x:int(x,0), default=None)
    ap.add_argument("--print-num-off", type=lambda x:int(x,0), default=None)
    ap.add_argument("--input-seg", type=lambda x:int(x,0), default=None)
    ap.add_argument("--input-off", type=lambda x:int(x,0), default=None)
    args = ap.parse_args()

    with open(args.exe,'rb') as f: data = f.read()
    header = parse_mz_header(data)
    print(f"[+] MZ header: header_bytes=0x{header['header_bytes']:x}")
    code_start = header['header_bytes']
    code_end = len(data)

    str_seg = detect_string_segment(data, code_start, code_end)
    if str_seg is None:
        print("[-] Строковый сегмент не найден, используется начало кода")
        str_seg = code_start
    else:
        print(f"[+] Строковый сегмент: file offset 0x{str_seg:x}")
    pstrings = decode_pstrings(data, str_seg, code_end)
    print(f"[+] Строк: {len(pstrings)}")
    with open(f"{args.out}_strings.txt",'w',encoding='utf-8') as f:
        for off,txt in sorted(pstrings.items()): f.write(f"0x{off:04x}: {txt}\n")

    scan_end = str_seg
    if args.max_scan is not None:
        scan_end = min(scan_end, code_start+args.max_scan)
        print(f"[+] Ограничение сканирования: 0x{args.max_scan:x}")

    print("[+] Дизассемблирование...")
    instrs = disasm_range(data, code_start, scan_end)
    print(f"[+] Инструкций: {len(instrs)}")

    data_seg = str_seg

    print("[+] Автоопределение целей вызова...")
    print_t, input_t, strcmp_t, floatcmp_t = auto_detect_calls(instrs, pstrings, data, str_seg)
    print(f"    PRINT_TEXT: {print_t}   INPUT_READ: {input_t}")
    print(f"    STRCMP: {strcmp_t}   FLOAT_COMPARE_HELPER: {floatcmp_t}")

    if args.input_seg is not None and args.input_off is not None:
        input_t = (args.input_seg, args.input_off)
        print(f"    INPUT_READ (ручной): {input_t}")

    print_num_t = None
    if args.print_num_seg is not None and args.print_num_off is not None:
        print_num_t = (args.print_num_seg, args.print_num_off)
        print(f"    PRINT_NUM (ручной): {print_num_t}")

    conditions = reconstruct_conditions(instrs, data, str_seg, strcmp_t, floatcmp_t)

    lines = build_pseudocode(instrs, pstrings, print_t, input_t, conditions,
                             data, data_seg, print_num_target=print_num_t, code_start=code_start)

    print("[+] Поиск подпрограмм (near CALL)...")
    call_re_near = re.compile(r"^call (0x[0-9a-f]+)$")

    def find_call_targets_with_idx(instr_list):
        found = []
        for idx,(off,kind,mnem,length,near,fa) in enumerate(instr_list):
            if kind=='X86':
                m = call_re_near.match(mnem)
                if m:
                    t_abs = int(m.group(1),16)
                    found.append((t_abs - code_start, idx))
        return found

    def find_call_targets(instr_list):
        return [t for t,idx in find_call_targets_with_idx(instr_list)]

    processed_subs = {}
    discarded_subs = []
    opaque_helpers = []
    caller_context = {}
    SUB_MAX_LEN = 2000
    for t_rel, idx in find_call_targets_with_idx(instrs):
        caller_context.setdefault(t_rel, (instrs, idx))
    worklist = list(dict.fromkeys(find_call_targets(instrs)))
    while worklist:
        t_rel = worklist.pop(0)
        if t_rel in processed_subs or t_rel in discarded_subs or t_rel in opaque_helpers: continue
        if not (0 <= t_rel < (code_end - code_start)): continue
        sub_file_start = code_start + t_rel

        probe = disasm_range(data, sub_file_start, min(sub_file_start+10, code_end), label_base=code_start)
        if probe and probe[0][1]=='X86' and probe[0][2].startswith('pop'):
            opaque_helpers.append(t_rel)
            continue

        sub_instrs = disasm_range(data, sub_file_start, min(sub_file_start+SUB_MAX_LEN, code_end),
                                   label_base=code_start, stop_on_ret=True)
        if not sub_instrs or not sub_instrs[-1][2].startswith('ret'):
            discarded_subs.append(t_rel)
            continue
        sub_conditions = reconstruct_conditions(sub_instrs, data, str_seg, strcmp_t, floatcmp_t)
        sub_lines = build_pseudocode(sub_instrs, pstrings, print_t, input_t, sub_conditions,
                                      data, data_seg, print_num_target=print_num_t, code_start=code_start)
        processed_subs[t_rel] = (sub_instrs, sub_lines)
        for t2, idx2 in find_call_targets_with_idx(sub_instrs):
            caller_context.setdefault(t2, (sub_instrs, idx2))
            if t2 not in processed_subs and t2 not in discarded_subs and t2 not in opaque_helpers:
                worklist.append(t2)
    print(f"[+] Найдено и раскрыто подпрограмм: {len(processed_subs)}")
    # Обрезаем подпрограммы, чтобы они не захватывали код следующих
    starts = sorted(processed_subs.keys())
    for i, t_rel in enumerate(starts):
        next_start = starts[i+1] if i+1 < len(starts) else None
        if next_start is not None:
            max_addr = next_start - 1
            sub_instrs, sub_lines = processed_subs[t_rel]
            # Запоминаем все ret
            ret_instrs = [instr for instr in sub_instrs if instr[2].startswith('ret')]
            new_sub_instrs = [instr for instr in sub_instrs if instr[5] <= code_start + max_addr]
            # Если какой-то ret был выброшен, возвращаем его
            for ret_instr in ret_instrs:
                if ret_instr not in new_sub_instrs:
                    new_sub_instrs.append(ret_instr)
            # Сортируем по файловому адресу, чтобы порядок инструкций сохранился
            new_sub_instrs.sort(key=lambda x: x[5])
            if new_sub_instrs != sub_instrs:
                sub_conditions = reconstruct_conditions(new_sub_instrs, data, str_seg, strcmp_t, floatcmp_t)
                new_sub_lines = build_pseudocode(new_sub_instrs, pstrings, print_t, input_t, sub_conditions,
                                                 data, data_seg, print_num_target=print_num_t, code_start=code_start)
                processed_subs[t_rel] = (new_sub_instrs, new_sub_lines)
    if opaque_helpers:
        print(f"[!] Непрозрачных вспомогательных функций: {len(opaque_helpers)}")
    if discarded_subs:
        print(f"[!] Отброшено подозрительных 'call': {len(discarded_subs)}")

    sub_ranges = []
    for t_rel, (sub_instrs, sub_lines) in processed_subs.items():
        real_end = sub_instrs[-1][0]
        sub_ranges.append((t_rel, real_end))
    sub_ranges.sort()

    def in_any_sub_range(addr):
        for lo, hi in sub_ranges:
            if lo <= addr <= hi:
                return True
            if lo > addr:
                break
        return False

    def strip_phantom_lines(line_list):
        out = []
        for line in line_list:
            m = re.match(r"^CODE:([0-9a-f]+):", line)
            if m and in_any_sub_range(int(m.group(1),16)):
                continue
            out.append(line)
        return out

    if sub_ranges:
        removed_before = len(lines)
        lines = strip_phantom_lines(lines)
        print(f"[+] Убрано фантомных строк: {removed_before - len(lines)}")

    main_lines = lines[:]
    all_lines_for_analysis = list(lines)
    for t_rel, (sub_instrs, sub_lines) in sorted(processed_subs.items()):
        all_lines_for_analysis.append(f"; ===== SUBROUTINE @0x{t_rel:04x} =====")
        all_lines_for_analysis.extend(sub_lines)
        all_lines_for_analysis.append(f"; ===== END SUBROUTINE @0x{t_rel:04x} =====")
    lines = all_lines_for_analysis

    assigned_vars = set()
    for line in lines:
        if line.lstrip().startswith("FORMULA "):
            m = re.match(r"\s*FORMULA (V_[0-9a-f]+) =", line)
            if m: assigned_vars.add(m.group(1))
        elif line.lstrip().startswith("INPUT -> "):
            m = re.match(r"\s*INPUT -> (V_[0-9a-f]+)", line)
            if m: assigned_vars.add(m.group(1))

    const_candidates = set()
    for line in lines:
        for match in re.finditer(r"V_[0-9a-f]+", line):
            const_candidates.add(match.group(0))

    const_defs = {}
    for var in const_candidates - assigned_vars:
        off = int(var[2:], 16)
        f = read_const_float(data, data_seg, off)
        if f is not None:
            if abs(f) > 1e-12 and abs(f) < 1e12:
                const_defs[var] = f"{f:g}"
        else:
            i = read_const_uint16(data, data_seg, off)
            if i is not None and i != 0:
                const_defs[var] = str(i)

    const_lines = []
    if const_defs:
        const_lines = ["; ----- CONSTANTS -----"]
        for var, val in sorted(const_defs.items(), key=lambda x: int(x[0][2:],16)):
            const_lines.append(f"; {var} = {val}")
        const_lines.append("; ---------------------")

    variables = {}
    for line in lines:
        idx_f = line.find("FORMULA ")
        if idx_f != -1:
            rest = line[idx_f+len("FORMULA "):].strip()
            if " = " in rest:
                var, rhs = rest.split(" = ", 1)
                var = var.strip()
                rhs = rhs.strip()
                if var not in variables:
                    val = None
                    try: val = float(rhs)
                    except ValueError: pass
                    if val is None:
                        m2 = re.fullmatch(r"V_[0-9a-f]+", rhs)
                        if m2:
                            ref_var = m2.group(0)
                            off = int(ref_var[2:], 16)
                            f = read_const_float(data, data_seg, off)
                            if f is not None: val = f
                            else:
                                i = read_const_uint16(data, data_seg, off)
                                if i is not None: val = float(i)
                    variables[var] = val
        idx_i = line.find("INPUT -> ")
        if idx_i != -1:
            var = line[idx_i+len("INPUT -> "):].strip()
            if var and var not in variables:
                variables[var] = None

    var_lines = []
    if variables:
        var_lines = ["; ----- VARIABLES -----"]
        for var in sorted(variables.keys()):
            val = variables[var]
            if val is not None:
                val_short = f"{val:.6g}" if isinstance(val, float) else str(val)
                var_lines.append(f"; {var} = {val_short} (initial)")
            else:
                var_lines.append(f"; {var}")
        var_lines.append("; ---------------------")

    new_lines = []
    for line in lines:
        m_if = re.match(r"^(CODE:\w+): IF \(([^)]+)\) GOTO (.+)$", line)
        if m_if:
            addr = m_if.group(1)
            cond = m_if.group(2)
            goto = m_if.group(3)
            m_op = re.search(r"\s*(==|!=|<=|>=|<|>)\s*", cond)
            if m_op:
                op = m_op.group(1)
                left = cond[:m_op.start()].strip()
                right = cond[m_op.end():].strip()
                if left in const_defs and (right.startswith("V_") or right.startswith("ARR_")):
                    left, right = right, left
                    cond = f"{left} {op} {right}"
            new_lines.append(f"{addr}: IF ({cond}) GOTO {goto}")
        else:
            new_lines.append(line)
    lines = new_lines

    call_sub_re = re.compile(r"^(CODE:[0-9a-f]+): CALL_SUB (0x[0-9a-f]+)$")
    def annotate_call_sub_line(line):
        m = call_sub_re.match(line)
        if not m:
            return line
        addr_s, target_hex = m.group(1), m.group(2)
        t_rel = int(target_hex, 16)
        if t_rel in processed_subs:
            return line
        elif t_rel in opaque_helpers:
            return (f"{addr_s}: CALL_SUB {target_hex}  [нестандартный вызов — использует свой "
                     f"адрес возврата как данные, не подчиняется call/ret; не разворачиваем]")
        elif t_rel in discarded_subs:
            return (f"{addr_s}: CALL_SUB {target_hex}  [не удалось разобрать как подпрограмму — "
                     f"вероятно, ложное срабатывание на данных]")
        else:
            return f"{addr_s}: CALL_SUB {target_hex}  [статус неизвестен]"
    lines = [annotate_call_sub_line(l) for l in lines]

    print("[+] Поиск подпрограмм со статически известным индексом...")
    call_sub_re2 = re.compile(r"^(CODE:([0-9a-f]+)): CALL_SUB (0x[0-9a-f]+)$")
    formula_re = re.compile(r"^CODE:([0-9a-f]+): FORMULA V_([0-9a-f]+) = (.+)$")

    def resolve_const(expr):
        expr = expr.strip()
        if expr in const_defs:
            try: return float(const_defs[expr])
            except ValueError: return None
        try: return float(expr)
        except ValueError: return None

    sub_index_info = {}
    for t_rel, (si, sl) in processed_subs.items():
        writes = detect_choice_writes(si, input_t, pstrings)
        if not writes:
            continue
        _, base0, stride0, fld_idx0 = writes[0]
        fld_mnem = si[fld_idx0][2]
        m = re.match(r"FLD m32real \[0x([0-9a-f]+)\]", fld_mnem)
        if not m:
            continue
        sub_index_info[t_rel] = {'index_addr': int(m.group(1), 16), 'writes': writes}

    call_line_indices = [i for i, l in enumerate(lines) if call_sub_re2.match(l)]
    all_calls_to_target = {}
    specialize_calls = {}
    for i in call_line_indices:
        m = call_sub_re2.match(lines[i])
        if not m:
            continue
        t_rel = int(m.group(3), 16)
        all_calls_to_target.setdefault(t_rel, []).append(i)
        if t_rel not in sub_index_info:
            continue
        index_addr = sub_index_info[t_rel]['index_addr']
        const_val = None
        for j in range(max(0, i-20), i):
            fm = formula_re.match(lines[j])
            if fm and int(fm.group(2), 16) == index_addr:
                const_val = resolve_const(fm.group(3))
        if const_val is not None:
            specialize_calls.setdefault(t_rel, {})[i] = const_val

    to_specialize = {t_rel: consts for t_rel, consts in specialize_calls.items()
                      if len(set(consts.values())) >= 2
                      and len(consts) == len(all_calls_to_target.get(t_rel, []))}
    to_specialize.pop(0x0d79, None)

    print(f"[+] Подпрограмм со статически известным индексом: {len(to_specialize)}")
    for t_rel, consts in to_specialize.items():
        idx_addr = sub_index_info[t_rel]['index_addr']
        print(f"    0x{t_rel:04x}: индекс V_{idx_addr:04x}, константы {sorted(set(consts.values()))}")

    def specialize_subroutine_lines(t_rel, const_val):
        si, _ = processed_subs[t_rel]
        writes = sub_index_info[t_rel]['writes']
        conditions = reconstruct_conditions(si, data, str_seg, strcmp_t, floatcmp_t)
        raw_lines = build_pseudocode(si, pstrings, print_t, input_t, conditions,
                                    data, data_seg, print_num_target=print_num_t,
                                    code_start=code_start)
        replacements = {}
        for (_, base, stride, _) in writes:
            concrete = base + int(const_val) * stride
            replacements[base] = f"V_{concrete:04x}"

        new_lines = []
        for line in raw_lines:
            m = re.match(r"(CODE:\w+): (INPUT -> |FORMULA )ARR_(SI|DI|BX|BP)\[\+(\d+)\]", line)
            if m:
                base_in_line = int(m.group(4))
                if base_in_line in replacements:
                    old_arr = f"ARR_SI[+{base_in_line}]"
                    new_var = replacements[base_in_line]
                    line = line.replace(old_arr, new_var, 1)
            new_lines.append(line)
        return new_lines

    def call_target_suffix(t_rel, const_val):
        return f"0x{t_rel:04x}__idx{const_val:g}"

    specialized_blocks = {}
    for t_rel, consts in to_specialize.items():
        for const_val in sorted(set(consts.values())):
            specialized_blocks[(t_rel, const_val)] = specialize_subroutine_lines(t_rel, const_val)

    new_lines = []
    for i, line in enumerate(lines):
        m = call_sub_re2.match(line)
        if m:
            t_rel = int(m.group(3), 16)
            if t_rel in to_specialize and i in specialize_calls.get(t_rel, {}):
                const_val = specialize_calls[t_rel][i]
                new_lines.append(f"{m.group(1)}: CALL_SUB {call_target_suffix(t_rel, const_val)}")
                continue
        new_lines.append(line)
    lines = new_lines

    def strip_generic_subroutine_block(lines, t_rel):
        start_marker = f"; ===== SUBROUTINE @0x{t_rel:04x} ====="
        end_marker = f"; ===== END SUBROUTINE @0x{t_rel:04x} ====="
        out, skip = [], False
        for l in lines:
            if l == start_marker: skip = True; continue
            if l == end_marker: skip = False; continue
            if not skip: out.append(l)
        return out

    for t_rel in to_specialize:
        lines = strip_generic_subroutine_block(lines, t_rel)

    for (t_rel, const_val), spec_lines in specialized_blocks.items():
        idx_addr = sub_index_info[t_rel]['index_addr']
        suffix = call_target_suffix(t_rel, const_val)
        lines.append(f"; ===== SUBROUTINE @{suffix} "
                     f"(индекс V_{idx_addr:04x} = {const_val:g}, определено распространением констант) =====")
        lines.extend(spec_lines)
        lines.append(f"; ===== END SUBROUTINE @{suffix} =====")

    final_lines = const_lines + var_lines + lines

    with open(f"{args.out}_pseudocode.txt",'w',encoding='utf-8') as f:
        f.write("\n".join(final_lines))
    print(f"[+] Псевдокод: {len(final_lines)} строк -> {args.out}_pseudocode.txt")

    print("[+] Структурирование if/while...")
    main_structured = structure_pseudocode(main_lines)
    struct_parts = [main_structured]
    for t_rel, (sub_instrs, sub_lines) in sorted(processed_subs.items()):
        sub_structured = structure_pseudocode(sub_lines)
        indented = "\n".join(("    "+l if l.strip() else l) for l in sub_structured.splitlines())
        struct_parts.append(f"\ndef sub_0x{t_rel:04x}():\n{indented}\n")
    structured = "\n".join(struct_parts)

    defined_subs = set(re.findall(r"^def (sub_0x[0-9a-f]+)\(\):", structured, re.M))
    opaque_names = {f"sub_0x{t:04x}" for t in opaque_helpers}
    def _fix_call(m):
        name = m.group(1)
        if name in defined_subs:
            return m.group(0)
        if name in opaque_names:
            return (f"pass  # {name}() — нестандартный вызов (использует свой адрес "
                    f"возврата как данные, не подчиняется call/ret; не разворачиваем)")
        return f"pass  # {name}() — цель не удалось разобрать как подпрограмму (возможно, ложное срабатывание на данных)"
    structured = re.sub(r"(?<!def )(sub_0x[0-9a-f]+)\(\)", _fix_call, structured)

    with open(f"{args.out}_structured.py",'w',encoding='utf-8') as f:
        f.write(structured)
    n_unresolved = structured.count('сложный переход') + structured.count('нераспознанный переход')
    n_total = len(structured.splitlines())
    print(f"[+] Структурировано: {args.out}_structured.py ({n_total} строк, "
          f"нераспознано переходов: {n_unresolved}, подпрограмм: {len(processed_subs)})")
    print("[+] Done.")

if __name__=="__main__":
    main()