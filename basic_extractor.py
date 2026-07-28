#!/usr/bin/env python3
"""
basic_extractor.py (v3.4) — полная версия с ручным указанием print-числа
"""
import sys, struct, re, argparse
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

def disasm_range(data, start, end):
    i = start; out = []
    while i < end:
        if data[i] == 0xCD and i+1 < end and data[i+1] in DECODERS:
            modrm = data[i+2] if i+2 < end else 0
            mod=(modrm>>6)&3; reg=(modrm>>3)&7; rm=modrm&7
            mem_bytes = data[i+3:i+5]
            try: mnem, consumed, near = DECODERS[data[i+1]](mod,reg,rm,mem_bytes)
            except Exception as e: mnem, consumed, near = f"ERR {e}", 0, None
            length = 3+consumed
            out.append((i-start,'FPU',mnem,length,near,i)); i += length
        else:
            chunk = data[i:i+16]
            dec = list(_md.disasm(chunk, i, count=1))
            if not dec:
                out.append((i-start,'???',f"db 0x{data[i]:02x}",1,None,i)); i += 1; continue
            insn = dec[0]
            out.append((i-start,'X86', f"{insn.mnemonic} {insn.op_str}".strip(), insn.size, None, i))
            i += insn.size
    return out

# ================= 5. sym() =================
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
        mc = LCALL_RE.match(mnem)                     # <-- новое RE
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

    # Второй проход для float-compare
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
    # Аналогично заменим call_re на LCALL_RE
    call_re = LCALL_RE
    jump_re = re.compile(r"^(j[a-z]+)\s+(0x[0-9a-f]+)$")
    conditions = {}

    # Float/strcmp
    stack_fpu = []
    push_imm_hist = []
    last_imm = None
    strcmp_literal_by_idx = {}  # idx перехода -> буква, с которой сравнивали (для OR-комбинаций типа N/n)
    i, n = 0, len(instrs)
    while i < n:
        off,kind,mnem,length,near,fa = instrs[i]
        if kind=='FPU':
            parts = mnem.split(" ",1); op=parts[0]; rest=parts[1] if len(parts)>1 else ""
            try:
                if op=="FLD":
                    stack_fpu.insert(0, sym(rest.split(" ",1)[1].strip()) if ("m32real" in rest or "m64real" in rest) else rest)
                elif op in ("FSTP","FST"):
                    if "ST(" in rest:
                        k = int(re.search(r"ST\((\d+)\)", rest).group(1))
                        if op=="FSTP": stack_fpu.pop(0)
                        else: stack_fpu[k] = stack_fpu[0]
                    elif op=="FSTP": stack_fpu.pop(0)
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

    # --- Комбинация двух предыдущих строковых сравнений через OR
    #     (идиома подтверждения ENTER/N, Y/y и т.п.):
    #       dec ax
    #       or ax, word ptr [bp - N]
    #       and ax, ax
    #       je/jne target
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
        # найти два предыдущих распознанных strcmp-сравнения (по возрастанию адреса, последние перед этим idx)
        prior = sorted(k for k in strcmp_literal_by_idx if k < idx-3)
        if len(prior) >= 2:
            lit1 = strcmp_literal_by_idx[prior[-2]]
            lit2 = strcmp_literal_by_idx[prior[-1]]
            or_expr = f"input_str == {lit1!r} or input_str == {lit2!r}"
            if jcc == 'je':
                # je срабатывает, когда обе строки НЕ совпали
                conditions[idx] = f"input_str != {lit1!r} and input_str != {lit2!r}"
            elif jcc == 'jne':
                # jne срабатывает, когда хотя бы одна строка совпала
                conditions[idx] = f"input_str == {lit1!r} or input_str == {lit2!r}"
            # для прочих jcc не трогаем — не должно встречаться для этой идиомы

    # Целочисленные cmp/test
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
        if is_test:
            if left == right: conditions[idx] = f"{left} {op} 0"
            else: conditions[idx] = f"({left} & {right}) {op} 0"
        else:
            conditions[idx] = f"{left} {op} {right}"
    return conditions

# ================= 8. Поиск констант =================
def lookup_var_value(var_name, data, str_seg_start, pstrings):
    m = re.match(r"V_([0-9a-f]+)", var_name)
    if not m: return None
    off = int(m.group(1), 16)
    f = read_const_float(data, str_seg_start, off)
    if f is not None and abs(f) > 1e-6:
        return f"{f:g}"
    return None

# ================= 9. Псевдокод =================
def build_pseudocode(instrs, pstrings, print_target, input_target, conditions,
                     data, str_seg_start, print_num_target=None, seg_label="CODE",
                     code_start=0):
    import bisect
    call_re = re.compile(r"lcall (0x[0-9a-f]+), (0x[0-9a-f]+)")
    jump_re = re.compile(r"^(j[a-z]+)\s+(0x[0-9a-f]+)$")
    last_imm = None; last_mov_bx = None; pending_push = None
    lines = []; stack_fpu = []

    # --- ПЕРВЫЙ ПРОХОД: определить, на каких адресах вообще будет строка псевдокода
    #     (нужно, чтобы GOTO мог "прилипнуть" к ближайшей РЕАЛЬНО существующей строке,
    #     а не в пустоту между строк — адрес перехода часто указывает на служебную
    #     инструкцию вроде "mov bx, imm", у которой своей строки нет)
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
            if mnem.startswith("ret"):
                emitted_addrs.append(off); continue
        elif kind=='FPU':
            parts = mnem.split(" ",1); op=parts[0]
            if op in ("FSTP","FST"):
                emitted_addrs.append(off)
    emitted_addrs = sorted(set(emitted_addrs))

    def snap(rel_addr):
        """Ближайший СЛЕДУЮЩИЙ адрес (>=), на котором реально есть строка псевдокода."""
        i = bisect.bisect_left(emitted_addrs, rel_addr)
        if i < len(emitted_addrs):
            return emitted_addrs[i]
        return rel_addr  # конец диапазона — оставляем как есть


    # --- Сбор всех целей переходов ---
    jump_targets = set()
    for idx, (off, kind, mnem, length, near, fa) in enumerate(instrs):
        if kind != 'X86': continue
        # безусловные jmp
        if mnem.startswith('jmp'):
            m = re.match(r"jmp\s+(0x[0-9a-f]+)", mnem)
            if m: jump_targets.add(int(m.group(1), 16))
        # условные jcc
        mj = jump_re.match(mnem)
        if mj and mj.group(1) != 'jmp':
            target = int(mj.group(2), 16)
            if idx in conditions:
                # IF NOT ... GOTO – цель тоже добавляем
                jump_targets.add(target)
            else:
                # нераспознанный jcc – всё равно цель
                jump_targets.add(target)
        # также lcall? не обязательно.

    def format_operand(op):
        if op.startswith("V_"):
            val = lookup_var_value(op, data, str_seg_start, pstrings)
            if val: return val
        return op

    for idx,(off,kind,mnem,length,near,fa) in enumerate(instrs):
        addr_s = f"{seg_label}:{off:04x}"
        generated = False   # была ли сгенерирована строка для этого адреса

        if kind == 'X86':
            m = re.match(r"mov bx, (0x[0-9a-f]+)$", mnem)
            if m: last_mov_bx = int(m.group(1),16)
            m = re.match(r"mov (\w+), (0x[0-9a-f]+|\d+)$", mnem)
            if m and m.group(1) in ('ax','bx','cx','dx'):
                last_imm = int(m.group(2),16) if m.group(2).startswith('0x') else int(m.group(2))
                continue
            # прямой push word ptr [0x…]
            m_push = re.match(r"push word ptr \[(0x[0-9a-f]+)\]", mnem)
            if m_push:
                pending_push = int(m_push.group(1), 16)
                continue
            if mnem.startswith("push ax") and last_imm is not None:
                pending_push = last_imm; continue
            mc = call_re.match(mnem)
            if mc:
                tgt = (int(mc.group(1),16), int(mc.group(2),16))
                if tgt == print_target and pending_push in pstrings:
                    lines.append(f"{addr_s}: PRINT \"{pstrings[pending_push].strip()}\"")
                    pending_push = None
                    generated = True
                elif tgt == input_target and (last_mov_bx is not None or pending_push is not None):
                    val = last_mov_bx if last_mov_bx is not None else pending_push
                    lines.append(f"{addr_s}: INPUT -> V_{val:04x}")
                    last_mov_bx = None
                    pending_push = None
                elif print_num_target is not None and tgt == print_num_target and pending_push is not None:
                    if pending_push > 0xF and pending_push not in pstrings:
                        lines.append(f"{addr_s}: PRINT V_{pending_push:04x}")
                    pending_push = None
                elif print_num_target is not None and tgt == print_num_target and pending_push is not None:
                    if pending_push > 0xF and pending_push not in pstrings:
                        lines.append(f"{addr_s}: PRINT V_{pending_push:04x}")
                    pending_push = None
                    generated = True
                continue
            mj = jump_re.match(mnem)
            if mj:
                jcc, target_abs = mj.group(1), int(mj.group(2),16)
                target_rel = target_abs - code_start
                target_snapped = snap(target_rel)
                target_str = f"0x{target_snapped:04x}" + (f" (raw 0x{target_rel:04x})" if target_snapped != target_rel else "")
                if idx in conditions:
                    cond = conditions[idx]
                    parts = cond.split(" ",2)
                    if len(parts)>=3:
                        left, op, right = parts[0], parts[1], parts[2]
                        left = format_operand(left)
                        right = format_operand(right)
                        cond = f"{left} {op} {right}"
                    lines.append(f"{addr_s}: IF ({cond}) GOTO {target_str}")
                    generated = True
                else:
                    if jcc == 'jmp':
                        lines.append(f"{addr_s}: jmp {target_str}")
                    else:
                        lines.append(f"{addr_s}: {jcc} {target_str}  [условие не распознано]")
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
                    target_disp = format_operand(target)
                    rhs_disp = format_operand(rhs)
                    lines.append(f"{addr_s}: FORMULA {target_disp} = {rhs_disp}")
                    generated = True
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

        # Если для данного адреса не сгенерировано строки, но он является целью перехода – вставим метку
        if not generated and off in jump_targets:
            lines.append(f"{addr_s}: ; метка перехода")

    return lines

# ================= main =================
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

    print("[+] Автоопределение целей вызова...")
    print_t, input_t, strcmp_t, floatcmp_t = auto_detect_calls(instrs, pstrings, data, str_seg)
    print(f"    PRINT_TEXT: {print_t}   INPUT_READ: {input_t}")
    print(f"    STRCMP: {strcmp_t}   FLOAT_COMPARE_HELPER: {floatcmp_t}")

    input_t = input_t   # из auto_detect_calls
    if args.input_seg is not None and args.input_off is not None:
        input_t = (args.input_seg, args.input_off)
        print(f"    INPUT_READ (ручной): {input_t}")

    print_num_t = None
    if args.print_num_seg is not None and args.print_num_off is not None:
        print_num_t = (args.print_num_seg, args.print_num_off)
        print(f"    PRINT_NUM (ручной): {print_num_t}")

    conditions = reconstruct_conditions(instrs, data, str_seg, strcmp_t, floatcmp_t)
    print(f"[+] Условий восстановлено: {len(conditions)}")

    lines = build_pseudocode(instrs, pstrings, print_t, input_t, conditions,
                             data, str_seg, print_num_target=print_num_t, code_start=code_start)
    with open(f"{args.out}_pseudocode.txt",'w',encoding='utf-8') as f:
        f.write("\n".join(lines))
    print(f"[+] Псевдокод: {len(lines)} строк -> {args.out}_pseudocode.txt")
    print("[+] Done.")

if __name__=="__main__":
    main()