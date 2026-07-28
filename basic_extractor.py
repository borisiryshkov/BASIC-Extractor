#!/usr/bin/env python3
"""
basic_extractor.py — extraction of pseudocode/formulas from DOS .EXE files
compiled with Microsoft BASIC Compiler (BASCOM / QuickBASIC / BASIC PDS),
using static (non-FPU) linking with the software 8087 emulator (INT 34h-3Bh).

Usage:
    python3 basic_extractor.py path/to/PROGRAM.EXE [--code-segments 1000,19bd] [--out prefix]

If --code-segments is not given, the script scans the whole file after the header.
"""
import sys, struct, re, argparse
from capstone import Cs, CS_ARCH_X86, CS_MODE_16

# ----------------------------------------------------------------------
# 1. MZ header parsing
# ----------------------------------------------------------------------
def parse_mz_header(data):
    if data[0:2] != b'MZ':
        raise ValueError("Not an MZ executable")
    fields = struct.unpack_from('<14H', data, 2)
    names = ['e_cblp','e_cp','e_crlc','e_cparhdr','e_minalloc','e_maxalloc',
             'e_ss','e_sp','e_csum','e_ip','e_cs','e_lfarlc','e_ovno']
    h = dict(zip(names, fields[:13]))
    h['header_bytes'] = h['e_cparhdr'] * 16
    return h

def file_offset_for_relseg(header, rel_seg):
    """rel_seg = segment value relative to load-module start (segment 0 = right after header)."""
    return header['header_bytes'] + rel_seg * 16

# ----------------------------------------------------------------------
# 2. Auto-detect the data ("DGROUP") segment holding Pascal-style strings
#    Format observed in this BASIC runtime:
#      [len:1][0x00][self_ptr:2 LE][text bytes...]   where self_ptr == near_offset+4
# ----------------------------------------------------------------------
def detect_string_segment(data, search_start, search_end):
    votes = {}
    i = search_start
    while i < search_end - 4:
        if data[i+1] == 0 and 4 <= data[i] <= 250:
            ptr = data[i+2] | (data[i+3] << 8)
            implied_base = i - (ptr - 4)
            if 0 <= implied_base < len(data):
                votes[implied_base] = votes.get(implied_base, 0) + 1
        i += 1
    if not votes:
        return None
    best = max(votes.items(), key=lambda kv: kv[1])
    return best[0]  # file offset of segment start

def decode_pstrings(data, seg_start, seg_end):
    results = {}
    i = seg_start
    while i < seg_end - 4:
        length = data[i]
        flag = data[i+1]
        ptr = data[i+2] | (data[i+3] << 8)
        near_off = i - seg_start
        if flag == 0 and ptr == near_off + 4 and length >= 4:
            text_len = length - 3
            if i+4+text_len <= len(data):
                raw = data[i+4:i+4+text_len]
                try:
                    text = raw.decode('cp866', errors='replace')
                except Exception:
                    text = raw.decode('latin1', errors='replace')
                results[near_off] = text
                i += 1 + length
                continue
        i += 1
    return results

# ----------------------------------------------------------------------
# 3. x87 "ESC-via-INT" decoder
#    MS runtimes without a real 8087 replace ESC opcodes D8-DF with
#    INT 34h-3Bh, leaving the following ModRM/operand bytes untouched.
# ----------------------------------------------------------------------
def modrm_mem_operand(mod, rm, bytes_at):
    bases = {0:"BX+SI",1:"BX+DI",2:"BP+SI",3:"BP+DI",4:"SI",5:"DI",6:"BP",7:"BX"}
    if mod == 0 and rm == 6:
        disp = struct.unpack_from('<H', bytes_at, 0)[0]
        return f"[0x{disp:04x}]", disp, 2
    elif mod == 0:
        return f"[{bases[rm]}]", None, 0
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
        s=DC_REG[reg]
        return (s.format(rm) if s else f"DC/{reg},{rm}(?)"),0,None
    op,near,c = modrm_mem_operand(mod,rm,mb); return f"{DC_MEM[reg]} m64real {op}",c,near
def decode_DD(mod,reg,rm,mb):
    if mod==3:
        names={0:"FFREE ST({0})",2:"FST ST({0})",3:"FSTP ST({0})",4:"FUCOM ST({0})",5:"FUCOMP ST({0})"}
        s=names.get(reg)
        return (s.format(rm) if s else f"DD/{reg},{rm}(?)"),0,None
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

# ----------------------------------------------------------------------
# 4. Combined disassembler: normal x86-16 (capstone) + x87-via-INT
# ----------------------------------------------------------------------
_md = Cs(CS_ARCH_X86, CS_MODE_16)

def disasm_range(data, start, end):
    """Returns list of (near_offset, kind['X86'|'FPU'], mnemonic, length, near_mem_addr, file_addr)"""
    i = start
    out = []
    while i < end:
        if data[i] == 0xCD and i+1 < end and data[i+1] in DECODERS:
            modrm = data[i+2] if i+2 < end else 0
            mod=(modrm>>6)&3; reg=(modrm>>3)&7; rm=modrm&7
            mem_bytes = data[i+3:i+5]
            try:
                mnem, consumed, near = DECODERS[data[i+1]](mod,reg,rm,mem_bytes)
            except Exception as e:
                mnem, consumed, near = f"ERR {e}", 0, None
            length = 3+consumed
            out.append((i-start,'FPU',mnem,length,near,i))
            i += length
        else:
            chunk = data[i:i+16]
            dec = list(_md.disasm(chunk, i, count=1))
            if not dec:
                out.append((i-start,'???',f"db 0x{data[i]:02x}",1,None,i))
                i += 1
                continue
            insn = dec[0]
            out.append((i-start,'X86', f"{insn.mnemonic} {insn.op_str}".strip(), insn.size, None, i))
            i += insn.size
    return out

def collect_all_jump_targets(instrs, code_start):
    """All near-offsets that ANY jmp/jcc/call in the program can land on —
    used so we never mark a range 'dead' that something else jumps into."""
    any_jump_re = re.compile(r"(?:j[a-z]*|call)\s+(0x[0-9a-f]+)$")
    targets = set()
    for off,kind,mnem,length,near,fileaddr in instrs:
        if kind != 'X86':
            continue
        m = any_jump_re.match(mnem)
        if m:
            targets.add(int(m.group(1),16) - code_start)
    return targets

def filter_dead_code(instrs, code_start):
    """Removes instructions that are provably unreachable: bytes located strictly
    between an unconditional 'jmp' and its (forward) target near-offset — but
    ONLY if no other jump/call anywhere in the program targets an address
    inside that range (otherwise we'd risk deleting real, reachable code)."""
    jmp_re = re.compile(r"jmp\s+(0x[0-9a-f]+)")
    all_targets = collect_all_jump_targets(instrs, code_start)
    out = []
    skip_until = None
    skipped_but_referenced = 0
    for off,kind,mnem,length,near,fileaddr in instrs:
        if skip_until is not None:
            if off < skip_until:
                continue
            skip_until = None
        out.append((off,kind,mnem,length,near,fileaddr))
        if kind == 'X86':
            mj = jmp_re.match(mnem)
            if mj:
                jtgt_near = int(mj.group(1),16) - code_start
                if jtgt_near > off:
                    # is there any jump elsewhere that lands strictly inside (off, jtgt_near)?
                    referenced_inside = any(off < t < jtgt_near for t in all_targets)
                    if referenced_inside:
                        skipped_but_referenced += 1
                    else:
                        skip_until = jtgt_near
    if skipped_but_referenced:
        print(f"[i] {skipped_but_referenced} forward-jmp ranges were NOT skipped "
              f"because something else jumps into them (kept as reachable)")
    return out

# ----------------------------------------------------------------------
# 5. Symbolic x87 stack simulator -> arithmetic formulas
# ----------------------------------------------------------------------
def sym(operand):
    m = re.match(r"\[0x([0-9a-f]+)\]", operand)
    if m: return f"V_{m.group(1)}"
    m = re.match(r"\[(SI|DI|BX|BP)([+\-]\d+)\]", operand)
    if m: return f"ARR_{m.group(1)}[{m.group(2)}]"
    return operand

def reconstruct_formulas(fpu_instrs):
    """fpu_instrs: list of (near_offset, mnem) for kind=='FPU', in program order."""
    stack = []
    formulas = []
    errors = 0
    for near_off, mnem in fpu_instrs:
        parts = mnem.split(" ", 1)
        op = parts[0]; rest = parts[1] if len(parts) > 1 else ""
        try:
            if op == "FLD":
                if "m32real" in rest or "m64real" in rest:
                    stack.insert(0, sym(rest.split(" ",1)[1].strip()))
                elif rest.startswith("ST("):
                    i = int(re.search(r"ST\((\d+)\)", rest).group(1))
                    stack.insert(0, stack[i])
                else:
                    stack.insert(0, rest)
            elif op in ("FSTP","FST"):
                if "ST(" in rest:
                    i = int(re.search(r"ST\((\d+)\)", rest).group(1))
                    stack[i] = stack[0]
                    if op=="FSTP": stack.pop(0)
                else:
                    target = sym(rest.split(" ",1)[-1].strip())
                    formulas.append((near_off, f"{target} = {stack[0]}"))
                    if op=="FSTP": stack.pop(0)
            elif op in ("FADD","FSUB","FMUL","FDIV","FSUBR","FDIVR"):
                if rest.startswith("ST,ST("):
                    i = int(re.search(r"ST\((\d+)\)", rest).group(1)); b = stack[i]
                elif any(t in rest for t in ("m32real","m64real","m32int")):
                    b = sym(rest.split(" ",1)[1].strip())
                else:
                    b = rest
                a = stack[0]
                so = {"FADD":"+","FSUB":"-","FMUL":"*","FDIV":"/","FSUBR":"-","FDIVR":"/"}[op]
                stack[0] = f"({b} {so} {a})" if op in ("FSUBR","FDIVR") else f"({a} {so} {b})"
            elif op in ("FADDP","FSUBP","FMULP","FDIVP","FSUBRP","FDIVRP"):
                i = int(re.search(r"ST\((\d+)\)", rest).group(1))
                a, b = stack[i], stack[0]
                base = op[:-1]
                so = {"FADD":"+","FSUB":"-","FMUL":"*","FDIV":"/","FSUBR":"-","FDIVR":"/"}[base]
                stack[i] = f"({b} {so} {a})" if base in ("FSUBR","FDIVR") else f"({a} {so} {b})"
                stack.pop(0)
            elif op == "FSQRT": stack[0] = f"sqrt({stack[0]})"
            elif op == "FCHS": stack[0] = f"(-{stack[0]})"
            elif op == "FABS": stack[0] = f"abs({stack[0]})"
            elif op in ("FCOMP","FUCOMP"): stack.pop(0)
            elif op == "FCOMPP": stack.pop(0); stack.pop(0)
            elif op == "FILD":
                stack.insert(0, f"int({sym(rest.split(' ',1)[-1].strip())})")
            elif op == "FXCH":
                i = int(re.search(r"ST\((\d+)\)", rest).group(1))
                stack[0], stack[i] = stack[i], stack[0]
        except Exception:
            errors += 1
            stack = []
    return formulas, errors

# ----------------------------------------------------------------------
# 6. Auto-detect PRINT_TEXT / INPUT_READ runtime call targets
# ----------------------------------------------------------------------
def auto_detect_runtime_calls(instrs, pstrings, str_seg_start, str_seg_end_relative):
    """
    instrs: full disasm_range() output for a code region.
    Returns dict: {'print_text': (seg,off) or None, 'input_read': (seg,off) or None}
    """
    call_re = re.compile(r"lcall (0x[0-9a-f]+), (0x[0-9a-f]+)")
    last_imm = None
    pending_last_push = None
    print_votes = {}
    input_votes = {}
    last_mov_bx = None
    bx_before_call = {}

    for idx,(off,kind,mnem,length,near,fileaddr) in enumerate(instrs):
        if kind != 'X86':
            continue
        m = re.match(r"mov bx, (0x[0-9a-f]+)$", mnem)
        if m:
            last_mov_bx = int(m.group(1),16)
        m = re.match(r"mov (\w+), (0x[0-9a-f]+|\d+)$", mnem)
        if m and m.group(1) in ('ax','bx','cx','dx'):
            last_imm = int(m.group(2),16) if m.group(2).startswith('0x') else int(m.group(2))
            continue
        if mnem.startswith("push ax") and last_imm is not None:
            pending_last_push = last_imm
            continue
        mc = call_re.match(mnem)
        if mc:
            tgt = (int(mc.group(1),16), int(mc.group(2),16))
            if pending_last_push is not None and pending_last_push in pstrings:
                print_votes[tgt] = print_votes.get(tgt,0) + 1
            if last_mov_bx is not None:
                input_votes[tgt] = input_votes.get(tgt,0) + 1
            pending_last_push = None
            last_mov_bx = None

    print_target = max(print_votes.items(), key=lambda kv: kv[1])[0] if print_votes else None
    input_target = max(input_votes.items(), key=lambda kv: kv[1])[0] if input_votes else None
    return print_target, input_target

# ----------------------------------------------------------------------
# 7. Pseudocode builder
# ----------------------------------------------------------------------
def build_pseudocode(data, instrs, pstrings, print_target, input_target, seg_label, code_start=0):
    call_re = re.compile(r"lcall (0x[0-9a-f]+), (0x[0-9a-f]+)")
    jmp_re = re.compile(r"(j[a-z]*)\s+(0x[0-9a-f]+)")
    last_imm = None
    last_mov_bx = None
    pending_push = None
    lines = []
    stack = []
    # NOTE: dead-code removal (if any) must already have been applied to `instrs`
    # via filter_dead_code() BEFORE calling this function — that check is
    # cross-reference-aware (safe). We don't re-skip anything here.

    for off,kind,mnem,length,near,fileaddr in instrs:
        addr_s = f"{seg_label}:{off:04x}"
        if kind == 'X86':
            m = re.match(r"mov bx, (0x[0-9a-f]+)$", mnem)
            if m: last_mov_bx = int(m.group(1),16)
            m = re.match(r"mov (\w+), (0x[0-9a-f]+|\d+)$", mnem)
            if m and m.group(1) in ('ax','bx','cx','dx'):
                last_imm = int(m.group(2),16) if m.group(2).startswith('0x') else int(m.group(2))
                continue
            if mnem.startswith("push ax") and last_imm is not None:
                pending_push = last_imm
                continue
            mc = call_re.match(mnem)
            if mc:
                tgt = (int(mc.group(1),16), int(mc.group(2),16))
                if tgt == print_target and pending_push in pstrings:
                    lines.append(f"{addr_s}: PRINT \"{pstrings[pending_push].strip()}\"")
                    pending_push = None
                elif tgt == input_target and last_mov_bx is not None:
                    lines.append(f"{addr_s}: INPUT -> V_{last_mov_bx:04x}")
                    last_mov_bx = None
                continue
            mj = jmp_re.match(mnem)
            if mj:
                jkind, jtgt_abs = mj.group(1), int(mj.group(2),16)
                jtgt_near = jtgt_abs - code_start
                direction = "НАЗАД (вероятно цикл/повтор)" if jtgt_near < off else "вперёд"
                lines.append(f"{addr_s}: {jkind} -> near 0x{jtgt_near:04x}  [{direction}]")
                continue
            if mnem.startswith("ret"):
                lines.append(f"{addr_s}: RETURN")
        elif kind == 'FPU':
            parts = mnem.split(" ",1); op=parts[0]; rest=parts[1] if len(parts)>1 else ""
            try:
                if op=="FLD":
                    if "m32real" in rest or "m64real" in rest:
                        stack.insert(0, sym(rest.split(" ",1)[1].strip()))
                    else:
                        stack.insert(0, rest)
                elif op in ("FSTP","FST"):
                    target = sym(rest.split(" ",1)[-1].strip())
                    lines.append(f"{addr_s}: FORMULA {target} = {stack[0]}")
                    if op=="FSTP": stack.pop(0)
                elif op in ("FADD","FSUB","FMUL","FDIV","FSUBR","FDIVR"):
                    b = sym(rest.split(" ",1)[1].strip()) if ("m32real" in rest or "m64real" in rest) else rest
                    a = stack[0]
                    so={"FADD":"+","FSUB":"-","FMUL":"*","FDIV":"/","FSUBR":"-","FDIVR":"/"}[op]
                    stack[0] = f"({b} {so} {a})" if op in ("FSUBR","FDIVR") else f"({a} {so} {b})"
                elif op=="FSQRT": stack[0]=f"sqrt({stack[0]})"
                elif op=="FABS": stack[0]=f"abs({stack[0]})"
                elif op=="FCHS": stack[0]=f"(-{stack[0]})"
            except Exception:
                stack = []
    return lines

# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--out", default="extracted")
    ap.add_argument("--max-scan", type=lambda x: int(x,0), default=None,
                     help="Остановить дизассемблирование на этом относительном near-offset "
                          "(в hex, напр. 0x9bd0), если известно, что дальше начинается "
                          "чужой рантайм/эмулятор сопроцессора, где линейный дизассемблер "
                          "теряет синхронизацию с реальными границами инструкций.")
    args = ap.parse_args()

    with open(args.exe, 'rb') as f:
        data = f.read()

    header = parse_mz_header(data)
    print(f"[+] MZ header: header_bytes=0x{header['header_bytes']:x}, "
          f"entry CS:IP={header['e_cs']:04x}:{header['e_ip']:04x}")

    code_start = header['header_bytes']
    code_end = len(data)

    print("[+] Detecting string data segment...")
    str_seg = detect_string_segment(data, code_start, code_end)
    if str_seg is None:
        print("[!] Could not auto-detect string segment. Exiting.")
        sys.exit(1)
    print(f"[+] String segment starts at file offset 0x{str_seg:x}")

    pstrings = decode_pstrings(data, str_seg, code_end)
    print(f"[+] Decoded {len(pstrings)} Pascal-strings")
    with open(f"{args.out}_strings.txt", 'w', encoding='utf-8') as f:
        for off, txt in sorted(pstrings.items()):
            f.write(f"0x{off:04x}: {txt}\n")

    scan_end = str_seg  # assume data segment follows code
    if args.max_scan is not None:
        capped = code_start + args.max_scan
        if capped < scan_end:
            scan_end = capped
            print(f"[+] Capping scan at relative offset 0x{args.max_scan:x} per --max-scan")

    print("[+] Disassembling code region (this may take a while)...")
    instrs_raw = disasm_range(data, code_start, scan_end)
    print(f"[+] Decoded {len(instrs_raw)} instructions (before dead-code filtering)")

    instrs = filter_dead_code(instrs_raw, code_start)
    print(f"[+] {len(instrs)} instructions remain after removing unreachable "
          f"code (dead branches after unconditional jmp)")

    fpu_only = [(off,mnem) for off,kind,mnem,length,near,fa in instrs if kind=='FPU']
    print(f"[+] Found {len(fpu_only)} FPU instructions")
    formulas, errors = reconstruct_formulas(fpu_only)
    print(f"[+] Reconstructed {len(formulas)} formulas ({errors} stack resync events)")
    with open(f"{args.out}_formulas.txt", 'w', encoding='utf-8') as f:
        for off, expr in formulas:
            f.write(f"0x{off:04x}: {expr}\n")

    print("[+] Auto-detecting PRINT/INPUT runtime call targets...")
    print_target, input_target = auto_detect_runtime_calls(instrs, pstrings, str_seg, None)
    print(f"    PRINT_TEXT target guess: {print_target}")
    print(f"    INPUT_READ target guess: {input_target}")

    lines = build_pseudocode(data, instrs, pstrings, print_target, input_target, "CODE", code_start)
    with open(f"{args.out}_pseudocode.txt", 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
    print(f"[+] Wrote {len(lines)} pseudocode lines to {args.out}_pseudocode.txt")
    print("[+] Done.")

if __name__ == "__main__":
    main()
