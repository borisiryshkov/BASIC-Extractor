"""
decoder.py -- decode ONE instruction at a time (not a whole range).
This is the building block for the worklist/CFG disassembler: unlike a
linear disasm_range(start,end), there is no notion of "end of range" here --
just "give me one instruction at this address and its length".
"""
import struct, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_16

# ================= x87 "ESC-via-INT" =================
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

_md = Cs(CS_ARCH_X86, CS_MODE_16)


class Instr:
    __slots__ = ('addr','kind','mnemonic','length','fpu_mem_near',
                 'is_call','is_jmp','is_jcc','is_ret','is_indirect','target')
    def __init__(self, addr, kind, mnemonic, length, fpu_mem_near=None):
        self.addr = addr
        self.kind = kind              # 'X86' | 'FPU' | 'BAD'
        self.mnemonic = mnemonic
        self.length = length
        self.fpu_mem_near = fpu_mem_near
        self.is_call = False
        self.is_jmp = False           # unconditional (near) jmp
        self.is_jcc = False           # conditional jump
        self.is_ret = False
        self.is_indirect = False      # jmp/call through a register or memory --
                                       # the target is NOT known statically, we
                                       # don't know it and don't guess -- we just
                                       # record the fact
        self.target = None            # absolute file address of the target (if any)

    def __repr__(self):
        return f"<{self.kind} @0x{self.addr:x} {self.mnemonic!r} len={self.length}>"


_JCC_RE = re.compile(r"^(j[a-z]+)\s+(0x[0-9a-f]+)$")
_CALL_NEAR_RE = re.compile(r"^call\s+(0x[0-9a-f]+)$")
_LCALL_RE = re.compile(r"^lcall\s+(0x[0-9a-f]+),\s*(0x[0-9a-f]+)$")
_JMP_RE = re.compile(r"^jmp\s+(0x[0-9a-f]+)$")
_LJMP_RE = re.compile(r"^ljmp\s+(0x[0-9a-f]+):(0x[0-9a-f]+)$")


def seg_off_to_file_addr(header_bytes, seg, off):
    """Converts (segment, offset) from an lcall instruction into an absolute
       file address. The segment in the instruction bytes itself is a REAL
       relative segment (0 = start of the loaded module, i.e. header_bytes),
       WITHOUT any shift applied."""
    return header_bytes + seg * 16 + off


def decode_one(data, addr, header_bytes=None):
    """Decodes exactly one instruction at absolute file address addr.
       header_bytes is only needed to convert lcall targets (SEG:OFF) into
       an absolute file address -- if it isn't passed, lcall is not treated
       as a control-flow transfer (just a plain instruction)."""
    if addr >= len(data):
        return Instr(addr, 'BAD', 'out-of-bounds', 1)

    if data[addr] == 0xCD and addr+1 < len(data) and data[addr+1] in DECODERS:
        modrm = data[addr+2] if addr+2 < len(data) else 0
        mod = (modrm>>6)&3; reg=(modrm>>3)&7; rm=modrm&7
        mem_bytes = data[addr+3:addr+5]
        try:
            mnem, consumed, near = DECODERS[data[addr+1]](mod, reg, rm, mem_bytes)
        except Exception as e:
            mnem, consumed, near = f"ERR {e}", 0, None
        length = 3 + consumed
        return Instr(addr, 'FPU', mnem, length, fpu_mem_near=near)

    chunk = data[addr:addr+16]
    dec = list(_md.disasm(chunk, addr, count=1))
    if not dec:
        return Instr(addr, 'BAD', f"db 0x{data[addr]:02x}", 1)
    insn = dec[0]
    mnemonic = f"{insn.mnemonic} {insn.op_str}".strip()
    instr = Instr(addr, 'X86', mnemonic, insn.size)

    if mnemonic.startswith('ret'):
        instr.is_ret = True
        return instr

    m = _CALL_NEAR_RE.match(mnemonic)
    if m:
        instr.is_call = True
        instr.target = int(m.group(1), 16)
        return instr

    m = _LCALL_RE.match(mnemonic)
    if m and header_bytes is not None:
        seg = int(m.group(1), 16); off = int(m.group(2), 16)
        instr.is_call = True
        instr.target = seg_off_to_file_addr(header_bytes, seg, off)
        return instr

    m = _JMP_RE.match(mnemonic)
    if m:
        instr.is_jmp = True
        instr.target = int(m.group(1), 16)
        return instr

    m = _LJMP_RE.match(mnemonic)
    if m and header_bytes is not None:
        seg = int(m.group(1), 16); off = int(m.group(2), 16)
        instr.is_jmp = True
        instr.target = seg_off_to_file_addr(header_bytes, seg, off)
        return instr

    m = _JCC_RE.match(mnemonic)
    if m and m.group(1) != 'jmp':
        instr.is_jcc = True
        instr.target = int(m.group(2), 16)
        return instr

    # Indirect call/jmp/lcall (through a register or memory) -- the target is
    # NOT known statically. We explicitly record this case and do NOT
    # continue the flow from here.
    if mnemonic.startswith('jmp') or mnemonic.startswith('call') or mnemonic.startswith('lcall') or mnemonic.startswith('ljmp'):
        instr.is_indirect = True
        if 'call' in mnemonic:
            instr.is_call = True
        else:
            instr.is_jmp = True
        return instr

    return instr
