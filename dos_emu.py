"""
dos_emu.py -- a minimal x86 real-mode emulator built on Unicorn Engine
with a hand-rolled DOS shim.

IDEA: instead of guessing what the program will write into "poison"
memory slots at run time, we just LET IT RUN for real (in a sandbox), and
Unicorn computes any register/flag effects itself -- we don't need to
model that symbolically.

Loading: we apply the relocation table OURSELVES (the same algorithm a
real DOS loader would use), place the image into emulated memory at a
load_segment of our choosing, and set up CS:IP/SS:SP from the header.

DOS shim: we intercept int 21h/int 10h/int 16h via UC_HOOK_INTR and
implement only what the program actually needs (based on the static
analysis already done: AH=09/40 for printing, AH=0A buffered input,
AH=25/35 interrupt-vector handling, AH=30/4A/4C, etc.).
"""
import struct
import sys
from unicorn import *
from unicorn.x86_const import *

LOAD_SEGMENT = 0x1000  # the segment WE ourselves choose to load the image at
                        # (a real DOS would pick its own -- we don't care
                        # which one, as long as it's self-consistent)
PSP_SEGMENT = LOAD_SEGMENT - 0x10  # the PSP is always 0x10 paragraphs before the image
STACK_SEGMENT = None  # determined from the header after relocation

# Relative segment where the DS/SS "runtime variables" area lives (found
# and used throughout the static analysis -- see cfg_builder.py).
RUNTIME_VARS_SEGMENT = 0x1330

# CONFIRMED IN A REAL DOSBox-X RUN (see project notes): a breakpoint on
# `call word ptr [0x422a]` (guarded by `cmp byte ptr [0x45df], 0x98; je`)
# never fired during actual interactive use of the program -- i.e. by the
# time this check runs, [0x45df] is genuinely 0x98 in real execution
# (statically the file default is 0x00). We don't yet know the exact
# mechanism that sets it (no literal writer found anywhere, even in the
# much larger graph now reachable -- it's presumably computed through an
# indexed address we can't find by text search). Rather than guess, we
# patch the confirmed real-world VALUE directly, honestly labeled as
# "informed by DOSBox ground truth", not as a reverse-engineered
# mechanism.
#
# OPEN ISSUE: even with this patch applied at startup, the emulator's
# indirect-call log still shows 0xea9f (the guarded call site) firing at
# least once during a full run -- meaning something LATER resets this
# flag back to a value that lets the call through. This one specific
# target (0xea9f -> 0xebce) is deliberately excluded from
# EMULATION_CONFIRMED_INDIRECT_TARGETS in cfg_builder.py until that's
# understood.
CONFIRMED_RUNTIME_PATCHES = {
    0x45df: 0x98,  # see comment above
}

# Default scripted answers for AH=0Ah (buffered keyboard input) and
# AH=0Ch (flush+read single character), used in the order they're needed,
# one per call; if we run out, we fall back to an empty line / Enter.
# This lets the emulator walk further into the real interactive flow
# instead of stalling on the very first prompt. These are arbitrary
# placeholder choices, not informed by the actual calculation domain --
# a good next step for anyone continuing this project is to pick more
# meaningful values here (see project notes on the "Illegal function
# call" that these defaults currently trigger).
DEFAULT_INPUT_SCRIPT = ["1\r", "1\r", "1\r", "1\r", "100\r", "1\r", "\r", "\r", "\r", "\r"]


def parse_mz_header(data):
    fields = struct.unpack_from('<14H', data, 2)
    names = ['e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc', 'e_maxalloc',
              'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs', 'e_lfarlc', 'e_ovno']
    h = dict(zip(names, fields[:13]))
    h['header_bytes'] = h['e_cparhdr'] * 16
    return h


def apply_relocations(data, header, load_segment):
    """Returns a patched copy of the image (without the MZ header, i.e.
       what should actually end up in memory starting at load_segment:0000)
       -- EXACTLY the way a real DOS loader would do it."""
    header_bytes = header['header_bytes']
    image = bytearray(data[header_bytes:])
    e_crlc = header['e_crlc']
    e_lfarlc = header['e_lfarlc']
    for i in range(e_crlc):
        entry_off = e_lfarlc + i * 4
        off, seg = struct.unpack_from('<HH', data, entry_off)
        patch_addr = seg * 16 + off  # address INSIDE image (relative to 0)
        if patch_addr + 2 <= len(image):
            cur = struct.unpack_from('<H', image, patch_addr)[0]
            struct.pack_into('<H', image, patch_addr, cur + load_segment)
    return bytes(image)


class DosEmu:
    def __init__(self, exe_path, load_segment=LOAD_SEGMENT, trace_indirect=True,
                 max_instructions=2_000_000, input_script=None):
        with open(exe_path, 'rb') as f:
            self.raw = f.read()
        self.header = parse_mz_header(self.raw)
        self.load_segment = load_segment
        self.psp_segment = load_segment - 0x10
        self.image = apply_relocations(self.raw, self.header, load_segment)
        self.mu = Uc(UC_ARCH_X86, UC_MODE_16)
        self.trace_indirect = trace_indirect
        self.indirect_log = []       # (real_cs, real_ip, mnemonic, target_cs, target_ip)
        self.int_log = []            # (ah, al, real_cs, real_ip) for interesting ints
        self.output_bytes = bytearray()  # everything the program "printed"
        self.max_instructions = max_instructions
        self.instr_count = 0
        self.stopped_reason = None
        self.input_script = list(input_script) if input_script is not None else list(DEFAULT_INPUT_SCRIPT)
        self.input_script_pos = 0
        self.input_log = []  # what we actually "typed" at each AH=0A/0C call, for review
        self._setup_memory()
        self._setup_hooks()

    def _setup_memory(self):
        mu = self.mu
        # Map the low 1MB of memory (real mode addresses with 20 bits)
        mu.mem_map(0, 0x100000)

        # PSP: a minimal stub at psp_segment:0000
        psp_addr = self.psp_segment * 16
        psp = bytearray(256)
        psp[0:2] = b'\xCD\x20'          # int 20h right at the start (standard)
        struct.pack_into('<H', psp, 2, 0x9fff)  # top of memory (paragraph) -- with headroom
        mu.mem_write(psp_addr, bytes(psp))

        # Place the program image at load_segment:0000
        mu.mem_write(self.load_segment * 16, self.image)

        # Apply confirmed real-world runtime patches (see
        # CONFIRMED_RUNTIME_PATCHES above) -- these are DS-relative
        # offsets in the RUNTIME_VARS_SEGMENT area.
        runtime_vars_base = (self.load_segment + RUNTIME_VARS_SEGMENT) * 16
        for off, val in CONFIRMED_RUNTIME_PATCHES.items():
            mu.mem_write(runtime_vars_base + off, bytes([val & 0xFF]))

        # Set up registers from the header (plus the load_segment relocation)
        h = self.header
        cs = h['e_cs'] + self.load_segment
        ip = h['e_ip']
        ss = h['e_ss'] + self.load_segment
        sp = h['e_sp']
        mu.reg_write(UC_X86_REG_CS, cs)
        mu.reg_write(UC_X86_REG_IP, ip)
        mu.reg_write(UC_X86_REG_SS, ss)
        mu.reg_write(UC_X86_REG_SP, sp)
        mu.reg_write(UC_X86_REG_DS, self.psp_segment)
        mu.reg_write(UC_X86_REG_ES, self.psp_segment)
        self.entry_cs, self.entry_ip = cs, ip
        print(f"[+] Loaded: CS:IP={cs:04x}:{ip:04x}  SS:SP={ss:04x}:{sp:04x}  "
              f"PSP={self.psp_segment:04x}  image={self.load_segment:04x}:0000 "
              f"({len(self.image)} bytes)")

    def _setup_hooks(self):
        self.mu.hook_add(UC_HOOK_INTR, self._on_interrupt)
        self.mu.hook_add(UC_HOOK_CODE, self._on_code)
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_mem_unmapped)

    def _on_mem_unmapped(self, uc, access, address, size, value, data):
        print(f"[!] Access to unmapped memory: addr=0x{address:x} size={size}")
        self.stopped_reason = f"unmapped_mem@0x{address:x}"
        return False  # stop emulation

    def _on_code(self, uc, address, size, data):
        self.instr_count += 1
        if self.instr_count > self.max_instructions:
            self.stopped_reason = "max_instructions"
            uc.emu_stop()
            return

        # If the previous instruction was an indirect call/jmp -- we are
        # NOW exactly where the CPU actually jumped to. That's the answer
        # we're looking for, with no guessing involved.
        pending = getattr(self, '_pending_indirect', None)
        if pending is not None:
            src_addr, kind = pending
            self.indirect_log.append((src_addr, kind, address))
            self._pending_indirect = None

        if not self.trace_indirect:
            return
        try:
            code = bytes(uc.mem_read(address, min(size, 16) if size else 8))
        except Exception:
            return
        b0 = code[0] if code else 0
        modrm_byte = code[1] if len(code) > 1 else 0
        reg_field = (modrm_byte >> 3) & 7
        is_indirect_ff = (b0 == 0xFF and reg_field in (2, 3, 4, 5))
        # FF/2,3 = call r/m (near/far), FF/4,5 = jmp r/m (near/far)
        if is_indirect_ff:
            kind = 'call' if reg_field in (2, 3) else 'jmp'
            self._pending_indirect = (address, kind)

    def _on_interrupt(self, uc, intno, data):
        ax = uc.reg_read(UC_X86_REG_AX)
        ah = (ax >> 8) & 0xFF
        al = ax & 0xFF
        cs = uc.reg_read(UC_X86_REG_CS)
        ip = uc.reg_read(UC_X86_REG_IP)

        if intno == 0x21:
            self._handle_int21(uc, ah, al, cs, ip)
        elif intno == 0x10:
            self._handle_int10(uc, ah, al)
        elif intno == 0x16:
            self._handle_int16(uc, ah, al)
        elif intno in (0x11, 0x1a, 0x2a):
            pass  # harmless -- just continue at the next instruction
        else:
            self.int_log.append((intno, ah, al, cs, ip))
            # unknown interrupt -- also just continue

    def _handle_int21(self, uc, ah, al, cs, ip):
        self.int_log.append((0x21, ah, al, cs, ip))
        ds = uc.reg_read(UC_X86_REG_DS)
        dx = uc.reg_read(UC_X86_REG_DX)
        cx = uc.reg_read(UC_X86_REG_CX)
        bx = uc.reg_read(UC_X86_REG_BX)

        if ah == 0x30:  # get DOS version
            uc.reg_write(UC_X86_REG_AX, 0x0005)  # version 5.0
            uc.reg_write(UC_X86_REG_BX, 0xff00)
        elif ah == 0x09:  # print $-terminated string
            addr = ds * 16 + dx
            s = bytearray()
            for i in range(4096):
                b = uc.mem_read(addr + i, 1)[0]
                if b == ord('$'):
                    break
                s.append(b)
            self.output_bytes.extend(s)
            self._log_print("AH=09", s)
        elif ah == 0x40:  # write handle
            addr = ds * 16 + dx
            data_out = bytes(uc.mem_read(addr, cx))
            self.output_bytes.extend(data_out)
            self._log_print(f"AH=40 handle={bx} len={cx}", data_out)
            uc.reg_write(UC_X86_REG_AX, cx)  # "wrote the same number of bytes"
            uc.reg_write(UC_X86_REG_EFLAGS, uc.reg_read(UC_X86_REG_EFLAGS) & ~1)
        elif ah == 0x02:  # print a single character (DL)
            dl = uc.reg_read(UC_X86_REG_DX) & 0xFF
            self.output_bytes.append(dl)
        elif ah == 0x06:  # direct console I/O -- DL=0xFF means "read", otherwise "write DL"
            dl = uc.reg_read(UC_X86_REG_DX) & 0xFF
            if dl != 0xFF:
                self.output_bytes.append(dl)
            else:
                uc.reg_write(UC_X86_REG_EFLAGS, uc.reg_read(UC_X86_REG_EFLAGS) | 0x40)  # ZF=1, no key ready
        elif ah == 0x0c:  # flush input buffer, then invoke the sub-function in AL
            sub_al = uc.reg_read(UC_X86_REG_AX) & 0xFF
            if sub_al == 0x0a:
                # AL=0Ah -- same as calling AH=0Ah directly afterward
                self._handle_int21(uc, 0x0a, sub_al, cs, ip)
            else:
                # AL=01/06/07/08 -- read a single character (with/without
                # echo). We don't have a real keyboard, so hand back a
                # scripted answer the same way as AH=0Ah, one character at
                # a time (defaults to Enter/'\r' if the script ran dry).
                if self.input_script_pos < len(self.input_script):
                    answer = self.input_script[self.input_script_pos]
                    self.input_script_pos += 1
                else:
                    answer = "\r"
                ch = answer[0] if answer else '\r'
                uc.reg_write(UC_X86_REG_AX, (uc.reg_read(UC_X86_REG_AX) & 0xFF00) | ord(ch))
                self.input_log.append((cs, ip, f"AH=0Ch/AL={sub_al:02x} -> {ch!r}"))
                print(f"[i] AH=0C (flush+read, AL=0x{sub_al:02x}) at {cs:04x}:{ip:04x} -- "
                      f"answering {ch!r} (scripted)")
        elif ah == 0x0a:  # buffered input
            addr = ds * 16 + dx
            maxlen = uc.mem_read(addr, 1)[0]
            if self.input_script_pos < len(self.input_script):
                answer = self.input_script[self.input_script_pos]
                self.input_script_pos += 1
            else:
                answer = "\r"  # ran out of scripted answers -- just press Enter
            # DOS buffered input format: byte0=maxlen (already read), byte1=
            # actual length written back, byte2.. = the characters (CR not
            # counted in the length, but IS placed in the buffer)
            raw = answer.encode('cp866', errors='replace')
            actual = raw[:max(0, maxlen - 1)]
            if not actual.endswith(b'\r'):
                actual = actual[:maxlen-2] + b'\r' if maxlen >= 2 else b'\r'
            uc.mem_write(addr + 1, bytes([len(actual) - 1 if actual.endswith(b'\r') else len(actual)]))
            uc.mem_write(addr + 2, actual)
            self.input_log.append((cs, ip, answer))
            print(f"[i] AH=0A (buffered input) at {cs:04x}:{ip:04x} -- "
                  f"answering {answer!r} (scripted, #{self.input_script_pos})")
        elif ah == 0x25:  # set interrupt vector
            pass  # we don't track a real IVT -- not critical for our purposes
        elif ah == 0x35:  # get interrupt vector
            uc.reg_write(UC_X86_REG_BX, 0)
            uc.reg_write(UC_X86_REG_ES, 0)
        elif ah == 0x4a:  # resize memory block
            uc.reg_write(UC_X86_REG_EFLAGS, uc.reg_read(UC_X86_REG_EFLAGS) & ~1)
        elif ah == 0x48:  # allocate memory
            uc.reg_write(UC_X86_REG_AX, 0x2000)  # hand out a fake segment
            uc.reg_write(UC_X86_REG_EFLAGS, uc.reg_read(UC_X86_REG_EFLAGS) & ~1)
        elif ah == 0x4c:  # terminate
            self.stopped_reason = "int21_4c_terminate"
            uc.emu_stop()
            return
        elif ah == 0x44:  # ioctl
            # AL=00h GetDeviceInfo -- return a realistic value for a
            # character device attached to CON (bit7=device, bit1=console
            # output, bit0=console input, bit4=fast INT-29h output
            # supported); this is the commonly documented value for a
            # CON-attached handle (Ralf Brown's Interrupt List /
            # int 21,44,0). Using a plausible real value here (rather than
            # an arbitrary stub) matters because at least one branch in
            # the program's own code depends on it.
            al2 = uc.reg_read(UC_X86_REG_AX) & 0xFF  # AL holds the subfunction
            if al2 == 0x00:
                uc.reg_write(UC_X86_REG_DX, 0x80D3)
                uc.reg_write(UC_X86_REG_AX, 0x80D3)
            else:
                uc.reg_write(UC_X86_REG_AX, 0x80)  # generic stub for other subfunctions
            uc.reg_write(UC_X86_REG_EFLAGS, uc.reg_read(UC_X86_REG_EFLAGS) & ~1)
        else:
            uc.reg_write(UC_X86_REG_EFLAGS, uc.reg_read(UC_X86_REG_EFLAGS) & ~1)

    def _handle_int10(self, uc, ah, al):
        pass

    def _handle_int16(self, uc, ah, al):
        if ah in (0x00, 0x10):
            uc.reg_write(UC_X86_REG_AX, 0x0D0D)  # pretend Enter was pressed
        elif ah in (0x01, 0x11):
            uc.reg_write(UC_X86_REG_EFLAGS, uc.reg_read(UC_X86_REG_EFLAGS) | 0x40)  # ZF=1, no keys

    def _log_print(self, tag, raw_bytes):
        try:
            text = raw_bytes.decode('cp866', errors='replace')
        except Exception:
            text = repr(raw_bytes)
        preview = text.replace('\r', '').replace('\n', '\\n')[:120]
        print(f"[PRINT {tag}] {preview!r}")

    def run(self, max_time_sec=30):
        try:
            self.mu.emu_start(self.entry_cs << 4 | self.entry_ip, 0xFFFFFFFF,
                               timeout=max_time_sec * 1_000_000)
        except UcError as e:
            self.stopped_reason = f"UcError: {e}"
            print(f"[!] Unicorn error: {e}")
        print(f"\n[+] Stopped. Reason: {self.stopped_reason}")
        print(f"[+] Instructions executed: {self.instr_count}")
        cs = self.mu.reg_read(UC_X86_REG_CS)
        ip = self.mu.reg_read(UC_X86_REG_IP)
        print(f"[+] Final CS:IP = {cs:04x}:{ip:04x}")


if __name__ == '__main__':
    emu = DosEmu('<filename>')
    emu.run()
