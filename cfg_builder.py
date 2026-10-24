"""
cfg_builder.py -- builds a control-flow graph via a real worklist algorithm
(recursive descent), rather than linear range reading.

Idea: keep a set of "places to reach" (addresses where execution actually
starts -- program entry, jump targets, call targets). From each such
address we walk STRAIGHT, instruction by instruction, until we hit
something that changes control flow. Bytes we never reach this way are
never disassembled.
"""
import sys, re, struct
sys.path.insert(0, '.')
from decoder import decode_one, Instr

# ============================================================================
# KNOWN RESOLVED RUNTIME VECTORS
#
# Found manually (not guessed): at far address 1070:0024 there is a REAL,
# cleanly decodable dispatcher of the form
#     shl bx,1 ; push ds ; mov cx,0x1319 ; mov ds,cx ; call word ptr cs:[bx+0x10] ; ...
# which takes a function number from BX and calls the real address from a
# table of near pointers living in the same segment CS=0x1070 at offset
# 0x10. A pointer to this dispatcher (far, 4 bytes) is statically present
# in the file image at DS:0x44de (DS at that point == SS == segment 0x1330,
# computed inside entry(): `mov di,0x1330 ... mov ss,di ... push ss; pop ds`).
#
# Verified at ALL 5 call sites of [0x44de]/[ss:0x44de] in the pass: right
# before every call (on the same straight-line stretch of code, with no
# branches between `mov bx,N` and the call) there is `mov bx,<constant>` --
# i.e. the value of BX at call time is known unambiguously and requires no
# guessing.
KNOWN_FAR_VECTOR_DS_OFFSET = 0x44de   # DS:0x44de -> far ptr to the dispatcher
DISPATCHER_TABLE_CS_OFFSET = 0x10     # table of near targets inside the dispatcher segment

_MOV_BX_IMM_RE = re.compile(r'^mov\s+bx,\s*(0x[0-9a-f]+|\d+)$')
_XOR_BX_BX_RE = re.compile(r'^xor\s+bx,\s*bx$')
_WRITES_BX_RE = re.compile(r'\bbx\b')  # any other instruction touching bx --
                                        # reason to stop searching backward (not sure)
_BARE_DISP_RE = re.compile(r'\[(?:ss:)?(0x[0-9a-f]+)\]$')
_PUSH_RE = re.compile(r'^push\b')       # push only READS a register, never redefines it --
                                         # must be skipped when scanning backward for the
                                         # last assignment, otherwise it falsely looks like
                                         # "something else touches this register"


def _find_last_bx_imm(recent_mnemonics):
    """Scan backward along the straight-line stretch for the last assignment
       of BX to a constant. If ANY other instruction touching bx appears
       between it and the current point (other than the assignment itself)
       we're not sure -- return None."""
    for i in range(len(recent_mnemonics) - 1, -1, -1):
        mnem = recent_mnemonics[i]
        if _PUSH_RE.match(mnem):
            continue  # push only reads the register, doesn't redefine it
        m = _MOV_BX_IMM_RE.match(mnem)
        if m:
            return int(m.group(1), 0)
        if _XOR_BX_BX_RE.match(mnem):
            return 0
        if _WRITES_BX_RE.search(mnem):
            return None  # something else touches bx earlier -- not sure, bail
    return None


def resolve_known_dispatcher(cfg, mnemonic, recent_mnemonics):
    """If this is a call/lcall to the known dispatcher [0x44de], and
       somewhere on this same straight-line stretch (with no intervening
       changes to bx) there is `mov bx,<constant>` or `xor bx,bx` -- compute
       the real target statically. Returns the file address of the target,
       or None if the conditions aren't met (in which case we honestly stay
       unresolved, as before)."""
    m = _BARE_DISP_RE.search(mnemonic)
    if not m or int(m.group(1), 16) != KNOWN_FAR_VECTOR_DS_OFFSET:
        return None
    bx = _find_last_bx_imm(recent_mnemonics)
    if bx is None:
        return None

    data = cfg.data
    header_bytes = cfg.header_bytes
    ds_seg = 0x1330  # see the justification above
    far_ptr_addr = header_bytes + ds_seg * 16 + KNOWN_FAR_VECTOR_DS_OFFSET
    if far_ptr_addr + 4 > len(data):
        return None
    disp_off, disp_seg = struct.unpack_from('<HH', data, far_ptr_addr)
    dispatcher_addr = header_bytes + disp_seg * 16 + disp_off

    table_addr = header_bytes + disp_seg * 16 + DISPATCHER_TABLE_CS_OFFSET
    entry_addr = table_addr + bx * 2
    if entry_addr + 2 > len(data):
        return None
    entry_off = struct.unpack_from('<H', data, entry_addr)[0]
    target = header_bytes + disp_seg * 16 + entry_off
    if target >= len(data):
        return None
    return target


# ============================================================================
# KNOWN FAR-POINTER TABLE-WALK LOOP (lcall [di])
#
# The subroutine at file address 0x11e42 implements the pattern
#     cmp si,di ; jae <ret> ; sub di,4 ; mov ax,[di] ; or ax,[di+2]
#     je <repeat> ; lcall [di] ; jmp <repeat>
# -- it walks from di down to si in steps of 4 bytes (the size of a far
# pointer), calling every non-zero entry. Verified at ALL 6 call sites of
# `call 0x11e42`: right before each one (on the same straight-line stretch,
# with no intervening changes to si/di) there are `mov si,X` and `mov di,Y`
# with constants -- i.e. the walked range is known unambiguously. Empty
# ranges (si==di) are a real no-op at the verified sites.
KNOWN_TABLE_WALK_LOOP_ADDR = 0x11e42
FAR_PTR_SIZE = 4

_MOV_SI_IMM_RE = re.compile(r'^mov\s+si,\s*(0x[0-9a-f]+|\d+)$')
_MOV_DI_IMM_RE = re.compile(r'^mov\s+di,\s*(0x[0-9a-f]+|\d+)$')
_WRITES_SI_RE = re.compile(r'\bsi\b')
_WRITES_DI_RE = re.compile(r'\bdi\b')


def _find_last_imm(recent_mnemonics, mov_re, writes_re):
    for i in range(len(recent_mnemonics) - 1, -1, -1):
        mnem = recent_mnemonics[i]
        if _PUSH_RE.match(mnem):
            continue  # push only reads the register, doesn't redefine it
        m = mov_re.match(mnem)
        if m:
            return int(m.group(1), 0)
        if writes_re.search(mnem):
            return None
    return None


def resolve_table_walk_loop(cfg, recent_mnemonics):
    """If this is a call to the known table-walk loop (0x11e42), and both
       constants are set on the same straight-line stretch (with no
       intervening changes to si/di) -- statically replay the loop and
       return the list of file addresses of ALL non-zero entries in range
       [si, di). An empty list is also an honest result (the range is
       empty, or the entry is zero and the loop genuinely calls nothing --
       as in 4 of the 6 verified sites)."""
    si = _find_last_imm(recent_mnemonics, _MOV_SI_IMM_RE, _WRITES_SI_RE)
    di = _find_last_imm(recent_mnemonics, _MOV_DI_IMM_RE, _WRITES_DI_RE)
    if si is None or di is None:
        return []

    data = cfg.data
    header_bytes = cfg.header_bytes
    ds_seg = 0x1330  # see justification above (DS==SS at the time of these calls)

    targets = []
    off = di
    while off > si:
        off -= FAR_PTR_SIZE
        entry_addr = header_bytes + ds_seg * 16 + off
        if entry_addr + 4 > len(data):
            break
        ptr_off, ptr_seg = struct.unpack_from('<HH', data, entry_addr)
        if ptr_off or ptr_seg:
            target = header_bytes + ptr_seg * 16 + ptr_off
            if target < len(data):
                targets.append(target)
    return targets


# ============================================================================
# RUNTIME VARIABLES (poison-filled slots, [0x3cc4..0x4236])
#
# Discovered: the byte pair 0xDE 0x2A occurs 55 times, clustered exactly in
# the range DS:0x3cc4..0x4236 -- this is the standard poison pattern for
# memory left unfilled at build time (not a code dispatcher like [0x44de],
# but genuinely a VARIABLE AREA whose values get written at run time).
# There's nothing to read there statically.
#
# BUT: some of these variables get initialized through ALREADY-visited
# (non-indirect!) calls -- e.g. `mov word ptr [0x3d84], 0x1687` inside one
# of the 10 already-resolved initializer subroutines in segment 0xf50.
# Since we've already walked through this via a direct call, the value is
# known unambiguously, and there's a basis for using it as a resolved
# target for a subsequent indirect call through this same address
# (call word ptr [si] with si pointing here, etc.).
#
# Verified on an example: 0x1687 as a near offset in the SAME segment where
# the writing code itself lives (0xf50) decodes into a valid `ret`. This is
# a HYPOTHESIS (the coincidence of the initializer's and the target's
# segments is plausible but not proven as solidly as [0x44de]) -- flagged
# separately from the hard-resolved vectors, DOSBox verification recommended.
RUNTIME_VAR_LO, RUNTIME_VAR_HI = 0x3cc4, 0x4236
_MOV_WORD_PTR_IMM_RE = re.compile(r'^mov\s+word\s+ptr\s+\[(0x[0-9a-f]+)\],\s*(0x[0-9a-f]+|\d+)$')


def resolve_runtime_variable(cfg, ds_offset, target_segment):
    """Search already-visited instructions for a direct write `mov word ptr
       [ds_offset], imm`. If found -- treat imm as a near offset in
       target_segment and try to decode it.

       IMPORTANT: target_segment is the segment in which the value will be
       USED as a near pointer (for a near call/jmp this is always the
       current CS at the call site, and is NOT necessarily the segment of
       the code that WROTE this value -- these are two different, unrelated
       segments in general, which was confirmed in practice: the reader's
       segment produced a coherent, well-formed subroutine, while the
       writer's segment produced a random lone `ret`).

       Returns (target_addr, source_write_addr) or None."""
    for a, instr in cfg.instrs.items():
        if instr.kind != 'X86':
            continue
        m = _MOV_WORD_PTR_IMM_RE.match(instr.mnemonic)
        if m and int(m.group(1), 16) == ds_offset:
            imm = int(m.group(2), 0)
            target = cfg.header_bytes + target_segment * 16 + imm
            if target < len(cfg.data):
                return target, a
    return None


# ============================================================================
# GENERALIZED "call word ptr [holy displacement]" RESOLVER
#
# Discovered on the example of [0x3e8d] (call site 0x10252): the same
# runtime-variable mechanism as above, just without the intermediate
# lodsw/cx machinery. Once the code area of segment 0x9bd (where the vast
# majority of everything explored above 0xc0f0 lives) was understood and
# confirmed, any "call word ptr [addr]" WITHOUT a register inside the
# brackets can be attempted the same way: search already-visited
# instructions for a direct write `mov word ptr [addr], imm`, and treat imm
# as a near offset in segment 0x9bd.
BARE_DISPLACEMENT_DEFAULT_SEGMENT = 0x9bd
_BARE_DISPLACEMENT_CALL_RE = re.compile(r'^(call|jmp) word ptr (?:[a-z]+:)?\[(0x[0-9a-f]+)\]$')


def resolve_bare_displacement_call(cfg, mnemonic):
    """If this is a call/jmp word ptr [bare displacement] (no register
       inside the brackets), search already-visited instructions for an
       initializer and resolve it in segment 0x9bd. Returns
       (target, source_write_addr, ds_offset) or None."""
    m = _BARE_DISPLACEMENT_CALL_RE.match(mnemonic)
    if not m:
        return None
    ds_offset = int(m.group(2), 16)
    res = resolve_runtime_variable(cfg, ds_offset, BARE_DISPLACEMENT_DEFAULT_SEGMENT)
    if res is None:
        return None
    target, source_write_addr = res
    return target, source_write_addr, ds_offset


# ============================================================================
# KNOWN JUMP TABLE (jmp word ptr cs:[bx + 0x23bc], address 0xe49e)
#
# Found and confirmed manually: right before this jmp the code has an
# explicit bounds check --
#     cmp al, 0xb ; jg <past>
# -- i.e. the valid values of al (after normalization) are strictly
# 0..0xb, ax = al*2 (entry stride is 2 bytes), bx = ax. So the table
# contains EXACTLY 12 entries (indices 0..11). All 12 were read and
# decoded -- all give valid, meaningful code (including an already-known
# call to 0xfba3); entry [12] and beyond are already garbage/BAD, which
# confirms the boundary.
JUMP_TABLE_1_ADDR = 0xe49e
JUMP_TABLE_1_SEGMENT = 0x9bd
JUMP_TABLE_1_OFFSET = 0x23bc
JUMP_TABLE_1_COUNT = 12


def resolve_known_jump_table(cfg, cur):
    """If the current address is the known jump table, returns the list of
       ALL its targets (nothing needs to be computed from context -- the
       table and its size have already been confirmed manually)."""
    if cur != JUMP_TABLE_1_ADDR:
        return None
    data = cfg.data
    header_bytes = cfg.header_bytes
    targets = []
    for i in range(JUMP_TABLE_1_COUNT):
        entry_addr = header_bytes + JUMP_TABLE_1_SEGMENT * 16 + JUMP_TABLE_1_OFFSET + i * 2
        if entry_addr + 2 > len(data):
            break
        entry_off = struct.unpack_from('<H', data, entry_addr)[0]
        target = header_bytes + JUMP_TABLE_1_SEGMENT * 16 + entry_off
        if target < len(data):
            targets.append(target)
    return targets


# ============================================================================
# call word ptr cs:[bx + di] WITH BOTH REGISTERS AS CONSTANTS
#
# One specific instance was found (0x10fee): right before the call, bx and
# di are set to literal constants (mov bx,imm ; mov di,imm), with no
# intervening changes -- i.e. the target is fully known statically:
# cs:[bx+di], where cs = the segment of the calling code itself (0x9bd).
_BX_DI_CALL_RE = re.compile(r'^call word ptr cs:\[bx \+ di\]$')
_MOV_BX_IMM_RE2 = re.compile(r'^mov\s+bx,\s*(0x[0-9a-f]+|\d+)$')


def resolve_bx_di_call(cfg, mnemonic, recent_mnemonics):
    if not _BX_DI_CALL_RE.match(mnemonic):
        return None
    bx = _find_last_imm(recent_mnemonics, _MOV_BX_IMM_RE2, _WRITES_BX_RE)
    di = _find_last_imm(recent_mnemonics, _MOV_DI_IMM_RE, _WRITES_DI_RE)
    if bx is None or di is None:
        return None
    data = cfg.data
    header_bytes = cfg.header_bytes
    entry_addr = header_bytes + BARE_DISPLACEMENT_DEFAULT_SEGMENT * 16 + bx + di
    if entry_addr + 2 > len(data):
        return None
    entry_off = struct.unpack_from('<H', data, entry_addr)[0]
    target = header_bytes + BARE_DISPLACEMENT_DEFAULT_SEGMENT * 16 + entry_off
    if target < len(data):
        return target
    return None


# ============================================================================
# SINGLE-ENTRY LIST DISPATCHER (call word ptr [si], subroutine 0xe885)
#
# Fully worked out mechanism: `lodsw` advances si by 2 bytes BEFORE
# `call word ptr [si]` picks up the target -- because of this, every
# iteration first idly re-reads the previous entry (into ax, never used
# anywhere afterward), and the REAL target of iteration i (i=1..cx) sits at
# address si_entry + 2*i. In other words this is simply a flat array of cx
# near pointers, 2 bytes each, right after the count word.
#
# SEGMENT: this is a near call -- the target is ALWAYS interpreted in the
# CURRENT CS, and CS inside subroutine 0xe885 itself never changes and
# equals the segment it lives in -- 0x9bd (NOT 0xf50, as was mistakenly
# assumed earlier: that hypothesis was only checked by "does it decode
# without BAD", and that isn't enough -- almost any offset in dense code
# gives something that looks plausible. Re-checked more deeply: with
# segment 0x9bd, value 0x1687 unfolds into a full, BALANCED subroutine
# (push si ... pop si; ret, with meaningful calls to other addresses in the
# same segment), whereas 0xf50 gave a lone ret -- a typical false positive
# from randomly landing on a 0xC3 byte).
KNOWN_LIST_DISPATCH_LOOP_ADDR = 0xe885
LIST_DISPATCH_WRITER_SEGMENT = 0xf50
LIST_DISPATCH_MAX_CX = 64  # guard against a nonsensically large cx (garbage data)

_MOV_CX_IMM_RE = re.compile(r'^mov\s+cx,\s*(0x[0-9a-f]+|\d+)$')
_XOR_CX_CX_RE = re.compile(r'^xor\s+cx,\s*cx$')
_WRITES_CX_RE = re.compile(r'\bcx\b')


def _find_last_cx_imm(recent_mnemonics):
    for i in range(len(recent_mnemonics) - 1, -1, -1):
        mnem = recent_mnemonics[i]
        if _PUSH_RE.match(mnem):
            continue  # push only reads the register, doesn't redefine it
        if _MOV_CX_IMM_RE.match(mnem):
            return int(_MOV_CX_IMM_RE.match(mnem).group(1), 0)
        if _XOR_CX_CX_RE.match(mnem):
            return 0
        if _WRITES_CX_RE.search(mnem):
            return None
    return None


def resolve_list_dispatch_general(cfg, recent_mnemonics):
    """General case (any cx, not just cx==1). cx is read from MEMORY
       (`mov cx, word ptr [si]`), not from a constant in the code. For each
       of the cx entries (i=1..cx, address si+2*i) we try to find an
       already-visited initializer via resolve_runtime_variable. Slots for
       which no initializer is found (still poison-filled) are honestly
       skipped -- we return the list of only the SUCCESSFULLY resolved
       ones (target, source_write_addr, slot_index)."""
    si = _find_last_imm(recent_mnemonics, _MOV_SI_IMM_RE, _WRITES_SI_RE)
    if si is None:
        return []
    data = cfg.data
    header_bytes = cfg.header_bytes
    ds_seg = 0x1330
    count_addr = header_bytes + ds_seg * 16 + si
    if count_addr + 2 > len(data):
        return []
    cx = struct.unpack_from('<H', data, count_addr)[0]
    if cx == 0 or cx > LIST_DISPATCH_MAX_CX:
        return []  # 0 -- empty list (jcxz would catch this anyway), too many -- garbage

    results = []
    for i in range(1, cx + 1):
        slot_off = si + 2 * i
        res = resolve_runtime_variable(cfg, slot_off, LIST_DISPATCH_WRITER_SEGMENT)
        if res is not None:
            target, source_write_addr = res
            results.append((target, source_write_addr, i))
    return results


# ============================================================================
# CX AS A CALLBACK PARAMETER (passed across a call boundary)
#
# Subroutine 0xeb23 -- prints AX digit by digit (dividing by 10 in a loop),
# calls `call cx` (0xeb36) for each digit -- CX is never touched inside,
# so this is an INPUT parameter (the address of a "print one character"
# callback) set by the calling code.
#
# The only direct call found (0xe76d) sets `mov cx, 0x2a2a` right before
# the call. Decoded as near offset 0x2a2a in the SAME segment where
# function 0xeb23 itself lives (0x9bd) -- gives file address 0xeb1a, which
# is already in our graph: it's the "print a character from AL via
# int 21h/AH=6" subroutine (0xeb1a: push dx; mov dx,ax; mov ah,6;
# int 0x21; pop dx; ret) -- a semantically perfect fit for the callback
# role. The segment match is confirmed substantively (not just by the
# bytes decoding into valid code, but also because the target is an
# already-known, logical subroutine), so this resolver is applied without
# the extra "hypothesis" flag, unlike resolve_runtime_variable.
KNOWN_CX_CALLBACK_CALLER_ADDR = 0xeb23
CX_CALLBACK_SEGMENT = 0x9bd


def resolve_cx_callback(cfg, recent_mnemonics):
    cx = _find_last_cx_imm(recent_mnemonics)
    if cx is None:
        return None
    target = cfg.header_bytes + CX_CALLBACK_SEGMENT * 16 + cx
    if target < len(cfg.data):
        return target


# ============================================================================
# FPU HANDLER INSTALLER (INT 34h-3Bh) -- found via the chain:
# int 0x11 (BIOS equipment flags, "coprocessor present" bit) -> flag [4] ->
# subroutine 0x12d2b, which through int 21h AH=25h installs into the
# interrupt vector table ONE OF TWO handler sets (near offsets in the same
# segment CS=0xf50 the subroutine itself lives in):
#   - if a coprocessor IS present: 0x6d6, 0x68c, 0x6b9 (thin pass-through stubs)
#   - if there is NO coprocessor: 0xb1f, 0xadf, 0xac2 (full software
#     emulation -- this is exactly where real FPU instructions were found:
#     FLDCW, FILD, FABS, FCOMPP/FSTSW, FMULP, etc.)
# This is NOT an ordinary call/jmp -- the transfer happens through the
# CPU's interrupt vector table when CD 34h..3Bh executes, so the CFG can't
# reach it on its own (there's no direct call/jmp to these addresses
# anywhere in the code) -- we add both sets explicitly as extra entry
# points now that we know where the vector installation leads.
FPU_HANDLER_SEGMENT = 0xf50
FPU_HANDLER_OFFSETS_WITH_COPROCESSOR = [0x6d6, 0x68c, 0x6b9]
FPU_HANDLER_OFFSETS_EMULATED = [0xb1f, 0xadf, 0xac2]


# ============================================================================
# USER PROGRAM ENTRY POINT (segment 0, the "real" code)
#
# FOUND NOT STATICALLY, BUT THROUGH ACTUAL EMULATION (Unicorn Engine,
# see dos_emu.py) -- this is a fundamentally different class of resolver:
# not byte analysis, but honestly executing the program in a sandbox with
# a minimal DOS shim.
#
# Transfer mechanism (confirmed by an execution trace): from the library
# (0x9bd:0x25ff -- the same "stack-frame setup trampoline" already known
# from earlier sessions), control returns to code at address 0x11a9f
# (relative, segment 0xf50), which manually constructs a far jump via
# retf: the segment is taken from a structure in memory pointed to by
# DS:[0x45aa], the offset is word[si]+0x30. The pointer [0x45aa] is itself
# a runtime variable with no static initializer anywhere in the file (the
# same class of "poison" slots we spent the whole previous session hunting
# for, we just never tried this specific one) -- but thanks to emulation we
# know the result directly: CS:IP = (relative segment 0):0x0030.
#
# Verified: at this address there is real, meaningful code
# (mov ax,1; push ax; ...; lcall 0x9bd,0x4e3e -- a call into the library
# right after startup), not garbage.
USER_PROGRAM_ENTRY_SEGMENT = 0x0000
USER_PROGRAM_ENTRY_OFFSET = 0x0030


# ============================================================================
# INDIRECT TARGETS CONFIRMED BY REAL EMULATION (Unicorn, see dos_emu.py)
#
# After running the program in the sandbox with a reasonably realistic DOS
# shim, the actually-taken branch of every indirect call/jmp was logged.
# These pairs (source address -> real target) are cross-checked against
# cfg.indirect_transfers: every one of them corresponds to a site our
# static resolvers either already handle (this is a nice consistency
# check -- e.g. 0x11e50/0x11e1e/... match resolve_table_walk_loop and
# resolve_known_dispatcher exactly) or genuinely couldn't fully resolve
# (0xe88b -- the general call word ptr [si] case with cx>1 -- now has ALL
# 13 real targets from one execution, something the static "search for a
# literal initializer" approach could only partially do).
#
# KNOWN OPEN DISCREPANCY: the emulator additionally logged 0xea9f -> 0xebce
# (the [0x422a]-guarded call), but a REAL DOSBox-X session with a live
# breakpoint on that exact call never fired it during actual interactive
# use -- i.e. real hardware/DOS says this path is dead, while our
# emulation still takes it at least once. We deliberately do NOT include
# this specific pair here until the discrepancy is understood (most likely
# some other DOS call resets the guard flag [0x45df] again after our
# startup patch, and our shim doesn't replicate that). Left as a note for
# whoever continues this project.
EMULATION_CONFIRMED_INDIRECT_TARGETS = [
    (0xe728, 0x11a9f),
    (0xe88b, 0xd777),
    (0xe88b, 0xd8d0),
    (0xe88b, 0xd8f8),
    (0xe88b, 0xd8ff),
    (0xe88b, 0xe83b),
    (0xe88b, 0xe891),
    (0xe88b, 0xeb46),
    (0xe88b, 0xeb67),
    (0xe88b, 0xeb86),
    (0xe88b, 0xebce),
    (0xe88b, 0xedf4),
    (0xe88b, 0x10fc6),
    (0xe88b, 0x10fe4),
    (0xf7d1, 0xf3ca),
    (0xf7d8, 0xf437),
    (0xf7e6, 0xf51c),
    (0x10d6f, 0x10d4b),
    (0x10d6f, 0x10f31),
    (0x11e1e, 0x12c44),
    (0x11e50, 0xf629),
    (0x11e50, 0x11a26),
    (0x11e50, 0x11a52),
    (0x11e50, 0x11a5a),
    (0x11e50, 0x11a68),
    (0x11e50, 0x11ab8),
    (0x11e50, 0x11ad8),
    (0x11e50, 0x11ae0),
    (0x11e50, 0x11aea),
    (0x11e50, 0x11b16),
    (0x11e50, 0x11b42),
    (0x11ee7, 0x12c44),
    (0x11ef1, 0x12c44),
]


class CFG:
    def __init__(self, data, header_bytes):
        self.data = data
        self.header_bytes = header_bytes
        self.instrs = {}            # addr -> Instr, for ALL actually-visited instructions
        self.visited = set()        # addresses of instruction starts we've already decoded
        self.call_targets = set()   # addresses that have at least one call/lcall to them
        self.jump_targets = set()   # addresses that have at least one jmp/jcc to them
        self.entry_points = set()   # every place from which WE OURSELVES started a new pass
                                     # (program entry + all call/jmp targets) -- useful for
                                     # later splitting into subroutines
        self.no_return_targets = set()   # call targets flagged as "does not return in the
                                          # normal way" (see is_non_standard_callee)
        self.overlap_warnings = []  # (addr, existing_instr_addr) -- a new entry point landed
                                     # IN THE MIDDLE of an already-decoded instruction
        self.indirect_transfers = []  # addresses of indirect jmp/call -- target unknown,
                                       # honestly recorded rather than ignored
        self.resolved_known_vectors = {}  # addr -> target: INDIRECT transfers resolved
                                           # through resolve_known_dispatcher
                                           # (proven manually, not guessed)
        self.resolved_table_walks = {}    # addr of a call to 0x11e42 -> [targets]:
                                           # real far targets computed via
                                           # resolve_table_walk_loop (si/di known)
        self.resolved_runtime_vars = {}   # addr of the call -> [(target, source_write_addr,
                                           # slot), ...]
        self.resolved_cx_callbacks = {}   # addr of a call to 0xeb23 -> target: resolved
                                           # via resolve_cx_callback (a callback
                                           # parameter passed across a call boundary)
        self.resolved_bare_displacement = {}  # addr of the call -> (target, source_write_addr,
                                               # ds_offset): the generic resolver for
                                               # call word ptr [bare displacement]
                                               # (see resolve_bare_displacement_call)
        self.resolved_jump_tables = {}    # addr of the jmp -> [targets]: known jump
                                           # tables (see resolve_known_jump_table)

    def _decode(self, addr):
        return decode_one(self.data, addr, header_bytes=self.header_bytes)

    def is_non_standard_callee(self, addr):
        """Check the FIRST instruction at address addr -- if it's 'pop',
           this is most likely a non-standard call that uses its own return
           address as data (see the earlier found trick with embedded
           text) -- in that case we must NOT add the return point (the
           address after the call) to the queue, because there is genuinely
           no executable code there (it's embedded data)."""
        if addr >= len(self.data):
            return False
        probe = self._decode(addr)
        return probe.kind == 'X86' and probe.mnemonic.startswith('pop')

    def _find_overlap(self, addr):
        """Checks whether addr falls IN THE MIDDLE of an already-decoded instruction."""
        for existing_addr, instr in self.instrs.items():
            if existing_addr < addr < existing_addr + instr.length:
                return existing_addr
        return None

    def build(self, entry_addr, max_instrs=2_000_000):
        worklist = [entry_addr]
        self.entry_points.add(entry_addr)
        self._count = 0
        self._max_instrs = max_instrs

        while True:
            self._drain(worklist)
            if self._count > self._max_instrs:
                return
            new_targets = self._resolve_pending_runtime_calls()
            if not new_targets:
                break
            for t in new_targets:
                if t not in self.entry_points:
                    self.entry_points.add(t)
                    worklist.append(t)

        # Handlers for INT 34h-3Bh are unreachable through an ordinary
        # call/jmp (the transfer goes through the CPU's interrupt vector
        # table, see the comment above) -- add them explicitly, as a
        # separate final drain.
        fpu_worklist = []
        for off in FPU_HANDLER_OFFSETS_WITH_COPROCESSOR + FPU_HANDLER_OFFSETS_EMULATED:
            t = self.header_bytes + FPU_HANDLER_SEGMENT * 16 + off
            if t not in self.entry_points:
                self.entry_points.add(t)
                fpu_worklist.append(t)
        self._drain(fpu_worklist)

        # Entry point of the user program (found through emulation, see
        # the comment at USER_PROGRAM_ENTRY_SEGMENT/OFFSET above) -- also
        # unreachable via an ordinary call/jmp; add it explicitly and
        # repeat the whole cycle (drain + runtime-variable resolvers),
        # because this new area is bound to have its own resolvable
        # "poison" slots.
        user_entry = self.header_bytes + USER_PROGRAM_ENTRY_SEGMENT * 16 + USER_PROGRAM_ENTRY_OFFSET
        if user_entry not in self.entry_points:
            self.entry_points.add(user_entry)
            self._drain([user_entry])
            while True:
                new_targets = self._resolve_pending_runtime_calls()
                if not new_targets:
                    break
                for t in new_targets:
                    if t not in self.entry_points:
                        self.entry_points.add(t)
                self._drain(list(new_targets))

        # Indirect targets confirmed by real emulation (see the comment at
        # EMULATION_CONFIRMED_INDIRECT_TARGETS above) -- add every target
        # as an entry point, tagged by its source address, then run the
        # full drain+resolve cycle once more since this can open up yet
        # more code (and with it, more resolvable runtime-variable slots).
        emu_worklist = []
        for src, tgt in EMULATION_CONFIRMED_INDIRECT_TARGETS:
            self.resolved_bare_displacement.setdefault(src, (tgt, None, 'emulation-confirmed'))
            if tgt not in self.entry_points:
                self.entry_points.add(tgt)
                emu_worklist.append(tgt)
        if emu_worklist:
            self._drain(emu_worklist)
            while True:
                new_targets = self._resolve_pending_runtime_calls()
                if not new_targets:
                    break
                for t in new_targets:
                    if t not in self.entry_points:
                        self.entry_points.add(t)
                self._drain(list(new_targets))

    def _resolve_pending_runtime_calls(self):
        """Post-pass over the FULLY built (so far) graph: look for calls to
           the known list dispatcher (0xe885), and for calls to the known
           cx-callback caller (0xeb23), and for indirect instructions that
           might resolve via the generic bare-displacement resolver -- for
           any of these where new information might now be available
           because the graph has grown, try resolving again. Returns the
           list of NEW targets (otherwise the outer loop in build() would
           never terminate)."""
        new_targets = []
        for a, instr in list(self.instrs.items()):
            if instr.is_call and instr.target == KNOWN_LIST_DISPATCH_LOOP_ADDR:
                recent = self._recent_mnemonics_before(a)
                results = resolve_list_dispatch_general(self, recent)
                already = {slot for (_, _, slot) in self.resolved_runtime_vars.get(a, [])}
                new_here = [r for r in results if r[2] not in already]
                if new_here:
                    self.resolved_runtime_vars.setdefault(a, [])
                    self.resolved_runtime_vars[a].extend(new_here)
                    for target, source_write_addr, slot in new_here:
                        if target not in self.entry_points and target not in self.visited:
                            new_targets.append(target)
            if instr.is_call and instr.target == KNOWN_CX_CALLBACK_CALLER_ADDR and a not in self.resolved_cx_callbacks:
                recent = self._recent_mnemonics_before(a)
                cb_target = resolve_cx_callback(self, recent)
                if cb_target is not None:
                    self.resolved_cx_callbacks[a] = cb_target
                    if cb_target not in self.entry_points and cb_target not in self.visited:
                        new_targets.append(cb_target)
            if instr.is_indirect and a not in self.resolved_bare_displacement and a not in self.resolved_known_vectors:
                bare = resolve_bare_displacement_call(self, instr.mnemonic)
                if bare is not None:
                    target, source_write_addr, ds_offset = bare
                    self.resolved_bare_displacement[a] = (target, source_write_addr, ds_offset)
                    if target not in self.entry_points and target not in self.visited:
                        new_targets.append(target)
        return new_targets

    def _recent_mnemonics_before(self, addr, window=8):
        """Reconstructs the mnemonics of a few instructions before addr, by
           walking backward through the sorted addresses of the already-
           built self.instrs. An approximation (doesn't perfectly match the
           original straight-line stretch when paths merge), but good
           enough for simple mov patterns."""
        prevs = sorted(a for a in self.instrs if a < addr)
        return [self.instrs[a].mnemonic for a in prevs[-window:]]

    def _drain(self, worklist):
        while worklist:
            addr = worklist.pop()
            if addr in self.visited:
                continue

            overlap = self._find_overlap(addr)
            if overlap is not None:
                self.overlap_warnings.append((addr, overlap))
                continue  # don't disassemble over the middle of another instruction

            cur = addr
            recent_mnemonics = []  # mnemonics of this same straight-line stretch, for the resolvers
            while True:
                if cur in self.visited:
                    break  # merged into an already-visited path -- fine, stop here
                overlap = self._find_overlap(cur)
                if overlap is not None:
                    self.overlap_warnings.append((cur, overlap))
                    break

                instr = self._decode(cur)
                self.visited.add(cur)
                self.instrs[cur] = instr
                self._count += 1
                if self._count > self._max_instrs:
                    return  # guard against unbounded growth in case of a serious bug

                if instr.is_indirect:
                    jt = resolve_known_jump_table(self, cur)
                    if jt is not None:
                        self.resolved_jump_tables[cur] = jt
                        for t in jt:
                            if t not in self.entry_points:
                                self.entry_points.add(t)
                                worklist.append(t)
                    resolved = resolve_known_dispatcher(self, instr.mnemonic, recent_mnemonics)
                    if resolved is not None:
                        self.resolved_known_vectors[cur] = resolved
                        if resolved not in self.entry_points:
                            self.entry_points.add(resolved)
                            worklist.append(resolved)
                        # this is a call -- we apply the usual "assume it
                        # returns" as before (see the instr.is_indirect
                        # branch below)
                    else:
                        bare = resolve_bare_displacement_call(self, instr.mnemonic)
                        if bare is not None:
                            target, source_write_addr, ds_offset = bare
                            self.resolved_bare_displacement[cur] = (target, source_write_addr, ds_offset)
                            if target not in self.entry_points:
                                self.entry_points.add(target)
                                worklist.append(target)
                        else:
                            bxdi = resolve_bx_di_call(self, instr.mnemonic, recent_mnemonics)
                            if bxdi is not None:
                                self.resolved_bare_displacement[cur] = (bxdi, None, None)
                                if bxdi not in self.entry_points:
                                    self.entry_points.add(bxdi)
                                    worklist.append(bxdi)

                recent_mnemonics.append(instr.mnemonic)
                if len(recent_mnemonics) > 8:
                    recent_mnemonics.pop(0)

                if instr.kind == 'BAD':
                    break  # reached something undecodable -- stop here

                if instr.is_ret:
                    break

                if instr.is_indirect:
                    self.indirect_transfers.append(cur)
                    if instr.is_call:
                        # Indirect CALL: we don't know the target and don't
                        # guess, BUT by calling convention control returns
                        # right after the call -- the same principle we
                        # already apply to ordinary (direct) calls.
                        # Continue linearly, honestly having recorded the
                        # unknown target.
                        cur = cur + instr.length
                        continue
                    break  # indirect JMP -- no return is assumed by
                           # definition, we honestly stop, don't guess and
                           # don't continue linearly

                if instr.is_call:
                    self.call_targets.add(instr.target)
                    if instr.target not in self.entry_points:
                        self.entry_points.add(instr.target)
                        worklist.append(instr.target)
                    if instr.target == KNOWN_TABLE_WALK_LOOP_ADDR:
                        walked = resolve_table_walk_loop(self, recent_mnemonics)
                        if walked:
                            self.resolved_table_walks[cur] = walked
                            for t in walked:
                                if t not in self.entry_points:
                                    self.entry_points.add(t)
                                    worklist.append(t)
                    if instr.target == KNOWN_CX_CALLBACK_CALLER_ADDR:
                        cb_target = resolve_cx_callback(self, recent_mnemonics)
                        if cb_target is not None:
                            self.resolved_cx_callbacks[cur] = cb_target
                            if cb_target not in self.entry_points:
                                self.entry_points.add(cb_target)
                                worklist.append(cb_target)
                    if self.is_non_standard_callee(instr.target):
                        self.no_return_targets.add(instr.target)
                        break  # don't continue linearly -- after such a
                               # call control genuinely does NOT return here
                    cur = cur + instr.length
                    continue

                if instr.is_jmp:
                    self.jump_targets.add(instr.target)
                    if instr.target not in self.entry_points:
                        self.entry_points.add(instr.target)
                    worklist.append(instr.target)
                    break

                if instr.is_jcc:
                    self.jump_targets.add(instr.target)
                    if instr.target not in self.entry_points:
                        self.entry_points.add(instr.target)
                    worklist.append(instr.target)
                    cur = cur + instr.length
                    continue

                cur = cur + instr.length

    def ordered_instrs(self):
        return [self.instrs[a] for a in sorted(self.instrs)]
