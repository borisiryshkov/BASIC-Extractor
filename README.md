# Recursive decompiler

A from-scratch, CFG-based recursive decompiler for a 16-bit real-mode DOS
executable (Microsoft BASIC PDS / QuickBASIC-compiled). No manual addresses, no ground-truth source -- everything
here was derived from the binary itself, cross-checked against real
execution (DOSBox-X and a custom x86 emulator).

## Why this exists

A naive linear disassembler reads bytes start-to-end and regularly falls
into data, producing garbage. This project instead builds a real
control-flow graph: start from the program's actual entry point and only
follow addresses the CPU would really execute (`call`/`jmp`/`jcc`
targets), the same way a worklist/recursive-descent disassembler would.
Indirect calls/jumps (`call word ptr [...]`, jump tables, etc.) are the
hard part -- by default the CFG honestly stops at them rather than
guessing. Most of this project is about *proving* what those targets
really are, one mechanism at a time, and feeding the proof back into the
graph builder.

## Files

| File                       | What it does                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `decoder.py`             | Decodes ONE instruction at a time (building block for the worklist algorithm, not a linear `disasm_range`). Includes a hand-written decoder for the `ESC`-via-`INT 34h-3Bh` software FPU emulation trick (8087 instructions compiled for a machine with no real coprocessor). |
| `cfg_builder.py`         | The CFG engine itself: worklist/recursive-descent traversal, plus every indirect-transfer resolver discovered during the project (see below). This is the file with all the historical/forensic comments explaining *why* each resolver exists.                                   |
| `pseudocode.py`          | Ported from an earlier linear-extractor prototype: symbolic emulation of the FPU stack (to reconstruct arithmetic formulas), `PRINT`/`INPUT`/`STRCMP`/float-compare runtime-routine detection by voting, and flat pseudocode generation.                                      |
| `structuring.py`         | Turns the flat pseudocode into `if`/`while` Python-like structure using real dominator/post-dominator analysis and natural-loop detection (back edges) -- not a heuristic.                                                                                                      |
| `run_full_pseudocode.py` | Driver: builds the CFG, splits it into functions, runs the pipeline above per function, writes `full_pseudocode.py.txt`.                                                                                                                                                          |
| `dos_emu.py`             | A minimal x86 real-mode emulator (Unicorn Engine) with a hand-rolled DOS shim (`int 21h`/`10h`/`16h`), used to *actually run* the program in a sandbox and observe real register/memory values for things that can't be resolved statically.                                |
| `test_cfg.py`            | Quick sanity-check script: builds the CFG and prints summary stats.                                                                                                                                                                                                                 |
| `full_pseudocode.py.txt` | Generated output -- the whole program's pseudocode, as of the last run. Regenerate with `run_full_pseudocode.py`.                                                                                                                                                                 |

## How to run

```bash
pip install capstone unicorn
# place file in the same directory
python3 test_cfg.py              # quick stats
python3 run_full_pseudocode.py   # full pseudocode -> full_pseudocode.py.txt
python3 dos_emu.py               # run the program in the sandbox emulator
```

## Architecture discovered along the way

- The executable's code is split across **8 real segments** (confirmed
  exhaustively via the MZ relocation table, not guessed): a dominant
  runtime-library segment `0x9bd` (1995 of 2368 relocations), the entry
  segment `0xf63`, an FPU-emulation segment `0xf50`, a few small helper
  segments, and -- found only through actual emulation, not statically
  reachable by any direct `call`/`jmp`/`int` anywhere in the file --
  **two large user-program segments, relative `0x0000` and `0x1000`**
  (2345 + 23 relocations respectively). This is where the real
  gear-calculation logic, `PRINT` text, and formulas live.
- The jump into the user-program segment happens through a hand-built
  `retf`-based far transfer (segment taken from a runtime-computed
  pointer structure, offset computed as `word[si]+constant`) -- a
  mechanism that genuinely cannot be found by any static search; it was
  only found by running the program in the Unicorn-based emulator and
  watching where it actually went.
- The program auto-detects whether a real 8087 coprocessor is present
  (`int 11h` BIOS equipment flags) and installs one of two different
  `INT 34h-3Bh` handler sets accordingly -- a thin hardware pass-through,
  or a full software FPU emulator (confirmed by finding real `FLDCW`,
  `FILD`, `FABS`, `FCOMPP`, `FMULP` instructions at the emulated-path
  addresses).
- A family of "poison-filled" runtime variables (`DS:0x3cc4..0x4236`,
  confirmed by the `0xDE 0x2A` fill-pattern signature occurring 55 times
  clustered exactly in that range) hold indirect-call targets that are
  computed and written at run time, not present anywhere in the static
  file image. Several resolution strategies were built for these (see
  below); the rest can only be found by watching real execution.

## Indirect-transfer resolvers in `cfg_builder.py`

Each one is documented in-place with how it was found and verified.
Roughly in order of specificity:

1. **Known BX-indexed dispatcher** (`[0x44de]`) -- a shared far-call-by-
   number helper; BX tracked backward through the straight-line code.
2. **Known far-pointer table-walk loop** (`0x11e42`, `lcall [di]`) -- si/di
   bounds tracked the same way, table replayed statically.
3. **Runtime-variable resolver** (`resolve_runtime_variable`) -- searches
   already-visited code for a literal `mov word ptr [addr], imm` that
   initializes a poison slot, then decodes the written value as a near
   pointer in a given segment.
4. **General list dispatcher** (`0xe885`, `call word ptr [si]`, any `cx`)
   -- cx read from memory, every slot resolved via (3) where possible.
5. **Generic bare-displacement call/jmp resolver** -- same idea as (3)
   but for any `call/jmp word ptr [addr]` with no register involved.
6. **Known 12-entry jump table** (`0xe49e`) -- bounds-checked in the code
   itself (`cmp al, 0xb`), all entries read and verified to decode cleanly.
7. **`cs:[bx+di]` with both registers as literal constants** -- one
   confirmed instance.
8. **Cross-call-boundary parameter** (`0xeb23`, digit-printing routine
   taking a "print char" callback in CX) -- resolved for its one caller.
9. **FPU interrupt-vector installer targets** -- not reachable by any
   call/jmp at all (the CPU jumps there through the interrupt vector
   table), added as explicit extra entry points once the installer
   routine was understood.
10. **User-program entry point** -- found purely through emulation (see
    above), added as an explicit entry point.
11. **`EMULATION_CONFIRMED_INDIRECT_TARGETS`** -- every indirect call/jmp
    target actually observed during a real `dos_emu.py` run, fed back
    into the graph as proven entry points. This is how the general
    `call word ptr [si]` case (point 4) got all of its real targets when
    static initializer search alone could only find some of them.

## Known open issues / where to continue

- **One known discrepancy between emulation and real DOSBox-X**: the
  emulator's indirect-call log shows `0xea9f -> 0xebce` firing at least
  once, but a live breakpoint on that exact call in a real DOSBox-X
  session never triggered during actual interactive use of the program.
  Most likely something resets the guard flag `[0x45df]` after our
  startup patch and the shim doesn't replicate it. This one pair is
  deliberately left out of `EMULATION_CONFIRMED_INDIRECT_TARGETS` until
  understood -- see the comment there.
- **`dos_emu.py`'s DOS shim is still rough.** `AH=0Ah`/`0Ch` keyboard
  input is answered from a fixed, arbitrary script
  (`DEFAULT_INPUT_SCRIPT`), not informed by the actual calculation
  domain -- the emulator currently runs into the program's own
  "Illegal function call" runtime-error trap because of this, not
  because of a shim bug. Smarter scripted input (or real interactive
  stepping) would let it go much further and resolve more indirect
  targets automatically.
- **~120 `IF` conditions are still reconstructed as opaque**
  (`condition not recognised`) in `full_pseudocode.py.txt`. The dominant
  unhandled pattern is a float comparison done through `int 0x3d`
  (immediately followed by `lcall 0xf63,0x423`, the auto-detected
  `FLOAT_COMPARE_HELPER`) where `int 0x3d` itself isn't one of the
  decoded `ESC`-via-`INT 34h-3Bh` opcodes (only `0x34-0x3B` are handled
  in `decoder.py`), so `pseudocode.py`'s `reconstruct_conditions` doesn't
  treat it specially. A second, smaller contributor is the `and X, X`
  zero-test idiom (same ZF-based semantics as the already-handled
  `test X, X` / `or X, X`), which `parse_cmp_operands` doesn't recognise
  yet. Both are concrete, scoped fixes for whoever picks this up next.
- **One function out of 319 fails to structure**
  (`RecursionError` in `structuring.py`, caught and reported gracefully,
  doesn't break the rest of the run) -- root cause is a backward jump
  that lands before the start of the address range
  `run_full_pseudocode.py`'s naive `call_targets`-based function
  partitioning assigned to that function. A proper function-boundary
  algorithm (rather than splitting purely by address ranges between
  known call targets) would fix this.
- **No semantic naming yet.** Variables are `V_xxxx` (raw hex DS
  offsets), functions are `sub_0xNNNN`. Cross-referencing nearby `PRINT`
  labels could give many of them meaningful names.
- **No domain validation.** The pseudocode's structure (what gets
  computed, in what order, under what conditions) has been verified
  against the binary's real behavior, but nobody has checked whether the
  reconstructed formulas match the actual mechanical-engineering
  equations for bevel-gear design. That's a separate, domain-expert task.
