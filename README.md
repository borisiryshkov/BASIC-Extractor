# CFG-based disassembler for BASIC DOS programs

## Status: working engine, but we haven't yet reached the main program logic

## Files
- `decoder.py` — decodes a SINGLE instruction (x86 16-bit via capstone + a custom FPU ESC decoder for `INT` instructions `0x34`–`0x3B`). Understands: near/far call, near/far jmp, jcc, ret/retf, and explicitly marks INDIRECT jumps (`is_indirect`) instead of silently falling into data.
- `cfg_builder.py` — builds the control flow graph via a worklist (recursive descent): follows only paths where execution actually leads, never disassembles unvisited bytes.
- `test_cfg.py` — test run.

## How to run
```
pip install capstone --break-system-packages
python3 test_cfg.py
```

## What has already been fixed and confirmed working
1. **Formula for converting `segment:offset → file address`** for `lcall`/`ljmp`:
   `file_addr = header_bytes + seg*16 + off` (WITHOUT subtracting `0x1000`! That was my mistake — `0x1000` was only added in Ghidra for convenience when labeling, but in the actual program bytes the segment is already relative to 0).
2. **Far jumps `ljmp SEG:OFF`** — previously they were not recognized at all (only `jmp near`), causing the engine to fall into garbage immediately after.
3. **Indirect call/jmp/lcall/ljmp** (via register or memory) — now explicitly recorded in `cfg.indirect_transfers`; the engine HONESTLY stops on them instead of guessing and falling into data.
4. Non-standard call targets (first instruction is `pop`, using their own return address as data — see the history of the "inline text trampoline") — are not considered returning; the return point is not added to the queue.

## Where we left off (next step)
The program entry point (`entry()`, file address `0x11c18`) successfully disassembles, goes through several `lcall`s into the BASIC runtime library (initialization), reaches `ljmp 0xf63:0x310` (this is already a found and understood function for command-line/environment initialization), and ultimately runs into **10 indirect transfers** that we cannot resolve statically:

```
0x11dcb: call word ptr [0x44d6]
0x11e1e: lcall [0x44de]
0x11e50: lcall [di]
0xe728:  ljmp [0x4144]
0xea60:  jmp cx
0xea9f:  call word ptr [0x422a]
0xeb36:  call cx
0x11ee7: lcall [0x44de]
0xe88b:  call word ptr [si]
0x11d03: lcall ss:[0x44de]
```

**Hypothesis (not fully verified yet):** judging by the code around `call word ptr [0x44d6]`, there is a check of the "magic" signature `0xD6D6` at `word ptr [0x44d0]` — it appears that the vector `[0x44d6]`/`[0x422a]`/`[0x44de]` is filled by the runtime either through a non-standard "homebrew" calling mechanism (in the very first decompilation of `entry()` via Ghidra, we saw manual memory writes like `*(puVar6-2) = 0x1f63; *(puVar6-4) = 0xf786;` before calling functions — resembling manually constructing a return address rather than a normal `call`), or it is a pointer to the actual "start point" of the compiled BASIC program (segment "1000"), which is set somewhere during initialization and which we have not yet found a direct constant write for.

**Where to go from here:**
1. Find WHERE and WITH WHAT the memory cells `0x44d6`, `0x422a`, and `0x44de` are filled — search not only for `mov word ptr [addr], imm` (we already checked, didn't find any), but also for writes via registers (`mov [addr], ax` after AX is computed) and via `stosw` / initialization chains right inside `entry()` (there were suspicious manual "pokes" (writes) into `puVar6`, see above — it is quite possible that these are precisely what set up those vectors).
2. Check whether the transition to segment "1000" is organized via stack manipulation before a `retf` (placing a "foreign" return address instead of the real one) — a classic DOS trick, characteristic of loaders/TSRs.
3. As soon as one of these vectors is resolved (at least for one specific case, manually) — add this as explicit, documented knowledge in `decoder.py`/`cfg_builder.py` (similar to what was done for the "inline text trampoline"), NOT as a heuristic, but as a confirmed fact.

## Overall architectural idea (already implemented, important not to lose it)
The old approach (`disasm_range(start, end)`) read bytes LINEARLY between two addresses, which constantly caused it to fall into data, the FPU emulator, inline strings, etc. — we had to hack together a bunch of separate patches for each specific case. The new approach goes ONLY where execution actually leads (`call`/`jmp`/`jcc`/fallthrough), and NEVER disassembles unvisited bytes — this should close all classes of errors discovered in this session all at once, rather than one by one.
