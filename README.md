# README.md – basic_extractor.py

## About this project

This tool was developed **entirely with the assistance of AI** – specifically **Claude Sonnet 5** and **DeepSeek** in **Expert mode**. The author (me) has a basic understanding of what the program does, but the code is a product of iterative prompting and debugging with the help of these AI models.

**External contributions are highly welcome!** If you are a human reverse‑engineer with experience in DOS executables, x86 assembly, or decompilation, your expertise can greatly improve this tool. Please feel free to submit issues, pull requests, or suggestions.

---

## Overview

`basic_extractor.py` is a static analysis tool for 16‑bit DOS MZ executables, specifically designed to reverse‑engineer programs compiled from Microsoft QuickBASIC (QBASIC) and similar languages. It disassembles the code, identifies string literals, floating‑point constants, input/output routines, and reconstructs high‑level control flow (if/while) into readable Python‑style pseudocode.

The tool is not limited to QBASIC – it can process any 16‑bit real‑mode DOS executable that uses the standard MZ header, x86 instructions, and typical runtime library patterns (e.g., `lcall` to print strings, read input, or perform floating‑point comparisons). However, it has been tuned and tested primarily on QBASIC‑generated executables, and may require adjustments for other compilers.

> **Important**  
> If the target executable is compressed or packed (e.g., with PKLITE, UPX, or other packers), you **must** unpack it first using a tool like `UNP.EXE` or a dedicated unpacker. The analysis expects raw, uncompressed code and data sections.

---

## Features

- **MZ header parsing** – reads the DOS executable header to locate the code segment.
- **Automatic string segment detection** – finds the segment containing packed Pascal‑style strings (length‑byte + text) and extracts them.
- **16‑bit x86 disassembly** – uses Capstone to decode real‑mode instructions, with special handling for x87 FPU instructions that are encoded via `int` opcodes (common in QBASIC).
- **Detection of runtime call targets** – automatically identifies the addresses of:
  - `PRINT` (text output)
  - `INPUT` (keyboard input)
  - `STRCMP` (string comparison helpers)
  - Floating‑point comparison helpers
- **Condition reconstruction** – translates `cmp`/`test` + conditional jumps into logical expressions (`==`, `!=`, `<`, `>`, etc.) and tracks the FPU stack to infer float comparisons.
- **Subroutine extraction** – follows near `call` instructions and recursively disassembles subroutines (up to a reasonable depth), producing separate functions in the output.
- **Constant propagation** – identifies variables that are never assigned and reads their initial values from the data segment (both 16‑bit integers and 32‑bit floats).
- **Index‑based dispatch specialisation** – detects subroutines that use an index (e.g., a menu choice) to access arrays and generates specialised versions for each known constant index.
- **Structured pseudocode** – converts linear assembly listings into `if`/`elif`/`else` ladders and `while` loops, with labels for jumps, to make the logic human‑readable.
- **Multiple output files** – produces:
  - `*_strings.txt` – list of all detected string literals.
  - `*_pseudocode.txt` – raw pseudocode with address labels.
  - `*_structured.py` – Python‑like structured code with functions for each subroutine.

---

## Requirements

- **Python 3.6+**
- **Capstone** disassembly framework:  
  `pip install capstone`
- The target executable must be **unpacked** (no compression/packing).

---

## Usage

```bash
python basic_extractor.py <exe_file> [--out PREFIX] [--max-scan N] \
    [--print-num-seg SEG] [--print-num-off OFF] \
    [--input-seg SEG] [--input-off OFF]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `exe` | Path to the 16‑bit MZ executable. |
| `--out PREFIX` | Prefix for output files (default: `extracted`). |
| `--max-scan N` | Maximum number of bytes to scan from the code start (hex or decimal). Useful for testing on partial files. |
| `--print-num-seg SEG` | Manually specify the segment of the print‑number routine (hex). |
| `--print-num-off OFF` | Manually specify the offset of the print‑number routine (hex). |
| `--input-seg SEG` | Manually specify the segment of the input‑read routine (hex). |
| `--input-off OFF` | Manually specify the offset of the input‑read routine (hex). |

If you do not supply manual targets for `INPUT` or `PRINT_NUM`, the tool will try to auto‑detect them using heuristics (string pointers and register usage). For best results, you may need to provide the correct segment:offset pairs, which you can find by running the program in a debugger or by examining the disassembly.

---

## Example

```bash
python basic_extractor.py MYPROG.EXE --out myprog_analysis
```

This will generate:
- `myprog_analysis_strings.txt`
- `myprog_analysis_pseudocode.txt`
- `myprog_analysis_structured.py`

---

## Output Files

### `*_strings.txt`
Each line contains the file‑offset (relative to the string segment) and the extracted text:

```
0x0012: Enter your name:
0x0020: Hello, 
```

### `*_pseudocode.txt`
A linear listing of statements with CODE segment offsets, e.g.:

```
CODE:0000: PRINT "Welcome"
CODE:0005: INPUT -> V_0100
CODE:0008: IF (V_0100 == 3) GOTO 0x0012
CODE:000a: jmp 0x0012 (raw 0x0012)
CODE:000c: ; jump target label
CODE:0012: RETURN
```

### `*_structured.py`
A Python‑like script with indented blocks, functions for each subroutine, and comments for unresolved jumps:

```python
# ----- CONSTANTS -----
; V_0100 = 3.14
; ---------------------
# ----- VARIABLES -----
; V_0200 = 0 (initial)
; ---------------------
CODE:0000: PRINT "Welcome"
CODE:0005: INPUT -> V_0100
if V_0100 == 3:
    # ...
while True:
    # loop body
    if condition:
        break
```

---

## How It Works (Briefly)

1. **MZ parsing** – locates the start of the code segment.
2. **String detection** – scans the code for pointers to packed strings and builds a dictionary of string offsets.
3. **Disassembly** – iterates over the code, decoding x86 instructions and handling special FPU sequences.
4. **Call target detection** – uses heuristics (push‑immediate + `lcall`, `mov bx`, etc.) to identify print/input routines.
5. **Condition reconstruction** – analyses `cmp`/`test` and following conditional jumps; simulates the FPU stack to interpret float comparisons.
6. **Subroutine extraction** – recursively finds near `call` instructions, disassembles the targets, and stores them as separate blocks.
7. **Constant and variable extraction** – reads unassigned memory locations from the data segment and treats them as constants; lists assigned variables.
8. **Specialisation** – for subroutines that use a computed index to read from an array, it creates specialised copies for each known constant index value.
9. **Pseudocode generation** – emits high‑level statements (`PRINT`, `INPUT`, `FORMULA`, `IF`, `jmp`, `RETURN`).
10. **Structuring** – converts the linear flow into `if`/`else` and `while` loops by analysing jump targets and detecting loops.

---

## Limitations & Caveats

- The tool assumes that the code segment starts immediately after the MZ header (i.e., no overlay or relocation). This holds for typical QBASIC executables.
- It expects the runtime library patterns used by QBASIC (e.g., `int 0x34`‑`0x3b` for FPU, `lcall` for print/input). For other compilers, auto‑detection may fail, and you will need to provide manual segment:offset pairs.
- The disassembly stops at `ret` instructions when extracting subroutines; any code that does not end with a clear `ret` may be truncated.
- Indirect jumps (`jmp [bx]`, `call [si]`, etc.) are **not** followed; the tool relies on direct near calls and `lcall` with immediate operands.
- Floating‑point operations are partially supported (common ones like `FADD`, `FMUL`, `FST`, etc.), but advanced FPU instructions may be misinterpreted or ignored.
- The tool does **not** handle self‑modifying code or obfuscated binaries.
- It is not a full decompiler – it produces a human‑readable approximation, not a compilable program.

---

## Contributing

We welcome contributions from the reverse‑engineering community! If you encounter bugs, have suggestions, or want to add support for additional runtime libraries, please:

- Fork the repository.
- Create a feature branch.
- Submit a pull request with a clear description of your changes.

Areas that would benefit from community effort:

- Improving detection of print/input routines for other compilers (Borland, Microsoft C, etc.).
- Adding support for far calls and indirect jumps.
- Enhancing FPU simulation to cover more instructions.
- Improving loop detection and structuring (e.g., `do‑while`, `for` loops).
- Integrating with IDA/Ghidra export formats.

---

## License

This project is provided under the MIT License – feel free to use, modify, and distribute it, but please retain the original copyright notice.

---

## Acknowledgments

- [Capstone](https://www.capstone-engine.org/) – for the disassembly engine.
- The DOS reverse‑engineering community for their invaluable documentation on QBASIC internals.
- **Claude Sonnet 5** and **DeepSeek** (Expert mode) – for assisting in the development of this tool.

---

**Happy reversing!**