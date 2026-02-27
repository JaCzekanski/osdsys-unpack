# osdsys-unpack

Extracts and decompresses modules (e.g. OSDSYS) from PlayStation 2 BIOS dumps into standalone ELF files suitable for analysis in tools like Ghidra or IDA.

## Disclaimer

This code was generated with the assistance of agentic coding. Review before use.

## Compatibility

Tested on **SCPH-70004** BIOS (version `0200EC20040614`, OSDSYS version 1.40).

Might fail on different other BIOSes.

## Background

PS2 BIOS dumps contain a ROM filesystem (ROMDIR) with multiple modules stored as compressed ELF payloads. The compression uses a custom LZ-based scheme. This tool parses the ROMDIR structure, extracts a named module, decompresses its code, and rebuilds a clean ELF that can be loaded into a disassembler at the correct base address.

For OSDSYS, the tool automatically matches symbols from the known HDD OSDSYS (thanks to @uyjulian
 and [osdsys_re projoect](github.com/ps2re/osdsys_re)) to the BIOS version using a multi-stage approach: masked instruction matching, call graph propagation, string reference matching, constant fingerprinting, call sequence analysis, and fuzzy matching. Matched symbols are embedded as `.symtab`/`.strtab` sections in the output ELF, making them directly visible in Ghidra and PCSX2.

## Usage

```
# List all modules
python3 osdsys-unpack.py SCPH-70004.rom0

# Extract and decompress OSDSYS
$ python3 osdsys-unpack.py SCPH-70004.rom0 OSDSYS
Extracted OSDSYS: 362760 bytes
Unpacking OSDSYS module...
Decompressed: 823156 bytes
Matching symbols...
  1675 functions, 4215 strings, 395 data symbols
  HDD OSDSYS base: 0x00200000, Size: 0x3ae819

[Stage 1] Masked instruction matching...
  Matched: 504, Not found: 980, Ambiguous: 63, Skipped: 128

[Stage 2] String content matching...
  Matched: 1098, Not found: 2190, Ambiguous: 923

[Stage 3] Call graph propagation...
  Stage 3 iteration 1: +94 functions
  Stage 3 iteration 2: +25 functions
  Stage 3 iteration 3: +1 functions
  Total: +120 functions

[Stage 4] Resolving ambiguous matches (63 candidates)...
  Resolved: 10

[Stage 5] String reference matching...
  Matched: 21
  Stage 5b iteration 1: +5 functions
  Stage 5b iteration 2: +3 functions
  Additional from propagation: +8

[Stage 6] Non-address constant fingerprinting...
  Matched: 26
  Stage 6b iteration 1: +3 functions
  Stage 6b iteration 2: +1 functions
  Additional from propagation: +4

[Stage 7] Call sequence + stack frame matching...
  Matched: 16
  Stage 7b iteration 1: +11 functions
  Stage 7b iteration 2: +2 functions
  Additional from propagation: +13

[Stage 8] Fuzzy matching...
  Matched: 40
  Stage 8b iteration 1: +6 functions
  Additional from propagation: +6

[Stage 9] Data symbol matching via XREF correlation...
  Data: 97, Strings via XREF: 12, Ambiguous: 4

============================================================
  Stage 1 (mask match):        504
  Stage 3 (call propagation):  120
  Stage 4 (disambiguate):      10 (+0 propagated)
  Stage 5 (string refs):       21 (+8 propagated)
  Stage 6 (const fingerprint): 26 (+4 propagated)
  Stage 7 (call sequence):     16 (+13 propagated)
  Stage 8 (fuzzy match):       40 (+6 propagated)
  Stage 9 (data XREF):         97 data, 12 strings
  ───────────────────────────────────
  TOTAL FUNCTIONS: 768
  TOTAL STRINGS:   1110
  TOTAL DATA:      97
  TOTAL SYMBOLS:   1975
============================================================
Matched 1975 symbols

Written SCPH-70004_unpacked/OSDSYS.elf (881632 bytes)
```

Output files are written to a `<bios_name>_unpacked/` directory. ELF modules get a `.elf` extension automatically.


## Requirements

Python 3.6+ (no external dependencies).

## Standalone symbol matching

`find_osdsys_symbols.py` can also be used independently on any BIOS OSDSYS ELF (e.g. one extracted by other means):

```
python3 find_osdsys_symbols.py <bios_osdsys.elf>
```

This writes `bios_symbol_addrs.txt` (matched symbols) and `bios_unmatched_symbols.txt` (unmatched symbols) to the current directory. Required reference files (`hddosd.elf`, `symbol_addrs.txt`) are downloaded automatically on first run.

## References

- [OSDSYS unpacker by uyjulian](https://gist.github.com/uyjulian/14388e84b008a6433aa805f5d0436c87)
- [osdsys_re — OSDSYS reverse engineering project by uyjulian](https://github.com/ps2re/osdsys_re)

## License

MIT
