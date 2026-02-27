# osdsys-unpack

Extracts and decompresses modules (e.g. OSDSYS) from PlayStation 2 BIOS dumps into standalone ELF files suitable for analysis in tools like Ghidra or IDA.

## Disclaimer

This code was generated with the assistance of agentic coding. Review before use.

## Compatibility

Tested on **SCPH-70004** BIOS (version `0200EC20040614`, OSDSYS version 1.40).

Might fail on different other BIOSes.

## Background

PS2 BIOS dumps contain a ROM filesystem (ROMDIR) with multiple modules stored as compressed ELF payloads. The compression uses a custom LZ-based scheme. This tool parses the ROMDIR structure, extracts a named module, decompresses its code, and rebuilds a clean ELF that can be loaded into a disassembler at the correct base address.

## Usage

```
# List all modules
python3 osdsys-unpack.py SCPH-70004.rom0

# Extract and decompress OSDSYS
python3 osdsys-unpack.py SCPH-70004.rom0 OSDSYS
```

Output files are written to a `<bios_name>_unpacked/` directory. ELF modules get a `.elf` extension automatically.


## Requirements

Python 3.6+ (no external dependencies).

## References

- [OSDSYS unpacker by uyjulian](https://gist.github.com/uyjulian/14388e84b008a6433aa805f5d0436c87)

## License

MIT
