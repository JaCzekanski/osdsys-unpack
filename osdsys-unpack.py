#!/usr/bin/env python3
import argparse
import struct
import sys
import os

from find_osdsys_symbols import match_symbols

ROMDIR_ENTRY = struct.Struct("<10sHI")  # name[10], ext_info_size, file_size
ELF_HDR = struct.Struct("<4s12sHHIIIIIHHHHHH")
PHDR = struct.Struct("<IIIIIIII")
PT_LOAD = 1
PF_RWX = 7

def find_romdir(bios):
    needle = b"RESET\x00\x00\x00\x00\x00"
    pos = 0
    while pos < len(bios):
        pos = bios.find(needle, pos)
        if pos == -1:
            return None
        if pos % 16 == 0:
            return pos
        pos += 1
    return None

def parse_romdir(bios):
    romdir_pos = find_romdir(bios)
    if romdir_pos is None:
        raise Exception("ROMDIR not found in BIOS dump")
    entries = []
    data_offset = 0
    pos = romdir_pos
    while pos + ROMDIR_ENTRY.size <= len(bios):
        name_raw, ext_info_size, file_size = ROMDIR_ENTRY.unpack_from(bios, pos)
        name = name_raw.split(b"\x00", 1)[0].decode("ascii")
        if not name:
            break
        entries.append({"name": name, "offset": data_offset, "size": file_size})
        data_offset += (file_size + 15) & ~15
        pos += ROMDIR_ENTRY.size
    return entries

def extract_module(bios, name):
    entries = parse_romdir(bios)
    for e in entries:
        if e["name"] == name:
            return bios[e["offset"]:e["offset"] + e["size"]]
    names = [e["name"] for e in entries]
    print(f"Module '{name}' not found. Available: {names}")
    sys.exit(1)

def decompress(src):
    length = int.from_bytes(src[0:4], byteorder="little")
    dst = bytearray(length)
    si, di, run = 4, 0, 0
    desc = mask = shift = 0

    def rd(buf, o):
        return buf[o] if 0 <= o < len(buf) else 0

    while di <= length:
        if run == 0:
            run = 30
            desc = 0
            for _ in range(4):
                desc = (desc << 8) | rd(src, si)
                si += 1
            n = desc & 3
            shift = 14 - n
            mask = 0x3FFF >> n
        if (desc & (1 << (run + 1))) == 0:
            if di < length:
                dst[di] = rd(src, si)
            di += 1
            si += 1
        else:
            h = rd(src, si) << 8
            si += 1
            h |= rd(src, si)
            si += 1
            co = di - ((h & mask) + 1)
            for _ in range(2 + (h >> shift) + 1):
                if di < length:
                    dst[di] = rd(dst, co)
                di += 1
                co += 1
        run -= 1
    return bytes(dst)

def parse_elf(data):
    magic, ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, \
        e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
        ELF_HDR.unpack_from(data)
    assert magic == b"\x7fELF", "Not an ELF file"
    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        phdrs.append(PHDR.unpack_from(data, off))
    return {
        "ident": ident, "type": e_type, "machine": e_machine,
        "version": e_version, "entry": e_entry, "flags": e_flags,
        "ehsize": e_ehsize, "phentsize": e_phentsize, "shentsize": e_shentsize,
    }, phdrs, data

SHDR = struct.Struct("<IIIIIIIIII")  # 40 bytes
SYMTAB_ENTRY = struct.Struct("<IIIBBH")  # 16 bytes

# ELF symbol type/binding helpers
STB_GLOBAL = 1
STT_FUNC = 2
STT_OBJECT = 1
STT_NOTYPE = 0
SHT_NULL = 0
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHF_ALLOC = 2

def build_elf(hdr, segments, symbols=None):
    """segments: list of (vaddr, bytes) tuples
    symbols: optional list of (name, addr, type, size) tuples"""
    phoff = ELF_HDR.size
    data_start = (phoff + PHDR.size * len(segments) + 0xF) & ~0xF

    seg_offsets = []
    off = data_start
    for _, d in segments:
        seg_offsets.append(off)
        off += (len(d) + 0xF) & ~0xF

    # Build segment data first
    out = bytearray()
    # Placeholder ELF header - will be patched later if we have symbols
    out += ELF_HDR.pack(
        b"\x7fELF", hdr["ident"], hdr["type"], hdr["machine"],
        hdr["version"], hdr["entry"], phoff, 0,
        hdr["flags"], hdr["ehsize"], PHDR.size, len(segments),
        0, 0, 0)

    for i, (vaddr, d) in enumerate(segments):
        out += PHDR.pack(PT_LOAD, seg_offsets[i], vaddr, vaddr,
                         len(d), len(d), PF_RWX, 0x10)

    out += b"\x00" * (data_start - len(out))

    for _, d in segments:
        out += d
        pad = ((len(d) + 0xF) & ~0xF) - len(d)
        out += b"\x00" * pad

    if symbols:
        # Determine which section index each symbol belongs to
        seg_ranges = []
        for i, (vaddr, d) in enumerate(segments):
            seg_ranges.append((vaddr, vaddr + len(d)))

        def find_shndx(addr):
            for i, (lo, hi) in enumerate(seg_ranges):
                if lo <= addr < hi:
                    return i + 1  # section 0 is SHT_NULL
            return 0  # SHN_UNDEF

        # Build .strtab
        strtab = bytearray(b"\x00")  # index 0 = empty string
        sym_name_offsets = []
        for name, addr, stype, size in symbols:
            sym_name_offsets.append(len(strtab))
            strtab += name.encode("ascii") + b"\x00"

        # Build .symtab
        symtab = bytearray()
        # Entry 0: STN_UNDEF (null symbol)
        symtab += SYMTAB_ENTRY.pack(0, 0, 0, 0, 0, 0)
        for i, (name, addr, stype, size) in enumerate(symbols):
            if stype == "func":
                st_type = STT_FUNC
            elif stype in ("data", "asciz", "s32", "u32", "s16", "u16", "s8", "u8"):
                st_type = STT_OBJECT
            else:
                st_type = STT_NOTYPE
            st_info = (STB_GLOBAL << 4) | st_type
            shndx = find_shndx(addr)
            symtab += SYMTAB_ENTRY.pack(sym_name_offsets[i], addr, size, st_info, 0, shndx)

        # Build .shstrtab
        shstrtab = bytearray(b"\x00")
        shstrtab_name = len(shstrtab); shstrtab += b".shstrtab\x00"
        strtab_name = len(shstrtab); shstrtab += b".strtab\x00"
        symtab_name = len(shstrtab); shstrtab += b".symtab\x00"

        # Align and append section data
        pad = ((len(out) + 3) & ~3) - len(out)
        out += b"\x00" * pad

        strtab_off = len(out)
        out += strtab

        pad = ((len(out) + 3) & ~3) - len(out)
        out += b"\x00" * pad

        symtab_off = len(out)
        out += symtab

        pad = ((len(out) + 3) & ~3) - len(out)
        out += b"\x00" * pad

        shstrtab_off = len(out)
        out += shstrtab

        # Align section header table to 4 bytes
        pad = ((len(out) + 3) & ~3) - len(out)
        out += b"\x00" * pad

        shoff = len(out)
        # Section headers: [0]=NULL, [1]=.strtab, [2]=.symtab, [3]=.shstrtab
        # SHT_NULL
        out += SHDR.pack(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)
        # .strtab
        out += SHDR.pack(strtab_name, SHT_STRTAB, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0)
        # .symtab (sh_link=1 -> .strtab, sh_info=1 -> first global symbol index)
        out += SHDR.pack(symtab_name, SHT_SYMTAB, 0, 0, symtab_off, len(symtab),
                         1, 1, 4, SYMTAB_ENTRY.size)
        # .shstrtab
        out += SHDR.pack(shstrtab_name, SHT_STRTAB, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1, 0)

        e_shnum = 4
        e_shstrndx = 3

        # Patch ELF header with section header info
        struct.pack_into("<I", out, 32, shoff)       # e_shoff
        struct.pack_into("<H", out, 46, SHDR.size)   # e_shentsize
        struct.pack_into("<H", out, 48, e_shnum)     # e_shnum
        struct.pack_into("<H", out, 50, e_shstrndx)  # e_shstrndx

    return bytes(out)

def unpack_osdsys(module):
    hdr, phdrs, raw = parse_elf(module)

    packed = module[0xE00:]
    decompressed = decompress(packed)
    print(f"Decompressed: {len(decompressed)} bytes")

    VADDR = 0x200000
    segments = [((VADDR, decompressed))]
    hdr["entry"] = VADDR

    print("Matching symbols...")
    symbols = match_symbols(VADDR, decompressed)
    print(f"Matched {len(symbols)} symbols")

    return build_elf(hdr, segments, symbols)

def main():
    parser = argparse.ArgumentParser(description="Extract modules from PS2 BIOS dumps")
    parser.add_argument("bios", help="Path to BIOS dump file")
    parser.add_argument("module", nargs="?", help="Module name to extract (lists modules if omitted)")

    args = parser.parse_args()

    with open(args.bios, "rb") as f:
        bios = f.read()

    entries = parse_romdir(bios)

    if args.module is None:
        for e in entries:
            if e["name"] == "ROMVER":
                romver = bios[e["offset"]:e["offset"] + e["size"]].split(b"\x00", 1)[0].decode("ascii")
                print(f"BIOS version: {romver}")
                break
        for e in entries:
            print(f"  {e['name']:10s}  offset=0x{e['offset']:08X}  size=0x{e['size']:X}")
        return

    module_name = args.module
    bios_filename = os.path.splitext(os.path.basename(args.bios))[0]
    output_path = f"{bios_filename}_unpacked/{module_name}"

    module = extract_module(bios, module_name)
    print(f"Extracted {module_name}: {len(module)} bytes")

    if module[:4] == b"\x7fELF":
        output_path += ".elf"

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if module_name == "OSDSYS":
        print("Unpacking OSDSYS module...")
        module = unpack_osdsys(module)

    with open(output_path, "wb") as f:
        f.write(module)
    print(f"\nWritten {output_path} ({len(module)} bytes)")

if __name__ == "__main__":
    main()
