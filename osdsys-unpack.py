#!/usr/bin/env python3
import argparse
import struct
import sys
import os

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

def build_elf(hdr, segments):
    """segments: list of (vaddr, bytes) tuples"""
    phoff = ELF_HDR.size
    data_start = (phoff + PHDR.size * len(segments) + 0xF) & ~0xF

    seg_offsets = []
    off = data_start
    for _, d in segments:
        seg_offsets.append(off)
        off += (len(d) + 0xF) & ~0xF

    out = bytearray()
    out += ELF_HDR.pack(
        b"\x7fELF", hdr["ident"], hdr["type"], hdr["machine"],
        hdr["version"], hdr["entry"], phoff, 0,
        hdr["flags"], hdr["ehsize"], PHDR.size, len(segments),
        hdr["shentsize"], 0, 0)

    for i, (vaddr, d) in enumerate(segments):
        out += PHDR.pack(PT_LOAD, seg_offsets[i], vaddr, vaddr,
                         len(d), len(d), PF_RWX, 0x10)

    out += b"\x00" * (data_start - len(out))

    for _, d in segments:
        out += d
        pad = ((len(d) + 0xF) & ~0xF) - len(d)
        out += b"\x00" * pad

    return bytes(out)

def unpack_osdsys(module):
    hdr, phdrs, raw = parse_elf(module)

    packed = module[0xE00:]
    decompressed = decompress(packed)
    print(f"Decompressed: {len(decompressed)} bytes")

    VADDR = 0x200000
    segments = [((VADDR, decompressed))]
    hdr["entry"] = VADDR

    return build_elf(hdr, segments)

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
    print(f"Written {output_path} ({len(module)} bytes)")

if __name__ == "__main__":
    main()
