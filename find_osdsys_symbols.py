#!/usr/bin/env python3
import struct
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.request import urlretrieve

SYMBOL_URL = "https://raw.githubusercontent.com/ps2re/osdsys_re/refs/heads/main/symbol_addrs.txt"
HDDOSD_URL = "https://archive.org/download/hddosd-sudc4-decrypted/OSDSYS_A_unpacked_110u.XLF"
SYMBOL_FILE = Path("symbol_addrs.txt")
ELF_FILE = Path("hddosd.elf")

OP_J = 0x02
OP_JAL = 0x03
OP_BEQ = 0x04
OP_BNE = 0x05
OP_BLEZ = 0x06
OP_BGTZ = 0x07
OP_ADDIU = 0x09
OP_SLTI = 0x0A
OP_SLTIU = 0x0B
OP_ANDI = 0x0C
OP_ORI = 0x0D
OP_XORI = 0x0E
OP_LUI = 0x0F
OP_REGIMM = 0x01

REG_GP = 28
REG_SP = 29

LOAD_STORE_OPS = {
    0x20, 0x21, 0x23, 0x24, 0x25, 0x27, 0x37,
    0x28, 0x29, 0x2B, 0x3F,
    0x22, 0x26, 0x2A, 0x2E,
    0x31, 0x39, 0x35, 0x3D,
    0x1E, 0x1F,
}

BRANCH_OPS = {OP_BEQ, OP_BNE, OP_BLEZ, OP_BGTZ, OP_REGIMM}


def download(url, path):
    if path.exists():
        return
    print(f"Downloading {path}...")
    urlretrieve(url, path)


def parse_symbol_addrs(path):
    funcs, strings, data_syms = [], [], []
    typed_re = re.compile(r"(\w+)\s*=\s*0x([0-9a-fA-F]+)\s*;\s*//\s*size:0x([0-9a-fA-F]+)\s+type:(\w+)")
    plain_re = re.compile(r"(\w+)\s*=\s*0x([0-9a-fA-F]+)\s*;")
    with open(path) as f:
        for line in f:
            line = line.strip()
            m = typed_re.match(line)
            if m:
                sym = {"name": m.group(1), "addr": int(m.group(2), 16),
                       "size": int(m.group(3), 16), "type": m.group(4)}
                if sym["type"] == "func":
                    funcs.append(sym)
                elif sym["type"] == "asciz":
                    strings.append(sym)
                else:
                    data_syms.append(sym)
                continue
            m = plain_re.match(line)
            if m:
                data_syms.append({"name": m.group(1), "addr": int(m.group(2), 16), "size": 0, "type": "data"})
    return funcs, strings, data_syms


def load_elf_code(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == b"\x7fELF"
    e_phoff = struct.unpack_from("<I", data, 28)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, _, p_filesz, *_ = struct.unpack_from("<IIIIIIII", data, off)
        if p_type == 1:
            return p_vaddr, data[p_offset:p_offset + p_filesz]
    raise ValueError(f"No LOAD segment in {path}")


def get_opcode(insn): return (insn >> 26) & 0x3F
def get_rs(insn): return (insn >> 21) & 0x1F
def get_rt(insn): return (insn >> 16) & 0x1F
def get_rd(insn): return (insn >> 11) & 0x1F
def sign_extend_16(val): return val - 0x10000 if val & 0x8000 else val


def is_gp_relative(insn):
    op = get_opcode(insn)
    if op in LOAD_STORE_OPS and get_rs(insn) == REG_GP:
        return True
    if op == OP_ADDIU and get_rs(insn) == REG_GP:
        return True
    return False


def create_mask(code):
    n_insns = len(code) // 4
    insns = list(struct.unpack(f"<{n_insns}I", code))
    masked, masks = [], []
    lui_regs = {}
    for i, insn in enumerate(insns):
        op = get_opcode(insn)
        if op in (OP_J, OP_JAL):
            masked.append(insn & 0xFC000000)
            masks.append(0xFC000000)
        elif op == OP_LUI:
            lui_regs[get_rt(insn)] = i
            masked.append(insn & 0xFFFF0000)
            masks.append(0xFFFF0000)
        elif is_gp_relative(insn):
            masked.append(insn & 0xFFFF0000)
            masks.append(0xFFFF0000)
        elif op in (OP_ADDIU, OP_ORI) and get_rs(insn) in lui_regs:
            del lui_regs[get_rs(insn)]
            masked.append(insn & 0xFFFF0000)
            masks.append(0xFFFF0000)
        elif op in LOAD_STORE_OPS and get_rs(insn) in lui_regs:
            masked.append(insn & 0xFFFF0000)
            masks.append(0xFFFF0000)
        else:
            if op == 0x00:
                lui_regs.pop(get_rd(insn), None)
            else:
                lui_regs.pop(get_rt(insn), None)
            masked.append(insn)
            masks.append(0xFFFFFFFF)
    return masked, masks


def extract_function(base_addr, data, func_addr, func_size):
    offset = func_addr - base_addr
    if offset < 0 or offset + func_size > len(data):
        return None
    return data[offset:offset + func_size]


def scan_for_match(target_insns, masked_insns, mask_bits):
    pattern_len = len(masked_insns)
    if pattern_len == 0:
        return []
    target_len = len(target_insns)
    first_full_idx = first_full_val = None
    for i, (mi, mb) in enumerate(zip(masked_insns, mask_bits)):
        if mb == 0xFFFFFFFF:
            first_full_idx, first_full_val = i, mi
            break
    matches = []
    for start in range(0, target_len - pattern_len + 1):
        if first_full_idx is not None and target_insns[start + first_full_idx] != first_full_val:
            continue
        match = True
        for j in range(pattern_len):
            if (target_insns[start + j] & mask_bits[j]) != masked_insns[j]:
                match = False
                break
        if match:
            matches.append(start * 4)
    return matches


def scan_for_fuzzy_match(target_insns, masked_insns, mask_bits, max_mismatch_ratio=0.05):
    pattern_len = len(masked_insns)
    if pattern_len == 0:
        return []
    target_len = len(target_insns)
    max_mismatches = int(pattern_len * max_mismatch_ratio)
    prefilter_checks = []
    for i, (mi, mb) in enumerate(zip(masked_insns, mask_bits)):
        if mb == 0xFFFFFFFF and mi != 0x00000000:
            prefilter_checks.append((i, mi))
            if len(prefilter_checks) >= 5:
                break
    results = []
    for start in range(0, target_len - pattern_len + 1):
        if prefilter_checks:
            if not any(target_insns[start + idx] == val for idx, val in prefilter_checks):
                continue
        mismatches = 0
        for j in range(pattern_len):
            if (target_insns[start + j] & mask_bits[j]) != masked_insns[j]:
                mismatches += 1
                if mismatches > max_mismatches:
                    break
        if mismatches <= max_mismatches:
            results.append((start * 4, mismatches))
    results.sort(key=lambda x: x[1])
    return results


def extract_address_pairs(hdd_insns, bios_insns, hdd_gp=0, bios_gp=0):
    pairs = []
    n = min(len(hdd_insns), len(bios_insns))
    hdd_lui, bios_lui = {}, {}
    for i in range(n):
        hi, bi = hdd_insns[i], bios_insns[i]
        h_op, b_op = get_opcode(hi), get_opcode(bi)
        if h_op == OP_LUI and b_op == OP_LUI and get_rt(hi) == get_rt(bi):
            rt = get_rt(hi)
            hdd_lui[rt] = (hi & 0xFFFF) << 16
            bios_lui[rt] = (bi & 0xFFFF) << 16
            continue
        if h_op == b_op and h_op in (OP_ADDIU, OP_ORI):
            h_rs, b_rs = get_rs(hi), get_rs(bi)
            if h_rs == b_rs and h_rs in hdd_lui and h_rs in bios_lui:
                if h_op == OP_ADDIU:
                    h_addr = (hdd_lui[h_rs] + sign_extend_16(hi & 0xFFFF)) & 0xFFFFFFFF
                    b_addr = (bios_lui[h_rs] + sign_extend_16(bi & 0xFFFF)) & 0xFFFFFFFF
                else:
                    h_addr = hdd_lui[h_rs] | (hi & 0xFFFF)
                    b_addr = bios_lui[h_rs] | (bi & 0xFFFF)
                pairs.append((h_addr, b_addr))
                del hdd_lui[h_rs]; del bios_lui[h_rs]
                continue
        if h_op == b_op and h_op in LOAD_STORE_OPS:
            h_rs, b_rs = get_rs(hi), get_rs(bi)
            if h_rs == b_rs and h_rs in hdd_lui and h_rs in bios_lui:
                h_addr = (hdd_lui[h_rs] + sign_extend_16(hi & 0xFFFF)) & 0xFFFFFFFF
                b_addr = (bios_lui[h_rs] + sign_extend_16(bi & 0xFFFF)) & 0xFFFFFFFF
                pairs.append((h_addr, b_addr))
                continue
        if h_op == b_op and hdd_gp and bios_gp:
            if h_op in LOAD_STORE_OPS and get_rs(hi) == REG_GP and get_rs(bi) == REG_GP:
                h_addr = (hdd_gp + sign_extend_16(hi & 0xFFFF)) & 0xFFFFFFFF
                b_addr = (bios_gp + sign_extend_16(bi & 0xFFFF)) & 0xFFFFFFFF
                pairs.append((h_addr, b_addr))
                continue
            if h_op == OP_ADDIU and get_rs(hi) == REG_GP and get_rs(bi) == REG_GP:
                h_addr = (hdd_gp + sign_extend_16(hi & 0xFFFF)) & 0xFFFFFFFF
                b_addr = (bios_gp + sign_extend_16(bi & 0xFFFF)) & 0xFFFFFFFF
                pairs.append((h_addr, b_addr))
                continue
        if h_op == 0x00: hdd_lui.pop(get_rd(hi), None)
        else: hdd_lui.pop(get_rt(hi), None)
        if b_op == 0x00: bios_lui.pop(get_rd(bi), None)
        else: bios_lui.pop(get_rt(bi), None)
    return pairs


def match_data_symbols(funcs, data_syms, strings, hdd_base, hdd_data, bios_base, bios_data,
                       matched_hdd_to_bios, hdd_gp=0, bios_gp=0):
    hdd_func_by_addr = {f["addr"]: f for f in funcs}
    addr_map = defaultdict(set)
    for hdd_addr, bios_addr in matched_hdd_to_bios.items():
        func = hdd_func_by_addr.get(hdd_addr)
        if func is None: continue
        hdd_code = extract_function(hdd_base, hdd_data, hdd_addr, func["size"])
        bios_code = extract_function(bios_base, bios_data, bios_addr, func["size"])
        if hdd_code is None or bios_code is None or len(hdd_code) != len(bios_code): continue
        n = len(hdd_code) // 4
        pairs = extract_address_pairs(
            struct.unpack(f"<{n}I", hdd_code), struct.unpack(f"<{n}I", bios_code), hdd_gp, bios_gp)
        for h, b in pairs:
            addr_map[h].add(b)
    all_data_addrs = {s["addr"]: s for s in data_syms}
    all_data_addrs.update({s["addr"]: s for s in strings})
    new_matches, ambiguous = {}, 0
    for hdd_addr, bios_addrs in addr_map.items():
        if hdd_addr not in all_data_addrs: continue
        if len(bios_addrs) == 1:
            new_matches[hdd_addr] = next(iter(bios_addrs))
        else:
            ambiguous += 1
    return new_matches, ambiguous


def extract_jal_targets(insns, func_vaddr):
    targets = []
    for insn in insns:
        if get_opcode(insn) == OP_JAL:
            targets.append((func_vaddr & 0xF0000000) | ((insn & 0x3FFFFFF) << 2))
    return targets


def extract_lui_addiu_addresses(insns):
    addresses, lui_vals = [], {}
    for insn in insns:
        op, rt, rs = get_opcode(insn), get_rt(insn), get_rs(insn)
        if op == OP_LUI:
            lui_vals[rt] = (insn & 0xFFFF) << 16
        elif op == OP_ADDIU and rs in lui_vals:
            addresses.append((lui_vals[rs] + sign_extend_16(insn & 0xFFFF)) & 0xFFFFFFFF)
            del lui_vals[rs]
        elif op == OP_ORI and rs in lui_vals:
            addresses.append(lui_vals[rs] | (insn & 0xFFFF))
            del lui_vals[rs]
        else:
            lui_vals.pop(get_rd(insn) if op == 0x00 else rt, None)
    return addresses


def get_stack_frame_size(insns):
    for insn in insns[:5]:
        if get_opcode(insn) == OP_ADDIU and get_rs(insn) == REG_SP and get_rt(insn) == REG_SP:
            imm = sign_extend_16(insn & 0xFFFF)
            if imm < 0:
                return -imm
    return None


def extract_non_address_constants(insns):
    constants, lui_regs = [], set()
    for insn in insns:
        op, rt, rs, imm = get_opcode(insn), get_rt(insn), get_rs(insn), insn & 0xFFFF
        if op == OP_LUI:
            lui_regs.add(rt)
            if 0x1000 <= imm <= 0x1FFF:
                constants.append(insn)
            continue
        if op in (OP_ADDIU, OP_ORI) and rs in lui_regs:
            lui_regs.discard(rs); continue
        if op in LOAD_STORE_OPS and rs in lui_regs: continue
        if is_gp_relative(insn): continue
        if op in (OP_J, OP_JAL): continue
        if op in BRANCH_OPS: continue
        if op in (OP_ADDIU, OP_SLTI, OP_SLTIU) and imm != 0:
            if rs == REG_SP and rt == REG_SP: continue
            constants.append(imm)
        elif op in (OP_ANDI, OP_ORI, OP_XORI) and imm != 0:
            constants.append(imm)
        if op == 0x00: lui_regs.discard(get_rd(insn))
        else: lui_regs.discard(rt)
    return constants


def propagate_via_calls(funcs, hdd_base, hdd_data, bios_base, bios_data, matched_hdd_to_bios):
    hdd_func_addrs = {f["addr"] for f in funcs}
    hdd_func_by_addr = {f["addr"]: f for f in funcs}
    proposals = {}
    for hdd_addr, bios_addr in matched_hdd_to_bios.items():
        func = hdd_func_by_addr.get(hdd_addr)
        if func is None: continue
        hdd_code = extract_function(hdd_base, hdd_data, hdd_addr, func["size"])
        bios_code = extract_function(bios_base, bios_data, bios_addr, func["size"])
        if hdd_code is None or bios_code is None: continue
        hdd_n, bios_n = len(hdd_code) // 4, len(bios_code) // 4
        if hdd_n != bios_n: continue
        hdd_insns = struct.unpack(f"<{hdd_n}I", hdd_code)
        bios_insns = struct.unpack(f"<{bios_n}I", bios_code)
        for hi, bi in zip(hdd_insns, bios_insns):
            if get_opcode(hi) == OP_JAL and get_opcode(bi) == OP_JAL:
                ht = (hdd_addr & 0xF0000000) | ((hi & 0x3FFFFFF) << 2)
                bt = (bios_addr & 0xF0000000) | ((bi & 0x3FFFFFF) << 2)
                if ht in matched_hdd_to_bios or ht not in hdd_func_addrs: continue
                proposals.setdefault(ht, set()).add(bt)
    return {k: next(iter(v)) for k, v in proposals.items() if len(v) == 1}


def resolve_ambiguous_via_callgraph(funcs, hdd_base, hdd_data, bios_base, bios_data,
                                     bios_insns, matched_hdd_to_bios, ambiguous_funcs):
    hdd_func_by_addr = {f["addr"]: f for f in funcs}
    bios_called_from_matched = defaultdict(set)
    for hdd_addr, bios_addr in matched_hdd_to_bios.items():
        func = hdd_func_by_addr.get(hdd_addr)
        if func is None: continue
        bios_code = extract_function(bios_base, bios_data, bios_addr, func["size"])
        if bios_code is None: continue
        for insn in struct.unpack(f"<{len(bios_code) // 4}I", bios_code):
            if get_opcode(insn) == OP_JAL:
                target = (bios_addr & 0xF0000000) | ((insn & 0x3FFFFFF) << 2)
                bios_called_from_matched[target].add(hdd_addr)
    all_bios_jal_targets = set()
    for insn in bios_insns:
        if get_opcode(insn) == OP_JAL:
            all_bios_jal_targets.add((bios_base & 0xF0000000) | ((insn & 0x3FFFFFF) << 2))  # noqa: E501
    new_matches = {}
    for func in ambiguous_funcs:
        hdd_code = extract_function(hdd_base, hdd_data, func["addr"], func["size"])
        if hdd_code is None: continue
        masked_insns, mask_bits = create_mask(hdd_code)
        matches = scan_for_match(bios_insns, masked_insns, mask_bits)
        if len(matches) < 2: continue
        candidates = [bios_base + m for m in matches]
        called = [c for c in candidates if c in bios_called_from_matched]
        if len(called) == 1:
            new_matches[func["addr"]] = called[0]; continue
        jal = [c for c in candidates if c in all_bios_jal_targets]
        if len(jal) == 1:
            new_matches[func["addr"]] = jal[0]; continue
        hdd_callers = set()
        for other in funcs:
            if other["addr"] not in matched_hdd_to_bios: continue
            oc = extract_function(hdd_base, hdd_data, other["addr"], other["size"])
            if oc is None: continue
            for insn in struct.unpack(f"<{len(oc) // 4}I", oc):
                if get_opcode(insn) == OP_JAL:
                    t = (other["addr"] & 0xF0000000) | ((insn & 0x3FFFFFF) << 2)
                    if t == func["addr"]:
                        hdd_callers.add(other["addr"])
        if hdd_callers:
            bios_targets = set()
            for ch in hdd_callers:
                cb = matched_hdd_to_bios[ch]
                cf = hdd_func_by_addr[ch]
                cbc = extract_function(bios_base, bios_data, cb, cf["size"])
                if cbc is None: continue
                for insn in struct.unpack(f"<{len(cbc) // 4}I", cbc):
                    if get_opcode(insn) == OP_JAL:
                        t = (cb & 0xF0000000) | ((insn & 0x3FFFFFF) << 2)
                        if t in candidates:
                            bios_targets.add(t)
            if len(bios_targets) == 1:
                new_matches[func["addr"]] = next(iter(bios_targets))
    return new_matches


def find_function_start(insns, ref_idx):
    for i in range(ref_idx, max(ref_idx - 512, -1), -1):
        insn = insns[i]
        if get_opcode(insn) == OP_ADDIU and get_rs(insn) == REG_SP and get_rt(insn) == REG_SP:
            if insn & 0xFFFF >= 0x8000:
                return i
        if i > 0 and insns[i - 1] == 0x03e00008:
            return i + 1
    return None


def match_via_string_refs(funcs, strings, hdd_base, hdd_data, bios_base, bios_data,
                          bios_insns, already_matched):
    hdd_str_to_bios = {}
    for sym in strings:
        sb = extract_function(hdd_base, hdd_data, sym["addr"], sym["size"])
        if sb is None or len(sb) < 4: continue
        ms, pos = [], 0
        while True:
            pos = bios_data.find(sb, pos)
            if pos == -1: break
            ms.append(pos); pos += 1
        if len(ms) == 1:
            hdd_str_to_bios[sym["addr"]] = bios_base + ms[0]
    lui_index = defaultdict(list)
    for idx, insn in enumerate(bios_insns):
        if get_opcode(insn) == OP_LUI:
            lui_index[insn & 0xFFFF].append(idx)
    new_matches = {}
    for func in funcs:
        if func["addr"] in already_matched: continue
        hdd_code = extract_function(hdd_base, hdd_data, func["addr"], func["size"])
        if hdd_code is None: continue
        hdd_insn_list = struct.unpack(f"<{len(hdd_code) // 4}I", hdd_code)
        loaded = extract_lui_addiu_addresses(hdd_insn_list)
        str_refs = [(a, hdd_str_to_bios[a]) for a in loaded if a in hdd_str_to_bios]
        if not str_refs: continue
        candidate_sets = []
        for _, bios_str_addr in str_refs:
            hi = (bios_str_addr >> 16) & 0xFFFF
            lo = bios_str_addr & 0xFFFF
            lui_imm = ((hi + 1) & 0xFFFF) if lo >= 0x8000 else hi
            ref_positions = set()
            for idx in lui_index.get(lui_imm, []):
                rt = get_rt(bios_insns[idx])
                for k in range(1, min(8, len(bios_insns) - idx)):
                    ni = bios_insns[idx + k]
                    nop = get_opcode(ni)
                    if nop in (OP_ADDIU, OP_ORI) and get_rs(ni) == rt:
                        if (ni & 0xFFFF) == lo:
                            ref_positions.add(idx * 4)
                        break
                    if (nop == OP_LUI and get_rt(ni) == rt) or (nop == 0x00 and get_rd(ni) == rt):
                        break
            candidate_sets.append(ref_positions)
        if not candidate_sets: continue
        candidate_sets.sort(key=len)
        rarest = candidate_sets[0]
        if len(rarest) == 1:
            fs = find_function_start(bios_insns, next(iter(rarest)) // 4)
            if fs is not None:
                new_matches[func["addr"]] = bios_base + fs * 4
    return new_matches


def match_via_constants(funcs, hdd_base, hdd_data, bios_base, bios_data, bios_insns, already_matched):
    bios_func_starts = []
    for i, insn in enumerate(bios_insns):
        if get_opcode(insn) == OP_ADDIU and get_rs(insn) == REG_SP and get_rt(insn) == REG_SP:
            if insn & 0xFFFF >= 0x8000:
                bios_func_starts.append(i)
    for i in range(len(bios_insns) - 1):
        if bios_insns[i] == 0x03e00008 and i + 2 < len(bios_insns):
            bios_func_starts.append(i + 2)
    bios_func_starts = sorted(set(bios_func_starts))
    bios_fps = defaultdict(list)
    for idx, start in enumerate(bios_func_starts):
        end = bios_func_starts[idx + 1] if idx + 1 < len(bios_func_starts) else min(start + 1024, len(bios_insns))
        fi = bios_insns[start:end]
        if len(fi) < 4: continue
        key = (get_stack_frame_size(fi), len(fi), tuple(sorted(extract_non_address_constants(fi))))
        if len(extract_non_address_constants(fi)) >= 3:
            bios_fps[key].append(start)
    new_matches = {}
    for func in funcs:
        if func["addr"] in already_matched: continue
        hdd_code = extract_function(hdd_base, hdd_data, func["addr"], func["size"])
        if hdd_code is None or func["size"] < 32: continue
        hdd_il = struct.unpack(f"<{len(hdd_code) // 4}I", hdd_code)
        consts = extract_non_address_constants(hdd_il)
        if len(consts) < 3: continue
        key = (get_stack_frame_size(hdd_il), len(hdd_il), tuple(sorted(consts)))
        cands = bios_fps.get(key, [])
        if len(cands) == 1:
            ba = bios_base + cands[0] * 4
            if ba not in {v for v in already_matched}:
                new_matches[func["addr"]] = ba
    return new_matches


def match_via_call_sequence(funcs, hdd_base, hdd_data, bios_base, bios_data, bios_insns,
                            matched_hdd_to_bios, already_matched):
    bios_to_hdd = {v: k for k, v in matched_hdd_to_bios.items()}
    bios_func_starts = []
    for i, insn in enumerate(bios_insns):
        if get_opcode(insn) == OP_ADDIU and get_rs(insn) == REG_SP and get_rt(insn) == REG_SP:
            if insn & 0xFFFF >= 0x8000:
                bios_func_starts.append(i)
    for i in range(len(bios_insns) - 1):
        if bios_insns[i] == 0x03e00008 and i + 2 < len(bios_insns):
            bios_func_starts.append(i + 2)
    bios_func_starts = sorted(set(bios_func_starts))
    bios_call_sigs = defaultdict(list)
    for idx, start in enumerate(bios_func_starts):
        end = bios_func_starts[idx + 1] if idx + 1 < len(bios_func_starts) else min(start + 1024, len(bios_insns))
        fi = bios_insns[start:end]
        if len(fi) < 4: continue
        bv = bios_base + start * 4
        cs = [bios_to_hdd[((bv & 0xF0000000) | ((insn & 0x3FFFFFF) << 2))]
              for insn in fi if get_opcode(insn) == OP_JAL
              and ((bv & 0xF0000000) | ((insn & 0x3FFFFFF) << 2)) in bios_to_hdd]
        if len(cs) >= 3:
            bios_call_sigs[(get_stack_frame_size(fi), tuple(cs))].append(start)
    new_matches = {}
    for func in funcs:
        if func["addr"] in already_matched: continue
        hdd_code = extract_function(hdd_base, hdd_data, func["addr"], func["size"])
        if hdd_code is None or func["size"] < 32: continue
        hdd_il = struct.unpack(f"<{len(hdd_code) // 4}I", hdd_code)
        cs = [((func["addr"] & 0xF0000000) | ((insn & 0x3FFFFFF) << 2))
              for insn in hdd_il if get_opcode(insn) == OP_JAL
              and ((func["addr"] & 0xF0000000) | ((insn & 0x3FFFFFF) << 2)) in matched_hdd_to_bios]
        if len(cs) < 3: continue
        key = (get_stack_frame_size(hdd_il), tuple(cs))
        cands = bios_call_sigs.get(key, [])
        if len(cands) == 1:
            new_matches[func["addr"]] = bios_base + cands[0] * 4
    return new_matches


def add_matches(new_matches, matched_hdd_to_bios, all_matched_hdd, hdd_func_by_addr, output_lines):
    count = 0
    for hdd_addr, bios_addr in new_matches.items():
        if hdd_addr not in matched_hdd_to_bios:
            matched_hdd_to_bios[hdd_addr] = bios_addr
            all_matched_hdd.add(hdd_addr)
            f = hdd_func_by_addr[hdd_addr]
            output_lines.append(f"{f['name']} = 0x{bios_addr:08x}; // size:0x{f['size']:x} type:func")
            count += 1
    return count


def propagate_calls_iteratively(label, funcs, hdd_base, hdd_data, bios_base, bios_data,
                                matched_hdd_to_bios, all_matched_hdd, hdd_func_by_addr, output_lines):
    total, iteration = 0, 0
    while True:
        iteration += 1
        nm = propagate_via_calls(funcs, hdd_base, hdd_data, bios_base, bios_data, matched_hdd_to_bios)
        if not nm: break
        added = add_matches(nm, matched_hdd_to_bios, all_matched_hdd, hdd_func_by_addr, output_lines)
        total += added
        print(f"  {label} iteration {iteration}: +{added} functions")
    return total


def match_symbols(bios_base, bios_data):
    """Match symbols from HDD OSDSYS to a BIOS OSDSYS binary.

    Returns list of (name, bios_addr, type, size) tuples for all matched symbols.
    Downloads hddosd.elf and symbol_addrs.txt if missing.
    """
    download(SYMBOL_URL, SYMBOL_FILE)
    download(HDDOSD_URL, ELF_FILE)

    funcs, strings, data_syms = parse_symbol_addrs(str(SYMBOL_FILE))
    print(f"  {len(funcs)} functions, {len(strings)} strings, {len(data_syms)} data symbols")

    hdd_base, hdd_data = load_elf_code(str(ELF_FILE))
    print(f"  HDD OSDSYS base: 0x{hdd_base:08x}, Size: 0x{len(hdd_data):x}")

    bios_n = len(bios_data) // 4
    bios_insns = struct.unpack(f"<{bios_n}I", bios_data[:bios_n * 4])

    MIN_FUNC_SIZE = 16
    hdd_func_by_addr = {f["addr"]: f for f in funcs}
    matched_hdd_to_bios = {}
    all_matched_hdd = set()
    output_lines = []
    ambiguous_funcs = []

    # Stage 1: Masked instruction matching
    print(f"\n[Stage 1] Masked instruction matching...")
    stage1 = skipped = not_found = ambiguous = 0
    for func in funcs:
        code = extract_function(hdd_base, hdd_data, func["addr"], func["size"])
        if code is None or func["size"] < MIN_FUNC_SIZE:
            skipped += 1; continue
        masked_insns, mask_bits = create_mask(code)
        matches = scan_for_match(bios_insns, masked_insns, mask_bits)
        if len(matches) == 1:
            ba = bios_base + matches[0]
            matched_hdd_to_bios[func["addr"]] = ba
            all_matched_hdd.add(func["addr"])
            output_lines.append(f"{func['name']} = 0x{ba:08x}; // size:0x{func['size']:x} type:func")
            stage1 += 1
        elif len(matches) == 0:
            not_found += 1
        else:
            ambiguous_funcs.append(func); ambiguous += 1
    print(f"  Matched: {stage1}, Not found: {not_found}, Ambiguous: {ambiguous}, Skipped: {skipped}")

    # Stage 2: String content matching
    print(f"\n[Stage 2] String content matching...")
    str_matched = str_not_found = str_ambiguous = 0
    for sym in strings:
        sb = extract_function(hdd_base, hdd_data, sym["addr"], sym["size"])
        if sb is None: continue
        ms, pos = [], 0
        while True:
            pos = bios_data.find(sb, pos)
            if pos == -1: break
            ms.append(pos); pos += 1
        if len(ms) == 1:
            na = bios_base + ms[0]
            output_lines.append(f"{sym['name']} = 0x{na:08x}; // size:0x{sym['size']:x} type:asciz")
            str_matched += 1
        elif len(ms) == 0: str_not_found += 1
        else: str_ambiguous += 1
    print(f"  Matched: {str_matched}, Not found: {str_not_found}, Ambiguous: {str_ambiguous}")

    # Stage 3: Call graph propagation
    print(f"\n[Stage 3] Call graph propagation...")
    stage3 = propagate_calls_iteratively("Stage 3", funcs, hdd_base, hdd_data, bios_base, bios_data,
                                         matched_hdd_to_bios, all_matched_hdd, hdd_func_by_addr, output_lines)
    print(f"  Total: +{stage3} functions")

    # Stage 4: Resolve ambiguous matches
    print(f"\n[Stage 4] Resolving ambiguous matches ({len(ambiguous_funcs)} candidates)...")
    am = resolve_ambiguous_via_callgraph(funcs, hdd_base, hdd_data, bios_base, bios_data,
                                         bios_insns, matched_hdd_to_bios, ambiguous_funcs)
    stage4 = add_matches(am, matched_hdd_to_bios, all_matched_hdd, hdd_func_by_addr, output_lines)
    print(f"  Resolved: {stage4}")
    stage4b = propagate_calls_iteratively("Stage 4b", funcs, hdd_base, hdd_data, bios_base, bios_data,
                                          matched_hdd_to_bios, all_matched_hdd, hdd_func_by_addr, output_lines)
    if stage4b: print(f"  Additional from propagation: +{stage4b}")

    # Stage 5: String reference matching
    print(f"\n[Stage 5] String reference matching...")
    srm = match_via_string_refs(funcs, strings, hdd_base, hdd_data, bios_base, bios_data,
                                bios_insns, all_matched_hdd)
    stage5 = add_matches(srm, matched_hdd_to_bios, all_matched_hdd, hdd_func_by_addr, output_lines)
    print(f"  Matched: {stage5}")
    stage5b = propagate_calls_iteratively("Stage 5b", funcs, hdd_base, hdd_data, bios_base, bios_data,
                                          matched_hdd_to_bios, all_matched_hdd, hdd_func_by_addr, output_lines)
    if stage5b: print(f"  Additional from propagation: +{stage5b}")

    # Stage 6: Non-address constant fingerprinting
    print(f"\n[Stage 6] Non-address constant fingerprinting...")
    cm = match_via_constants(funcs, hdd_base, hdd_data, bios_base, bios_data, bios_insns, all_matched_hdd)
    stage6 = add_matches(cm, matched_hdd_to_bios, all_matched_hdd, hdd_func_by_addr, output_lines)
    print(f"  Matched: {stage6}")
    stage6b = propagate_calls_iteratively("Stage 6b", funcs, hdd_base, hdd_data, bios_base, bios_data,
                                          matched_hdd_to_bios, all_matched_hdd, hdd_func_by_addr, output_lines)
    if stage6b: print(f"  Additional from propagation: +{stage6b}")

    # Stage 7: Call sequence + stack frame matching
    print(f"\n[Stage 7] Call sequence + stack frame matching...")
    csm = match_via_call_sequence(funcs, hdd_base, hdd_data, bios_base, bios_data, bios_insns,
                                  matched_hdd_to_bios, all_matched_hdd)
    stage7 = add_matches(csm, matched_hdd_to_bios, all_matched_hdd, hdd_func_by_addr, output_lines)
    print(f"  Matched: {stage7}")
    stage7b = propagate_calls_iteratively("Stage 7b", funcs, hdd_base, hdd_data, bios_base, bios_data,
                                          matched_hdd_to_bios, all_matched_hdd, hdd_func_by_addr, output_lines)
    if stage7b: print(f"  Additional from propagation: +{stage7b}")

    # Stage 8: Fuzzy matching
    print(f"\n[Stage 8] Fuzzy matching...")
    stage8 = 0
    used_bios = set(matched_hdd_to_bios.values())
    def get_max_ratio(n):
        if n >= 100: return 0.50
        if n >= 50: return 0.40
        if n >= 20: return 0.30
        if n >= 10: return 0.20
        return 0.0
    candidates = []
    for func in funcs:
        if func["addr"] in all_matched_hdd or func["size"] < 40: continue
        code = extract_function(hdd_base, hdd_data, func["addr"], func["size"])
        if code is None: continue
        mr = get_max_ratio(func["size"] // 4)
        if mr == 0.0: continue
        mi, mb = create_mask(code)
        res = scan_for_fuzzy_match(bios_insns, mi, mb, mr)
        if res: candidates.append((func, res))
    candidates.sort(key=lambda x: -x[0]["size"])
    for func, results in candidates:
        results = [(o, m) for o, m in results if (bios_base + o) not in used_bios]
        if not results: continue
        if len(results) == 1:
            accept = True
        elif len(results) >= 2:
            bm, sm = results[0][1], results[1][1]
            accept = (bm == 0 and sm > 0) or (sm > 0 and bm < sm * 0.7) or (sm - bm >= 3)
        else:
            accept = False
        if accept:
            ba = bios_base + results[0][0]
            matched_hdd_to_bios[func["addr"]] = ba
            all_matched_hdd.add(func["addr"])
            used_bios.add(ba)
            output_lines.append(f"{func['name']} = 0x{ba:08x}; // size:0x{func['size']:x} type:func")
            stage8 += 1
    print(f"  Matched: {stage8}")
    stage8b = propagate_calls_iteratively("Stage 8b", funcs, hdd_base, hdd_data, bios_base, bios_data,
                                          matched_hdd_to_bios, all_matched_hdd, hdd_func_by_addr, output_lines)
    if stage8b: print(f"  Additional from propagation: +{stage8b}")

    # Stage 9: Data symbol matching
    print(f"\n[Stage 9] Data symbol matching via XREF correlation...")
    hdd_gp = 0x377970
    bios_gp = 0
    dm, da = match_data_symbols(funcs, data_syms, strings, hdd_base, hdd_data, bios_base, bios_data,
                                matched_hdd_to_bios, hdd_gp, bios_gp)
    data_sym_by_addr = {s["addr"]: s for s in data_syms}
    str_sym_by_addr = {s["addr"]: s for s in strings}
    matched_str_addrs = set()
    for line in output_lines:
        if "type:asciz" in line:
            m = re.search(r"= 0x([0-9a-fA-F]+)", line)
            if m: matched_str_addrs.add(int(m.group(1), 16))
    new_data = new_str_xref = 0
    for ha, ba in dm.items():
        if ha in data_sym_by_addr:
            s = data_sym_by_addr[ha]
            st = s.get("type", "data")
            sz = f" // size:0x{s['size']:x}" if s["size"] else ""
            if st and st != "data":
                output_lines.append(f"{s['name']} = 0x{ba:08x};{sz} type:{st}")
            else:
                output_lines.append(f"{s['name']} = 0x{ba:08x};")
            new_data += 1
        elif ha in str_sym_by_addr:
            s = str_sym_by_addr[ha]
            if ba not in matched_str_addrs:
                output_lines.append(f"{s['name']} = 0x{ba:08x}; // size:0x{s['size']:x} type:asciz")
                new_str_xref += 1
    print(f"  Data: {new_data}, Strings via XREF: {new_str_xref}, Ambiguous: {da}")

    # Summary
    total_funcs = len(all_matched_hdd)
    print(f"\n{'='*60}")
    print(f"  Stage 1 (mask match):        {stage1}")
    print(f"  Stage 3 (call propagation):  {stage3}")
    print(f"  Stage 4 (disambiguate):      {stage4} (+{stage4b} propagated)")
    print(f"  Stage 5 (string refs):       {stage5} (+{stage5b} propagated)")
    print(f"  Stage 6 (const fingerprint): {stage6} (+{stage6b} propagated)")
    print(f"  Stage 7 (call sequence):     {stage7} (+{stage7b} propagated)")
    print(f"  Stage 8 (fuzzy match):       {stage8} (+{stage8b} propagated)")
    print(f"  Stage 9 (data XREF):         {new_data} data, {new_str_xref} strings")
    print(f"  {'─'*35}")
    print(f"  TOTAL FUNCTIONS: {total_funcs}")
    print(f"  TOTAL STRINGS:   {str_matched + new_str_xref}")
    print(f"  TOTAL DATA:      {new_data}")
    total_all = total_funcs + str_matched + new_str_xref + new_data
    print(f"  TOTAL SYMBOLS:   {total_all}")
    print(f"{'='*60}")

    # Build result list from output_lines
    type_re = re.compile(r"(\w+)\s*=\s*0x([0-9a-fA-F]+)\s*;\s*//\s*size:0x([0-9a-fA-F]+)\s+type:(\w+)")
    plain_re = re.compile(r"(\w+)\s*=\s*0x([0-9a-fA-F]+)\s*;")
    result = []
    for line in output_lines:
        m = type_re.match(line)
        if m:
            result.append((m.group(1), int(m.group(2), 16), m.group(4), int(m.group(3), 16)))
            continue
        m = plain_re.match(line)
        if m:
            result.append((m.group(1), int(m.group(2), 16), "data", 0))
    result.sort(key=lambda x: x[1])
    return result


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <bios_osdsys.elf>")
        sys.exit(1)
    bios_elf = sys.argv[1]

    print(f"Loading BIOS OSDSYS from {bios_elf}...")
    bios_base, bios_data = load_elf_code(bios_elf)
    print(f"  Base: 0x{bios_base:08x}, Size: 0x{len(bios_data):x}")

    result = match_symbols(bios_base, bios_data)

    output_lines = []
    for name, addr, stype, size in result:
        if size:
            output_lines.append(f"{name} = 0x{addr:08x}; // size:0x{size:x} type:{stype}")
        else:
            output_lines.append(f"{name} = 0x{addr:08x};")

    output_path = "bios_symbol_addrs.txt"
    with open(output_path, "w") as f:
        for line in output_lines:
            f.write(line + "\n")
    print(f"\nWrote {len(output_lines)} symbols to {output_path}")

    unmatched_path = "bios_unmatched_symbols.txt"
    download(SYMBOL_URL, SYMBOL_FILE)
    funcs, strings, data_syms = parse_symbol_addrs(str(SYMBOL_FILE))
    matched_names = {name for name, _, _, _ in result}
    unmatched = []
    for func in funcs:
        if func["name"] not in matched_names:
            unmatched.append(f"{func['name']} = 0x{func['addr']:08x}; // size:0x{func['size']:x} type:func")
    for sym in strings:
        if sym["name"] not in matched_names:
            unmatched.append(f"{sym['name']} = 0x{sym['addr']:08x}; // size:0x{sym['size']:x} type:asciz")
    for sym in data_syms:
        if sym["name"] not in matched_names:
            if sym["size"]:
                unmatched.append(f"{sym['name']} = 0x{sym['addr']:08x}; // size:0x{sym['size']:x} type:{sym['type']}")
            else:
                unmatched.append(f"{sym['name']} = 0x{sym['addr']:08x};")
    unmatched.sort(key=lambda l: int(re.search(r"0x([0-9a-fA-F]+)", l).group(1), 16))
    with open(unmatched_path, "w") as f:
        for line in unmatched:
            f.write(line + "\n")
    print(f"Wrote {len(unmatched)} unmatched symbols to {unmatched_path}")


if __name__ == "__main__":
    main()
