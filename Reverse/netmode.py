"""Static finder for the inlined UWorld::GetNetMode checks in the client build.

The client build's GetNetMode is `if (NetDriver) return NM_Client; ... AttemptDeriveFromURL()`; it is inlined into
~1000 functions. Each site is `cmp qword [world+0x38], 0` (or `mov r,[world+0x38]; test r,r`) followed by a
conditional jump. We rewrite the jump so the NetDriver != null case takes the same path as the null case, which
ends in AttemptDeriveFromURL (hooked to return NM_DedicatedServer).
"""
import re
from scan import disasm, fmt

NETDRIVER_OFF = 0x38
DEMO_OFF = 0xF0


def _reads_demo(img, rva, n=4):
    """Does the block at rva start by reading World->DemoNetDriver (the null path)?"""
    for x in disasm(img, rva, n=32, count=n):
        if "+ 0xf0]" in x.op_str:
            return True
        if x.mnemonic in ("ret", "jmp", "call"):
            break
    return False


def _returns_client(img, rva, n=3):
    for x in disasm(img, rva, n=24, count=n):
        if x.mnemonic == "mov" and re.match(r"e\w\w, 3$", x.op_str):
            return True
    return False


def _calls(img, rva, target, n=4):
    for x in disasm(img, rva, n=32, count=n):
        if x.mnemonic in ("call", "jmp") and x.op_str.startswith("0x") and int(x.op_str, 16) - img.image_base == target:
            return True
        if x.mnemonic == "ret":
            break
    return False


def find_sites(img, sc, attempt_derive, netdriver_getnetmode):
    funcs = sorted(set(f for f in (img.func_start(c) for c in sc.callers(attempt_derive)) if f))
    patches = []      # (rva, old_bytes, new_bytes, note)
    unhandled = []
    for f in funcs:
        ins = disasm(img, f)
        for i, x in enumerate(ins):
            is_cmp = x.mnemonic == "cmp" and x.op_str.startswith("qword ptr [") and "+ 0x38]" in x.op_str and x.op_str.endswith(", 0")
            is_load = x.mnemonic == "mov" and "+ 0x38]" in x.op_str and x.op_str.startswith("r") and "qword ptr [" in x.op_str
            if not (is_cmp or is_load):
                continue
            base = x.op_str.split("[")[1].split(" ")[0]
            if base in ("rsp", "rbp"):      # stack slot, not a UWorld
                continue
            j = i + 1
            if is_load:
                # expect `test r, r` next (allow one instruction in between)
                if j < len(ins) and ins[j].mnemonic != "test":
                    j += 1
                if j >= len(ins) or ins[j].mnemonic != "test" or ins[j].op_str.split(",")[0] not in x.op_str.split(",")[0]:
                    continue
                j += 1
            if j >= len(ins):
                continue
            br = ins[j]
            if br.mnemonic not in ("je", "jne"):
                continue
            tgt = int(br.op_str, 16) - img.image_base
            fall = br.address - img.image_base + br.size
            rva = br.address - img.image_base
            old = bytes(img.read(rva, br.size))
            if br.mnemonic == "je":
                # je null_path : make it unconditional if the target is the null path
                if _reads_demo(img, tgt) or _is_attempt_call(img, tgt, attempt_derive):
                    new = b"\xEB" + old[1:] if br.size == 2 else b"\x90\xE9" + old[2:]
                    patches.append((rva, old, new, "je->jmp in 0x%X" % f))
                    continue
            else:
                # jne client_path : drop it if the fallthrough is the null path
                if _reads_demo(img, fall) or _is_attempt_call(img, fall, attempt_derive):
                    new = b"\x90" * br.size
                    patches.append((rva, old, new, "nop jne in 0x%X" % f))
                    continue
            # sites that hand the driver to UNetDriver::GetNetMode are covered by hooking that
            if _calls(img, tgt, netdriver_getnetmode) or _calls(img, fall, netdriver_getnetmode):
                continue
            unhandled.append((f, rva, fmt(img, br)))
    return patches, unhandled


def _is_attempt_call(img, rva, attempt_derive, n=4):
    for x in disasm(img, rva, n=32, count=n):
        if x.mnemonic in ("call", "jmp") and x.op_str.startswith("0x") and int(x.op_str, 16) - img.image_base == attempt_derive:
            return True
        if x.mnemonic in ("ret",):
            break
    return False
