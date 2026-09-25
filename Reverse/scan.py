"""Code scanning helpers on top of pe.Image (x64 rip-relative refs, calls, vtables)."""
import struct, re
from pe import Image


class Scanner:
    def __init__(self, img: Image):
        self.img = img
        self.text_lo, self.text_hi = img.sec_range(".text")
        self.rdata_lo, self.rdata_hi = img.sec_range(".rdata")
        self.text_off = img.rva2off(self.text_lo)
        self.text = img.d[self.text_off:self.text_off + (self.text_hi - self.text_lo)]
        self._lea_index = None
        self._call_index = None

    # ---- rip-relative lea / mov refs ----
    def _build_lea_index(self):
        """Index every `lea/mov r64,[rip+disp]` in .text by target RVA."""
        idx = {}
        t = self.text
        base = self.text_lo
        for m in re.finditer(rb"[\x48\x4C][\x8D\x8B][\x05\x0D\x15\x1D\x25\x2D\x35\x3D]", t):
            i = m.start()
            disp = struct.unpack_from("<i", t, i + 3)[0]
            idx.setdefault(base + i + 7 + disp, []).append(base + i)
        self._lea_index = idx

    def refs_to(self, rva):
        if self._lea_index is None:
            self._build_lea_index()
        return self._lea_index.get(rva, [])

    # ---- calls / jmps ----
    def _build_call_index(self):
        idx = {}
        t = self.text
        base = self.text_lo
        for m in re.finditer(rb"\xE8", t):
            i = m.start()
            if i + 5 > len(t):
                break
            disp = struct.unpack_from("<i", t, i + 1)[0]
            tgt = base + i + 5 + disp
            if self.text_lo <= tgt < self.text_hi:
                idx.setdefault(tgt, []).append(base + i)
        self._call_index = idx

    def callers(self, target):
        if self._call_index is None:
            self._build_call_index()
        return self._call_index.get(target, [])

    def calls_in(self, start, end):
        """(site, target) for every E8 inside [start,end)."""
        out = []
        t = self.text
        base = self.text_lo
        for i in range(start - base, end - base):
            if t[i] == 0xE8:
                disp = struct.unpack_from("<i", t, i + 1)[0]
                tgt = base + i + 5 + disp
                if self.text_lo <= tgt < self.text_hi:
                    out.append((base + i, tgt))
        return out

    def call_target(self, site):
        return site + 5 + self.img.i32(site + 1)

    # ---- strings ----
    def funcs_referencing(self, s, wide=True, exact=True):
        """{func_start: [ref sites]} for every function that lea's the string."""
        if wide:
            strs = self.img.find_wide_exact(s, sec=".rdata") if exact else self.img.find_wide(s, sec=".rdata")
        else:
            strs = self.img.find_ascii_exact(s, sec=".rdata") if exact else self.img.find_ascii(s, sec=".rdata")
        funcs = {}
        for srva in strs:
            for site in self.refs_to(srva):
                fs = self.img.func_start(site)
                if fs:
                    funcs.setdefault(fs, []).append(site)
        return funcs

    # ---- vtables ----
    def ptrs_to(self, func):
        """RVAs in .rdata holding ImageBase+func (vtable slots)."""
        return self.img.find_all(struct.pack("<Q", self.img.image_base + func), sec=".rdata")

    def vtable_len(self, vtable_rva, limit=2000):
        """Number of consecutive code pointers starting at vtable_rva."""
        n = 0
        while n < limit:
            v = self.img.u64(vtable_rva + n * 8) - self.img.image_base
            if not (self.text_lo <= v < self.text_hi):
                break
            n += 1
        return n

    def vtable_index(self, vtable_rva, func):
        i = 0
        while True:
            v = self.img.u64(vtable_rva + i * 8)
            if v == self.img.image_base + func:
                return i
            if v < self.img.image_base or v >= self.img.image_base + self.img.size_of_image:
                return None
            i += 1

    def read_vtable(self, vtable_rva, count):
        return [self.img.u64(vtable_rva + i * 8) - self.img.image_base for i in range(count)]

    def hexdump(self, rva, n=32):
        return " ".join("%02X" % b for b in self.img.read(rva, n))


# ---- disassembly (capstone) ----
def disasm(img, rva, n=None, count=None):
    """Yield capstone instructions for a function (whole .pdata range by default)."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    if n is None:
        b = img.func_bounds(rva)
        n = (b[1] - rva) if b else 0x200
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    code = img.read(rva, n)
    out = []
    for ins in md.disasm(code, img.image_base + rva):
        out.append(ins)
        if count and len(out) >= count:
            break
    return out


def fmt(img, ins):
    return "%08X  %-8s %s" % (ins.address - img.image_base, ins.mnemonic, ins.op_str)


def dump(img, rva, n=None, count=None):
    for ins in disasm(img, rva, n, count):
        print(fmt(img, ins))


def rip_target(img, ins):
    """Target RVA of a rip-relative operand, or None."""
    m = re.search(r"rip ([+-]) 0x([0-9a-f]+)", ins.op_str)
    if not m:
        return None
    d = int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
    return ins.address - img.image_base + ins.size + d


class ClassInfo:
    """Static facts about a UClass pulled from its GetPrivateStaticClass registration."""

    def __init__(self, sc: Scanner, name):
        self.sc = sc
        img = sc.img
        self.name = name
        self.static_class_fn = self.class_ptr = self.ctor = self.internal_ctor = self.vtable = self.size = None
        for h in img.find_wide(name, sec=".rdata"):
            if img.read(h + len(name) * 2, 2) != b"\0\0" or img.read(h - 2, 2) != b"\0\0":
                continue
            for site in sc.refs_to(h + 2):          # registration passes Name+1 (prefix stripped)
                fs = img.func_start(site)
                if not fs:
                    continue
                ins = disasm(img, fs)
                if not any(x.mnemonic == "call" for x in ins):
                    continue
                self.static_class_fn = fs
                self._parse(ins)
                return

    def _parse(self, ins):
        img = self.sc.img
        stores = {}   # [rsp+X] -> lea target
        last_lea = None
        for x in ins:
            if x.mnemonic == "mov" and "[rip" in x.op_str and x.op_str.startswith("rax"):
                self.class_ptr = rip_target(img, x)
            if x.mnemonic == "lea" and "rip" in x.op_str:
                last_lea = rip_target(img, x)
            if x.mnemonic == "mov" and x.op_str.startswith("qword ptr [rsp + ") and x.op_str.endswith("], rax"):
                stores[int(x.op_str.split("+ ")[1].split("]")[0], 16)] = last_lea
            if x.mnemonic == "mov" and x.op_str.startswith("dword ptr [rsp + 0x20],"):
                self.size = int(x.op_str.split(", ")[1], 16)
        self.internal_ctor = stores.get(0x48)
        if self.internal_ctor:
            self.ctor = self._follow_ctor(self.internal_ctor)
            if self.ctor:
                self.vtable = self._find_vtable(self.ctor)

    def _follow_ctor(self, fn):
        """InternalConstructor<T> is a thin wrapper: take its first call/jmp into .text."""
        for x in disasm(self.sc.img, fn, count=40):
            if x.mnemonic in ("call", "jmp") and x.op_str.startswith("0x"):
                t = int(x.op_str, 16) - self.sc.img.image_base
                if self.sc.text_lo <= t < self.sc.text_hi:
                    return t
        return None

    def _find_vtable(self, ctor):
        """First `lea rax,[rdata]` in the ctor that looks like a long vtable (>=20 code pointers).
        Later ones are interface sub-vtables stored at non-zero offsets."""
        img = self.sc.img
        for x in disasm(img, ctor):
            if x.mnemonic == "lea" and x.op_str.startswith("rax, [rip"):
                t = rip_target(img, x)
                if self.sc.rdata_lo <= t < self.sc.rdata_hi and self.sc.vtable_len(t) >= 20:
                    return t
        return None

    def __repr__(self):
        f = lambda v: ("0x%X" % v) if v is not None else "?"
        return "%s: StaticClass=%s ClassPtr=%s Ctor=%s VTable=%s Size=%s" % (
            self.name, f(self.static_class_fn), f(self.class_ptr), f(self.ctor), f(self.vtable), f(self.size))


def log_record_funcs(sc: Scanner, s, wide=True, exact=False):
    """UE5 log format strings live inside static FStaticBasicLogRecord structs in .rdata.
    Find string -> pointer(s) to it -> code lea'ing that record -> {func: [sites]}."""
    img = sc.img
    if wide:
        strs = img.find_wide_exact(s, sec=".rdata") if exact else img.find_wide(s, sec=".rdata")
    else:
        strs = img.find_ascii_exact(s, sec=".rdata") if exact else img.find_ascii(s, sec=".rdata")
    funcs = {}
    for srva in strs:
        # walk back to the start of the string so partial matches still hit the record pointer
        start = srva
        if wide:
            while img.read(start - 2, 2) != b"\0\0":
                start -= 2
        else:
            while img.read(start - 1, 1) != b"\0":
                start -= 1
        for rec in sc.ptrs_to(start) + sc.ptrs_to(srva):
            for site in sc.refs_to(rec):
                fs = img.func_start(site)
                if fs:
                    funcs.setdefault(fs, []).append(site)
    return funcs


def any_rip_refs(sc: Scanner, target, lens=(5, 6, 7, 8, 9, 10, 11)):
    """Brute-force rip-relative references of any instruction form to `target` (slow-ish, ~10s)."""
    import numpy as np
    t = np.frombuffer(sc.text, dtype=np.uint8)
    base = sc.text_lo
    n = len(t)
    # little-endian int32 at every offset
    d = np.frombuffer(sc.text, dtype=np.uint8).astype(np.int64)
    disp = d[:n-3] | (d[1:n-2] << 8) | (d[2:n-1] << 16) | (d[3:n] << 24)
    disp = np.where(disp >= 2**31, disp - 2**32, disp)
    out = []
    for L in lens:
        # instruction occupies [i, i+L), disp at i+L-4, next ip = i+L
        idx = np.arange(0, n - L + 1)
        hits = idx[(base + idx + L + disp[idx + L - 4]) == target]
        for i in hits:
            out.append(base + int(i))
    return sorted(set(out))
