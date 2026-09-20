"""Tiny PE helper: loads the 31.41 dump and maps RVA <-> file offset."""
import struct, mmap, os

# Flat memory dump of the 31.41 client (RVA layout intact, .pdata intact). First one that exists wins.
DUMP_CANDIDATES = [
    os.environ.get("FN_DUMP", ""),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "31.41.exe"),
    r"C:\Users\mharr\OneDrive\Desktop\31.41 Dumps\31.41.exe",
]
DEFAULT_DUMP = next((p for p in DUMP_CANDIDATES if p and os.path.exists(p)), DUMP_CANDIDATES[-1])


class Image:
    def __init__(self, path=DEFAULT_DUMP):
        self.path = path
        self.f = open(path, "rb")
        self.d = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        e = struct.unpack_from("<I", self.d, 0x3C)[0]
        nsec = struct.unpack_from("<H", self.d, e + 6)[0]
        optsz = struct.unpack_from("<H", self.d, e + 20)[0]
        self.image_base = struct.unpack_from("<Q", self.d, e + 24 + 24)[0]
        self.size_of_image = struct.unpack_from("<I", self.d, e + 24 + 56)[0]
        # exception directory (index 3)
        self.pdata_rva, self.pdata_size = struct.unpack_from("<II", self.d, e + 24 + 112 + 3 * 8)
        self.secs = []
        s0 = e + 24 + optsz
        for i in range(nsec):
            o = s0 + i * 40
            name = self.d[o:o + 8].rstrip(b"\0").decode(errors="ignore")
            vs, va, rs, raw = struct.unpack_from("<IIII", self.d, o + 8)
            self.secs.append((name, va, vs, raw, rs))

    def sec(self, name):
        for s in self.secs:
            if s[0] == name:
                return s
        raise KeyError(name)

    def rva2off(self, rva):
        for _, va, vs, raw, rs in self.secs:
            if va <= rva < va + max(vs, rs):
                return raw + (rva - va)
        raise ValueError("rva 0x%X not in any section" % rva)

    def off2rva(self, off):
        for _, va, vs, raw, rs in self.secs:
            if raw <= off < raw + rs:
                return va + (off - raw)
        raise ValueError("off 0x%X not in any section" % off)

    def read(self, rva, n):
        o = self.rva2off(rva)
        return self.d[o:o + n]

    def u8(self, rva):  return self.read(rva, 1)[0]
    def u16(self, rva): return struct.unpack("<H", self.read(rva, 2))[0]
    def u32(self, rva): return struct.unpack("<I", self.read(rva, 4))[0]
    def i32(self, rva): return struct.unpack("<i", self.read(rva, 4))[0]
    def u64(self, rva): return struct.unpack("<Q", self.read(rva, 8))[0]

    def sec_range(self, name):
        _, va, vs, raw, rs = self.sec(name)
        return va, va + min(vs, rs)

    def find_all(self, pat, sec=None, first=None):
        """Byte pattern search; returns RVAs."""
        if sec:
            _, va, vs, raw, rs = self.sec(sec)
            lo, hi = raw, raw + rs
        else:
            lo, hi = 0, len(self.d)
        out = []
        i = self.d.find(pat, lo, hi)
        while i != -1:
            out.append(self.off2rva(i))
            if first and len(out) >= first:
                break
            i = self.d.find(pat, i + 1, hi)
        return out

    def find_wide(self, s, **kw):  return self.find_all(s.encode("utf-16-le"), **kw)
    def find_ascii(self, s, **kw): return self.find_all(s.encode("ascii"), **kw)

    def find_wide_exact(self, s, **kw):
        """Wide string preceded by a null wchar (start of string) and followed by a terminator."""
        pat = b"\0\0" + s.encode("utf-16-le") + b"\0\0"
        return [r + 2 for r in self.find_all(pat, **kw)]

    def find_ascii_exact(self, s, **kw):
        pat = b"\0" + s.encode("ascii") + b"\0"
        return [r + 1 for r in self.find_all(pat, **kw)]

    def func_bounds(self, rva):
        """Function start/end from .pdata (follows chained unwind info)."""
        off = self.rva2off(self.pdata_rva)
        lo, hi = 0, self.pdata_size // 12
        while lo < hi:
            mid = (lo + hi) // 2
            s, en, u = struct.unpack_from("<III", self.d, off + mid * 12)
            if rva < s:
                hi = mid
            elif rva >= en:
                lo = mid + 1
            else:
                # chained unwind info -> parent
                while (self.u8(u) >> 3) & 4:
                    cnt = self.u8(u + 2)
                    p = u + 4 + 2 * ((cnt + 1) & ~1)
                    s, en, u = self.u32(p), self.u32(p + 4), self.u32(p + 8)
                return s, en
        return None

    def func_start(self, rva):
        b = self.func_bounds(rva)
        return b[0] if b else None
