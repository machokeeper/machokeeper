# Independent Mach-O page-hash checker. Counts stale CODE slots across
# every slice and every CodeDirectory (SHA-1 and SHA-256), clamping the
# final page to codeLimit. No shared code with the engine under test.
import sys, struct, hashlib, math
data = open(sys.argv[1],'rb').read()
def be32(o): return struct.unpack('>I', data[o:o+4])[0]
def le32(o,b=data): return struct.unpack('<I', b[o:o+4])[0]
def slices():
    m = struct.unpack('>I', data[0:4])[0]
    if m in (0xcafebabe,0xcafebabf):
        is64=m==0xcafebabf; n=be32(4); base=8; step=32 if is64 else 20
        for i in range(n):
            o=base+i*step
            off = struct.unpack('>Q',data[o+8:o+16])[0] if is64 else be32(o+8)
            yield off
    else:
        yield 0
stale=0
for sb0 in slices():
    magic=le32(sb0)
    if magic not in (0xfeedface,0xfeedfacf): continue
    is64=magic==0xfeedfacf; hdr=32 if is64 else 28
    ncmds=le32(sb0+16); off=sb0+hdr; sig=None
    for _ in range(ncmds):
        c=le32(off); sz=le32(off+4)
        if c==0x1d: sig=(le32(off+8), le32(off+12))
        off+=sz
    if not sig: continue
    sboff=sb0+sig[0]
    if be32(sboff)!=0xfade0cc0: continue
    cnt=be32(sboff+8)
    for i in range(cnt):
        t=be32(sboff+12+i*8); o=be32(sboff+16+i*8); cd=sboff+o
        if be32(cd)!=0xfade0c02: continue
        hashOffset=be32(cd+16); nCode=be32(cd+28); codeLimit=be32(cd+32)
        hs=data[cd+36]; ht=data[cd+37]; pl=data[cd+39]; psz=1<<pl
        ha='sha256' if ht==2 else 'sha1'
        slots=cd+hashOffset
        for p in range(nCode):
            ps=sb0+p*psz; pe=sb0+min((p+1)*psz, codeLimit)
            h=hashlib.new(ha,data[ps:pe]).digest()[:hs]
            if h!=data[slots+p*hs:slots+p*hs+hs]: stale+=1
print(stale)
