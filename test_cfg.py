import sys, struct
sys.path.insert(0, '.')
from cfg_builder import CFG

def parse_mz_header(data):
    fields = struct.unpack_from('<14H', data, 2)
    names = ['e_cblp','e_cp','e_crlc','e_cparhdr','e_minalloc','e_maxalloc',
             'e_ss','e_sp','e_csum','e_ip','e_cs','e_lfarlc','e_ovno']
    h = dict(zip(names, fields[:13]))
    h['header_bytes'] = h['e_cparhdr'] * 16
    return h

with open('<filename>','rb') as f:
    data = f.read()

header = parse_mz_header(data)
header_bytes = header['header_bytes']
entry_addr = header_bytes + header['e_cs']*16 + header['e_ip']
print(f"header_bytes=0x{header_bytes:x}, entry CS:IP={header['e_cs']:04x}:{header['e_ip']:04x}")
print(f"Entry point (file address): 0x{entry_addr:x}")

cfg = CFG(data, header_bytes)
cfg.build(entry_addr)

print(f"\nTotal instructions visited by real control flow: {len(cfg.instrs)}")
print(f"Entry points (entry_points, i.e. call/jmp targets + start): {len(cfg.entry_points)}")
print(f"call targets: {len(cfg.call_targets)}")
print(f"Indirect transfers (target unknown, honestly stopped): {len(cfg.indirect_transfers)}")

seg1000_lo, seg1000_hi = header_bytes, header_bytes + 0x9bd0
in_seg1000 = [a for a in cfg.instrs if seg1000_lo <= a < seg1000_hi]
print(f"\nInstructions in the 'segment 1000' range (user calculation logic): {len(in_seg1000)}")
