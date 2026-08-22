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

with open('/mnt/user-data/uploads/KONN2_UN.EXE','rb') as f:
    data = f.read()

header = parse_mz_header(data)
header_bytes = header['header_bytes']
entry_addr = header_bytes + header['e_cs']*16 + header['e_ip']
print(f"header_bytes=0x{header_bytes:x}, entry CS:IP={header['e_cs']:04x}:{header['e_ip']:04x}")
print(f"Точка входа (файловый адрес): 0x{entry_addr:x}")

cfg = CFG(data, header_bytes)
cfg.build(entry_addr)

print(f"\nВсего инструкций пройдено реальным потоком управления: {len(cfg.instrs)}")
print(f"Точек входа (entry_points, т.е. call/jmp целей + старт): {len(cfg.entry_points)}")
print(f"call-целей: {len(cfg.call_targets)}")
print(f"Нестандартных (не возвращаются обычным образом): {len(cfg.no_return_targets)}")
print(f"Предупреждений о наложении (overlap): {len(cfg.overlap_warnings)}")
print(f"Косвенных переходов (цель неизвестна, честно остановились): {len(cfg.indirect_transfers)}")
for a in cfg.indirect_transfers:
    print(f"  0x{a:x}: {cfg.instrs[a].mnemonic}")

seg1000_lo, seg1000_hi = header_bytes, header_bytes + 0x9bd0
in_seg1000 = [a for a in cfg.instrs if seg1000_lo <= a < seg1000_hi]
print(f"\nИнструкций в диапазоне 'сегмента 1000' (расчётная логика): {len(in_seg1000)}")
