"""
cfg_builder.py — построение графа потока управления через реальный
worklist-алгоритм (рекурсивный спуск), а не линейное чтение диапазона.

Идея: держим множество "куда дойти" (адреса, откуда реально начинается
исполнение — вход программы, цели переходов, цели call). Идём от каждого
такого адреса ПРЯМО, инструкция за инструкцией, пока не встретим что-то,
что меняет поток управления. Байты, до которых мы не дошли таким образом,
никогда не дизассемблируются.
"""
import sys
sys.path.insert(0, '/home/claude/cfg_version')
from decoder import decode_one, Instr


class CFG:
    def __init__(self, data, header_bytes):
        self.data = data
        self.header_bytes = header_bytes
        self.instrs = {}            # addr -> Instr, для ВСЕХ реально пройденных инструкций
        self.visited = set()        # адреса начала инструкций, которые мы уже декодировали
        self.call_targets = set()   # адреса, куда есть хотя бы один call/lcall
        self.jump_targets = set()   # адреса, куда есть хотя бы один jmp/jcc
        self.entry_points = set()   # все места, откуда МЫ САМИ начинали новый проход
                                     # (вход программы + все call/jmp цели) — полезно
                                     # для последующего разбиения на подпрограммы
        self.no_return_targets = set()   # call-цели, помеченные как "не возвращается
                                          # обычным образом" (см. is_non_standard_callee)
        self.overlap_warnings = []  # (addr, existing_instr_addr) — новая точка входа
                                     # попала В СЕРЕДИНУ уже декодированной инструкции
        self.indirect_transfers = []  # адреса косвенных jmp/call — цель неизвестна,
                                       # честно зафиксированы, а не проигнорированы

    def _decode(self, addr):
        return decode_one(self.data, addr, header_bytes=self.header_bytes)

    def is_non_standard_callee(self, addr):
        """Проверяем ПЕРВУЮ инструкцию по адресу addr — если это 'pop', то это,
           скорее всего, нестандартный вызов, который использует свой же адрес
           возврата как данные (см. найденный ранее трюк с встроенным текстом) —
           тогда НЕЛЬЗЯ добавлять точку возврата (адрес после call) в очередь,
           потому что там реально нет исполняемого кода (там встроенные данные)."""
        if addr >= len(self.data):
            return False
        probe = self._decode(addr)
        return probe.kind == 'X86' and probe.mnemonic.startswith('pop')

    def _find_overlap(self, addr):
        """Проверяет, не попадает ли addr в СЕРЕДИНУ уже декодированной инструкции."""
        for existing_addr, instr in self.instrs.items():
            if existing_addr < addr < existing_addr + instr.length:
                return existing_addr
        return None

    def build(self, entry_addr, max_instrs=2_000_000):
        worklist = [entry_addr]
        self.entry_points.add(entry_addr)
        count = 0

        while worklist:
            addr = worklist.pop()
            if addr in self.visited:
                continue

            overlap = self._find_overlap(addr)
            if overlap is not None:
                self.overlap_warnings.append((addr, overlap))
                continue  # не дизассемблируем поверх середины другой инструкции

            cur = addr
            while True:
                if cur in self.visited:
                    break  # слились с уже пройденным путём — это нормально, останавливаемся
                overlap = self._find_overlap(cur)
                if overlap is not None:
                    self.overlap_warnings.append((cur, overlap))
                    break

                instr = self._decode(cur)
                self.visited.add(cur)
                self.instrs[cur] = instr
                count += 1
                if count > max_instrs:
                    return  # защита от неограниченного роста на случай серьёзной ошибки

                if instr.kind == 'BAD':
                    break  # дошли до чего-то нерасшифровываемого — останавливаемся здесь

                if instr.is_ret:
                    break

                if instr.is_indirect:
                    self.indirect_transfers.append(cur)
                    break  # цель неизвестна — честно останавливаемся, не гадаем
                           # и не продолжаем линейно (там могут быть данные)

                if instr.is_call:
                    self.call_targets.add(instr.target)
                    if instr.target not in self.entry_points:
                        self.entry_points.add(instr.target)
                        worklist.append(instr.target)
                    if self.is_non_standard_callee(instr.target):
                        self.no_return_targets.add(instr.target)
                        break  # не продолжаем линейно — после такого call
                               # управление реально НЕ возвращается сюда
                    cur = cur + instr.length
                    continue

                if instr.is_jmp:
                    self.jump_targets.add(instr.target)
                    if instr.target not in self.entry_points:
                        self.entry_points.add(instr.target)
                    worklist.append(instr.target)
                    break

                if instr.is_jcc:
                    self.jump_targets.add(instr.target)
                    if instr.target not in self.entry_points:
                        self.entry_points.add(instr.target)
                    worklist.append(instr.target)
                    cur = cur + instr.length
                    continue

                cur = cur + instr.length

    def ordered_instrs(self):
        return [self.instrs[a] for a in sorted(self.instrs)]
