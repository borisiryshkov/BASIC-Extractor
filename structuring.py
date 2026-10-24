"""
structuring.py -- honest if/while structuring via DOMINATORS and
POST-DOMINATORS, replacing the detect_ladder()/render_ladder() heuristic
from the linear extractor.

Interface is identical to the old one: structure_pseudocode(lines) -> str.
The input line format is the same one build_pseudocode() from
pseudocode.py produces: "CODE:addr: TEXT" (PRINT/INPUT/FORMULA/IF (..) GOTO/
jmp/RETURN/CALL_SUB/comments).
"""
import re

LINE_RE = re.compile(r"^CODE:([0-9a-f]+): (.+)$")
GOTO_RE = re.compile(r"GOTO (0x[0-9a-f]+)")
JMP_RE = re.compile(r"^jmp (0x[0-9a-f]+)")
IF_RE = re.compile(r"^IF \((.+)\) GOTO 0x[0-9a-f]+")
UNRECOGNISED_JCC_RE = re.compile(
    r"^(j[a-z]+) (0x[0-9a-f]+)(?: \(raw (0x[0-9a-f]+)\))?  \[condition not recognised\]$")


class Stmt:
    __slots__ = ('addr', 'kind', 'text', 'target', 'cond')

    def __init__(self, addr, kind, text, target=None, cond=None):
        self.addr = addr; self.kind = kind; self.text = text
        self.target = target; self.cond = cond

    def __repr__(self):
        return f"<{self.kind} @{self.addr:04x} target={self.target}>"


def parse_statements(lines):
    stmts = []
    for line in lines:
        if line.startswith(';') or not line.strip():
            continue
        m = LINE_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        rest = m.group(2)
        if rest.startswith('PRINT '):
            stmts.append(Stmt(addr, 'PRINT', rest))
        elif rest.startswith('INPUT -> '):
            stmts.append(Stmt(addr, 'INPUT', rest))
        elif rest.startswith('FORMULA '):
            stmts.append(Stmt(addr, 'FORMULA', rest))
        elif rest.startswith('CALL_SUB '):
            stmts.append(Stmt(addr, 'CALL_SUB', rest))
        elif rest.startswith('IF ('):
            gm = GOTO_RE.search(rest); im = IF_RE.match(rest)
            target = int(gm.group(1), 16) if gm else None
            cond = im.group(1) if im else '?'
            stmts.append(Stmt(addr, 'IF', rest, target, cond))
        elif rest.startswith('jmp '):
            jm = JMP_RE.match(rest)
            target = int(jm.group(1), 16) if jm else None
            stmts.append(Stmt(addr, 'JMP', rest, target))
        elif rest.startswith('RETURN'):
            stmts.append(Stmt(addr, 'RETURN', rest))
        else:
            um = UNRECOGNISED_JCC_RE.match(rest)
            if um:
                jcc = um.group(1)
                target = int(um.group(2), 16)
                # The condition is semantically unrecognised (e.g. a
                # carry/zero check after a call, which parse_cmp_operands
                # doesn't know how to interpret) -- BUT the graph edge
                # itself genuinely exists and must be kept, otherwise
                # structuring would work on a knowingly incomplete CFG.
                # We mark the condition as opaque.
                stmts.append(Stmt(addr, 'IF', rest, target,
                                   cond=f"<{jcc}, condition not recognised>"))
    return stmts


def build_index(stmts):
    return {s.addr: i for i, s in enumerate(stmts)}


def make_target_resolver(stmts):
    """Comment-only labels ("; jump target label") don't produce a Stmt, so
       a jump target may point to an address with no node in the graph --
       we snap it forward to the nearest FOLLOWING real Stmt (the same
       principle as snap() in build_pseudocode, just one level up)."""
    import bisect
    addrs = [s.addr for s in stmts]

    def resolve(target_addr):
        if target_addr is None:
            return None
        i = bisect.bisect_left(addrs, target_addr)
        return i if i < len(addrs) else None
    return resolve


def build_successors(stmts, addr2idx, resolve_target=None):
    n = len(stmts)
    succ = {i: [] for i in range(n)}
    if resolve_target is None:
        resolve_target = lambda a: addr2idx.get(a)
    for i, s in enumerate(stmts):
        if s.kind == 'IF':
            t = resolve_target(s.target)
            if t is not None:
                succ[i].append(t)
            if i + 1 < n:
                succ[i].append(i + 1)
        elif s.kind == 'JMP':
            t = resolve_target(s.target)
            if t is not None:
                succ[i].append(t)
            # an unconditional jmp with an unresolved target -- a dead end
            # (same as in the old code)
        elif s.kind == 'RETURN':
            pass
        else:
            if i + 1 < n:
                succ[i].append(i + 1)
    return succ


def build_predecessors(nodes, succ):
    pred = {u: [] for u in nodes}
    for u in nodes:
        for v in succ.get(u, []):
            if v in pred:
                pred[v].append(u)
    return pred


def reachable_from(entry, succ):
    seen = {entry}
    stack = [entry]
    while stack:
        u = stack.pop()
        for v in succ.get(u, []):
            if v not in seen:
                seen.add(v); stack.append(v)
    return seen


# ============================================================================
# ================= Dominators (iterative fixed point) ======================
def compute_dominators(entry, succ, nodes):
    """nodes -- the set of nodes (including entry). succ -- dict node ->
       list of successors (may point outside nodes -- such edges are
       ignored, as leaving the analyzed area)."""
    nodes = set(nodes)
    pred = build_predecessors(nodes, succ)

    dom = {u: set(nodes) for u in nodes}
    dom[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for u in nodes:
            if u == entry:
                continue
            preds = [p for p in pred[u] if p in dom]
            if not preds:
                new_dom = {u}
            else:
                new_dom = None
                for p in preds:
                    new_dom = set(dom[p]) if new_dom is None else (new_dom & dom[p])
                new_dom.add(u)
            if new_dom != dom[u]:
                dom[u] = new_dom
                changed = True
    return dom


def immediate_dominator_map(entry, dom, nodes):
    """idom(u) -- the element of dom[u]\\{u} with the largest |dom[.]|
       (the dominators of a node form a chain from the entry down to u, so
       the "closest" dominator is the one whose own dominator set is
       itself the largest)."""
    idom = {entry: None}
    for u in nodes:
        if u == entry:
            continue
        candidates = dom[u] - {u}
        if not candidates:
            idom[u] = None
            continue
        idom[u] = max(candidates, key=lambda d: len(dom[d]))
    return idom


def dominator_children(idom, nodes):
    children = {u: [] for u in nodes}
    for u, p in idom.items():
        if p is not None:
            children.setdefault(p, []).append(u)
    return children


# ============================================================================
# ================= Post-dominators (same algorithm, reversed graph) ========
SINK = -1


def compute_postdominators(nodes, succ):
    """Build the reversed graph with a virtual sink SINK, reached by edges
       from every node with no successors within nodes (real exits --
       RETURN, dead-end jumps). Dominators of SINK in the reversed graph
       are the post-dominators of the original graph."""
    nodes = set(nodes)
    rev_succ = {u: [] for u in nodes}
    rev_succ[SINK] = []
    for u in nodes:
        outs = [v for v in succ.get(u, []) if v in nodes]
        if not outs:
            rev_succ[SINK].append(u)
        for v in outs:
            rev_succ[v].append(u)
    all_nodes = nodes | {SINK}
    pdom = compute_dominators(SINK, rev_succ, all_nodes)
    return pdom


# ============================================================================
# ================= Natural loops (back edges) =======================
def find_back_edges(nodes, succ, dom):
    back_edges = []
    for u in nodes:
        for v in succ.get(u, []):
            if v in nodes and v in dom.get(u, set()):
                back_edges.append((u, v))
    return back_edges


def natural_loop_body(u, v, pred):
    """The natural-loop body for back edge u->v (v is the header): every
       node from which u can be reached without passing through v."""
    loop = {v, u}
    stack = [] if u == v else [u]
    while stack:
        w = stack.pop()
        for p in pred.get(w, []):
            if p not in loop:
                loop.add(p)
                stack.append(p)
    return loop


def merge_loops_by_header(back_edges, nodes, pred):
    """Several back edges into the same header (e.g. 'continue' from
       different places in the loop) -- merge the bodies into one whole."""
    loops = {}  # header -> set(body)
    tails = {}  # header -> set(tail)
    for u, v in back_edges:
        body = natural_loop_body(u, v, pred)
        loops[v] = loops.get(v, set()) | body
        tails.setdefault(v, set()).add(u)
    return loops, tails


# ============================================================================
# ================= Rendering the structure =======================================
INDENT = "    "


def stmt_text(s):
    if s.kind == 'CALL_SUB':
        m = re.match(r"CALL_SUB (0x[0-9a-f]+)", s.text)
        if m:
            return f"sub_{m.group(1)}()"
        return s.text
    return s.text


class Structurer:
    def __init__(self, stmts, addr2idx):
        self.stmts = stmts
        self.addr2idx = addr2idx
        self.n = len(stmts)
        resolve_target = make_target_resolver(stmts)
        self.succ = build_successors(stmts, addr2idx, resolve_target)
        self.entry = 0 if self.n else None
        if self.entry is None:
            self.reach = set()
            self.dom = {}
            self.pdom = {}
            self.loops = {}
            self.tails = {}
            return
        self.reach = reachable_from(self.entry, self.succ)
        self.pred = build_predecessors(self.reach, self.succ)
        self.dom = compute_dominators(self.entry, self.succ, self.reach)
        self.pdom = compute_postdominators(self.reach, self.succ)
        back_edges = find_back_edges(self.reach, self.succ, self.dom)
        self.loops, self.tails = merge_loops_by_header(back_edges, self.reach, self.pred)
        # loop_of[node] = header of the MOST DEEPLY NESTED loop containing node
        self.loop_of = {}
        for header, body in sorted(self.loops.items(), key=lambda kv: -len(kv[1])):
            for node in body:
                self.loop_of[node] = header  # a deeper (smaller) iteration will overwrite

    def ipdom(self, i):
        cand = self.pdom.get(i, set()) - {i}
        if not cand:
            return None
        best = max(cand, key=lambda d: len(self.pdom.get(d, set())))
        return best if best != SINK else None

    def render(self, out=None):
        if self.entry is None:
            return ""
        out = []
        self._render_region(self.entry, stop=None, out=out, depth=0, loop_ctx=None)
        return "\n".join(out)

    def _render_region(self, start, stop, out, depth, loop_ctx):
        """Renders the chain of nodes starting at start until we reach stop
           (exclusive) -- or the end of the reachable graph. loop_ctx is
           (header, tails) of the currently enclosing loop, if any (needed
           to correctly treat a back edge as continue/break)."""
        pad = INDENT * depth
        i = start
        visited_here = set()
        while i is not None and i != stop and i not in visited_here:
            visited_here.add(i)

            # Entering a new (deeper) loop with header i?
            if i in self.loops and (loop_ctx is None or i != loop_ctx[0]) and \
               self.loop_of.get(i) == i:
                header = i
                body = self.loops[header]
                tails = self.tails[header]
                out.append(f"{pad}while True:  # loop, header Stmt#{header} "
                           f"(addr 0x{self.stmts[header].addr:04x})")
                exit_i = self._render_loop_body(header, body, tails, out, depth + 1)
                i = exit_i
                continue

            s = self.stmts[i]
            if s.kind == 'IF':
                merge = self.ipdom(i)
                targets = self.succ[i]  # [taken, fallthrough] or fewer
                taken = targets[0] if targets else None
                fall = targets[1] if len(targets) > 1 else None
                if fall is not None and (merge is None or fall == merge or
                                          fall not in (self.reach - {stop} if stop is not None else self.reach)):
                    # Normal case: the fallthrough IS the "else" branch,
                    # taken is the "if" body. If taken itself leads
                    # straight to merge -- it just means "if (cond):
                    # <empty/skip>".
                    out.append(f"{pad}if {s.cond}:")
                    body_stop = merge if merge is not None else stop
                    sub_out = []
                    self._render_region(taken, body_stop, sub_out, depth + 1, loop_ctx)
                    out.extend(sub_out if sub_out else [f"{pad}{INDENT}pass"])
                    i = merge if merge is not None else fall
                    if i is None:
                        i = fall
                    continue
                else:
                    out.append(f"{pad}if {s.cond}:  # [branch not structured unambiguously]")
                    out.append(f"{pad}{INDENT}pass  # goto Stmt#{taken}")
                    i = fall if fall is not None else None
                    continue

            elif s.kind == 'JMP':
                t = self.succ[i][0] if self.succ[i] else None
                if loop_ctx is not None:
                    header, tails = loop_ctx
                    if t == header:
                        out.append(f"{pad}continue")
                        return  # exit the current region render (see the caller)
                    if t is not None and t not in self.loops.get(header, set()):
                        out.append(f"{pad}break  # goto Stmt#{t} (leaving the loop)")
                        return
                if t is not None:
                    i = t
                    continue
                else:
                    out.append(f"{pad}pass  # jmp to an unresolved address")
                    return

            elif s.kind == 'RETURN':
                out.append(f"{pad}return")
                return

            else:  # PRINT / INPUT / FORMULA / CALL_SUB
                out.append(f"{pad}{stmt_text(s)}")
                i = self.succ[i][0] if self.succ[i] else None

        return

    def _render_loop_body(self, header, body, tails, out, depth):
        """Renders the body of the loop with header `header`. Returns the
           index of the node RIGHT AFTER the loop (where the caller's
           region render should continue), or None if there is no ordinary
           exit from the loop (e.g. the only exit is a return from
           inside)."""
        pad = INDENT * depth
        loop_ctx = (header, tails)
        exit_targets = set()

        i = header
        visited_here = set()
        while i is not None and i not in visited_here:
            visited_here.add(i)
            if i not in body:
                # reached a node OUTSIDE the loop body -- a natural exit
                exit_targets.add(i)
                break
            s = self.stmts[i]

            if i in self.loops and i != header and self.loop_of.get(i) == i:
                inner_header = i
                inner_body = self.loops[inner_header]
                inner_tails = self.tails[inner_header]
                out.append(f"{pad}while True:  # nested loop, header Stmt#{inner_header}")
                nxt = self._render_loop_body(inner_header, inner_body, inner_tails, out, depth + 1)
                if nxt is None or nxt not in body:
                    if nxt is not None:
                        exit_targets.add(nxt)
                    break
                i = nxt
                continue

            if s.kind == 'IF':
                targets = self.succ[i]
                taken = targets[0] if targets else None
                fall = targets[1] if len(targets) > 1 else None
                taken_in_body = taken in body
                fall_in_body = fall in body if fall is not None else False

                if taken == header:
                    out.append(f"{pad}if {s.cond}:")
                    out.append(f"{pad}{INDENT}continue")
                    if fall_in_body:
                        i = fall; continue
                    else:
                        if fall is not None:
                            exit_targets.add(fall)
                        break
                if fall == header:
                    out.append(f"{pad}if not ({s.cond}):")
                    out.append(f"{pad}{INDENT}continue")
                    if taken_in_body:
                        i = taken; continue
                    else:
                        if taken is not None:
                            exit_targets.add(taken)
                        break
                if taken is not None and not taken_in_body:
                    out.append(f"{pad}if {s.cond}:")
                    out.append(f"{pad}{INDENT}break  # goto Stmt#{taken} (leaving the loop)")
                    exit_targets.add(taken)
                    if fall_in_body:
                        i = fall; continue
                    else:
                        break
                if fall is not None and not fall_in_body:
                    out.append(f"{pad}if not ({s.cond}):")
                    out.append(f"{pad}{INDENT}break  # goto Stmt#{fall} (leaving the loop)")
                    exit_targets.add(fall)
                    if taken_in_body:
                        i = taken; continue
                    else:
                        break
                # both branches are inside the loop body -- an ordinary if/else inside the loop
                merge = self.ipdom(i)
                out.append(f"{pad}if {s.cond}:")
                sub_out = []
                self._render_region(taken, merge, sub_out, depth + 1, loop_ctx)
                out.extend(sub_out if sub_out else [f"{pad}{INDENT}pass"])
                i = merge if merge is not None else fall
                continue

            elif s.kind == 'JMP':
                t = self.succ[i][0] if self.succ[i] else None
                if t == header:
                    out.append(f"{pad}continue")
                    break
                if t is not None and t not in body:
                    out.append(f"{pad}break  # goto Stmt#{t} (leaving the loop)")
                    exit_targets.add(t)
                    break
                if t is not None:
                    i = t; continue
                out.append(f"{pad}pass  # jmp to an unresolved address")
                break

            elif s.kind == 'RETURN':
                out.append(f"{pad}return")
                break

            else:
                out.append(f"{pad}{stmt_text(s)}")
                i = self.succ[i][0] if self.succ[i] else None

        if len(exit_targets) == 1:
            return next(iter(exit_targets))
        elif len(exit_targets) > 1:
            # several different exit points -- take the header's common
            # post-dominator as the most likely "place after the loop"
            return self.ipdom(header)
        return None


def structure_pseudocode(lines):
    """Public interface, identical to the old structure_pseudocode(lines)."""
    stmts = parse_statements(lines)
    addr2idx = build_index(stmts)
    s = Structurer(stmts, addr2idx)
    return s.render()
