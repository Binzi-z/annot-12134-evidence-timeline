"""约束图引擎：三类顺序判定与可复核最小冲突集。

硬约束（可信证据）：
  1. seq 边：同一分区内相邻日志位置（分区内日志顺序可信）；
  2. anchor 边：签名锚点链上的相邻锚点（跨分区同样可信）。
软证据：观察时间区间，只用于注释与相容/矛盾解释，绝不单独产生顺序结论。

三类结果：
  - determined     硬约束图中存在有向路径，因果顺序确定；
  - indeterminate  同一弱连通分量内互不达，且区间相交（相容但无法排序），
                    或属于不同分量（无任何证据可比较）；
  - contradiction  硬约束有向环 / 同事件区间不相交 / 锚点链异常 / 序号重复。

所有判定仅依赖证据内容，不依赖记录的输入顺序。
"""
from __future__ import annotations

from collections import defaultdict, deque

from .anchors import analyze_anchors
from .graph import ComponentResult, Conflict, HardEdge, PairResult, TimelineResult
from .intervals import Interval
from .model import Node, Record, node_key
from .versioning import canonical_json, sha256_hex

# 单个强连通分量中最多枚举并上报的简单环数（防御性上限，不影响判定正确性）
CYCLE_REPORT_LIMIT = 16


def _make_conflict(kind: str, evidence: tuple, message: str,
                   record_hashes: list[str]) -> Conflict:
    cid = sha256_hex(
        "conflict:" + kind + "|"
        + canonical_json(sorted(evidence, key=lambda x: canonical_json(x)))
    )[:16]
    return Conflict(cid, kind, evidence, message, tuple(sorted(set(record_hashes))))


def _tarjan_scc(nodes: list[str], adj: dict[str, list[str]]) -> list[list[str]]:
    """Tarjan 强连通分量（递归实现，输入规模为单分量内的少量事件）。"""
    index = {}
    low = {}
    stack: list[str] = []
    on_stack = set()
    counter = [0]
    result: list[list[str]] = []

    def strongconnect(v: str) -> None:
        index[v] = counter[0]
        low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in adj.get(v, ()):  # 邻接表已去重
            if w not in index:
                strongconnect(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                comp.append(w)
                if w == v:
                    break
            result.append(comp)

    for v in nodes:  # nodes 已排序，保证确定性
        if v not in index:
            strongconnect(v)
    return result


def _elementary_cycles(
    nodes: list[str], adj: dict[str, list[str]], limit: int
) -> list[list[str]]:
    """枚举简单环，每个环以“最小节点为首”的规范形式只出现一次。

    对每个候选起点 s，仅访问 >= s 的节点做 DFS，找回边到 s。
    每个简单环都是边集意义上的最小不可满足子集（去掉任一边环即消失）。
    """
    cycles: list[list[str]] = []
    node_set = set(nodes)

    for s in nodes:
        if len(cycles) >= limit:
            break
        path = [s]
        on_path = {s}

        def dfs(v: str) -> None:
            if len(cycles) >= limit:
                return
            for w in adj.get(v, ()):
                if w not in node_set or w < s:
                    continue
                if w == s:
                    # 回到起点即构成简单环（path 至少有 2 个不同节点，
                    # 单节点自环在循环结束后单独处理）
                    if len(path) >= 2:
                        cycles.append(list(path))
                elif w not in on_path:
                    path.append(w)
                    on_path.add(w)
                    dfs(w)
                    path.pop()
                    on_path.discard(w)

        dfs(s)
    # 自环（u -> u）本身就是最小环
    for u in nodes:
        if u in adj.get(u, ()) and len(cycles) < limit:
            cycles.append([u])
    return cycles


def _weak_components(
    nodes: list[str], adj: dict[str, list[str]]
) -> list[list[str]]:
    undirected: dict[str, set[str]] = {n: set() for n in nodes}
    for u, outs in adj.items():
        for v in outs:
            undirected[u].add(v)
            undirected[v].add(u)
    seen: set[str] = set()
    comps: list[list[str]] = []
    for start in nodes:
        if start in seen:
            continue
        comp = []
        dq = deque([start])
        seen.add(start)
        while dq:
            v = dq.popleft()
            comp.append(v)
            for w in undirected[v]:
                if w not in seen:
                    seen.add(w)
                    dq.append(w)
        comps.append(sorted(comp))
    return comps


def _interval_note(a: Node, b: Node) -> str | None:
    if a.conflict is not None or b.conflict is not None:
        return None
    if not a.interval.overlaps(b.interval):
        if a.interval.disjoint_before(b.interval):
            return "agrees"      # 区间先后与 hard 路径方向一致
        return "disagrees"       # 时钟证据与硬顺序相反（仅注释，不单独构成矛盾）
    return "overlap"


def build_timeline(records: list[Record], trust_key: bytes) -> TimelineResult:
    # ---- 1. 内容去重（同一记录重复导入不是冲突） ---------------------------
    unique: dict[str, Record] = {}
    for r in records:
        unique[r.content_hash()] = r
    active = [r for r in unique.values() if not r.revoked]

    conflicts: list[Conflict] = []

    # ---- 2. 同分区序号冲突：相同 (partition, seq) 但内容不同 ---------------
    seq_map: dict[tuple[str, int], list[Record]] = defaultdict(list)
    for r in active:
        seq_map[(r.partition, r.seq)].append(r)
    for (part, seq), group in sorted(seq_map.items()):
        if len({r.content_hash() for r in group}) > 1:
            conflicts.append(
                _make_conflict(
                    "duplicate_sequence",
                    ("duplicate_sequence", part, seq),
                    f"分区 {part} 序号 {seq} 存在 {len(group)} 条内容不同的记录",
                    [r.content_hash() for r in group],
                )
            )

    # ---- 3. 构建事件节点：同 (cid, incarnation) 合并为同一物理操作 --------
    nodes: dict[str, Node] = {}
    grouped: dict[str, list[Record]] = defaultdict(list)
    for r in active:
        grouped[node_key(r.correlation_id, r.incarnation)].append(r)
    for key in sorted(grouped):
        group = grouped[key]
        node = Node(
            key=key,
            correlation_id=group[0].correlation_id,
            incarnation=group[0].incarnation,
            interval=group[0].interval,
            record_hashes=[],
        )
        iv: Interval | None = group[0].interval
        for r in group[1:]:
            assert iv is not None
            iv = iv.intersect(r.interval)
            if iv is None:
                break
        node.record_hashes = sorted(r.content_hash() for r in group)
        if iv is None:
            # 一维凸区间交集为空 ⇒ 必存在不相交的记录对，逐对给出最小冲突集
            node.conflict = "disjoint_intervals"
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    ri, rj = group[i], group[j]
                    if not ri.interval.overlaps(rj.interval):
                        conflicts.append(
                            _make_conflict(
                                "node_interval_disjoint",
                                (
                                    "node_interval_disjoint",
                                    key,
                                    ri.content_hash(),
                                    rj.content_hash(),
                                ),
                                f"同一事件 {key} 的两条日志时间区间不相交："
                                f"{ri.interval} vs {rj.interval}",
                                [ri.content_hash(), rj.content_hash()],
                            )
                        )
            # 保留首条区间供后续注释使用，但节点已标记冲突
            node.interval = group[0].interval
        else:
            node.interval = iv
        nodes[key] = node

    # ---- 4. 分区内顺序硬边 ------------------------------------------------
    edges: list[HardEdge] = []
    by_partition: dict[str, list[Record]] = defaultdict(list)
    for r in active:
        by_partition[r.partition].append(r)
    for part in sorted(by_partition):
        ordered = sorted(by_partition[part], key=lambda r: (r.seq, r.content_hash()))
        for prev, nxt in zip(ordered, ordered[1:]):
            if prev.seq == nxt.seq:
                continue  # 同序号重复已作为冲突上报，不产生顺序边
            edges.append(
                HardEdge(
                    src=node_key(prev.correlation_id, prev.incarnation),
                    dst=node_key(nxt.correlation_id, nxt.incarnation),
                    reason="partition_sequence",
                    evidence=("seq", part, prev.seq, nxt.seq),
                    record_hashes=(prev.content_hash(), nxt.content_hash()),
                )
            )

    # ---- 5. 签名锚点链 ----------------------------------------------------
    anchor_edges, anchor_conflicts = analyze_anchors(active, trust_key)
    edges.extend(anchor_edges)
    conflicts.extend(anchor_conflicts)

    # 边去重（同一节点对可能由 seq 与 anchor 同时支撑，保留两条不同理由的边；
    # 完全相同的硬边去重）
    dedup_edges: list[HardEdge] = []
    seen_edge: set[tuple] = set()
    for e in edges:
        sig = (e.src, e.dst, e.reason, e.evidence)
        if sig not in seen_edge:
            seen_edge.add(sig)
            dedup_edges.append(e)
    edges = dedup_edges

    # ---- 6. 邻接表 / SCC / 弱连通分量 ------------------------------------
    all_nodes = sorted(nodes)
    adj: dict[str, list[str]] = {n: [] for n in all_nodes}
    for e in edges:
        if e.dst not in adj[e.src]:
            adj[e.src].append(e.dst)
    for v in adj:
        adj[v].sort()

    sccs = _tarjan_scc(all_nodes, adj)
    scc_of: dict[str, int] = {}
    cyclic_sccs: set[int] = set()
    for idx, comp in enumerate(sccs):
        for n in comp:
            scc_of[n] = idx
        if len(comp) > 1 or comp[0] in adj.get(comp[0], ()):
            cyclic_sccs.add(idx)

    # 环 → 最小冲突集（边证据构成的简单环）
    edge_lookup: dict[tuple[str, str], list[HardEdge]] = defaultdict(list)
    for e in edges:
        edge_lookup[(e.src, e.dst)].append(e)
    for idx, comp in enumerate(sccs):
        if idx not in cyclic_sccs:
            continue
        cycles = _elementary_cycles(sorted(comp), adj, CYCLE_REPORT_LIMIT)
        for cyc in cycles:
            cyc_edges: list[HardEdge] = []
            ok = True
            for i in range(len(cyc)):
                u, v = cyc[i], cyc[(i + 1) % len(cyc)]
                if not edge_lookup.get((u, v)):
                    ok = False
                    break
                cyc_edges.append(edge_lookup[(u, v)][0])
            if not ok:
                continue
            evidence = tuple(
                sorted([e.evidence for e in cyc_edges],
                       key=lambda x: canonical_json(x))
            )
            rh = sorted({h for e in cyc_edges for h in e.record_hashes})
            conflicts.append(
                _make_conflict(
                    "ordering_cycle",
                    ("ordering_cycle",) + evidence,
                    f"硬约束有向环：{' -> '.join(cyc)} -> {cyc[0]}",
                    rh,
                )
            )

    weak_comps = _weak_components(all_nodes, adj)

    # ---- 7. 分量内可达性与三类判定 ---------------------------------------
    pair_index: dict[str, PairResult] = {}
    component_results: list[ComponentResult] = []

    for comp_nodes in weak_comps:
        cset = set(comp_nodes)
        reach: dict[str, set[str]] = {}
        for src in comp_nodes:
            seen = {src}
            dq = deque([src])
            while dq:
                v = dq.popleft()
                for w in adj.get(v, ()):
                    if w in cset and w not in seen:
                        seen.add(w)
                        dq.append(w)
            reach[src] = seen

        pairs: list[PairResult] = []
        for i in range(len(comp_nodes)):
            for j in range(i + 1, len(comp_nodes)):
                u, v = comp_nodes[i], comp_nodes[j]
                in_cycle = (
                    scc_of[u] == scc_of[v] and scc_of[u] in cyclic_sccs
                )
                if in_cycle:
                    pr = PairResult(u, v, "contradiction",
                                    "mutually_reachable_hard_edges")
                elif v in reach[u]:
                    note = _interval_note(nodes[u], nodes[v])
                    pr = PairResult(
                        u, v, "determined", "hard_path",
                        interval_note=note,
                        via=tuple(_one_path(u, v, adj, cset)),
                    )
                elif u in reach[v]:
                    note = _interval_note(nodes[v], nodes[u])
                    pr = PairResult(
                        v, u, "determined", "hard_path",
                        interval_note=note,
                        via=tuple(_one_path(v, u, adj, cset)),
                    )
                else:
                    nu, nv = nodes[u], nodes[v]
                    if (
                        nu.conflict is None and nv.conflict is None
                        and not nu.interval.overlaps(nv.interval)
                    ):
                        # 区间不相交给出了“顺序暗示”，但没有任何硬约束支撑，
                        # 时钟可能跳变/漂移，故仍判无法排序，仅标注分歧。
                        pr = PairResult(
                            u, v, "indeterminate",
                            "disjoint_intervals_without_hard_evidence",
                            interval_note="disjoint_no_hard_edge",
                        )
                    else:
                        pr = PairResult(
                            u, v, "indeterminate",
                            "intervals_compatible_no_hard_path",
                            interval_note=_interval_note(nu, nv),
                        )
                pairs.append(pr)
                pair_index[f"{pr.src}|{pr.dst}"] = pr

        comp_conflicts = [
            c for c in conflicts
            if any(h in {rh for n in comp_nodes
                         for rh in nodes[n].record_hashes}
                   for h in c.record_hashes)
        ]
        status = "contradictory" if comp_conflicts else "consistent"

        digest = sha256_hex(
            canonical_json(
                {
                    "nodes": comp_nodes,
                    "edges": sorted(
                        [
                            {
                                "src": e.src, "dst": e.dst, "reason": e.reason,
                                "evidence": list(e.evidence),
                                "record_hashes": list(e.record_hashes),
                            }
                            for e in edges
                            if e.src in cset and e.dst in cset
                        ],
                        key=lambda x: canonical_json(x),
                    ),
                    "conflicts": sorted(
                        [
                            {"kind": c.kind, "evidence": list(c.evidence)}
                            for c in comp_conflicts
                        ],
                        key=lambda x: canonical_json(x),
                    ),
                }
            )
        )
        component_results.append(
            ComponentResult(
                component_id="C" + digest[:12],
                nodes=tuple(comp_nodes),
                status=status,
                conflicts=comp_conflicts,
                pairs=pairs,
                digest=digest,
            )
        )

    stats = {
        "records_total": len(records),
        "records_active": len(active),
        "records_revoked": sum(1 for r in records if r.revoked),
        "records_duplicate_imports": len(records) - len(unique),
        "nodes": len(nodes),
        "hard_edges": len(edges),
        "conflicts": len(conflicts),
        "components": len(component_results),
        "pairs_determined": sum(
            1 for p in pair_index.values() if p.category == "determined"
        ),
        "pairs_indeterminate": sum(
            1 for p in pair_index.values() if p.category == "indeterminate"
        ),
        "pairs_contradiction": sum(
            1 for p in pair_index.values() if p.category == "contradiction"
        ),
    }
    return TimelineResult(
        nodes=nodes,
        edges=edges,
        conflicts=conflicts,
        components=component_results,
        pair_index=pair_index,
        stats=stats,
    )


def _one_path(src: str, dst: str, adj: dict[str, list[str]],
              allowed: set[str]) -> list[str]:
    """BFS 取一条 src→dst 的有向路径（确定性：邻接表已排序）。"""
    prev = {src: None}
    dq = deque([src])
    while dq:
        v = dq.popleft()
        if v == dst:
            break
        for w in adj.get(v, ()):
            if w in allowed and w not in prev:
                prev[w] = v
                dq.append(w)
    path = [dst]
    while prev[path[-1]] is not None:
        path.append(prev[path[-1]])  # type: ignore[arg-type]
    path.reverse()
    return path
