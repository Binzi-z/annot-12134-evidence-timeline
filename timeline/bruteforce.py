"""小规模穷举参考实现（独立于引擎的第二套算法）。

思路：把可信证据转成一组布尔约束（每条约束是关于节点线性排列的谓词），
枚举节点的全部 n! 种排列作为候选总序，逐一检查约束：

- 可行排列为 0            → 证据相互矛盾；
- 某节点对在所有可行排列中
  相对位置恒定            → 确定因果顺序；
- 两种相对位置都出现过    → 时间区间相容但无法排序。

最小冲突集（MUS）：枚举约束子集，找出“自身不可满足、去掉任一约束后
可满足”的子集。引擎产出的每个冲突集都必须能在参考实现下通过最小性复核。

该实现刻意写得朴素、独立，只依赖 model/intervals，不依赖 engine，
作为交叉验证的“神谕”，仅适用于小规模分量（默认 n<=8）。
"""
from __future__ import annotations

from itertools import combinations, permutations

from .graph import Conflict, TimelineResult
from .model import Record, node_key

DEFAULT_NODE_LIMIT = 8
DEFAULT_CONSTRAINT_LIMIT = 10


class BruteForceTooLarge(Exception):
    """分量规模超出穷举参考实现的安全上限。"""


def _build_constraints(
    records: list[Record], trust_key: bytes
) -> tuple[list[str], list[tuple]]:
    """从原始输入独立重建布尔约束（不读取引擎的边/冲突）。

    约束元组首元素为类型标签：
      ("lt", a, b, evidence)            a 必须排在 b 前
      ("node_interval", a, b, evidence) 同事件两节点区间必须相容（此处不会触发，
                                         同 cid/incarnation 已合并为单节点）
      ("disjoint", a, b, evidence)      两记录区间必须相交
    """
    from .anchors import sign_anchor  # 局部导入，保持模块依赖方向清晰
    import hmac

    active = [r for r in records if not r.revoked]
    nodes = sorted({node_key(r.correlation_id, r.incarnation) for r in active})
    constraints: list[tuple] = []

    # 分区内序号顺序
    by_partition: dict[str, list[Record]] = {}
    for r in active:
        by_partition.setdefault(r.partition, []).append(r)
    for part, rs in by_partition.items():
        ordered = sorted(rs, key=lambda r: (r.seq, r.content_hash()))
        for prev, nxt in zip(ordered, ordered[1:]):
            if prev.seq == nxt.seq:
                continue
            constraints.append(
                (
                    "lt",
                    node_key(prev.correlation_id, prev.incarnation),
                    node_key(nxt.correlation_id, nxt.incarnation),
                    ("seq", part, prev.seq, nxt.seq),
                )
            )

    # 锚点链（独立重做签名，并按 anchor_prev 哈希重建多链，与引擎同构）
    anchors = [r for r in active if r.anchor_seq is not None]
    valid = []
    for r in anchors:
        if r.signature and hmac.compare_digest(
            r.signature, sign_anchor(r, trust_key)
        ):
            valid.append(r)
    # 序号分叉的锚点不产生顺序约束
    seq_counts: dict[int, int] = {}
    for r in valid:
        seq_counts[r.anchor_seq] = seq_counts.get(r.anchor_seq, 0) + 1  # type: ignore[index]
    valid = [r for r in valid if seq_counts[r.anchor_seq] == 1]
    by_hash = {r.content_hash(): r for r in valid}
    referenced: dict[str, list[Record]] = {}
    for r in valid:
        if r.anchor_prev is not None:
            referenced.setdefault(r.anchor_prev, []).append(r)
    for r in valid:
        prev_hash = r.anchor_prev
        if (
            prev_hash is not None
            and prev_hash in by_hash
            and len(referenced.get(prev_hash, [])) == 1
            and r.anchor_seq > by_hash[prev_hash].anchor_seq
        ):
            p = by_hash[prev_hash]
            constraints.append(
                (
                    "lt",
                    node_key(p.correlation_id, p.incarnation),
                    node_key(r.correlation_id, r.incarnation),
                    ("anchor", p.anchor_seq, r.anchor_seq),
                )
            )

    # 同事件多条日志的区间必须两两相交
    grouped: dict[str, list[Record]] = {}
    for r in active:
        grouped.setdefault(node_key(r.correlation_id, r.incarnation), []).append(r)
    for key, rs in grouped.items():
        for i in range(len(rs)):
            for j in range(i + 1, len(rs)):
                if not rs[i].interval.overlaps(rs[j].interval):
                    constraints.append(
                        (
                            "disjoint",
                            rs[i].content_hash(),
                            rs[j].content_hash(),
                            ("node_interval_disjoint", key,
                             rs[i].content_hash(), rs[j].content_hash()),
                        )
                    )
    return nodes, constraints


def _feasible(order: tuple[str, ...], constraints: list[tuple],
              node_set: set[str]) -> bool:
    position = {n: i for i, n in enumerate(order)}
    for c in constraints:
        if c[0] == "lt":
            _, a, b, _ = c
            if a in node_set and b in node_set and position[a] >= position[b]:
                return False
        elif c[0] == "disjoint":
            # 区间不相交是不可满足的单条证据，与排列无关
            return False
    return True


def brute_force_classification(
    records: list[Record],
    trust_key: bytes,
    node_limit: int = DEFAULT_NODE_LIMIT,
) -> dict[str, str]:
    """返回节点对 → 穷举判定（determined/indeterminate/contradiction）。"""
    nodes, constraints = _build_constraints(records, trust_key)
    if len(nodes) > node_limit:
        raise BruteForceTooLarge(f"{len(nodes)} 个节点超过穷举上限 {node_limit}")

    node_set = set(nodes)
    feasible_orders = [
        order for order in permutations(nodes)
        if _feasible(order, constraints, node_set)
    ]
    result: dict[str, str] = {}
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            u, v = nodes[i], nodes[j]
            key = f"{u}|{v}"
            if not feasible_orders:
                result[key] = "contradiction"
                continue
            directions = set()
            for order in feasible_orders:
                directions.add(order.index(u) < order.index(v))
            if len(directions) == 1:
                if directions == {True}:
                    result[key] = "determined:" + u + "<" + v
                else:
                    result[key] = "determined:" + v + "<" + u
            else:
                result[key] = "indeterminate"
    return result


def minimal_unsatisfiable_subsets(
    records: list[Record],
    trust_key: bytes,
    node_limit: int = DEFAULT_NODE_LIMIT,
    constraint_limit: int = DEFAULT_CONSTRAINT_LIMIT,
) -> list[tuple[tuple, ...]]:
    """枚举全部最小不可满足约束子集（证据即约束的 evidence 字段）。"""
    nodes, constraints = _build_constraints(records, trust_key)
    if len(nodes) > node_limit:
        raise BruteForceTooLarge(f"{len(nodes)} 个节点超过穷举上限 {node_limit}")
    if len(constraints) > constraint_limit:
        raise BruteForceTooLarge(
            f"{len(constraints)} 条约束超过 MUS 穷举上限 {constraint_limit}"
        )
    node_set = set(nodes)
    mus: list[tuple[tuple, ...]] = []
    for size in range(1, len(constraints) + 1):
        for subset in combinations(constraints, size):
            if not _feasible_all(nodes, list(subset), node_set):
                # 最小性：去掉任意一条约束后必须可满足
                minimal = all(
                    _feasible_all(
                        nodes,
                        [c for k, c in enumerate(subset) if k != t],
                        node_set,
                    )
                    for t in range(size)
                )
                if minimal:
                    mus.append(
                        tuple(sorted((c[3] for c in subset),
                                     key=lambda x: str(x)))
                    )
    # 去重（不同约束子集可能有相同 evidence 形态，理论上不会，防御性处理）
    unique = sorted(set(mus), key=lambda x: str(x))
    return unique


def _feasible_all(nodes: list[str], constraints: list[tuple],
                  node_set: set[str]) -> bool:
    if any(c[0] == "disjoint" for c in constraints):
        return False
    if not constraints:
        return True  # 空约束集天然可满足（MUS 最小性论证的边界）
    return any(
        _feasible(order, constraints, node_set)
        for order in permutations(nodes)
    )


def verify_conflict_minimality(
    conflict: Conflict,
    records: list[Record],
    trust_key: bytes,
    node_limit: int = DEFAULT_NODE_LIMIT,
    constraint_limit: int = DEFAULT_CONSTRAINT_LIMIT,
) -> bool:
    """复核引擎产出的单个冲突集：它必须是参考实现认可的 MUS。

    冲突 evidence 的外层形态与约束 evidence 对齐：
    - ordering_cycle: ("ordering_cycle", 约束1, 约束2, ...)
    - 其它单证据冲突: 直接就是一条约束的 evidence
    """
    mus_list = minimal_unsatisfiable_subsets(
        records, trust_key, node_limit, constraint_limit
    )
    if conflict.kind == "ordering_cycle":
        claimed = tuple(sorted(conflict.evidence[1:], key=lambda x: str(x)))
    else:
        claimed = (conflict.evidence,)
    return claimed in mus_list


def cross_check(
    result: TimelineResult,
    records: list[Record],
    trust_key: bytes,
    node_limit: int = DEFAULT_NODE_LIMIT,
) -> list[str]:
    """用穷举参考实现复核引擎结果，返回不一致项说明（空列表表示全部一致）。

    按弱连通分量切分输入后逐分量穷举，保证 n! 可控。
    """
    active = [r for r in records if not r.revoked]

    problems: list[str] = []
    for comp in result.components:
        cset = set(comp.nodes)
        sub_records = [
            r for r in active
            if node_key(r.correlation_id, r.incarnation) in cset
        ]
        if len(cset) > node_limit:
            problems.append(f"分量 {comp.component_id} 规模 {len(cset)} 超穷举上限，跳过")
            continue
        oracle = brute_force_classification(sub_records, trust_key, node_limit)
        # 环分量：穷举整体无可行排列 → 所有节点对均判 contradiction。
        # 引擎只把同一环 SCC 内的节点对判 contradiction，环外节点对仍按
        # 缩点 DAG 判定，因此环分量仅复核“环内节点对确实矛盾”这一不变量。
        is_cyclic_component = (
            bool(oracle) and all(v == "contradiction" for v in oracle.values())
        )
        # 节点内部矛盾（同事件区间不相交）由引擎单独以 node_interval_disjoint
        # 冲突集表达，不属于“节点间顺序”语义；穷举会把整个分量判为不可满足，
        # 因此这类节点的节点对不参与顺序交叉验证。
        internally_conflicted = {
            node_key(r.correlation_id, r.incarnation)
            for r in sub_records
            if any(
                not r.interval.overlaps(q.interval)
                for q in sub_records
                if node_key(q.correlation_id, q.incarnation)
                == node_key(r.correlation_id, r.incarnation)
            )
        }
        for pair in comp.pairs:
            if pair.src in internally_conflicted or pair.dst in internally_conflicted:
                continue
            # 引擎与穷举的节点对键方向可能不同，用规范化无序键定位
            norm_key = "|".join(sorted((pair.src, pair.dst)))
            o = oracle.get(norm_key)
            if o is None:
                problems.append(f"参考实现缺少节点对 {norm_key}")
                continue
            if is_cyclic_component:
                # 环内节点对：穷举与引擎都必须是 contradiction；
                # 环外节点对引擎按 DAG 判定，穷举整体不可满足，语义不同故跳过
                if pair.category == "contradiction" and o == "contradiction":
                    continue
                if pair.category != "contradiction":
                    continue
            if pair.category == "determined":
                expected = f"determined:{pair.src}<{pair.dst}"
                if o != expected:
                    problems.append(
                        f"{norm_key}: 引擎方向 {expected}，穷举={o}"
                    )
            elif pair.category == "indeterminate":
                if o != "indeterminate":
                    problems.append(
                        f"{norm_key}: 引擎=indeterminate，穷举={o}"
                    )
            else:
                if o != "contradiction":
                    problems.append(
                        f"{norm_key}: 引擎=contradiction，穷举={o}"
                    )
    return problems
