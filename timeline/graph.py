"""约束图与分析结果的数据结构。"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HardEdge:
    """可信硬约束：src 对应的物理事件必然先于 dst。"""

    src: str
    dst: str
    reason: str
    evidence: tuple          # 机器可读证据元组，用于冲突集与摘要
    record_hashes: tuple[str, ...]  # 涉及的日志记录内容哈希


@dataclass(frozen=True)
class Conflict:
    """一条矛盾证据及其可复核的最小冲突集。"""

    conflict_id: str
    kind: str                # 矛盾类型
    evidence: tuple          # 最小冲突集（约束/记录的机器可读标识）
    message: str
    record_hashes: tuple[str, ...]


@dataclass(frozen=True)
class PairResult:
    """两个事件节点之间的三类判定之一。"""

    src: str
    dst: str
    category: str            # determined | indeterminate | contradiction
    reason: str
    interval_note: str | None = None  # agrees | disagrees | overlap
    via: tuple[str, ...] = ()        # determined 时的一条有向路径


@dataclass
class ComponentResult:
    """弱连通分量的分析结果，也是增量重算的最小单位。"""

    component_id: str
    nodes: tuple[str, ...]
    status: str              # consistent | contradictory
    conflicts: list[Conflict] = field(default_factory=list)
    pairs: list[PairResult] = field(default_factory=list)
    digest: str = ""         # 分量输入（节点+边+冲突）摘要，用于缓存命中


@dataclass
class TimelineResult:
    nodes: dict[str, object]  # key -> Node（避免与 model 循环导入，用 object 注解）
    edges: list[HardEdge]
    conflicts: list[Conflict]
    components: list[ComponentResult]
    pair_index: dict[str, PairResult]
    stats: dict[str, int]
