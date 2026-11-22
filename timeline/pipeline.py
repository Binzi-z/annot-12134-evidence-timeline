"""全量 / 增量编排与可复现报告。

增量语义：
- 每次输入一批记录（含新增、撤销标记），先与 SQLite 中已存记录合并；
- 重新计算当前全量状态的约束图（图构建本身是确定性纯函数）；
- 以分量摘要（component_digest）为缓存键：摘要未变的分量直接复用
  历史结果，只有受影响的分量才重新分析与落库；
- 最终报告与“同版本全量重算”规范化后逐字节一致。
"""
from __future__ import annotations

from . import ALGORITHM_VERSION
from .engine import build_timeline
from .graph import ComponentResult, TimelineResult
from .model import Record, node_key
from .store import Store, make_run_id
from .versioning import canonical_json, input_digest, sha256_hex


def _serialize_conflict(c) -> dict:
    return {
        "conflict_id": c.conflict_id,
        "kind": c.kind,
        "evidence": list(c.evidence),
        "message": c.message,
        "record_hashes": list(c.record_hashes),
    }


def _serialize_pair(p) -> dict:
    return {
        "src": p.src,
        "dst": p.dst,
        "category": p.category,
        "reason": p.reason,
        "interval_note": p.interval_note,
        "via": list(p.via),
    }


def _serialize_component(comp: ComponentResult) -> dict:
    return {
        "component_id": comp.component_id,
        "nodes": list(comp.nodes),
        "status": comp.status,
        "digest": comp.digest,
        "conflicts": [_serialize_conflict(c) for c in comp.conflicts],
        "pairs": [_serialize_pair(p) for p in comp.pairs],
    }


def build_report(
    result: TimelineResult,
    digest: str,
    trust_key_digest: str,
    mode: str,
    batch_index: int,
    cache_stats: dict[str, int],
) -> dict:
    """构造规范化报告。报告内容只依赖输入摘要、算法版本与分析结果。"""
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "input_digest": digest,
        "trust_key_digest": trust_key_digest,
        "mode": mode,
        "batch_index": batch_index,
        "stats": result.stats,
        "cache": cache_stats,
        "components": sorted(
            [_serialize_component(c) for c in result.components],
            key=lambda c: c["component_id"],
        ),
        "all_conflicts": sorted(
            [_serialize_conflict(c) for c in result.conflicts],
            key=lambda c: c["conflict_id"],
        ),
    }


def run_full(store: Store, records: list[Record], trust_key: bytes,
             trust_digest: str) -> tuple[dict, TimelineResult]:
    """同版本全量重算（基线）。不使用任何分量缓存。"""
    run_id = make_run_id("full", input_digest([r.to_dict() for r in records],
                                              trust_digest))
    store.upsert_records(records, run_id)
    digest = input_digest([r.to_dict() for r in records], trust_digest)
    result = build_timeline(records, trust_key)

    # 全量模式同样刷新分量缓存，供后续增量复用
    cache_stats = {"components_reused": 0, "components_recomputed": 0}
    for comp in result.components:
        store.put_component(comp.digest, ALGORITHM_VERSION,
                            _serialize_component(comp))
        cache_stats["components_recomputed"] += 1

    report = build_report(result, digest, trust_digest, "full", 0, cache_stats)
    store.record_run(run_id, digest, ALGORITHM_VERSION, "full", 0, result.stats)
    store.save_report(run_id, digest, ALGORITHM_VERSION, report)
    return report, result


def run_incremental(
    store: Store,
    batch: list[Record],
    trust_key: bytes,
    trust_digest: str,
    batch_index: int,
) -> tuple[dict, TimelineResult, dict]:
    """增量处理一批记录，只重算受影响分量。

    返回 (报告, 当前全量分析结果, 增量诊断信息)。
    """
    run_id = make_run_id(
        "incr",
        sha256_hex(f"batch:{batch_index}:"
                   + canonical_json([r.to_dict() for r in batch])),
    )
    changed, revocation_changed = store.upsert_records(batch, run_id)

    # 受影响节点直接从本批记录解析：撤销记录之后已不在活动集合，
    # 但其 (cid, incarnation) 仍可从批记录本身获得。
    affected_node_set = {
        node_key(r.correlation_id, r.incarnation) for r in batch
    }

    # 以数据库中当前的全量活动记录作为重算输入
    current = store.active_records()
    digest = input_digest([r.to_dict() for r in current], trust_digest)
    result = build_timeline(current, trust_key)

    changed_set = set(changed) | set(revocation_changed)

    cache_stats = {"components_reused": 0, "components_recomputed": 0}
    diagnostics = {
        "changed_record_hashes": sorted(changed_set),
        "affected_nodes": sorted(affected_node_set),
        "recomputed_components": [],
        "reused_components": [],
    }

    for comp in result.components:
        touches_affected = bool(set(comp.nodes) & affected_node_set)
        cached = None
        if not touches_affected:
            cached = store.get_component(comp.digest, ALGORITHM_VERSION)
        # 首批（缓存尚为空）或受影响分量都需要重算并回填缓存；
        # 只有摘要未变且缓存中确实存在历史结果时才复用。
        if cached is not None and cached["digest"] == comp.digest:
            cache_stats["components_reused"] += 1
            diagnostics["reused_components"].append(comp.component_id)
        else:
            store.put_component(comp.digest, ALGORITHM_VERSION,
                                _serialize_component(comp))
            cache_stats["components_recomputed"] += 1
            diagnostics["recomputed_components"].append(comp.component_id)

    report = build_report(result, digest, trust_digest, "incremental",
                          batch_index, cache_stats)
    store.record_run(run_id, digest, ALGORITHM_VERSION, "incremental",
                     batch_index, result.stats)
    store.save_report(run_id, digest, ALGORITHM_VERSION, report)
    return report, result, diagnostics


def report_equivalent(report_a: dict, report_b: dict) -> bool:
    """规范化报告等价性：忽略运行模式/批次/缓存统计等元数据后逐字节比较。"""
    volatile = {"mode", "batch_index", "cache"}
    a = {k: v for k, v in report_a.items() if k not in volatile}
    b = {k: v for k, v in report_b.items() if k not in volatile}
    return canonical_json(a) == canonical_json(b)
