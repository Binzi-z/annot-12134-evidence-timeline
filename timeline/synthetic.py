"""合成数据：分区恢复、时钟回拨、同 ID 重用、冲突锚点。

所有场景均为确定性数据（固定时间戳与密钥），可反复复现。
每个场景返回 dict：records / trust_key / expectations（人工可复核的预期）。
"""
from __future__ import annotations

import random

from .anchors import sign_anchor
from .model import Record

TRUST_KEY = b"offline-evidence-shared-secret"


def _anchor(rec: Record, key: bytes) -> Record:
    return Record(**{**rec.to_dict(), "signature": sign_anchor(rec, key)})


def scenario_partition_recovery() -> dict:
    """分区恢复：网络分区期间日志延迟送达，物理顺序与送达顺序不同。

    预期：禁止按输入顺序补全；打乱输入后结果完全一致；
    事件 A→B→C 的确定顺序由同分区 seq 边与锚点链共同支撑。
    """
    key = TRUST_KEY
    records = [
        _anchor(Record("host", 1, 1000, 50, "evt-A", 0, "login",
                       anchor_seq=1, anchor_prev=None), key),
        _anchor(Record("network", 1, 1100, 200, "evt-B", 0, "connect",
                       anchor_seq=2, anchor_prev=None), key),  # prev 后补
        _anchor(Record("audit", 1, 1300, 100, "evt-C", 0, "grant",
                       anchor_seq=3, anchor_prev=None), key),
        Record("host", 2, 1200, 200, "evt-B", 0, "connect-dup"),
        Record("network", 2, 1500, 250, "evt-C", 0, "grant-dup"),
    ]
    # 恢复送达后补全锚点前置哈希
    records[1] = _anchor(
        Record("network", 1, 1100, 200, "evt-B", 0, "connect",
               anchor_seq=2, anchor_prev=records[0].content_hash()), key
    )
    records[2] = _anchor(
        Record("audit", 1, 1300, 100, "evt-C", 0, "grant",
               anchor_seq=3, anchor_prev=records[1].content_hash()), key
    )
    # 物理顺序 A,B,C 与列表顺序不同：先给 C/B 再给 A，模拟乱序送达
    shuffled = [records[2], records[4], records[1], records[3], records[0]]
    return {
        "name": "partition_recovery",
        "records": shuffled,
        "trust_key": key,
        "expectations": {
            "determined_pairs": [
                ("evt-A#i0", "evt-B#i0"),
                ("evt-B#i0", "evt-C#i0"),
                ("evt-A#i0", "evt-C#i0"),
            ],
            "conflict_kinds": [],
        },
    }


def scenario_clock_rollback() -> dict:
    """时钟回拨：本地时钟跳变使观察时间倒退，但区间仍相容。

    预期：seq/锚点给出 B 在 A 之后的确定顺序；区间注释为 disagrees
    （时钟证据与硬顺序相反），但不构成矛盾；无硬边的节点对保持无法排序。
    """
    key = TRUST_KEY
    a = _anchor(Record("host", 1, 2000, 100, "evt-A", 0, "write",
                       anchor_seq=1), key)
    b = _anchor(Record("host", 2, 1500, 100, "evt-B", 0, "read",
                       anchor_seq=2, anchor_prev=a.content_hash()), key)
    c = Record("network", 1, 3000, 500, "evt-C", 0, "probe")  # 与 A/B 无硬边
    return {
        "name": "clock_rollback",
        "records": [c, b, a],  # 乱序输入
        "trust_key": key,
        "expectations": {
            "determined_pairs": [("evt-A#i0", "evt-B#i0")],
            "determined_interval_notes": {
                "evt-A#i0|evt-B#i0": "disagrees"
            },
            "indeterminate_pairs": [
                "evt-A#i0|evt-C#i0",
                "evt-B#i0|evt-C#i0",
            ],
            "conflict_kinds": [],
        },
    }


def scenario_id_reuse() -> dict:
    """同 ID 重用：同一 correlation_id 出现多个代次（incarnation）。

    预期：i0 与 i1 是两个独立事件，不会被错误合并；
    同代次重复观测正常合并；另含一组同事件区间不相交的矛盾数据。
    """
    key = TRUST_KEY
    e1 = Record("host", 1, 1000, 50, "cid-X", 0, "open")
    e1_dup = Record("audit", 1, 1020, 200, "cid-X", 0, "open-dup")
    e2 = Record("host", 2, 5000, 50, "cid-X", 1, "reopen")  # ID 重用，新代次
    # 同事件两条日志区间不相交 → 矛盾
    bad1 = Record("network", 1, 9000, 10, "cid-Y", 0, "sync")
    bad2 = Record("audit", 2, 9500, 10, "cid-Y", 0, "sync-dup")
    return {
        "name": "id_reuse",
        "records": [bad2, e2, e1_dup, bad1, e1],
        "trust_key": key,
        "expectations": {
            "nodes": ["cid-X#i0", "cid-X#i1", "cid-Y#i0"],
            "conflict_kinds": ["node_interval_disjoint"],
            "contradiction_nodes": ["cid-Y#i0"],
        },
    }


def scenario_conflicting_anchors() -> dict:
    """冲突锚点：签名篡改 + 锚点序号分叉 + 硬约束环。

    预期：三类锚点/顺序矛盾各自产出可复核最小冲突集；
    被篡改锚点不产生锚点边；环上节点对判为 contradiction。
    """
    key = TRUST_KEY
    a = _anchor(Record("host", 1, 100, 20, "evt-A", 0, "a",
                       anchor_seq=1), key)
    b = _anchor(Record("network", 1, 200, 20, "evt-B", 0, "b",
                       anchor_seq=2, anchor_prev=a.content_hash()), key)
    # 分叉：另一条记录也声称 anchor_seq=2
    fork = _anchor(Record("audit", 1, 210, 20, "evt-F", 0, "fork",
                          anchor_seq=2, anchor_prev=a.content_hash()), key)
    # 篡改：签名对不上（负载被改过但签名保留伪造值）
    tampered = Record(
        "host", 2, 300, 20, "evt-T", 0, "tampered",
        anchor_seq=4, anchor_prev=b.content_hash(),
        signature="0" * 64,
    )
    # 硬约束环（同 audit 分区）：
    #   seq 边 D(audit,2)→E(audit,3)
    #   独立锚点域（使用不与主链冲突的高序号，链首 prev=None）：
    #   E(anchor_seq=10, 链首) → D(anchor_seq=11, prev=E)
    # 于是 anchor 边 E→D 与 seq 边 D→E 构成二元硬约束环，且不产生断链/分叉。
    e = _anchor(Record("audit", 3, 500, 20, "evt-E", 0, "e",
                       anchor_seq=10), key)
    d = _anchor(Record("audit", 2, 400, 20, "evt-D", 0, "d",
                       anchor_seq=11, anchor_prev=e.content_hash()), key)
    # audit 分区 seq 边：F(audit,1)→D(audit,2)→E(audit,3)；
    # 独立锚点子链 E→D 与 seq 边 D→E 构成硬约束环（两条边均为最小冲突集）。
    return {
        "name": "conflicting_anchors",
        "records": [d, e, tampered, fork, b, a],
        "trust_key": key,
        "expectations": {
            "conflict_kinds": [
                "anchor_signature",
                "anchor_seq_duplicate",
                "ordering_cycle",
            ],
            "contradiction_pairs": ["evt-D#i0|evt-E#i0"],
        },
    }


def all_scenarios() -> list[dict]:
    return [
        scenario_partition_recovery(),
        scenario_clock_rollback(),
        scenario_id_reuse(),
        scenario_conflicting_anchors(),
    ]


def shuffled_copy(records: list[Record], seed: int) -> list[Record]:
    """确定性打乱（验证“禁止以输入顺序强行补全”）。"""
    rng = random.Random(seed)
    copy = list(records)
    rng.shuffle(copy)
    return copy


def generate_fuzz_case(seed: int, n_partitions: int = 3,
                       n_events: int = 6) -> dict:
    """随机模糊用例：随机时钟漂移、重复观测、代次重用与锚点子链。

    生成后再随机打乱记录顺序，供属性测试使用。
    """
    rng = random.Random(seed)
    key = TRUST_KEY
    records: list[Record] = []
    partitions = ["host", "network", "audit"][:n_partitions]
    seq_counters = {p: 0 for p in partitions}
    prev_anchor_hash: str | None = None
    anchor_seq = 0

    for ev in range(n_events):
        cid = f"fuzz-{ev % max(2, n_events - 1)}"  # 刻意制造 ID 重用
        incarnation = ev // max(2, n_events - 1)
        true_time = 1000 + ev * 500
        copies = rng.randint(1, 3)
        for k in range(copies):
            part = rng.choice(partitions)
            seq_counters[part] += 1
            drift = rng.uniform(-300, 300)       # 时钟漂移/回拨
            uncertainty = rng.choice([20, 100, 400])
            rec = Record(
                partition=part,
                seq=seq_counters[part],
                observed_ts=true_time + drift,
                uncertainty_ms=uncertainty,
                correlation_id=cid,
                incarnation=incarnation,
                op=f"op-{ev}",
                payload=f"copy-{k}",
            )
            if rng.random() < 0.4 and part == partitions[0]:
                anchor_seq += 1
                rec = Record(
                    **{**rec.to_dict(),
                       "anchor_seq": anchor_seq,
                       "anchor_prev": prev_anchor_hash}
                )
                rec = _anchor(rec, key)
                prev_anchor_hash = rec.content_hash()
            records.append(rec)

    rng.shuffle(records)
    return {"name": f"fuzz-{seed}", "records": records, "trust_key": key,
            "expectations": {}}
