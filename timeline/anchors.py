"""HMAC-SHA256 签名锚点链校验。

锚点链是跨分区的可信时间线索引：
- 每条锚点记录用预共享密钥对其规范化负载做 HMAC 签名；
- ``anchor_prev`` 指向前一锚点的记录内容哈希，链上严格递增的
  ``anchor_seq`` 给出跨分区的先后硬约束；
- 签名失败、断链、序号回退/重复、分叉均作为矛盾证据上报，
  且不把不可信的锚点边加入约束图（宁可少约束，不可伪造顺序）。
"""
from __future__ import annotations

import hashlib
import hmac

from .graph import Conflict, HardEdge
from .model import Record, node_key
from .versioning import sha256_hex


def sign_anchor(record: Record, trust_key: bytes) -> str:
    """生成锚点签名（合成数据与测试使用）。"""
    return hmac.new(trust_key, record.anchor_payload().encode("utf-8"),
                    hashlib.sha256).hexdigest()


def trust_key_digest(trust_key: bytes) -> str:
    return sha256_hex(b"trust-key:" + trust_key)


def _conflict(kind: str, evidence: tuple, message: str,
              record_hashes: list[str]) -> Conflict:
    cid = sha256_hex(
        "conflict:"
        + kind
        + "|"
        + ",".join(str(e) for e in sorted(evidence, key=lambda x: str(x)))
    )[:16]
    return Conflict(cid, kind, evidence, message, tuple(sorted(set(record_hashes))))


def analyze_anchors(
    records: list[Record],
    trust_key: bytes,
) -> tuple[list[HardEdge], list[Conflict]]:
    """校验全部锚点记录，返回可信锚点边与锚点冲突。"""
    edges: list[HardEdge] = []
    conflicts: list[Conflict] = []
    anchors = [r for r in records if not r.revoked and r.anchor_seq is not None]

    valid: list[Record] = []
    for r in anchors:
        rh = r.content_hash()
        expected = sign_anchor(r, trust_key)
        if r.signature is None or not hmac.compare_digest(expected, r.signature):
            conflicts.append(
                _conflict(
                    "anchor_signature",
                    ("anchor_signature", rh),
                    f"锚点 {r.partition}/{r.seq} 签名校验失败，负载可能被篡改",
                    [rh],
                )
            )
        else:
            valid.append(r)

    # 同一 anchor_seq 只允许一个有效锚点，重复即分叉（链标识冲突）
    by_seq: dict[int, list[Record]] = {}
    for r in valid:
        by_seq.setdefault(r.anchor_seq, []).append(r)  # type: ignore[arg-type]

    seq_dups: set[int] = set()
    for seq, group in by_seq.items():
        if len(group) > 1:
            seq_dups.add(seq)
            conflicts.append(
                _conflict(
                    "anchor_seq_duplicate",
                    ("anchor_seq_duplicate", seq),
                    f"锚点序号 {seq} 被 {len(group)} 条记录重用，锚点链分叉",
                    [x.content_hash() for x in group],
                )
            )

    # 多链模型：以 anchor_prev 内容哈希为链接指针，每个 prev 最多被一个
    # 有效锚点引用；链首 anchor_prev=None。这样允许存在多条互相独立的
    # 锚点链（不同信任域/恢复批次），不强制全局单链。
    by_hash = {r.content_hash(): r for r in valid}
    referenced: dict[str, list[Record]] = {}
    for r in valid:
        if r.anchor_prev is not None:
            referenced.setdefault(r.anchor_prev, []).append(r)

    for prev_hash, successors in referenced.items():
        if len(successors) > 1:
            conflicts.append(
                _conflict(
                    "anchor_fork",
                    ("anchor_fork", prev_hash),
                    f"锚点 {prev_hash[:12]} 被 {len(successors)} 条后续锚点引用，链分叉",
                    [s.content_hash() for s in successors],
                )
            )

    # 逐条链校验：前置存在、序号严格递增，并为完整链接产生可信硬边
    chain_heads = [
        r for r in valid
        if r.anchor_seq not in seq_dups and r.anchor_prev is None
    ]
    visited: set[str] = set()
    for head in sorted(chain_heads, key=lambda r: (r.anchor_seq, r.content_hash())):
        cur = head
        prev_rec: Record | None = None
        while True:
            cur_hash = cur.content_hash()
            if cur_hash in visited:
                break  # 防御性：环式链接
            visited.add(cur_hash)
            if prev_rec is not None:
                if cur.anchor_seq <= prev_rec.anchor_seq:  # type: ignore[operator]
                    conflicts.append(
                        _conflict(
                            "anchor_seq_regression",
                            ("anchor_seq_regression",
                             prev_rec.content_hash(), cur_hash),
                            f"锚点 {cur.partition}/{cur.seq} 序号未严格递增",
                            [prev_rec.content_hash(), cur_hash],
                        )
                    )
                else:
                    edges.append(
                        HardEdge(
                            src=node_key(prev_rec.correlation_id,
                                         prev_rec.incarnation),
                            dst=node_key(cur.correlation_id, cur.incarnation),
                            reason="anchor_chain",
                            evidence=("anchor", prev_rec.anchor_seq,
                                      cur.anchor_seq),
                            record_hashes=(prev_rec.content_hash(), cur_hash),
                        )
                    )
            successors = referenced.get(cur_hash, [])
            if not successors or len(successors) != 1:
                break
            prev_rec = cur
            cur = successors[0]

    # 悬挂前置：anchor_prev 指向的哈希在有效锚点中不存在
    for r in valid:
        if r.anchor_prev is not None and r.anchor_prev not in by_hash:
            conflicts.append(
                _conflict(
                    "anchor_dangling",
                    ("anchor_dangling", r.content_hash()),
                    f"锚点 {r.partition}/{r.seq} 的前置 {r.anchor_prev[:12]} 不存在",
                    [r.content_hash()],
                )
            )
    return edges, conflicts
