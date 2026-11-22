"""离线日志记录与事件节点的数据模型。"""
from __future__ import annotations

from dataclasses import dataclass, field

from .intervals import Interval
from .versioning import canonical_json, sha256_hex

# 三种离线日志分区
PARTITIONS = ("host", "network", "audit")


@dataclass(frozen=True)
class Record:
    """一条离线日志记录。

    partition / seq : 分区内日志位置（仅同分区内构成顺序硬约束）
    observed_ts     : 观察到的本地时钟时间（可能回拨/跳变，不可直接跨分区比较）
    uncertainty_ms  : 时钟漂移/抖动半径，真实时间 ∈ observed_ts ± uncertainty_ms
    correlation_id  : 可信相关 ID，同一物理操作的多条日志共享
    incarnation     : 相关 ID 的代次，用于检测同 ID 重用
    op / payload    : 操作类型与负载
    anchor_seq      : 签名锚点链序号（None 表示该记录不在锚点链上）
    anchor_prev     : 前一锚点的记录内容哈希（None 表示链首）
    signature       : 对锚点负载的 HMAC-SHA256 十六进制签名
    revoked         : 事件撤销标记（撤销后该记录不参与约束图）
    """

    partition: str
    seq: int
    observed_ts: float
    uncertainty_ms: float
    correlation_id: str
    incarnation: int
    op: str
    payload: str = ""
    anchor_seq: int | None = None
    anchor_prev: str | None = None
    signature: str | None = None
    revoked: bool = False

    def anchor_payload(self) -> str:
        """签名覆盖的规范化内容（含分区、序号、时钟与相关 ID）。"""
        return canonical_json(
            {
                "partition": self.partition,
                "seq": self.seq,
                "observed_ts": self.observed_ts,
                "uncertainty_ms": self.uncertainty_ms,
                "correlation_id": self.correlation_id,
                "incarnation": self.incarnation,
                "op": self.op,
                "payload": self.payload,
                "anchor_seq": self.anchor_seq,
                "anchor_prev": self.anchor_prev,
            }
        )

    def content_hash(self) -> str:
        """记录内容哈希（不含 revoked，撤销是外部状态，不是内容本身）。"""
        return sha256_hex(
            canonical_json(
                {
                    "partition": self.partition,
                    "seq": self.seq,
                    "observed_ts": self.observed_ts,
                    "uncertainty_ms": self.uncertainty_ms,
                    "correlation_id": self.correlation_id,
                    "incarnation": self.incarnation,
                    "op": self.op,
                    "payload": self.payload,
                    "anchor_seq": self.anchor_seq,
                    "anchor_prev": self.anchor_prev,
                    "signature": self.signature,
                }
            )
        )

    @property
    def interval(self) -> Interval:
        return Interval.around(self.observed_ts, self.uncertainty_ms)

    def to_dict(self) -> dict:
        return {
            "partition": self.partition,
            "seq": self.seq,
            "observed_ts": self.observed_ts,
            "uncertainty_ms": self.uncertainty_ms,
            "correlation_id": self.correlation_id,
            "incarnation": self.incarnation,
            "op": self.op,
            "payload": self.payload,
            "anchor_seq": self.anchor_seq,
            "anchor_prev": self.anchor_prev,
            "signature": self.signature,
            "revoked": self.revoked,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Record":
        return cls(**d)


def node_key(correlation_id: str, incarnation: int) -> str:
    """事件节点的规范标识：可信相关 ID + 代次。

    同 (cid, incarnation) 的多条日志是同一物理操作的重复观测；
    不同 incarnation 即使 cid 相同也是不同事件（同 ID 重用）。
    """
    return f"{correlation_id}#i{incarnation}"


@dataclass
class Node:
    key: str
    correlation_id: str
    incarnation: int
    interval: Interval
    record_hashes: list[str] = field(default_factory=list)
    conflict: str | None = None  # 同一事件内部的证据矛盾（区间不相交等）
