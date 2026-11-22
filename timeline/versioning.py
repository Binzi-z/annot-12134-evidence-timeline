"""算法版本、规范化序列化与输入摘要。

历史报告复现的基础：
- ``ALGORITHM_VERSION`` 随报告持久化，规则变化必须升版本号；
- ``canonical_json`` 保证字节级确定的序列化（排序键、无多余空白）；
- ``input_digest`` 覆盖全部输入要素（记录、信任密钥），与版本号一起
  即可唯一标识一次计算的输入与算法。
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from . import ALGORITHM_VERSION


def canonical_json(obj: Any) -> str:
    """与平台无关的规范化 JSON 字符串。

    - sort_keys 保证字典顺序不影响结果；
    - 分隔符固定、ensure_ascii=False（再统一 UTF-8 编码）；
    - 不允许集合等不可 JSON 序列化类型，调用方须先转元组/列表。
    """
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    )


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def input_digest(records: Iterable[dict], trust_key_digest: str) -> str:
    """计算一批输入的摘要。

    摘要基于记录的规范化字段而不是对象 id，因此：
    - 记录打乱顺序后摘要不变（禁止以输入顺序强行补全的前提保障之一）；
    - 同一批数据在任何机器上摘要一致。
    """
    fields = sorted(
        {
            "partition",
            "seq",
            "observed_ts",
            "uncertainty_ms",
            "correlation_id",
            "incarnation",
            "op",
            "payload",
            "anchor_seq",
            "anchor_prev",
            "signature",
            "revoked",
        }
    )
    normalized = [
        {k: r.get(k) for k in fields if k in r}
        for r in records
    ]
    normalized.sort(key=lambda r: canonical_json(r))
    blob = canonical_json(
        {"records": normalized, "trust_key_digest": trust_key_digest}
    )
    return sha256_hex(blob)


def algorithm_version() -> str:
    return ALGORITHM_VERSION
