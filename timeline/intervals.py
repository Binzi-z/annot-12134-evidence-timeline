"""带误差半径的时间区间。

每条离线日志只声称事件真实发生时间落在
``[observed_ts - uncertainty_ms, observed_ts + uncertainty_ms]`` 内。
时钟跳变 / 漂移通过足够大的 uncertainty 表达，区间本身不假设单调。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Interval:
    lo: float
    hi: float

    def __post_init__(self) -> None:
        if self.hi < self.lo:
            raise ValueError(f"非法时间区间: lo={self.lo} > hi={self.hi}")

    @classmethod
    def around(cls, observed_ts: float, uncertainty_ms: float) -> "Interval":
        return cls(observed_ts - uncertainty_ms, observed_ts + uncertainty_ms)

    def intersect(self, other: "Interval") -> "Interval | None":
        lo = max(self.lo, other.lo)
        hi = min(self.hi, other.hi)
        if hi < lo:
            return None
        return Interval(lo, hi)

    def overlaps(self, other: "Interval") -> bool:
        return not (self.hi < other.lo or other.hi < self.lo)

    def disjoint_before(self, other: "Interval") -> bool:
        """self 与 other 不相交，且 self 完全早于 other。"""
        return self.hi < other.lo

    def as_tuple(self) -> tuple[float, float]:
        return (self.lo, self.hi)
