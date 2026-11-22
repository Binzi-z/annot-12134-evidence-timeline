"""引擎三类判定与最小冲突集的单元测试（基于合成场景）。"""
from __future__ import annotations

import unittest

from timeline.engine import build_timeline
from timeline.synthetic import all_scenarios, shuffled_copy
from timeline.versioning import canonical_json


class ScenarioExpectationTests(unittest.TestCase):
    def _result(self, scenario):
        return build_timeline(scenario["records"], scenario["trust_key"])

    def test_partition_recovery_determined_order(self):
        sc = next(s for s in all_scenarios() if s["name"] == "partition_recovery")
        res = self._result(sc)
        for src, dst in sc["expectations"]["determined_pairs"]:
            pair = res.pair_index.get(f"{src}|{dst}")
            self.assertIsNotNone(pair, f"缺少节点对 {src}|{dst}")
            self.assertEqual(pair.category, "determined")
            self.assertEqual(pair.reason, "hard_path")
        self.assertEqual(res.conflicts, [])
        # 重复观测被合并为同一节点
        self.assertEqual(res.stats["nodes"], 3)
        self.assertIn("anchor_chain", [e.reason for e in res.edges])

    def test_input_order_does_not_drive_results(self):
        """禁止以输入顺序强行补全：任意打乱输入，规范化结果不变。"""
        sc = next(s for s in all_scenarios() if s["name"] == "partition_recovery")
        base = build_timeline(sc["records"], sc["trust_key"])
        baseline = canonical_json(_snapshot(base))
        for seed in range(8):
            shuffled = shuffled_copy(sc["records"], seed)
            other = build_timeline(shuffled, sc["trust_key"])
            self.assertEqual(
                canonical_json(_snapshot(other)),
                baseline,
                f"seed={seed} 时结果依赖输入顺序",
            )

    def test_clock_rollback_disagrees_but_not_contradiction(self):
        sc = next(s for s in all_scenarios() if s["name"] == "clock_rollback")
        res = self._result(sc)
        pair = res.pair_index["evt-A#i0|evt-B#i0"]
        self.assertEqual(pair.category, "determined")
        self.assertEqual(pair.interval_note, "disagrees")
        # C 与 A/B 无任何硬边，落在独立弱连通分量；跨分量不存在节点对，
        # 即没有任何证据可用于排序（相容但无法排序的跨分量形态）。
        self.assertEqual(len(res.components), 2)
        component_nodes = {n for c in res.components for n in c.nodes}
        self.assertIn("evt-C#i0", component_nodes)
        for key in ("evt-A#i0|evt-C#i0", "evt-B#i0|evt-C#i0"):
            self.assertNotIn(key, res.pair_index)
        self.assertEqual(res.conflicts, [])

    def test_id_reuse_keeps_incarnations_apart(self):
        sc = next(s for s in all_scenarios() if s["name"] == "id_reuse")
        res = self._result(sc)
        self.assertEqual(sorted(res.nodes), sc["expectations"]["nodes"])
        kinds = sorted({c.kind for c in res.conflicts})
        self.assertEqual(kinds, ["node_interval_disjoint"])
        # 每个区间不相交记录对都是最小冲突集（仅两条记录证据）
        for c in res.conflicts:
            self.assertEqual(len(c.record_hashes), 2)
            self.assertTrue(c.conflict_id)

    def test_conflicting_anchors(self):
        sc = next(s for s in all_scenarios() if s["name"] == "conflicting_anchors")
        res = self._result(sc)
        kinds = {c.kind for c in res.conflicts}
        for expected in sc["expectations"]["conflict_kinds"]:
            self.assertIn(expected, kinds)
        # 被篡改/分叉的锚点不得产生锚点边
        anchor_edges = [e for e in res.edges if e.reason == "anchor_chain"]
        anchor_nodes = {n for e in anchor_edges for n in (e.src, e.dst)}
        self.assertNotIn("evt-T#i0", anchor_nodes)
        self.assertNotIn("evt-F#i0", anchor_nodes)
        # 环上节点对判为矛盾
        pair = res.pair_index["evt-D#i0|evt-E#i0"]
        self.assertEqual(pair.category, "contradiction")
        # 环冲突集至少包含两条相互对立的硬约束证据
        cycle_conflicts = [c for c in res.conflicts if c.kind == "ordering_cycle"]
        self.assertTrue(cycle_conflicts)
        for c in cycle_conflicts:
            self.assertGreaterEqual(len(c.evidence) - 1, 2)


def _snapshot(result) -> dict:
    """只包含证据决定的内容，用于顺序无关性比较。"""
    return {
        "edges": sorted(
            [
                {"src": e.src, "dst": e.dst, "reason": e.reason,
                 "evidence": list(e.evidence)}
                for e in result.edges
            ],
            key=canonical_json,
        ),
        "conflicts": sorted(
            [c.kind + ":" + str(list(c.evidence)) for c in result.conflicts]
        ),
        "pairs": sorted(
            [
                {"k": k, "category": p.category, "reason": p.reason,
                 "note": p.interval_note}
                for k, p in result.pair_index.items()
            ],
            key=canonical_json,
        ),
        "stats": result.stats,
    }


if __name__ == "__main__":
    unittest.main()
