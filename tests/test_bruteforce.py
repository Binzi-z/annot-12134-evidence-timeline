"""穷举参考实现交叉验证：顺序判定与最小冲突集解释。"""
from __future__ import annotations

import unittest

from timeline.bruteforce import (
    brute_force_classification,
    cross_check,
    minimal_unsatisfiable_subsets,
    verify_conflict_minimality,
)
from timeline.engine import build_timeline
from timeline.synthetic import all_scenarios, generate_fuzz_case


class CrossCheckTests(unittest.TestCase):
    def test_all_scenarios_match_brute_force(self):
        for sc in all_scenarios():
            with self.subTest(scenario=sc["name"]):
                result = build_timeline(sc["records"], sc["trust_key"])
                problems = cross_check(result, sc["records"], sc["trust_key"])
                self.assertEqual(problems, [], f"穷举交叉验证发现不一致: {problems}")

    def test_fuzz_cases_match_brute_force(self):
        for seed in range(12):
            with self.subTest(seed=seed):
                sc = generate_fuzz_case(seed)
                result = build_timeline(sc["records"], sc["trust_key"])
                problems = cross_check(result, sc["records"], sc["trust_key"])
                self.assertEqual(problems, [])

    def test_conflict_sets_are_minimal(self):
        """引擎上报的环/区间冲突必须通过穷举 MUS 最小性复核。"""
        for sc in all_scenarios():
            result = build_timeline(sc["records"], sc["trust_key"])
            for c in result.conflicts:
                if c.kind not in ("ordering_cycle", "node_interval_disjoint"):
                    continue
                with self.subTest(scenario=sc["name"], conflict=c.conflict_id):
                    self.assertTrue(
                        verify_conflict_minimality(
                            c, sc["records"], sc["trust_key"]
                        ),
                        f"冲突集 {c.conflict_id} 未通过最小性复核",
                    )

    def test_mus_reports_two_opposing_edges_for_cycle(self):
        sc = next(s for s in all_scenarios()
                  if s["name"] == "conflicting_anchors")
        mus_list = minimal_unsatisfiable_subsets(
            sc["records"], sc["trust_key"]
        )
        # 至少存在一个仅由 lt 约束构成、大小为 2 的 MUS（D→E 与 E→D）
        small = [m for m in mus_list if len(m) == 2
                 and all(item[0] in ("seq", "anchor") for item in m)]
        self.assertTrue(small, f"未找到二元最小冲突集: {mus_list}")

    def test_indeterminate_requires_both_directions(self):
        """相容但无法排序：穷举中两个方向都必须存在可行排列。"""
        sc = next(s for s in all_scenarios() if s["name"] == "clock_rollback")
        oracle = brute_force_classification(sc["records"], sc["trust_key"])
        self.assertEqual(
            oracle["evt-A#i0|evt-C#i0"], "indeterminate"
        )
        self.assertEqual(
            oracle["evt-B#i0|evt-C#i0"], "indeterminate"
        )

    def test_contradiction_when_no_feasible_order(self):
        sc = next(s for s in all_scenarios()
                  if s["name"] == "conflicting_anchors")
        oracle = brute_force_classification(sc["records"], sc["trust_key"])
        self.assertEqual(
            oracle["evt-D#i0|evt-E#i0"], "contradiction"
        )

    def test_brute_force_is_order_agnostic(self):
        from timeline.synthetic import shuffled_copy
        sc = next(s for s in all_scenarios() if s["name"] == "partition_recovery")
        first = brute_force_classification(sc["records"], sc["trust_key"])
        for seed in range(5):
            again = brute_force_classification(
                shuffled_copy(sc["records"], seed), sc["trust_key"]
            )
            self.assertEqual(again, first)


if __name__ == "__main__":
    unittest.main()
