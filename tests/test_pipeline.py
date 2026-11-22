"""SQLite 持久化、增量重算范围与全量/增量等价性测试。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from timeline.anchors import trust_key_digest
from timeline.model import Record
from timeline.pipeline import (
    report_equivalent,
    run_full,
    run_incremental,
)
from timeline.store import Store
from timeline.synthetic import (
    TRUST_KEY,
    generate_fuzz_case,
    scenario_partition_recovery,
    shuffled_copy,
)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "timeline.db"
        self.trust_digest = trust_key_digest(TRUST_KEY)

    def tearDown(self):
        self.tmp.cleanup()

    def test_incremental_equals_full_recompute(self):
        """核心等价性：分批增量处理的最终报告 == 同版本全量重算。"""
        sc = scenario_partition_recovery()
        records = sc["records"]

        with Store(self.db) as store:
            # 分三批增量喂入（含乱序）
            batches = [records[:2], records[2:4], records[4:]]
            incr_report = None
            for i, batch in enumerate(batches):
                incr_report, _, _ = run_incremental(
                    store, batch, TRUST_KEY, self.trust_digest, i
                )

        with Store(self.db) as store:
            full_report, _ = run_full(
                store, records, TRUST_KEY, self.trust_digest
            )

        self.assertTrue(
            report_equivalent(incr_report, full_report),
            "增量报告与全量重算报告不一致",
        )
        self.assertEqual(
            incr_report["input_digest"], full_report["input_digest"]
        )
        self.assertEqual(
            incr_report["algorithm_version"], full_report["algorithm_version"]
        )

    def test_only_affected_components_recomputed(self):
        """撤销/补到事件后，只有受影响分量被重算，其余分量命中缓存。"""
        sc = scenario_partition_recovery()
        records = list(sc["records"])
        # 追加一个与现有分量无任何边的独立事件：
        # 使用全新分区且无锚点，确保不会被 seq/anchor 边连入既有分量
        isolated = Record("sandbox", 1, 9999, 10, "iso-Z", 0, "isolated")
        records_with_iso = records + [isolated]

        with Store(self.db) as store:
            run_incremental(store, records, TRUST_KEY,
                            self.trust_digest, 0)
            _, result_before, diag = run_incremental(
                store, [isolated], TRUST_KEY, self.trust_digest, 1
            )
            # 新事件只影响它自己所在的新分量
            self.assertEqual(diag["affected_nodes"], ["iso-Z#i0"])
            self.assertEqual(len(diag["recomputed_components"]), 1)
            self.assertGreaterEqual(len(diag["reused_components"]), 1)
            reused_before = set(diag["reused_components"])

            # 撤销 isolated：原分量应重新命中缓存
            revoked = Record(**{**isolated.to_dict(), "revoked": True})
            _, _, diag2 = run_incremental(
                store, [revoked], TRUST_KEY, self.trust_digest, 2
            )
            self.assertEqual(diag2["affected_nodes"], ["iso-Z#i0"])
            # 原有的 A/B/C 分量在整个过程中摘要不变
            original_comp = next(
                c for c in result_before.components
                if "evt-A#i0" in c.nodes
            )
            self.assertIn(original_comp.component_id, reused_before)

    def test_revocation_removes_evidence_and_recomputes(self):
        sc = scenario_partition_recovery()
        with Store(self.db) as store:
            run_incremental(store, sc["records"], TRUST_KEY,
                            self.trust_digest, 0)
            before = store.active_records()
            self.assertEqual(len(before), 5)

            target = next(
                r for r in sc["records"]
                if r.correlation_id == "evt-A" and r.anchor_seq == 1
            )
            revoked = Record(**{**target.to_dict(), "revoked": True})
            report, result, diag = run_incremental(
                store, [revoked], TRUST_KEY, self.trust_digest, 1
            )
            # 该记录内容哈希已从活动集合移除
            self.assertEqual(result.stats["records_active"], 4)
            self.assertIn("evt-A#i0", diag["affected_nodes"])
            # 撤销后该锚点边消失
            anchor_records = [
                r for r in store.active_records() if r.anchor_seq is not None
            ]
            self.assertEqual(len(anchor_records), 2)

    def test_history_report_reproducible_by_digest(self):
        """历史报告可用输入摘要 + 算法版本取回，且内容确定。"""
        sc = scenario_partition_recovery()
        with Store(self.db) as store:
            report1, _ = run_full(store, sc["records"], TRUST_KEY,
                                  self.trust_digest)
            fetched = store.find_report(
                report1["input_digest"], report1["algorithm_version"]
            )
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched, report1)

    def test_shuffled_inputs_same_digest_and_report(self):
        """打乱输入顺序不改变输入摘要与规范化报告。"""
        sc = scenario_partition_recovery()
        with Store(self.db) as store:
            report_a, _ = run_full(
                store, sc["records"], TRUST_KEY, self.trust_digest
            )
        with tempfile.TemporaryDirectory() as d2:
            with Store(Path(d2) / "other.db") as store2:
                report_b, _ = run_full(
                    store2, shuffled_copy(sc["records"], 7),
                    TRUST_KEY, self.trust_digest
                )
        self.assertEqual(
            report_a["input_digest"], report_b["input_digest"]
        )
        self.assertTrue(report_equivalent(report_a, report_b))

    def test_fuzz_incremental_equivalence(self):
        for seed in range(6):
            with self.subTest(seed=seed):
                sc = generate_fuzz_case(seed, n_events=5)
                records = sc["records"]
                with tempfile.TemporaryDirectory() as d:
                    db = Path(d) / "f.db"
                    half = max(1, len(records) // 2)
                    with Store(db) as store:
                        r1, _, _ = run_incremental(
                            store, records[:half], TRUST_KEY,
                            self.trust_digest, 0
                        )
                        r2, _, _ = run_incremental(
                            store, records[half:], TRUST_KEY,
                            self.trust_digest, 1
                        )
                    with Store(db) as store:
                        full, _ = run_full(
                            store, records, TRUST_KEY, self.trust_digest
                        )
                    self.assertTrue(report_equivalent(r2, full))


if __name__ == "__main__":
    unittest.main()
