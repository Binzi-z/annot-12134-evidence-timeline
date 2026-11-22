"""锚点链专项与记录去重的单元测试。"""
from __future__ import annotations

import unittest

from timeline.anchors import analyze_anchors, sign_anchor
from timeline.engine import build_timeline
from timeline.model import Record
from timeline.synthetic import TRUST_KEY


class AnchorTests(unittest.TestCase):
    def _chain(self):
        a = Record("host", 1, 100, 10, "A", 0, "x", anchor_seq=1)
        a_signed = Record(**{**a.to_dict(),
                             "signature": sign_anchor(a, TRUST_KEY)})
        b = Record("network", 1, 200, 10, "B", 0, "y", anchor_seq=2,
                   anchor_prev=a_signed.content_hash())
        b_signed = Record(**{**b.to_dict(),
                             "signature": sign_anchor(b, TRUST_KEY)})
        return a_signed, b_signed

    def test_intact_chain_produces_cross_partition_edge(self):
        a, b = self._chain()
        edges, conflicts = analyze_anchors([b, a], TRUST_KEY)
        self.assertEqual(conflicts, [])
        self.assertEqual(len(edges), 1)
        self.assertEqual((edges[0].src, edges[0].dst),
                         ("A#i0", "B#i0"))

    def test_bad_signature_is_flagged_and_no_edge(self):
        a, b = self._chain()
        bad = Record(**{**b.to_dict(), "signature": "ff" * 32})
        edges, conflicts = analyze_anchors([a, bad], TRUST_KEY)
        self.assertEqual([c.kind for c in conflicts], ["anchor_signature"])
        self.assertEqual(edges, [])

    def test_broken_prev_is_dangling_and_no_edge(self):
        # 前置哈希指向不存在的锚点：多链模型下作为悬挂前置上报，且不产生边
        a, b = self._chain()
        broken = Record(**{**b.to_dict(), "anchor_prev": "deadbeef"})
        broken = Record(**{**broken.to_dict(),
                           "signature": sign_anchor(broken, TRUST_KEY)})
        edges, conflicts = analyze_anchors([a, broken], TRUST_KEY)
        self.assertEqual([c.kind for c in conflicts], ["anchor_dangling"])
        self.assertEqual(edges, [])

    def test_independent_anchor_chains_both_produce_edges(self):
        # 两条独立锚点链（不同序号域、互不引用）都应产生可信边，不判断链
        a, b = self._chain()
        e = Record("audit", 3, 500, 10, "E", 0, "e", anchor_seq=10)
        e = Record(**{**e.to_dict(), "signature": sign_anchor(e, TRUST_KEY)})
        d = Record("audit", 2, 400, 10, "D", 0, "d", anchor_seq=11,
                   anchor_prev=e.content_hash())
        d = Record(**{**d.to_dict(), "signature": sign_anchor(d, TRUST_KEY)})
        edges, conflicts = analyze_anchors([a, b, e, d], TRUST_KEY)
        self.assertEqual(conflicts, [])
        pairs = sorted((x.src, x.dst) for x in edges)
        self.assertEqual(pairs, [("A#i0", "B#i0"), ("E#i0", "D#i0")])

    def test_dangling_first_anchor(self):
        a, _ = self._chain()
        dangling = Record(**{**a.to_dict(), "anchor_prev": "ghost"})
        dangling = Record(
            **{**dangling.to_dict(),
               "signature": sign_anchor(dangling, TRUST_KEY)}
        )
        _, conflicts = analyze_anchors([dangling], TRUST_KEY)
        self.assertEqual([c.kind for c in conflicts], ["anchor_dangling"])

    def test_duplicate_import_is_idempotent(self):
        a, b = self._chain()
        r1 = build_timeline([a, b, a, b], TRUST_KEY)
        r2 = build_timeline([b, a], TRUST_KEY)
        self.assertEqual(r1.stats["records_active"], 2)
        self.assertEqual(r1.stats["records_duplicate_imports"], 2)
        self.assertEqual(r1.edges, r2.edges)
        self.assertEqual(r1.conflicts, r2.conflicts)

    def test_same_seq_different_content_conflicts(self):
        r1 = Record("host", 1, 100, 5, "X", 0, "one")
        r2 = Record("host", 1, 100, 5, "Y", 0, "two")
        result = build_timeline([r1, r2], TRUST_KEY)
        self.assertEqual(
            [c.kind for c in result.conflicts], ["duplicate_sequence"]
        )


if __name__ == "__main__":
    unittest.main()
