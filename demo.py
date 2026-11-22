"""端到端演示：四类合成场景 + 穷举复核 + 增量/全量等价性证明。

运行：python demo.py
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from timeline.anchors import trust_key_digest
from timeline.bruteforce import cross_check, verify_conflict_minimality
from timeline.engine import build_timeline
from timeline.pipeline import report_equivalent, run_full, run_incremental
from timeline.store import Store
from timeline.synthetic import all_scenarios
from timeline.versioning import algorithm_version


def hr(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> None:
    print(f"算法版本: {algorithm_version()}")

    for sc in all_scenarios():
        hr(f"场景：{sc['name']}")
        result = build_timeline(sc["records"], sc["trust_key"])

        print(f"活动记录 {result.stats['records_active']} 条，"
              f"事件节点 {result.stats['nodes']} 个，"
              f"硬约束边 {result.stats['hard_edges']} 条")
        print("三类判定计数："
              f"确定={result.stats['pairs_determined']}，"
              f"无法排序={result.stats['pairs_indeterminate']}，"
              f"矛盾={result.stats['pairs_contradiction']}")

        for pair in sorted(result.pair_index.values(),
                           key=lambda p: (p.category, p.src, p.dst)):
            note = f" [区间:{pair.interval_note}]" if pair.interval_note else ""
            print(f"  - {pair.src} ~ {pair.dst}: {pair.category}"
                  f" ({pair.reason}){note}")

        if result.conflicts:
            print("最小冲突集（可复核）：")
            for c in result.conflicts:
                minimal = (
                    verify_conflict_minimality(
                        c, sc["records"], sc["trust_key"]
                    )
                    if c.kind in ("ordering_cycle", "node_interval_disjoint")
                    else "n/a(锚点类冲突为单证据最小集)"
                )
                print(f"  - [{c.kind}] {c.message}")
                print(f"      证据: {c.evidence}")
                print(f"      记录: {c.record_hashes}")
                print(f"      穷举 MUS 最小性复核: {minimal}")

        problems = cross_check(result, sc["records"], sc["trust_key"])
        print(f"穷举参考实现交叉验证: {'通过' if not problems else problems}")

    # ---- 增量 vs 全量等价性证明 ------------------------------------------
    hr("等价性证明：分批增量处理 vs 同版本全量重算")
    sc = all_scenarios()[0]
    digest_td = trust_key_digest(sc["trust_key"])
    records = sc["records"]
    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "demo.db"
        with Store(db) as store:
            batches = [records[:2], records[2:4], records[4:]]
            incr_report = None
            for i, batch in enumerate(batches):
                incr_report, _, diag = run_incremental(
                    store, batch, sc["trust_key"], digest_td, i
                )
                print(f"批次 {i}: 重算分量 {diag['recomputed_components']}，"
                      f"复用分量 {diag['reused_components']}")
            full_report, _ = run_full(
                store, records, sc["trust_key"], digest_td
            )
            equivalent = report_equivalent(incr_report, full_report)
            reproducible = store.find_report(
                incr_report["input_digest"],
                incr_report["algorithm_version"],
            ) is not None
        print(f"输入摘要一致: {incr_report['input_digest'] == full_report['input_digest']}")
        print(f"算法版本一致: {incr_report['algorithm_version'] == full_report['algorithm_version']}")
        print(f"规范化报告逐字节等价: {equivalent}")
        print(f"历史报告可按摘要复现: {reproducible}")
        assert equivalent, "增量与全量结果不一致"

    print("\n全部演示与复核通过。")


if __name__ == "__main__":
    main()
