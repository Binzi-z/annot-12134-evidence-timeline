"""SQLite 持久化层。

表结构：
- records        : 记录内容哈希 → 记录 JSON / 撤销状态（内容哈希为主键，天然去重）
- runs           : 每次计算的输入摘要、算法版本、批次数与统计
- component_cache: 分量摘要 → 分量分析结果（增量重算的缓存）
- reports        : 规范化历史报告（输入摘要 + 算法版本即可复现/索引）
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .model import Record
from .versioning import canonical_json, sha256_hex

SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    content_hash TEXT PRIMARY KEY,
    record_json  TEXT NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0,
    updated_run  TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    run_id        TEXT PRIMARY KEY,
    input_digest  TEXT NOT NULL,
    algo_version  TEXT NOT NULL,
    mode          TEXT NOT NULL,
    batch_index   INTEGER NOT NULL,
    stats_json    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS component_cache (
    component_digest TEXT PRIMARY KEY,
    algo_version     TEXT NOT NULL,
    component_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
    run_id       TEXT PRIMARY KEY,
    input_digest TEXT NOT NULL,
    algo_version TEXT NOT NULL,
    report_json  TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- 记录 -------------------------------------------------------------
    def upsert_records(
        self, records: list[Record], run_id: str
    ) -> tuple[list[str], list[str]]:
        """写入记录，返回 (新增或内容变化的哈希, 受撤销状态变化的哈希)。"""
        changed: list[str] = []
        revocation_changed: list[str] = []
        for r in records:
            h = r.content_hash()
            row = self.conn.execute(
                "SELECT revoked FROM records WHERE content_hash=?", (h,)
            ).fetchone()
            if row is None:
                self.conn.execute(
                    "INSERT INTO records(content_hash, record_json, revoked, updated_run)"
                    " VALUES (?,?,?,?)",
                    (h, canonical_json(r.to_dict()), int(r.revoked), run_id),
                )
                changed.append(h)
            else:
                if int(row["revoked"]) != int(r.revoked):
                    self.conn.execute(
                        "UPDATE records SET revoked=?, updated_run=? WHERE content_hash=?",
                        (int(r.revoked), run_id, h),
                    )
                    revocation_changed.append(h)
                # 内容相同（主键即内容哈希），重复导入无副作用
        self.conn.commit()
        return changed, revocation_changed

    def active_records(self) -> list[Record]:
        rows = self.conn.execute(
            "SELECT record_json FROM records WHERE revoked=0"
        ).fetchall()
        return [Record.from_dict(json.loads(r["record_json"])) for r in rows]

    def all_records(self) -> list[Record]:
        rows = self.conn.execute("SELECT record_json FROM records").fetchall()
        return [Record.from_dict(json.loads(r["record_json"])) for r in rows]

    # ---- 运行 -------------------------------------------------------------
    def record_run(self, run_id: str, digest: str, algo_version: str,
                   mode: str, batch_index: int, stats: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO runs(run_id, input_digest, algo_version, mode,"
            " batch_index, stats_json) VALUES (?,?,?,?,?,?)",
            (run_id, digest, algo_version, mode, batch_index,
             canonical_json(stats)),
        )
        self.conn.commit()

    # ---- 分量缓存 ---------------------------------------------------------
    def get_component(self, digest: str, algo_version: str):
        row = self.conn.execute(
            "SELECT component_json FROM component_cache"
            " WHERE component_digest=? AND algo_version=?",
            (digest, algo_version),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["component_json"])

    def put_component(self, digest: str, algo_version: str,
                      component_json: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO component_cache(component_digest, algo_version,"
            " component_json) VALUES (?,?,?)",
            (digest, algo_version, canonical_json(component_json)),
        )
        self.conn.commit()

    def cached_digests(self, algo_version: str) -> set[str]:
        rows = self.conn.execute(
            "SELECT component_digest FROM component_cache WHERE algo_version=?",
            (algo_version,),
        ).fetchall()
        return {r["component_digest"] for r in rows}

    # ---- 报告 -------------------------------------------------------------
    def save_report(self, run_id: str, digest: str, algo_version: str,
                    report: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO reports(run_id, input_digest, algo_version,"
            " report_json) VALUES (?,?,?,?)",
            (run_id, digest, algo_version, canonical_json(report)),
        )
        self.conn.commit()

    def find_report(self, digest: str, algo_version: str) -> dict | None:
        """按输入摘要 + 算法版本取回历史报告（复现入口）。"""
        row = self.conn.execute(
            "SELECT report_json FROM reports WHERE input_digest=? AND algo_version=?",
            (digest, algo_version),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["report_json"])

    def report_count(self) -> int:
        return int(
            self.conn.execute("SELECT COUNT(*) AS c FROM reports").fetchone()["c"]
        )


def make_run_id(prefix: str, digest: str) -> str:
    return f"{prefix}-{sha256_hex(prefix + ':' + digest)[:12]}"
