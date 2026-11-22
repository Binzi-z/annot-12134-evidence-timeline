"""安全事件证据时间线重建工具包。

模块划分：
- versioning: 算法版本、规范化 JSON 与输入摘要
- intervals:  带误差半径的时间区间
- model:      离线日志记录与事件节点的数据模型
- anchors:    HMAC 签名锚点链校验
- engine:     约束图引擎（三类判定 + 最小冲突集）
- bruteforce: 小规模穷举参考实现
- store:      SQLite 持久化与分量结果缓存
- pipeline:   全量 / 增量编排与可复现报告
- synthetic:  合成数据生成
"""

ALGORITHM_VERSION = "1.0.0"
