# MEV 与链上风险监控系统

## 用途

交易池与区块流摄取、模式识别与风险评分、规则与阈值管理、告警路由与抑制、事件回放与归因报告。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `mevwatch/`，命令入口位于 `cmd/mevwatch/`。

```bash
go run ./cmd/mevwatch demo
go run ./cmd/mevwatch version
go test ./...
```

## 离线区块回放与证据归档

`replay` 导入逐行 JSON 的区块文件并归档风险报告，`report` 按区块标识查询已归档报告（不依赖原输入文件）：

```bash
go run ./cmd/mevwatch replay <输入文件> <归档目录>
go run ./cmd/mevwatch report <归档目录> <chainId> <blockHash>
```

输入每行一个 JSON 对象：`chainId`、`blockHash`（非空字符串）、`blockNumber`（非负整数）、`swaps` 数组（可为空，空白行忽略）。交换记录使用 `TxHash`/`Pool`/`Trader`/`In`/`Out`/`GasPrice`/`Index` 字段。同一交易哈希的完全重复记录去重，字段冲突或不同交易占用同一 `Index` 会拒绝整个文件并指出行号。

回放按 `Index` 排列同池交换并逐笔检查相邻交易：同一交易者前后夹击且 GasPrice 均更高为夹子（严重度 3），否则前一笔 GasPrice 严格超过两倍为位移（严重度 2）。报告含区块标识、高度、去重后交换数量与按严重度降序、交易哈希升序排列的结论，每条结论附参与判断的交换原始字段。

归档整体原子提交：任一失败不写入任何报告，已有报告不被覆盖；归档被其他进程占用时返回忙碌错误。

## 技术方向

mev, mev-detection, sandwich-attack, anomaly-detection, transaction-monitoring, risk-engine, onchain-analytics

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
