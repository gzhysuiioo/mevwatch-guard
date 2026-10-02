# MEV 与链上风险监控系统

## 用途

交易池与区块流摄取、模式识别与风险评分、规则与阈值管理、告警路由与抑制、事件回放与归因报告。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `mevwatch/`，命令入口位于 `cmd/mevwatch/`。

```bash
go run ./cmd/mevwatch demo
go run ./cmd/mevwatch version
go run ./cmd/mevwatch help replicate
go test ./...
```

## replicate 子命令

在单次进程内模拟一个 Raft 跟随者：标准输入接收一份 JSON（当前任期、已提交
索引、日志，以及顺序到达的复制请求），标准输出返回一份 JSON（每条请求的
接收结果、处理后的任期与已提交索引，以及最终完整日志）。状态只在本次调用内
保留，仅使用标准库，不连接网络。

```bash
echo '{
  "currentTerm": 1,
  "committedIndex": 0,
  "log": [],
  "requests": [
    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0,
     "entries": [{"index": 1, "term": 1, "command": "set x=1"}],
     "leaderCommit": 0}
  ]
}' | go run ./cmd/mevwatch replicate
```

字段含义与全部处理规则见 `go run ./cmd/mevwatch help replicate`。

可选的键值应用：输入增加 `"applyKV": true` 后，已提交命令会被解释为
`set <key>=<value>` / `delete <key>` 键值操作，在本次调用内从空表开始随
提交位置推进逐条应用；输出增加每条请求的 `appliedIndex`/`applyError` 与
最终的 `finalAppliedIndex`/`finalKV`/`finalApplyError`。省略或为 `false`
时输出与处理行为保持不变。

## 技术方向

mev, mev-detection, sandwich-attack, anomaly-detection, transaction-monitoring, risk-engine, onchain-analytics

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
