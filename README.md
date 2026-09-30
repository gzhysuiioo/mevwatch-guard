# MEV 与链上风险监控系统

## 用途

交易池与区块流摄取、模式识别与风险评分、规则与阈值管理、告警路由与抑制、事件回放与归因报告。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `mevwatch/`，命令入口位于 `cmd/mevwatch/`。

```bash
go run ./cmd/mevwatch demo
go run ./cmd/mevwatch version
go test ./...
```

## 技术方向

mev, mev-detection, sandwich-attack, anomaly-detection, transaction-monitoring, risk-engine, onchain-analytics

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
