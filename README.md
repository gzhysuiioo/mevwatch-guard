# MEV 与链上风险监控系统

## 用途

交易池与区块流摄取、模式识别与风险评分、规则与阈值管理、告警路由与抑制、事件回放与归因报告。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `mevwatch/`，命令入口位于 `cmd/mevwatch/`。

```bash
go run ./cmd/mevwatch demo
go run ./cmd/mevwatch version
go run ./cmd/mevwatch replay <输入文件> <归档目录>
go run ./cmd/mevwatch report <归档目录> <chainId> <blockHash>
go test ./...
```

## 离线区块回放与证据归档

`replay` 逐行读取 JSON 区块（每行一个区块），按 `chainId` 与 `blockHash` 共同标识区块，将去重后的交换集合与风险结论归档到指定目录。归档只使用标准库，可在本机离线复现。

输入每行格式：

```json
{"chainId":"0x1","blockHash":"0xaa","blockNumber":100,"swaps":[{"TxHash":"0xf","Pool":"p","Trader":"bot","In":1,"Out":1,"GasPrice":100,"Index":0}]}
```

- `chainId`、`blockHash` 为非空字符串；`blockNumber` 为非负整数；`swaps` 为数组（可为空）。
- 交换字段：`TxHash`、`Pool`、`Trader` 不能为空；`In`、`Out`、`GasPrice`、`Index` 为非负整数。
- 空白行忽略；任一行校验失败时错误指出行号，进程非零退出，归档保持原状。

归档规则：

- 同一区块内同一 `TxHash` 的完全相同记录只保留一份；字段冲突或不同交易占用同一 `Index` 时拒绝整个文件。
- 交换按 `Pool` 分组、按 `Index` 排列，只比较相邻交换：前后交易属于同一交易者、与受害者不同且两者 GasPrice 均更高时产生严重度 3 的夹子结论；否则前一笔 GasPrice 严格超过受害交易 GasPrice 两倍时产生严重度 2 的位移结论（池内最后一笔也能被识别）。
- 结论按严重度降序、`TxHash` 升序排列，每条结论附带受害交易与参与判断的交换原始字段供核对。
- 相同区块再次导入返回原报告，不增加记录；同一标识的高度或交换内容变化则拒绝。
- 一次 replay 的全部新报告共同生效：写入临时文件后原子提交，中断后重新打开只能看到完整提交；已有报告不会被重放覆盖。
- 多进程并发写同一归档时，后到者可报忙碌错误并非零退出，但不会丢失记录或留下半份报告。

`report` 只读取归档，不依赖原输入文件；未知区块非零退出且不输出报告。

## 技术方向

mev, mev-detection, sandwich-attack, anomaly-detection, transaction-monitoring, risk-engine, onchain-analytics

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
