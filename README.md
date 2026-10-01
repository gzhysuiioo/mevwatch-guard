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

## 规则版本

系统内置代表当前固定规则的 `builtin` 版本（夹子 severity 3、位移 severity 2、倍率 2），其参数可查询且不可覆盖。未启用新版本时，检测结果与内置版本一致。

版本按归档目录保存，不同归档互不影响；重启后仍可使用。版本标识必须非空，每个版本完整声明两条规则的启停状态与严重度（1 至 5 的整数）；位移规则还需声明 2 至 100 的整数倍率，只有前一笔 GasPrice 严格超过受害交易的该倍数才命中（大整数比较不溢出）。字段缺失、类型错误、范围越界或出现未知规则时登记失败并指出原因。

```bash
go run ./cmd/mevwatch version register <归档目录> '<版本JSON>'   # 或 @文件
go run ./cmd/mevwatch version list <归档目录>
go run ./cmd/mevwatch version enable <归档目录> <版本标识>
```

同一标识与相同参数重复登记成功但不增加版本，同一标识配不同参数拒绝。启用未知版本失败，原启用版本不变。

回放可指定已登记版本，否则采用该归档当前启用的版本；一次回放中的所有新区块使用同一版本，即使期间有人切换也不混用。报告保存所用版本标识及完整参数，查询时无需原规则文件；再次导入内容相同的区块仍返回最初归档的报告。

```bash
go run ./cmd/mevwatch replay <输入文件> <归档目录> --version <版本标识>
```

## 按版本比较结论

`compare` 只读取归档中的交换记录，按指定版本重新检测，并与归档结论比较；不依赖原输入文件，也不更改历史报告或启用版本。

```bash
go run ./cmd/mevwatch compare <归档目录> <chainId> <blockHash> <版本标识>
```

输出原版本与比较版本的参数、双方完整结论与原始交换证据，并按交易哈希列出新增、消失以及类型或严重度变化的结论；同一交易的类型变化只列为变化。各类差异按交易哈希升序排列。未知区块或版本返回明确错误。旧格式归档按内置版本解释，可直接查询、比较及继续导入，已有结论和证据保持原样。

## 技术方向

mev, mev-detection, sandwich-attack, anomaly-detection, transaction-monitoring, risk-engine, onchain-analytics

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
