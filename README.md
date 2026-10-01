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

检测规则按版本治理。每个版本完整声明两条规则：夹子（`sandwich`）与位移（`displacement`）各自的启停和严重度（1-5 整数），位移还需声明倍率（2-100 整数，前一笔 GasPrice 严格超过受害交易的该倍数才命中，大整数比较不溢出）。夹子启用且命中时优先于位移；两条都关闭时结论为空数组。内置版本 `builtin` 代表最初的固定规则（夹子严重度 3、位移严重度 2 倍率 2），始终可用且不可覆盖。

```bash
go run ./cmd/mevwatch rules list <归档目录>                  # 列出版本与当前启用项
go run ./cmd/mevwatch rules show <归档目录> <版本标识>        # 查看完整参数
go run ./cmd/mevwatch rules register <归档目录> <规格文件>    # 登记版本（'-' 从标准输入读）
go run ./cmd/mevwatch rules enable <归档目录> <版本标识>      # 启用已登记版本
go run ./cmd/mevwatch replay [--version <标识>] <输入文件> <归档目录>
go run ./cmd/mevwatch compare <归档目录> <chainId> <blockHash> <版本标识>
```

登记规格示例：`{"id":"strict","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":4,"multiplier":5}}}`。字段缺失、类型错误、范围越界或出现未知规则都会拒绝并指出原因；同标识同参数重复登记成功但不新增，同标识不同参数拒绝。版本随归档目录持久化，不同归档互不影响。

回放可指定已登记版本，否则用归档当前启用的版本；一次回放内所有新区块使用同一版本。新报告保存所用版本标识及完整参数；再次导入内容相同的区块仍返回最初归档的报告。`compare` 只读取归档中的交换记录，按指定版本重新判定并与归档结论对比，输出双方版本参数、完整结论、原始交换证据，以及按交易哈希升序列出的新增、消失和类型或严重度变化的结论；不修改历史报告与启用版本。旧格式归档按内置版本解释，可直接查询、比较并继续导入。

## 离线告警与抑制

告警从**已归档结论**中按条件生成，不按当前启用规则重新检测。每次生成需指定链、包含两端的区块高度范围、最低严重度（1-5 整数，等于门槛也算命中）和接收通道（非空名称，仅用于区分接收方；结果以 JSON 输出，不连接外部服务）。没有符合条件的结论时返回空数组。

```bash
go run ./cmd/mevwatch alerts generate <归档目录> <chainId> <start> <end> <minSeverity> <channel>
go run ./cmd/mevwatch alerts query <归档目录> <chainId> <channel> <start> <end>
go run ./cmd/mevwatch suppress register <归档目录> <规格文件>   # '-' 从标准输入读
go run ./cmd/mevwatch suppress list <归档目录>
```

同一链、区块哈希、受害交易哈希、结论类型和通道共同确定一条处理记录。已生成告警或已抑制的记录，重复导入、重复生成、扩大或交叠高度范围、切换检测版本及重启后都不会再次生成；不同通道分别处理，同高度不同区块哈希也分别处理。低于门槛的结论不留下处理记录，之后降低门槛可以补发。生成操作只返回本次新增的处理记录，并用 `status` 区分 `alerted`（告警）与 `suppressed`（抑制）。

处理记录保存完整区块身份、受害交易所在池、结论、原始交换证据、检测版本及参数、生成时门槛，以及命中的抑制条件与原因。查询按链、通道和高度范围过滤，结果统一按高度、区块哈希、交易哈希、类型升序排列；查询无结果返回空数组，后续登记的抑制条件不会改变已查到的历史内容。

抑制条件规格示例：`{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"webhook","start":10,"end":20,"reason":"已知做市商自成交"}`。仅支持 `sandwich` 与 `displacement` 两种类型；链、池、类型、通道全部精确匹配，池以受害交易的原始交换记录为准；高度为非负 64 位整数，起点不得大于终点，区间包含两端。抑制按事件所在高度判断，不受操作时间、导入顺序或归档最高高度影响。重叠条件同时命中时，保存所有命中标识并按字典序排列。同标识同内容重复登记成功且不新增，不同内容则拒绝；新增条件只影响尚未处理的结论，历史告警不会被改成抑制，已抑制记录也不会在区间结束后补发。

一次生成的全部新记录要么一起保存，要么全部不保存；并发处理同一归档不会重复告警或丢失记录，归档被写操作占用时返回已有忙碌错误。空名称、未知类型、越界门槛、无效高度及损坏归档均明确报错且不改变已有数据。没有告警数据的旧归档仍可使用，原有回放、报告、规则管理和比较入口保留原行为。

## 技术方向

mev, mev-detection, sandwich-attack, anomaly-detection, transaction-monitoring, risk-engine, onchain-analytics

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
