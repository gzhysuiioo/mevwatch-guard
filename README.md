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

离线告警只消费已归档结论，**不按当前启用规则重新检测**：处理记录沿用归档时的结论、原始交换证据和检测版本参数。本次输出为 JSON，不连接任何外部服务；通道只是非空的接收方名称。

```bash
go run ./cmd/mevwatch alerts generate <归档目录> <chainId> <起始高度> <终止高度> <最低严重度> <通道>
go run ./cmd/mevwatch alerts history <归档目录> <chainId> <通道> <起始高度> <终止高度>
go run ./cmd/mevwatch suppressions register <归档目录> <规格文件>   # '-' 从标准输入读
go run ./cmd/mevwatch suppressions list <归档目录>
```

生成时在指定链上取包含两端的高度范围内的归档结论，严重度大于等于门槛（1-5 整数，等于门槛也算命中）的结论才会处理，没有符合条件的结论时输出 `[]`。命中抑制条件的结论状态为 `suppressed`，其余为 `alert`；命令只返回**本次新增**的处理记录，按高度、区块哈希、交易哈希、类型升序排列。

处理记录身份由「链、区块哈希、受害交易哈希、结论类型、通道」共同确定。已生成告警或已抑制的身份，重复导入、重复生成、扩大或交叠高度范围、切换检测版本、重启后都不会再次生成；不同通道各自独立处理，同高度但区块哈希不同也分别处理。严重度低于门槛的结论**不留下任何记录**，之后降低门槛可以补发。

每条处理记录保存完整区块身份、池、结论、原始交换证据、检测版本及完整参数、生成时门槛，以及命中的全部抑制条件标识与原因。

抑制条件登记规格示例：`{"id":"ops-1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":1000,"endHeight":2000,"reason":"已知夹子机器人维护窗口"}`。字段含义：

- `id`/`chainId`/`pool`/`kind`/`channel`/`reason` 均为非空字符串；`kind` 仅支持 `sandwich` 与 `displacement`，出现未知类型拒绝。
- `pool` 以受害交易的**原始交换记录**为准；所有字段精确匹配。
- `startHeight`/`endHeight` 为非负 64 位整数，起点不得大于终点，抑制区间包含两端；抑制按事件所在高度判断，与操作时间、导入顺序、归档最高高度无关。
- 多个重叠条件同时命中时，保存全部命中标识并按字典序排列。
- 同 `id` 同内容重复登记成功且不新增（返回 `created:false`），同 `id` 不同内容拒绝且不改动已有数据。
- 新登记条件只影响**尚未处理**的结论：历史告警不会被改写成抑制，已抑制记录也不会在区间结束后补发。

`alerts history` 按链、通道和包含两端的高度范围查询已保存的处理记录，排序规则与生成结果一致，无结果时输出 `[]`；事后登记或修改抑制条件不会改变查到的历史内容。

一次生成的全部新记录在同一次原子提交中要么全部保存、要么全部不保存；对同一归档的并发生成通过文件锁串行化，不会重复告警或丢失记录，归档被其他写操作占用时返回忙碌错误。空名称、未知类型、越界门槛、无效高度及损坏归档都会明确报错且不改变已有数据。没有告警数据的旧归档可直接使用本功能；`replay`、`report`、`rules`、`compare` 入口行为保持不变。

## 人工复核与规则误报分析

人工复核在归档结论之上追加判定，不重新检测、不自动撤销或补发告警。复核对象由「链、区块哈希、受害交易哈希、结论类型」共同确定，不随告警通道改变；同高度不同区块分别处理。

```bash
go run ./cmd/mevwatch review submit <归档目录> <规格文件>   # '-' 从标准输入读
go run ./cmd/mevwatch review history <归档目录> <chainId> <blockHash> <txHash> <kind>
go run ./cmd/mevwatch review evaluate <归档目录> <chainId> <起始高度> <终止高度> <版本标识>
```

提交规格示例：`{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","commitId":"c1","operator":"alice","reason":"真实受害者","expectedVersion":0,"status":"real-risk"}`。字段含义：

- `chainId`/`blockHash`/`txHash`/`kind` 确定复核对象，结论必须已在归档中存在；`kind` 仅支持 `sandwich` 与 `displacement`。
- `commitId` 为归档内唯一的提交标识，非空；`operator`/`reason` 非空。
- `status` 为 `real-risk`（真实风险）、`false-positive`（误报）或 `unreviewed`（未复核/撤回）。
- `expectedVersion` 为预期复核版本号，非负整数；首次提交必须为 0。

提交采用乐观并发：新提交标识仅在预期版本等于对象当前版本时成功，成功后对象版本加 1；改判和撤回都新增修订，旧记录保留。相同提交标识与字段值重试返回原修订（即使后来已改判也不追加）；相同标识内容不同或预期版本过期时报冲突。并发提交通过文件锁串行化，不会覆盖他人修改。任何失败不改变已有数据；写入为原子提交，重启后历史与重试结果一致。

`review history` 返回对象当前状态、版本及按版本升序排列的全部修订，每版保留提交内容，并附原结论、检测版本参数与原始交换证据。没有复核数据的对象状态为 `unreviewed`、版本为 `0`、修订为 `[]`；不存在的结论或修订用 `null` 表示。

`review evaluate` 用指定已登记规则版本对包含两端高度范围内的各区块重新判定，整次评估采用一致的归档与最新复核状态。只对标为 `real-risk` 或 `false-positive` 的原结论统计：真实风险分为「保留」（候选仍命中）与「漏掉」（候选未命中），误报分为「仍命中」与「已消除」。同一交易且类型相同才算匹配，严重度变化不影响；类型改变时原类型算未命中，新类型按未复核结论列出。候选版本命中但没有有效复核的结论单列「待复核」，不计入四项；撤回后的对象按未复核处理。输出四项数量、待复核数量及对应明细，明细带区块身份、采用的复核修订、原结论与候选结论、各自规则参数及交换证据，按高度、区块哈希、交易哈希、类型升序排列。范围内没有区块时各项为 0、明细为 `[]`。评估不修改报告、启用版本或告警记录；旧归档可直接使用本功能。

## 技术方向

mev, mev-detection, sandwich-attack, anomaly-detection, transaction-monitoring, risk-engine, onchain-analytics

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
