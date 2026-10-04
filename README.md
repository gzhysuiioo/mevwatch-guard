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

`replicate` 在**单次进程内模拟一个 Raft 跟随者**：从标准输入读入一份 JSON
（当前任期、已提交索引、日志，以及顺序到达的复制请求），向标准输出写回一份
JSON（每条请求的接收结果、处理后的任期与已提交索引、最终完整日志）。它：

- 不连接网络、不进行选举、不与任何集群节点通信；
- 没有持久化，所有状态只保留到本次调用结束，下次调用从输入给定的初始状态重新开始；
- 仅使用 Go 标准库，行为可在本机离线、确定性地复现。

输入中的 `applyKV` 是**可选**的键值应用开关（见下文）。省略或为 `false` 时，
日志命令只是不加解释的字符串，复制与提交逻辑不受影响。

### 三个层次：复制、提交、键值生效

读输出时要区分三件不同的事，不能只看 `accepted: true`：

1. **日志已经复制**：对应请求的 `accepted` 为 `true`、`reason` 为 `"ok"`，
   且命令出现在 `finalLog` 中。这只表示跟随者收下了日志条目；被拒绝的请求
   `accepted` 为 `false` 并带有具体 `reason`（如任期更低、前置日志不匹配），
   日志与提交位置保持原样。实际因前置日志不匹配而拒绝时，结果还带有
   `conflict` 对象（`{"index", "term"}`），按本次请求检查时的本地日志给出
   建议的重发起点与冲突位置的本地任期：`prevLogIndex` 越过日志末尾时为
   末尾加一、任期 0（空日志即索引 1）；索引存在但任期不同时为该位置的本地
   任期及其在完整本地日志（含已提交前缀）中第一次出现的索引；索引 0 携带
   非零前置任期时为 `{"index": 1, "term": 0}`。成功请求与其他原因的拒绝
   都不输出 `conflict`。
2. **日志已经提交**：该请求结果中的 `committedIndex` 前进（提交位置推进到
   `min(leaderCommit, 本次确认的最后索引)`，且不会后退）。条目可以早已复制但
   一直未提交。
3. **键值命令已经生效**：仅在 `applyKV: true` 时存在。已提交条目按索引顺序
   真正作用到键值表，体现在 `appliedIndex`（已应用到哪条）与 `finalKV`
   （键值表内容）上。未提交的条目不应用；已提交但格式错误的命令会产生
   `applyError`，应用位置停在出错条目之前。

全部字段含义与复制处理规则见 `go run ./cmd/mevwatch help replicate`。

### 基本用法（不开启键值应用）

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

`applyKV` 省略或为 `false` 时，`command` 是**不解释的任意字符串**：

```bash
echo '{
  "currentTerm": 1,
  "committedIndex": 0,
  "log": [],
  "requests": [
    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 3,
     "entries": [
       {"index": 1, "term": 1, "command": "set alpha=1"},
       {"index": 2, "term": 1, "command": "set broken"},
       {"index": 3, "term": 1, "command": "delete alpha"}
     ]}
  ]
}' | go run ./cmd/mevwatch replicate
```

即使索引 2 的 `set broken` 缺少等号，它也只是一条普通字符串。三条日志一次
复制并提交到 3，输出里**没有任何应用字段**：

```json
{
  "results": [
    {
      "accepted": true,
      "reason": "ok",
      "term": 1,
      "committedIndex": 3
    }
  ],
  "finalTerm": 1,
  "finalCommittedIndex": 3,
  "finalLog": [
    {"index": 1, "term": 1, "command": "set alpha=1"},
    {"index": 2, "term": 1, "command": "set broken"},
    {"index": 3, "term": 1, "command": "delete alpha"}
  ]
}
```

### 开启 applyKV 的完整示例

输入增加 `"applyKV": true` 后，键值表在本次调用内从空表 `{}` 开始，只有
**已提交**的命令才会按索引顺序应用。下面这份输入包含五个请求：先复制三条
未提交命令，再用空条目请求把提交位置推到 3，最后追加并提交一条格式正确的
写入。

```bash
cat > /tmp/replicate-kv.json <<'EOF'
{
  "currentTerm": 1,
  "committedIndex": 0,
  "log": [],
  "applyKV": true,
  "requests": [
    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 0,
     "entries": [{"index": 1, "term": 1, "command": "set alpha=1"}]},
    {"term": 1, "prevLogIndex": 1, "prevLogTerm": 1, "leaderCommit": 0,
     "entries": [{"index": 2, "term": 1, "command": "set broken"}]},
    {"term": 1, "prevLogIndex": 2, "prevLogTerm": 1, "leaderCommit": 0,
     "entries": [{"index": 3, "term": 1, "command": "delete alpha"}]},
    {"term": 1, "prevLogIndex": 3, "prevLogTerm": 1, "leaderCommit": 3,
     "entries": []},
    {"term": 1, "prevLogIndex": 3, "prevLogTerm": 1, "leaderCommit": 4,
     "entries": [{"index": 4, "term": 1, "command": "set beta=2"}]}
  ]
}
EOF
go run ./cmd/mevwatch replicate < /tmp/replicate-kv.json
```

#### 阶段一：复制了三条命令，但一条都没提交（前三条请求）

前三条请求各自带一条新条目，`leaderCommit` 都是 0。它们都被接受
（`accepted: true`），日志里已有索引 1–3，但：

- 三条结果的 `committedIndex` 都是 0——**复制不等于提交**；
- 没有任何已提交条目，因此 `appliedIndex` 都是 0，`applyError` 都是 `null`；
- 索引 2 的 `set broken` 虽然缺等号，但它**尚未提交**，格式错误不会提前暴露；
- 键值表仍为空。

只发送这三条请求时，输出末尾是：

```json
  "finalTerm": 1,
  "finalCommittedIndex": 0,
  "finalLog": [
    {"index": 1, "term": 1, "command": "set alpha=1"},
    {"index": 2, "term": 1, "command": "set broken"},
    {"index": 3, "term": 1, "command": "delete alpha"}
  ],
  "finalAppliedIndex": 0,
  "finalKV": {},
  "finalApplyError": null
```

#### 阶段二：空条目请求提交到 3（第四条请求）

第四条请求 `entries` 为空、`prevLogIndex: 3`、`prevLogTerm: 1` 与本地日志
匹配、`leaderCommit: 3`。它不带新日志，作用是确认提交位置：

- 复制仍然被接受（心跳式空条目请求同样返回 `accepted: true`）；
- `committedIndex` 从 0 前进到 **3**；
- 应用器随即按顺序应用新提交的索引 1–3：
  - 索引 1 `set alpha=1` 生效，键值表变为 `{"alpha": "1"}`；
  - 索引 2 `set broken` 缺少等号，成为**第一个应用错误**；
  - `appliedIndex` 停在 **1**（出错条目的前一条），`applyError` 指向索引 2；
  - 索引 3 的 `delete alpha` 在出错条目之后，**不能执行**——键值表里
    `alpha` 仍然存在。

发送到第四条请求为止，第四条结果与最终字段为（仅列相关字段）：

```json
    {
      "accepted": true,
      "reason": "ok",
      "term": 1,
      "committedIndex": 3,
      "appliedIndex": 1,
      "applyError": {
        "index": 2,
        "reason": "invalid command: set requires '=' between key and value"
      }
    }
```

```json
  "finalCommittedIndex": 3,
  "finalAppliedIndex": 1,
  "finalKV": {"alpha": "1"},
  "finalApplyError": {
    "index": 2,
    "reason": "invalid command: set requires '=' between key and value"
  }
```

#### 阶段三：追加并提交一条格式正确的写入（第五条请求）

第五条请求在索引 4 追加 `set beta=2`，`leaderCommit: 4`，提交位置随之到 4。
但由于索引 2 的错误已经让应用停住，**之后的条目在本次调用内永远不再应用**：

- 复制与提交不受影响：`accepted` 仍为 `true`，`finalLog` 增长到 4 条，
  `finalCommittedIndex` 前进到 **4**；
- `finalAppliedIndex` 仍是 **1**，`finalKV` 仍是 `{"alpha": "1"}`，
  `finalApplyError` 仍是**第一次**错误（索引 2）；
- 索引 4 的 `set beta=2` 虽已提交且格式正确，也不会写入键值表。

完整输入对应的完整输出如下：

```json
{
  "results": [
    {
      "accepted": true,
      "reason": "ok",
      "term": 1,
      "committedIndex": 0,
      "appliedIndex": 0,
      "applyError": null
    },
    {
      "accepted": true,
      "reason": "ok",
      "term": 1,
      "committedIndex": 0,
      "appliedIndex": 0,
      "applyError": null
    },
    {
      "accepted": true,
      "reason": "ok",
      "term": 1,
      "committedIndex": 0,
      "appliedIndex": 0,
      "applyError": null
    },
    {
      "accepted": true,
      "reason": "ok",
      "term": 1,
      "committedIndex": 3,
      "appliedIndex": 1,
      "applyError": {
        "index": 2,
        "reason": "invalid command: set requires '=' between key and value"
      }
    },
    {
      "accepted": true,
      "reason": "ok",
      "term": 1,
      "committedIndex": 4,
      "appliedIndex": 1,
      "applyError": {
        "index": 2,
        "reason": "invalid command: set requires '=' between key and value"
      }
    }
  ],
  "finalTerm": 1,
  "finalCommittedIndex": 4,
  "finalLog": [
    {"index": 1, "term": 1, "command": "set alpha=1"},
    {"index": 2, "term": 1, "command": "set broken"},
    {"index": 3, "term": 1, "command": "delete alpha"},
    {"index": 4, "term": 1, "command": "set beta=2"}
  ],
  "finalAppliedIndex": 1,
  "finalKV": {
    "alpha": "1"
  },
  "finalApplyError": {
    "index": 2,
    "reason": "invalid command: set requires '=' between key and value"
  }
}
```

### set / delete 命令格式

命令区分大小写，命令名后必须恰好有一个普通空格，命令首尾不做任何裁剪：

- `set <key>=<value>`：写入或覆盖一个键。以键后的**第一个**等号分隔值，值
  按原文保留，**可以为空**，也可以包含空格、中文和额外等号。因此
  `set empty=` 合法（值为空字符串），`set msg=hello world 你好=a=b` 得到
  键 `msg`、值 `hello world 你好=a=b`。
- `delete <key>`：删除一个键。**删除不存在的键仍算成功**，该位置照常标记
  为已应用。
- 键不能为空、不能含空白字符、不能含等号。注意区分：`set empty=` 是
  **空值**（合法），`set =` 是**空键**（报错 `invalid command: key is
  empty`）；`set a b=1` 的键含空格，同样报错。
- 其他任何形状（无法识别的命令名、`set` 后没有等号、缺空格等）都是格式
  错误。未提交条目的格式错误不可见；只有已提交命令出错时才生成
  `applyError`。

下例一次提交四条命令，前三条应用成功（含空值、原文保留的值、删除不存在的
键），第四条空键出错，应用停在 3：

```json
{
  "currentTerm": 1,
  "committedIndex": 0,
  "log": [],
  "applyKV": true,
  "requests": [
    {"term": 1, "prevLogIndex": 0, "prevLogTerm": 0, "leaderCommit": 4,
     "entries": [
       {"index": 1, "term": 1, "command": "set empty="},
       {"index": 2, "term": 1, "command": "set msg=hello world 你好=a=b"},
       {"index": 3, "term": 1, "command": "delete ghost"},
       {"index": 4, "term": 1, "command": "set ="}
     ]}
  ]
}
```

输出末尾为：

```json
  "finalAppliedIndex": 3,
  "finalKV": {
    "empty": "",
    "msg": "hello world 你好=a=b"
  },
  "finalApplyError": {
    "index": 4,
    "reason": "invalid command: key is empty"
  }
```

### 应用错误不等于调用失败

- `applyError` / `finalApplyError` 出现在**正常的输出 JSON** 中，进程退出码
  仍为 0，对应复制请求的 `accepted` 也仍为 `true`。它只表示键值应用在该索引
  停住，复制、任期与提交位置的处理照常继续。
- 单条请求违反字段规则（如任期为负、条目不连续）时，输出中记为一次拒绝
  （`accepted: false` 加具体 `reason`），不改变任何状态，随后继续处理下一条
  请求。
- **无法解析的输入 JSON** 或**非法初始状态**（如 `committedIndex` 超过日志
  长度、日志索引不连续、条目任期超过当前任期）不会产生输出 JSON，而是以
  **非零退出码**结束并在标准错误给出消息，例如：

```text
$ echo '{not json' | go run ./cmd/mevwatch replicate
replicate: parse input JSON: invalid character 'n' looking for beginning of object key string
# 退出码 1

$ echo '{"currentTerm":1,"committedIndex":5,"log":[],"requests":[]}' | go run ./cmd/mevwatch replicate
replicate: invalid initial state: committedIndex 5 exceeds log length 0
# 退出码 1
```

## 技术方向

mev, mev-detection, sandwich-attack, anomaly-detection, transaction-monitoring, risk-engine, onchain-analytics

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
