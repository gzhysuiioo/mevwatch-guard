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

### 能力边界

`replicate` 在**单次进程调用内**模拟一个 Raft 跟随者处理日志复制：

- 标准输入读入**一份 JSON**：跟随者的初始状态（当前任期、已提交索引、已有日志）与一组**顺序到达**的复制请求；
- 标准输出返回**一份 JSON**：每条请求的接收结果、处理后的任期与已提交索引，以及最终完整日志；
- 状态**只保留到本次调用结束**，下次调用从输入给的初始状态重新开始；
- 仅使用标准库、**不连接网络**，也没有领导者选举、集群成员通信或磁盘持久化——它只是对跟随者一侧追加日志规则的确定性模拟。

字段含义与全部处理规则（任期、前缀匹配、冲突截断、拒绝原因等）以 `go run ./cmd/mevwatch help replicate` 为权威参考。

### 怎样判断：日志已复制、已提交、键值命令已生效

这是三件不同的事，输出里分别由不同字段表达，**不能只看 `accepted: true`**：

- **日志已经复制**：该请求的结果为 `"accepted": true, "reason": "ok"`，并且它带来的条目出现在最终日志 `finalLog` 中。被拒绝时 `accepted` 为 `false`、`reason` 给出具体原因，日志与已提交索引保持原样（唯一例外：携带更高任期的请求即使后续被拒，当前任期仍会更新，体现在 `term` 上）。完全匹配的短请求或重复请求也会 `accepted: true`，但不会重复添加条目。
- **日志已经提交**：处理后的 `committedIndex`（以及最终的 `finalCommittedIndex`）前进。一次成功复制只把提交位置推进到 `min(leaderCommit, prevLogIndex + len(entries))`，所以“请求被接受、日志里有了条目”并不等于条目已提交——若 `leaderCommit` 更小或为 0，提交位置可以原地不动。
- **键值命令已经生效**：只有输入设置 `"applyKV": true` 时才存在这一层。某条命令真正写入键值表，需要它既已提交、又被成功应用：其索引不超过结果中的 `appliedIndex`，效果体现在最终的 `finalKV` 中。`applyError` 非空表示第一个格式错误的已提交命令，此后的命令一律不再应用。

### 基本用法（不启用键值应用）

省略 `applyKV` 或显式设为 `false` 时，`command` 是**不加解释的任意字符串**：

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

输出：

```json
{
  "results": [
    {
      "accepted": true,
      "reason": "ok",
      "term": 1,
      "committedIndex": 0
    }
  ],
  "finalTerm": 1,
  "finalCommittedIndex": 0,
  "finalLog": [
    {
      "index": 1,
      "term": 1,
      "command": "set x=1"
    }
  ]
}
```

这里 `accepted: true` 且索引 1 出现在 `finalLog` 中，表示**日志已复制**；但 `leaderCommit` 为 0，所以 `committedIndex` 仍是 0——**尚未提交**。由于未启用 `applyKV`，输出中没有任何应用字段，`"set x=1"` 与其他任意文本（例如缺少等号的 `"set broken"`）没有区别，既不会被解析，也不可能产生键值应用错误。

### 启用 applyKV 的完整示例

下面从空日志开始，用一组请求依次演示“复制但未提交”“提交时遇到格式错误”“出错后继续复制提交”三种状态。把它保存为 `input.json`：

```json
{
  "currentTerm": 1,
  "committedIndex": 0,
  "log": [],
  "applyKV": true,
  "requests": [
    {
      "term": 1,
      "prevLogIndex": 0,
      "prevLogTerm": 0,
      "leaderCommit": 0,
      "entries": [
        {"index": 1, "term": 1, "command": "set user=alice"},
        {"index": 2, "term": 1, "command": "set broken"},
        {"index": 3, "term": 1, "command": "delete user"}
      ]
    },
    {
      "term": 1,
      "prevLogIndex": 3,
      "prevLogTerm": 1,
      "leaderCommit": 3,
      "entries": []
    },
    {
      "term": 1,
      "prevLogIndex": 3,
      "prevLogTerm": 1,
      "leaderCommit": 4,
      "entries": [
        {"index": 4, "term": 1, "command": "set note=你好 world=x"}
      ]
    }
  ]
}
```

运行：

```bash
go run ./cmd/mevwatch replicate < input.json
```

对应输出（进程退出码为 0）：

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
    {"index": 1, "term": 1, "command": "set user=alice"},
    {"index": 2, "term": 1, "command": "set broken"},
    {"index": 3, "term": 1, "command": "delete user"},
    {"index": 4, "term": 1, "command": "set note=你好 world=x"}
  ],
  "finalAppliedIndex": 1,
  "finalKV": {
    "user": "alice"
  },
  "finalApplyError": {
    "index": 2,
    "reason": "invalid command: set requires '=' between key and value"
  }
}
```

逐条看状态变化：

1. **请求 1：三条命令被复制，但都未提交。** 三条条目进入日志（`finalLog` 长度为 3），但 `leaderCommit: 0`，所以结果里 `committedIndex` 仍为 0。未提交的条目不应用：`appliedIndex` 为 0、`applyError` 为 `null`，即使索引 2 的 `set broken` 缺少等号，此刻也**不会**报格式错误；键值表为空。
2. **请求 2：空条目请求把提交位置推进到 3。** `prevLogIndex: 3` 与 `prevLogTerm: 1` 和本地日志匹配，空 `entries` 是合法的确认请求，复制照样 `accepted: true`，`committedIndex` 前进到 3。随后按索引顺序应用新提交的条目：索引 1 的 `set user=alice` 成功，键值表变为 `{"user": "alice"}`；索引 2 的 `set broken` 因缺少等号报格式错误，**应用位置停在 1**；索引 3 的 `delete user` 因此**不再执行**，`user` 没有被删除。错误只记录在 `applyError` 中，不影响这次复制本身的结果。
3. **请求 3：在出错之后继续复制并提交新条目。** 索引 4 被正常追加、提交位置随 `leaderCommit: 4` 前进到 4，说明应用错误不会阻止后续复制与提交；但应用状态已被索引 2 的错误锁死：`appliedIndex` 停在 1，`applyError` 仍是索引 2 的那一条，索引 4 的写入不会生效，`finalKV` 保持 `{"user": "alice"}`。最终结论：日志到 4、提交位置到 4、应用位置到 1、键值表只有 `user`。

### 键值命令的格式

启用 `applyKV` 后，已提交命令按下列规则解释（区分大小写，命令名后必须恰好一个普通空格，命令两端不做裁剪）：

- `set <key>=<value>`：写入或覆盖一个键。键后**第一个** `=` 分隔键与值。
  - 键必须非空，且不能包含空白字符或 `=`；
  - 值可以为**空**（`set empty=` 写入空字符串，合法），这与**空键**（`set =v` 或 `delete ` 加空键名，报 `key is empty`）是两回事；
  - 值中的空格、中文与额外等号**原样保留**：`set greet=你好 world` 的值是 `你好 world`，`set eq=a=b=c` 的值是 `a=b=c`。
- `delete <key>`：删除一个键。键的规则同上；**删除一个不存在的键仍算成功**，该索引照常计入已应用位置。
- 其他任何形状（未知命令名、缺少 `=`、键为空/含空白或等号）都是格式错误。未提交条目的格式错误不可见；已提交条目的第一个格式错误会冻结后续应用，规则与上例相同。

### 应用错误不等于调用失败

- `applyError` / `finalApplyError` 是**正常结果 JSON 的一部分**，进程仍以退出码 0 结束——它表示“这条已提交命令无法应用、应用在此停住”，不表示 replicate 调用失败。
- 单条请求违反字段规则（如任期为负、条目不连续）时，该请求记录为一次 `accepted: false` 的拒绝、不改变任何状态，随后继续处理下一条请求。
- 只有**输入 JSON 无法解析**或**初始状态非法**（如 `committedIndex` 超过日志长度、日志索引不连续、任期非法）才是调用失败：不产生结果 JSON，错误信息写到标准错误并以非零退出码结束，例如：

```bash
$ echo '{not json' | go run ./cmd/mevwatch replicate
replicate: parse input JSON: invalid character 'n' looking for beginning of object key string
# 退出码非零（通过 go run 运行时还会附带一行 exit status 1）
```

## 技术方向

mev, mev-detection, sandwich-attack, anomaly-detection, transaction-monitoring, risk-engine, onchain-analytics

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
