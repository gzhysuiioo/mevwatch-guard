// 复制结果的 JSON 编解码统一在本文件组织，replicate.go 只保留结果类型与
// 复制逻辑。
//
// 复制结果有两层：逐请求结果 AppendResult 与整次调用结果 ReplicateOutput。
// 两层各带一组“键值应用字段”，它们是否出现在 JSON 中只取决于本层：
//
//   - 本次调用未启用键值应用（或读入的 JSON 本层完全没有应用字段）时，
//     该层输出保持原有形状，应用字段一个都不新增；
//   - 启用（或读入的 JSON 本层出现任一应用字段）时，该层输出完整的一组
//     应用字段：索引为 0 也出现、无错误输出 null、空键值表输出 {}，
//     不因值为空而省略。
//
// 两层的字段出现性各自记录、互不从属推断：最终层出现不代表逐条层出现，
// 反之亦然。读入始终是对目标对象的完整替换：先读一份启用应用的结果再读
// 一份未启用的结果时，后者不补字段，前者残留的表、位置与错误也被清掉。
package mevwatch

import "encoding/json"

// appendResultApplyKeys 是 AppendResult 层的键值应用字段；出现任一个即
// 表示该层携带应用字段，再次输出时要给齐整组。
var appendResultApplyKeys = []string{"appliedIndex", "applyError"}

// replicateOutputApplyKeys 是 ReplicateOutput 层的键值应用字段。
var replicateOutputApplyKeys = []string{"finalAppliedIndex", "finalKV", "finalApplyError"}

// 以下 defined 类型刻意不继承原类型的 MarshalJSON/UnmarshalJSON 方法：
// 既作为未启用应用时的直接输出形状（字段标签与 omitempty 行为保持原样），
// 又可安全嵌入强制输出视图，避免在自定义 MarshalJSON 中递归调用自身。
type appendResultFields AppendResult
type replicateOutputFields ReplicateOutput

// appendResultWithApply 是 AppendResult 启用应用时的输出视图：外层同名字段
// 提升后覆盖嵌入体里的 omitempty 字段，强制输出 appliedIndex（0 也出现）
// 与 applyError（无错误为 null）。
type appendResultWithApply struct {
	appendResultFields
	AppliedIndex int         `json:"appliedIndex"`
	ApplyError   *ApplyError `json:"applyError"`
}

// replicateOutputWithApply 是 ReplicateOutput 启用应用时的输出视图：
// finalAppliedIndex 为 0 也出现、finalKV 空表输出 {}、finalApplyError
// 无错误输出 null。
type replicateOutputWithApply struct {
	replicateOutputFields
	FinalAppliedIndex int               `json:"finalAppliedIndex"`
	FinalKV           map[string]string `json:"finalKV"`
	FinalApplyError   *ApplyError       `json:"finalApplyError"`
}

// marshalApplyJSON 统一两层的输出开关：present 为 false 时编码 without
// （应用字段按原 omitempty 形状缺席），为 true 时编码 with（调用方给齐
// 该层完整应用字段）。
func marshalApplyJSON(present bool, without, with any) ([]byte, error) {
	if present {
		return json.Marshal(with)
	}
	return json.Marshal(without)
}

// decodeApplyJSON 统一两层的读入：先解码进 dst（调用方传入不带自定义方法
// 的字段视图，字段类型不合法时原样返回解码错误，错误内容不会被当成零值
// 接受），再按 keys 中任一键是否在 JSON 对象中出现，得到该层的字段出现性。
// 调用方随后应整体替换目标对象并写回出现性，保证不残留上一次读入的状态。
func decodeApplyJSON(data []byte, dst any, keys []string) (bool, error) {
	if err := json.Unmarshal(data, dst); err != nil {
		return false, err
	}
	return jsonObjectHasAnyKey(data, keys...)
}

// jsonObjectHasAnyKey 报告 JSON 对象文本中是否出现任一给定键；data 不是
// 合法 JSON 对象时返回其解码错误。
func jsonObjectHasAnyKey(data []byte, keys ...string) (bool, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return false, err
	}
	for _, key := range keys {
		if _, ok := raw[key]; ok {
			return true, nil
		}
	}
	return false, nil
}

// derefOrZero 解引用指针，nil 时返回元素类型零值。用于把 *int 形式的
// 应用索引以普通 int 强制输出（0 也出现）。
func derefOrZero[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

// nonNilKV 保证键值表以非 nil 映射输出，使空表编码为 {} 而不是 null。
func nonNilKV(kv map[string]string) map[string]string {
	if kv == nil {
		return map[string]string{}
	}
	return kv
}

// AppendResult 的编解码只负责声明本层字段视图，出现性判定、解码错误与
// 零值规则全部走上面的统一辅助逻辑。

func (r AppendResult) MarshalJSON() ([]byte, error) {
	fields := appendResultFields(r)
	return marshalApplyJSON(r.applyFields, fields, appendResultWithApply{
		appendResultFields: fields,
		AppliedIndex:       derefOrZero(r.AppliedIndex),
		ApplyError:         r.ApplyError,
	})
}

func (r *AppendResult) UnmarshalJSON(data []byte) error {
	var fields appendResultFields
	present, err := decodeApplyJSON(data, &fields, appendResultApplyKeys)
	if err != nil {
		return err
	}
	*r = AppendResult(fields)
	r.applyFields = present
	return nil
}

// ReplicateOutput 的编解码同样只声明本层视图。Results 元素仍是
// AppendResult，逐条结果由其自身的 UnmarshalJSON 各自恢复本层出现性，
// 与最终层互不推断。

func (o ReplicateOutput) MarshalJSON() ([]byte, error) {
	fields := replicateOutputFields(o)
	return marshalApplyJSON(o.applyFields, fields, replicateOutputWithApply{
		replicateOutputFields: fields,
		FinalAppliedIndex:     derefOrZero(o.FinalAppliedIndex),
		FinalKV:               nonNilKV(o.FinalKV),
		FinalApplyError:       o.FinalApplyError,
	})
}

func (o *ReplicateOutput) UnmarshalJSON(data []byte) error {
	var fields replicateOutputFields
	present, err := decodeApplyJSON(data, &fields, replicateOutputApplyKeys)
	if err != nil {
		return err
	}
	*o = ReplicateOutput(fields)
	o.applyFields = present
	return nil
}
