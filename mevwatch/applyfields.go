// 结果 JSON 中键值应用字段的编解码规则。逐条请求结果（AppendResult）与整次
// 调用结果（ReplicateOutput）两层共用本文件的同一套约定，避免两处各自实现
// 导致行为漂移。本文件只做纯逻辑处理。
package mevwatch

import (
	"bytes"
	"encoding/json"
)

// 两层结果共用的应用字段规则：
//
// 输出：是否输出应用字段由该层结果上的应用字段开关（applyFields）决定，
// 开关只在启用键值应用（ReplicateOptions.ApplyKV）的结果上打开。开关关闭
// 时应用字段整体缺省（字段上的 omitempty 生效，命令按任意字符串处理的原
// 有输出形状不变）；开关打开时该层全部应用字段强制输出，零值照常出现——
// 索引为 0 输出 0、空键值表输出 {}、无错误输出 null，不因值为空而省略。
//
// 填充：开启键值应用时，每条结果必须填已应用索引与应用错误，最终结果必须
// 填已应用索引、键值表与应用错误；没有复制请求时最终结果同样反映初始已
// 提交前缀的应用状态。
//
// 读入：按该层 JSON 中是否出现任一应用字段恢复开关，判定与解码接受的键名
// 规则一致：字段名只改字母大小写（如 "ApplyError"、"FINALKV"）也按出现处理，
// 与其值是否为空无关；与应用字段名只是相似的无关键不触发。出现任一字段即视
// 为启用应用的结果，再次输出时带上该层完整应用字段；完全未出现则不补上。
// 两层各自独立判断，互不推断。读入会用解码出的新值完整替换结果对象，不残留
// 上一次读入的键值表、应用位置或错误；JSON 无法解析或字段类型不合法照常返回
// 解码错误，结果对象保持读入前的内容，不会把错误内容当作零值接受。

// appendResultApplyKeys 是 AppendResult 一层用于判定应用字段是否出现的键名。
var appendResultApplyKeys = []string{"appliedIndex", "applyError"}

// replicateOutputApplyKeys 是 ReplicateOutput 一层用于判定应用字段是否出现的键名。
var replicateOutputApplyKeys = []string{"finalAppliedIndex", "finalKV", "finalApplyError"}

// marshalApplyFields 按开关选择输出形状：开关关闭时编码 plain（应用字段因
// omitempty 整体缺省）；开关打开时编码 forced（应用字段以零值兜底全部出现）。
func marshalApplyFields(plain any, applyFields bool, forced any) ([]byte, error) {
	if !applyFields {
		return json.Marshal(plain)
	}
	return json.Marshal(forced)
}

// unmarshalApplyFields 把 data 解码到 dst 指向的别名对象，并报告 data 中是否
// 出现 keys 里的任一应用字段键。解码成功时 *dst 被新值完整替换，不残留此前
// 读入的应用状态；JSON 无法解析或字段类型不合法时返回错误，*dst 保持不变。
func unmarshalApplyFields[T any](data []byte, dst *T, keys []string) (present bool, err error) {
	var decoded T
	if err := json.Unmarshal(data, &decoded); err != nil {
		return false, err
	}
	present, err = jsonHasAnyKey(data, keys...)
	if err != nil {
		return false, err
	}
	*dst = decoded
	return present, nil
}

// jsonHasAnyKey 报告 JSON 对象中是否出现任一给定键。判定与 encoding/json
// 解码时的字段匹配规则一致：键名比较按 Unicode 大小写折叠（等价于
// bytes.EqualFold），因此只改字母大小写的应用字段名（如 "ApplyError"）
// 同样算出现；与字段名只是相似的其他键不会命中。
func jsonHasAnyKey(data []byte, keys ...string) (bool, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return false, err
	}
	for presentKey := range raw {
		for _, key := range keys {
			if bytes.EqualFold([]byte(presentKey), []byte(key)) {
				return true, nil
			}
		}
	}
	return false, nil
}

// derefInt 返回指针指向的索引值，nil 按 0 处理（强制输出时的零值兜底）。
func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// nonNilStringMap 把 nil 键值表替换为空表，保证强制输出时得到 {} 而不是 null。
func nonNilStringMap(kv map[string]string) map[string]string {
	if kv == nil {
		return map[string]string{}
	}
	return kv
}

// setApplyFields 填充单条请求结果的应用字段并打开该层的应用字段开关：
// 处理本请求后已应用的最高日志索引与首个应用错误（无错误为 nil）。
func (r *AppendResult) setApplyFields(appliedIndex int, applyErr *ApplyError) {
	r.AppliedIndex = &appliedIndex
	r.ApplyError = applyErr
	r.applyFields = true
}

// setApplyFields 填充整次调用结果的应用字段并打开该层的应用字段开关：
// 最终已应用的最高日志索引、最终键值表与首个应用错误（无错误为 nil）。
func (o *ReplicateOutput) setApplyFields(appliedIndex int, kv map[string]string, applyErr *ApplyError) {
	o.FinalAppliedIndex = &appliedIndex
	o.FinalKV = kv
	o.FinalApplyError = applyErr
	o.applyFields = true
}

// MarshalJSON 按共用规则输出应用字段：未启用键值应用时保持原有输出形状；
// 启用时强制输出 appliedIndex 与 applyError（索引 0 照常出现，无错误时为 null）。
func (r AppendResult) MarshalJSON() ([]byte, error) {
	type alias AppendResult
	return marshalApplyFields(alias(r), r.applyFields, struct {
		alias
		AppliedIndex int         `json:"appliedIndex"`
		ApplyError   *ApplyError `json:"applyError"`
	}{
		alias:        alias(r),
		AppliedIndex: derefInt(r.AppliedIndex),
		ApplyError:   r.ApplyError,
	})
}

// UnmarshalJSON 按共用规则读入应用字段：出现 appendResultApplyKeys 中任一键
// （键名只改字母大小写也算，与解码的字段匹配规则一致）即视为启用键值应用的
// 结果，再次编码会原样保留这些字段（含 0、null）；未出现时按未启用处理。
// 整个对象被完整替换，不会残留上一次读入的应用状态。字段类型错误照常返回
// 解码错误，结果保持读入前的内容。
func (r *AppendResult) UnmarshalJSON(data []byte) error {
	type alias AppendResult
	var decoded alias
	present, err := unmarshalApplyFields(data, &decoded, appendResultApplyKeys)
	if err != nil {
		return err
	}
	*r = AppendResult(decoded)
	r.applyFields = present
	return nil
}

// MarshalJSON 按共用规则输出应用字段：未启用键值应用时保持原有输出形状；
// 启用时强制输出 finalAppliedIndex、finalKV（空表为 {}）与 finalApplyError
// （无错误为 null）。
func (o ReplicateOutput) MarshalJSON() ([]byte, error) {
	type alias ReplicateOutput
	return marshalApplyFields(alias(o), o.applyFields, struct {
		alias
		FinalAppliedIndex int               `json:"finalAppliedIndex"`
		FinalKV           map[string]string `json:"finalKV"`
		FinalApplyError   *ApplyError       `json:"finalApplyError"`
	}{
		alias:             alias(o),
		FinalAppliedIndex: derefInt(o.FinalAppliedIndex),
		FinalKV:           nonNilStringMap(o.FinalKV),
		FinalApplyError:   o.FinalApplyError,
	})
}

// UnmarshalJSON 按共用规则读入应用字段，语义同 AppendResult.UnmarshalJSON：
// 出现 replicateOutputApplyKeys 中任一键（键名只改字母大小写也算）时再次编码
// 保留 finalAppliedIndex、finalKV（空表为 {}）与 finalApplyError（无错误为
// null）；未出现时整个对象被完整替换，不残留上一次读入的键值表、错误或应用
// 位置。Results 中每条请求结果由 AppendResult.UnmarshalJSON 各自恢复。字段
// 类型错误照常返回解码错误，结果保持读入前的内容。
func (o *ReplicateOutput) UnmarshalJSON(data []byte) error {
	type alias ReplicateOutput
	var decoded alias
	present, err := unmarshalApplyFields(data, &decoded, replicateOutputApplyKeys)
	if err != nil {
		return err
	}
	*o = ReplicateOutput(decoded)
	o.applyFields = present
	return nil
}
