//go:build (!amd64 && !arm64) || json_std

package json

import (
	"bytes"
	"encoding/json"
	"io"
)

// 本文件是 32 位 ARM（linux/arm, GOARM=6/7）等架构下的 JSON 后端。
//
// sonic 在 32 位架构上不提供任何实现（internal/utils/skip.go 里有
// _Sonic_Not_Support_32Bit_Arch_ 编译期触发器），因此这些架构只能改用标准库
// encoding/json。对外导出的面与 json.go / adapter.go 保持一致。
//
// 与 sonic 后端的已知差异：标准库恒定对 map 键排序，因此缓存序列化字节序
// 与 amd64/arm64 构建不同；同一份缓存目录不要在两种二进制之间共用。

type stdAPI struct{}

// API 与 sonic.Config 同位：调用方通过它拿 Encoder/Decoder。
var API = stdAPI{}

func (stdAPI) Marshal(v interface{}) ([]byte, error) { return json.Marshal(v) }

func (stdAPI) MarshalIndent(v interface{}, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(v, prefix, indent)
}

func (stdAPI) Unmarshal(data []byte, v interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(v)
}

func (stdAPI) NewEncoder(w io.Writer) *json.Encoder { return json.NewEncoder(w) }

func (stdAPI) NewDecoder(r io.Reader) *json.Decoder {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	return dec
}

// Decoder 是解码器类型（标准库为指针类型）。
type Decoder = *json.Decoder

// Encoder 是编码器类型（标准库为指针类型）。
type Encoder = *json.Encoder

// RawMessage 与 encoding/json 的同名类型语义一致。
type RawMessage = json.RawMessage

// Number 与 encoding/json 的同名类型一致，与 UseNumber 配置配套。
type Number = json.Number

func NewDecoder(r io.Reader) Decoder { return API.NewDecoder(r) }

func NewEncoder(w io.Writer) Encoder { return API.NewEncoder(w) }

func Marshal(v interface{}) ([]byte, error) { return API.Marshal(v) }

func Unmarshal(data []byte, v interface{}) error { return API.Unmarshal(data, v) }

func MarshalString(v interface{}) (string, error) {
	b, err := API.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func UnmarshalString(str string, v interface{}) error {
	return API.Unmarshal([]byte(str), v)
}

func MarshalIndent(v interface{}, prefix, indent string) ([]byte, error) {
	return API.MarshalIndent(v, prefix, indent)
}
