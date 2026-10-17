// Package secrets 生成配置中使用的随机凭据：密码、UUID、Reality 密钥对等。
package secrets

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Password 生成 24 个字符的随机密码（base64url 字符集）
func Password() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// UUID 生成随机（v4）UUID
func UUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// RealityKeyPair 生成 Reality 使用的 X25519 密钥对，格式与 sing-box generate reality-keypair 相同
func RealityKeyPair() (privateKey, publicKey string) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err) // crypto/rand 不会失败
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(key.Bytes()), enc.EncodeToString(key.PublicKey().Bytes())
}

// RealityPublicKey 由私钥推导公钥
func RealityPublicKey(privateKey string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("不是 base64url 编码")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("不是 X25519 私钥")
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// ShortID 生成 16 位十六进制的 Reality short_id
func ShortID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Key 生成 n 字节随机密钥的标准 base64 编码，用作 Shadowsocks 2022 的密码
// （与 sing-box generate rand --base64 <n> 相同）
func Key(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
