package ruler

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
)

// hkdf — HKDF-SHA256 (RFC 5869).
func hkdf(ikm, salt, info []byte, n int) []byte {
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	prk := ext.Sum(nil)
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

func hmacSHA256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// ccm — AES-CCM (RFC 3610) с nonce 12 байт, тегом 4 байта и без AAD.
type ccm struct{ b cipher.Block }

const (
	ccmNonceLen = 12
	ccmTagLen   = 4
)

func newCCM(key []byte) (*ccm, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &ccm{b}, nil
}

func (c *ccm) cbcMac(nonce, aad, msg []byte) [16]byte {
	var b0 [16]byte
	b0[0] = byte(((ccmTagLen-2)/2)<<3 | (15 - ccmNonceLen - 1)) // 0x0a
	if len(aad) > 0 {
		b0[0] |= 0x40
	}
	copy(b0[1:13], nonce)
	b0[13], b0[14], b0[15] = byte(len(msg)>>16), byte(len(msg)>>8), byte(len(msg))
	var x [16]byte
	c.b.Encrypt(x[:], b0[:])
	absorb := func(data []byte) {
		for i := 0; i < len(data); i += 16 {
			var blk [16]byte
			copy(blk[:], data[i:])
			for j := range x {
				x[j] ^= blk[j]
			}
			c.b.Encrypt(x[:], x[:])
		}
	}
	if len(aad) > 0 { // длина AAD < 0xFF00: 2 байта big-endian
		absorb(append([]byte{byte(len(aad) >> 8), byte(len(aad))}, aad...))
	}
	absorb(msg)
	return x
}

func (c *ccm) ctrBlock(nonce []byte, i int) [16]byte {
	var a, s [16]byte
	a[0] = 15 - ccmNonceLen - 1 // 0x02
	copy(a[1:13], nonce)
	a[13], a[14], a[15] = byte(i>>16), byte(i>>8), byte(i)
	c.b.Encrypt(s[:], a[:])
	return s
}

func (c *ccm) xorStream(nonce, in []byte) []byte {
	out := make([]byte, len(in))
	for i := 0; i < len(in); i += 16 {
		s := c.ctrBlock(nonce, i/16+1)
		for j := 0; j < 16 && i+j < len(in); j++ {
			out[i+j] = in[i+j] ^ s[j]
		}
	}
	return out
}

// seal возвращает шифртекст || тег(4).
func (c *ccm) seal(nonce, plain []byte) []byte { return c.sealAAD(nonce, nil, plain) }

func (c *ccm) sealAAD(nonce, aad, plain []byte) []byte {
	t := c.cbcMac(nonce, aad, plain)
	s0 := c.ctrBlock(nonce, 0)
	out := c.xorStream(nonce, plain)
	for i := 0; i < ccmTagLen; i++ {
		out = append(out, t[i]^s0[i])
	}
	return out
}

var errAuth = errors.New("ccm: неверный MIC")

func (c *ccm) open(nonce, ct []byte) ([]byte, error) { return c.openAAD(nonce, nil, ct) }

func (c *ccm) openAAD(nonce, aad, ct []byte) ([]byte, error) {
	if len(ct) < ccmTagLen {
		return nil, errors.New("ccm: слишком короткое сообщение")
	}
	body, tag := ct[:len(ct)-ccmTagLen], ct[len(ct)-ccmTagLen:]
	plain := c.xorStream(nonce, body)
	t := c.cbcMac(nonce, aad, plain)
	s0 := c.ctrBlock(nonce, 0)
	var want [ccmTagLen]byte
	for i := range want {
		want[i] = t[i] ^ s0[i]
	}
	if subtle.ConstantTimeCompare(want[:], tag) != 1 {
		return nil, errAuth
	}
	return plain, nil
}
