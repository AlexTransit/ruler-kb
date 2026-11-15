package ruler

import (
	"encoding/binary"
	"errors"
)

// deriveKeys выводит ключи сессии из токена и двух случайных чисел логина.
func deriveKeys(token, appRand, devRand []byte) (devKey, appKey []byte, devIV, appIV [4]byte) {
	salt := append(append([]byte{}, appRand...), devRand...)
	okm := hkdf(token, salt, []byte("mible-login-info"), 64)
	devKey, appKey = okm[0:16], okm[16:32]
	copy(devIV[:], okm[32:36])
	copy(appIV[:], okm[36:40])
	return
}

// session — зашифрованный канал после логина.
// Формат пакета: счётчик(2, LE) || AES-CCM(шифртекст || MIC 4).
type session struct {
	dev, app     *ccm
	devIV, appIV [4]byte
	tx           uint16
}

func newSession(devKey, appKey []byte, devIV, appIV [4]byte) (*session, error) {
	d, err := newCCM(devKey)
	if err != nil {
		return nil, err
	}
	a, err := newCCM(appKey)
	if err != nil {
		return nil, err
	}
	return &session{dev: d, app: a, devIV: devIV, appIV: appIV}, nil
}

func nonce(iv [4]byte, cnt uint16) []byte {
	n := make([]byte, ccmNonceLen)
	copy(n, iv[:])
	binary.LittleEndian.PutUint32(n[8:], uint32(cnt))
	return n
}

// decrypt расшифровывает пакет от устройства.
func (s *session) decrypt(pkt []byte) (plain []byte, cnt uint16, err error) {
	if len(pkt) < 2+ccmTagLen {
		return nil, 0, errors.New("короткий пакет")
	}
	cnt = binary.LittleEndian.Uint16(pkt)
	plain, err = s.dev.open(nonce(s.devIV, cnt), pkt[2:])
	return plain, cnt, err
}

// encrypt готовит пакет для устройства (счётчик растёт сам).
func (s *session) encrypt(plain []byte) []byte {
	cnt := s.tx
	s.tx++
	out := make([]byte, 2, 2+len(plain)+ccmTagLen)
	binary.LittleEndian.PutUint16(out, cnt)
	return append(out, s.app.seal(nonce(s.appIV, cnt), plain)...)
}
