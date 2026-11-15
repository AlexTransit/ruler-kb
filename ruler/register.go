package ruler

import (
	"crypto/ecdh"
	"errors"
	"fmt"
)

// RegResult — результат регистрации: токен для логина и ключ для MiBeacon-рекламы.
type RegResult struct {
	Token   []byte // 12 байт
	BindKey []byte // 16 байт
}

var (
	regNonce = []byte{16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27}
	regAAD   = []byte("devID")
	regOK    = []byte{0x11, 0, 0, 0}
)

func isMsgMin(typ byte, n int) func([]byte) bool {
	return func(b []byte) bool {
		return len(b) >= n && b[0] == 0 && b[1] == 0 && b[2] == 2 && b[3] == typ
	}
}

// Register регистрирует новый токен на устройстве (режим сопряжения: значок BLE мигает).
// Серверы Xiaomi не нужны. После успеха прежняя привязка (Mi Home) перестаёт работать.
func (c *Client) Register() (*RegResult, error) {
	if err := c.link.SubscribeAVDTP(push(c.avdtp)); err != nil {
		return nil, fmt.Errorf("подписка avdtp: %w", err)
	}
	if err := c.link.WriteUPNP([]byte{0xa4}); err != nil {
		return nil, err
	}
	c.mtuProbe()
	if err := c.link.SubscribeUPNP(push(c.upnp)); err != nil {
		return nil, fmt.Errorf("подписка upnp: %w", err)
	}

	// 1. Информация об устройстве.
	if err := c.link.WriteUPNP([]byte{0xa2, 0, 0, 0}); err != nil {
		return nil, err
	}
	m, err := c.waitAVDTP("информация об устройстве (устройство не в режиме сопряжения?)", isMsgMin(0x00, 10))
	if err != nil {
		return nil, err
	}
	info := m[4:]
	c.Logf("remote info: %x", info)
	if err := c.link.WriteAVDTP(ackRecv); err != nil {
		return nil, err
	}

	// 2. Обмен ключами ECDH P-256 (публичный ключ — сырые X||Y, 64 байта).
	if err := c.link.WriteUPNP([]byte{0x15, 0, 0, 0}); err != nil {
		return nil, err
	}
	priv, err := ecdh.P256().GenerateKey(c.rnd)
	if err != nil {
		return nil, err
	}
	if err := c.sendMsg(0x03, priv.PublicKey().Bytes()[1:]); err != nil {
		return nil, fmt.Errorf("отправка ключа: %w", err)
	}
	m, err = c.waitAVDTP("ключ устройства", isMsg(0x03, 68))
	if err != nil {
		return nil, err
	}
	devPub, err := ecdh.P256().NewPublicKey(append([]byte{4}, m[4:]...))
	if err != nil {
		return nil, fmt.Errorf("ключ устройства: %w", err)
	}
	if err := c.link.WriteAVDTP(ackRecv); err != nil {
		return nil, err
	}
	secret, err := priv.ECDH(devPub)
	if err != nil {
		return nil, err
	}

	// 3. Токен, bind key и ключ A; подтверждаем did зашифрованным сообщением.
	okm := hkdf(secret, nil, []byte("mible-setup-info"), 64)
	res := &RegResult{Token: okm[0:12], BindKey: okm[12:28]}
	a, err := newCCM(okm[28:44])
	if err != nil {
		return nil, err
	}
	if len(info) <= 4 {
		return nil, errors.New("слишком короткая информация об устройстве")
	}
	didCT := a.sealAAD(regNonce, regAAD, info[4:])
	if err := c.sendMsg(0x00, didCT); err != nil {
		return nil, fmt.Errorf("отправка did: %w", err)
	}
	if err := c.link.WriteUPNP([]byte{0x13, 0, 0, 0}); err != nil {
		return nil, err
	}

	select {
	case b := <-c.upnp:
		if string(b) != string(regOK) {
			return nil, fmt.Errorf("устройство отклонило регистрацию: %x", b)
		}
	case <-timeAfter(stepTimeout):
		return nil, errors.New("таймаут: нет результата регистрации")
	}
	return res, nil
}
