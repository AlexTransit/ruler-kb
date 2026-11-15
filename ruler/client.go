// Package ruler реализует клиент BLE-рулетки (Xiaomi Mi Secure Connect):
// логин по токену и разбор зашифрованных уведомлений с замерами.
package ruler

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"
)

// Link — транспорт BLE. Все записи — "write without response".
type Link interface {
	SubscribeAVDTP(cb func([]byte)) error // характеристика 0x0019
	SubscribeUPNP(cb func([]byte)) error  // характеристика 0x0010
	SubscribeData(cb func([]byte)) error  // 0xFEA8 (notify)
	WriteUPNP(b []byte) error
	WriteAVDTP(b []byte) error
	WriteData(b []byte) error // 0xFEA7
}

// ErrBadToken — токен не подходит к устройству.
var ErrBadToken = errors.New("токен не подходит: HMAC устройства не совпал")

const stepTimeout = 4 * time.Second

var (
	ackReady = []byte{0, 0, 1, 1}
	ackDone  = []byte{0, 0, 1, 0}
	ackRecv  = []byte{0, 0, 3, 0}
	loginOK  = []byte{0x21, 0, 0, 0}
)

type Client struct {
	Logf func(format string, args ...any)

	link    Link
	token   []byte
	rnd     io.Reader
	avdtp   chan []byte
	upnp    chan []byte
	data    chan []byte
	backlog [][]byte
	sess    *session
}

func NewClient(link Link, token []byte) *Client {
	return &Client{
		Logf:  func(string, ...any) {},
		link:  link,
		token: token,
		rnd:   rand.Reader,
		avdtp: make(chan []byte, 64),
		upnp:  make(chan []byte, 16),
		data:  make(chan []byte, 64),
	}
}

func push(ch chan []byte) func([]byte) {
	return func(b []byte) {
		select {
		case ch <- append([]byte(nil), b...):
		default:
		}
	}
}

func (c *Client) waitAVDTP(what string, pred func([]byte) bool) ([]byte, error) {
	for i, b := range c.backlog {
		if pred(b) {
			c.backlog = append(c.backlog[:i], c.backlog[i+1:]...)
			return b, nil
		}
	}
	t := time.NewTimer(stepTimeout)
	defer t.Stop()
	for {
		select {
		case b := <-c.avdtp:
			c.Logf("avdtp rx %x", b)
			if pred(b) {
				return b, nil
			}
			c.backlog = append(c.backlog, b)
		case <-t.C:
			return nil, fmt.Errorf("таймаут: нет %s", what)
		}
	}
}

func eq(want []byte) func([]byte) bool {
	return func(b []byte) bool { return bytes.Equal(b, want) }
}

func prefix(want ...byte) func([]byte) bool {
	return func(b []byte) bool { return bytes.HasPrefix(b, want) }
}

func isMsg(typ byte, n int) func([]byte) bool {
	return func(b []byte) bool {
		return len(b) == n && b[0] == 0 && b[1] == 0 && b[2] == 2 && b[3] == typ
	}
}

// sendMsg отправляет сообщение из одного кадра: заголовок -> "готов" -> данные -> "принято".
func (c *Client) sendMsg(typ byte, data []byte) error {
	if err := c.link.WriteAVDTP([]byte{0, 0, 0, typ, 1, 0}); err != nil {
		return err
	}
	if _, err := c.waitAVDTP("подтверждение 0101", eq(ackReady)); err != nil {
		return err
	}
	if err := c.link.WriteAVDTP(append([]byte{1, 0}, data...)); err != nil {
		return err
	}
	_, err := c.waitAVDTP("подтверждение 0100", eq(ackDone))
	return err
}

// mtuProbe повторяет обмен из лога Mi Home; ошибки не фатальны.
func (c *Client) mtuProbe() {
	if err := c.link.WriteAVDTP([]byte{0, 0, 5, 0, 6, 0xf2}); err != nil {
		c.Logf("mtu-проба: %v", err)
		return
	}
	if _, err := c.waitAVDTP("эхо 0400", prefix(0, 0, 4, 0)); err != nil {
		c.Logf("mtu-проба: %v", err)
		return
	}
	blk := append([]byte{0, 0, 5, 1}, bytes.Repeat([]byte{0xf2}, 240)...)
	if err := c.link.WriteAVDTP(blk); err != nil {
		c.Logf("mtu-проба: %v", err)
		return
	}
	if _, err := c.waitAVDTP("эхо 0401", prefix(0, 0, 4, 1)); err != nil {
		c.Logf("mtu-проба: %v", err)
	}
}

// Login выполняет вход по токену.
func (c *Client) Login() error {
	if err := c.link.SubscribeAVDTP(push(c.avdtp)); err != nil {
		return fmt.Errorf("подписка avdtp: %w", err)
	}
	if err := c.link.WriteUPNP([]byte{0xa4}); err != nil {
		return err
	}
	c.mtuProbe()
	if err := c.link.SubscribeUPNP(push(c.upnp)); err != nil {
		return fmt.Errorf("подписка upnp: %w", err)
	}
	if err := c.link.WriteUPNP([]byte{0x24, 0, 0, 0}); err != nil {
		return err
	}

	appRand := make([]byte, 16)
	if _, err := io.ReadFull(c.rnd, appRand); err != nil {
		return err
	}
	if err := c.sendMsg(0x0b, appRand); err != nil {
		return fmt.Errorf("отправка random: %w", err)
	}
	m, err := c.waitAVDTP("random устройства", isMsg(0x0d, 20))
	if err != nil {
		return err
	}
	devRand := m[4:]
	if err := c.link.WriteAVDTP(ackRecv); err != nil {
		return err
	}
	m, err = c.waitAVDTP("подтверждение устройства", isMsg(0x0c, 36))
	if err != nil {
		return err
	}
	devConf := m[4:]
	if err := c.link.WriteAVDTP(ackRecv); err != nil {
		return err
	}

	devKey, appKey, devIV, appIV := deriveKeys(c.token, appRand, devRand)
	if !bytes.Equal(devConf, hmacSHA256(devKey, devRand, appRand)) {
		return ErrBadToken
	}
	if err := c.sendMsg(0x0a, hmacSHA256(appKey, appRand, devRand)); err != nil {
		return fmt.Errorf("отправка подтверждения: %w", err)
	}

	select {
	case b := <-c.upnp:
		if !bytes.Equal(b, loginOK) {
			return fmt.Errorf("устройство отклонило вход: %x", b)
		}
	case <-time.After(stepTimeout):
		return errors.New("таймаут: нет результата логина")
	}

	if c.sess, err = newSession(devKey, appKey, devIV, appIV); err != nil {
		return err
	}
	if err := c.link.SubscribeData(push(c.data)); err != nil {
		return fmt.Errorf("подписка на данные: %w", err)
	}
	return nil
}

// parseMeasurement: 00 00 05 80 04 00 HI LO — расстояние в мм (big-endian).
func parseMeasurement(pt []byte) (int, bool) {
	if len(pt) == 8 && pt[0] == 0 && pt[1] == 0 && pt[2] == 0x05 && pt[3] == 0x80 {
		return int(pt[6])<<8 | int(pt[7]), true
	}
	return 0, false
}

// Run обрабатывает уведомления до отмены ctx. onMeasure получает миллиметры.
func (c *Client) Run(ctx context.Context, onMeasure func(mm int)) error {
	if c.sess == nil {
		return errors.New("сначала Login")
	}
	last := -1
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case pkt := <-c.data:
			pt, cnt, err := c.sess.decrypt(pkt)
			if err != nil {
				c.Logf("не расшифровано (%x): %v", pkt, err)
				continue
			}
			if int(cnt) <= last {
				continue // повтор
			}
			last = int(cnt)
			c.Logf("data #%d: %x", cnt, pt)
			if mm, ok := parseMeasurement(pt); ok {
				onMeasure(mm)
				continue
			}
			// Служебный запрос устройства (00 00 04 80 ..): Mi Home отвечает "10 00".
			if len(pt) >= 4 && pt[2] == 0x04 && pt[3] == 0x80 {
				if err := c.link.WriteData(c.sess.encrypt([]byte{0x10, 0x00})); err != nil {
					return err
				}
			}
		}
	}
}

func timeAfter(d time.Duration) <-chan time.Time { return time.After(d) }
