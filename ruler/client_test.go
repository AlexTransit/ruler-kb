package ruler

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"testing"
	"time"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Векторы получены независимой реализацией (Python cryptography, AESCCM, tag=4).
func TestCCMVectors(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	n := make([]byte, 12)
	for i := range n {
		n[i] = byte(100 + i)
	}
	c, _ := newCCM(key)
	p1 := mustHex("0000058004000675")
	p2 := make([]byte, 40)
	for i := range p2 {
		p2[i] = byte(i)
	}
	for _, tc := range []struct {
		plain []byte
		want  string
	}{
		{p1, "a04992a1b91bfd9284053a8f"},
		{p2, "a0489522b91efde0d8f1b0e2b1ccaa456e2886e09148e4e13450a76f077873e8348033b31a0e948e1fe84e08"},
	} {
		ct := c.seal(n, tc.plain)
		if hex.EncodeToString(ct) != tc.want {
			t.Fatalf("seal: got %x want %s", ct, tc.want)
		}
		pt, err := c.open(n, ct)
		if err != nil || !bytes.Equal(pt, tc.plain) {
			t.Fatalf("open: %v %x", err, pt)
		}
		ct[0] ^= 1
		if _, err := c.open(n, ct); err == nil {
			t.Fatal("подделка не обнаружена")
		}
	}
}

// fakeDevice повторяет сторону рулетки из лога Mi Home.
type fakeDevice struct {
	mu       sync.Mutex
	token    []byte
	avdtp    func([]byte)
	upnp     func([]byte)
	data     func([]byte)
	expect   string
	appRand  []byte
	devRand  []byte
	acks     int
	sess     *session // сторона устройства: dev/app поменяны местами не нужны — шифруем dev-ключом
	devCnt   uint16
	gotAcks  [][]byte
	appSess  *session
	loggedIn bool
}

func (f *fakeDevice) SubscribeAVDTP(cb func([]byte)) error { f.avdtp = cb; return nil }
func (f *fakeDevice) SubscribeUPNP(cb func([]byte)) error  { f.upnp = cb; return nil }
func (f *fakeDevice) SubscribeData(cb func([]byte)) error {
	f.data = cb
	f.devSend([]byte{0, 0, 4, 0x80, 2, 1, 0})
	f.devSend([]byte{0, 0, 4, 0x80, 2, 2, 0})
	return nil
}
func (f *fakeDevice) WriteUPNP(b []byte) error { return nil }

func (f *fakeDevice) devSend(pt []byte) {
	f.devCnt++
	out := []byte{byte(f.devCnt), byte(f.devCnt >> 8)}
	out = append(out, f.sess.dev.seal(nonce(f.sess.devIV, f.devCnt), pt)...)
	f.data(out)
}

func (f *fakeDevice) measure(mm int) {
	f.devSend([]byte{0, 0, 5, 0x80, 4, 0, byte(mm >> 8), byte(mm)})
}

func (f *fakeDevice) WriteData(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cnt := uint16(b[0]) | uint16(b[1])<<8
	pt, err := f.sess.app.open(nonce(f.sess.appIV, cnt), b[2:])
	if err != nil {
		return err
	}
	f.gotAcks = append(f.gotAcks, pt)
	return nil
}

func (f *fakeDevice) WriteAVDTP(v []byte) error {
	switch {
	case bytes.Equal(v, []byte{0, 0, 5, 0, 6, 0xf2}):
		f.avdtp([]byte{0, 0, 4, 0, 6, 0xf2})
	case bytes.HasPrefix(v, []byte{0, 0, 5, 1}):
		f.avdtp(append([]byte{0, 0, 4, 1}, v[4:]...))
	case bytes.Equal(v, []byte{0, 0, 0, 0x0b, 1, 0}):
		f.expect = "rand"
		f.avdtp([]byte{0, 0, 1, 1})
	case bytes.Equal(v, []byte{0, 0, 0, 0x0a, 1, 0}):
		f.expect = "conf"
		f.avdtp([]byte{0, 0, 1, 1})
	case bytes.HasPrefix(v, []byte{1, 0}) && f.expect == "rand":
		f.appRand = append([]byte(nil), v[2:]...)
		f.devRand = mustHex("1641864591f4e37eba2d7c6aa77f9421")
		f.avdtp([]byte{0, 0, 1, 0})
		f.avdtp(append([]byte{0, 0, 2, 0x0d}, f.devRand...))
	case bytes.Equal(v, ackRecv):
		f.acks++
		if f.acks == 1 {
			devKey, _, _, _ := deriveKeys(f.token, f.appRand, f.devRand)
			f.avdtp(append([]byte{0, 0, 2, 0x0c}, hmacSHA256(devKey, f.devRand, f.appRand)...))
		}
	case bytes.HasPrefix(v, []byte{1, 0}) && f.expect == "conf":
		devKey, appKey, devIV, appIV := deriveKeys(f.token, f.appRand, f.devRand)
		if !bytes.Equal(v[2:], hmacSHA256(appKey, f.appRand, f.devRand)) {
			f.upnp([]byte{0x23, 0, 0, 0})
			return nil
		}
		f.sess, _ = newSession(devKey, appKey, devIV, appIV)
		f.avdtp([]byte{0, 0, 1, 0})
		f.upnp([]byte{0x21, 0, 0, 0})
	}
	return nil
}

func TestLoginAndMeasure(t *testing.T) {
	token := mustHex("000102030405060708090a0b")
	dev := &fakeDevice{token: token}
	cl := NewClient(dev, token)
	if err := cl.Login(); err != nil {
		t.Fatal(err)
	}
	got := make(chan int, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go cl.Run(ctx, func(mm int) { got <- mm })
	time.Sleep(50 * time.Millisecond)
	for _, mm := range []int{711, 1159, 1653, 40000} {
		dev.measure(mm)
		select {
		case v := <-got:
			if v != mm {
				t.Fatalf("got %d want %d", v, mm)
			}
		case <-time.After(time.Second):
			t.Fatal("нет замера", mm)
		}
	}
	dev.mu.Lock()
	defer dev.mu.Unlock()
	if len(dev.gotAcks) != 2 || !bytes.Equal(dev.gotAcks[0], []byte{0x10, 0}) {
		t.Fatalf("ответы на служебные запросы: %x", dev.gotAcks)
	}
}

func TestBadToken(t *testing.T) {
	dev := &fakeDevice{token: mustHex("000102030405060708090a0b")}
	cl := NewClient(dev, mustHex("ffffffffffffffffffffffff"))
	if err := cl.Login(); err != ErrBadToken {
		t.Fatalf("ожидалась ErrBadToken, получено %v", err)
	}
}

// Вектор с AAD получен независимо (Python cryptography, AESCCM tag=4, aad="devID").
func TestCCMAADVector(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	c, _ := newCCM(key)
	pt := append([]byte{0}, "blt.6.18m3vfjlcsg00"...)
	ct := c.sealAAD(regNonce, regAAD, pt)
	if hex.EncodeToString(ct) != "23d7d5d46cc2038332c14cb6120eb7e508d0e28749f963e5" {
		t.Fatalf("got %x", ct)
	}
	if _, err := c.openAAD(regNonce, []byte("devXX"), ct); err == nil {
		t.Fatal("AAD не учитывается")
	}
}

// regDevice — сторона рулетки в режиме сопряжения.
type regDevice struct {
	avdtp, upnp func([]byte)
	info        []byte
	priv        *ecdh.PrivateKey
	appPub      []byte
	expect      string
	token, bind []byte
	okDID       bool
	didSeen     []byte
}

func (d *regDevice) SubscribeAVDTP(cb func([]byte)) error { d.avdtp = cb; return nil }
func (d *regDevice) SubscribeUPNP(cb func([]byte)) error  { d.upnp = cb; return nil }
func (d *regDevice) SubscribeData(cb func([]byte)) error  { return nil }
func (d *regDevice) WriteData(b []byte) error             { return nil }
func (d *regDevice) WriteUPNP(b []byte) error {
	switch {
	case bytes.Equal(b, []byte{0xa2, 0, 0, 0}):
		d.avdtp(append([]byte{0, 0, 2, 0}, d.info...))
	case bytes.Equal(b, []byte{0x13, 0, 0, 0}):
		if d.okDID {
			d.upnp([]byte{0x11, 0, 0, 0})
		} else {
			d.upnp([]byte{0x12, 0, 0, 0})
		}
	}
	return nil
}
func (d *regDevice) WriteAVDTP(v []byte) error {
	switch {
	case bytes.Equal(v, []byte{0, 0, 5, 0, 6, 0xf2}):
		d.avdtp([]byte{0, 0, 4, 0, 6, 0xf2})
	case bytes.HasPrefix(v, []byte{0, 0, 5, 1}):
		d.avdtp(append([]byte{0, 0, 4, 1}, v[4:]...))
	case bytes.Equal(v, []byte{0, 0, 0, 3, 1, 0}):
		d.expect = "key"
		d.avdtp([]byte{0, 0, 1, 1})
	case bytes.Equal(v, []byte{0, 0, 0, 0, 1, 0}):
		d.expect = "did"
		d.avdtp([]byte{0, 0, 1, 1})
	case bytes.HasPrefix(v, []byte{1, 0}) && d.expect == "key":
		d.appPub = append([]byte(nil), v[2:]...)
		d.avdtp([]byte{0, 0, 1, 0})
		d.avdtp(append([]byte{0, 0, 2, 3}, d.priv.PublicKey().Bytes()[1:]...))
	case bytes.HasPrefix(v, []byte{1, 0}) && d.expect == "did":
		d.avdtp([]byte{0, 0, 1, 0})
		pub, _ := ecdh.P256().NewPublicKey(append([]byte{4}, d.appPub...))
		secret, _ := d.priv.ECDH(pub)
		okm := hkdf(secret, nil, []byte("mible-setup-info"), 64)
		d.token, d.bind = okm[0:12], okm[12:28]
		a, _ := newCCM(okm[28:44])
		pt, err := a.openAAD(regNonce, regAAD, v[2:])
		d.didSeen = pt
		d.okDID = err == nil && bytes.Equal(pt, d.info[4:])
	}
	return nil
}

func TestRegister(t *testing.T) {
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	info := append([]byte{1, 0, 0, 0, 0}, "blt.6.18m3vfjlcsg00"...)
	dev := &regDevice{priv: priv, info: info}
	cl := NewClient(dev, nil)
	res, err := cl.Register()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Token, dev.token) || !bytes.Equal(res.BindKey, dev.bind) {
		t.Fatal("токен не совпал с устройством")
	}
	if !bytes.Equal(dev.didSeen, info[4:]) || len(res.Token) != 12 || len(res.BindKey) != 16 {
		t.Fatalf("did: %x", dev.didSeen)
	}
}
