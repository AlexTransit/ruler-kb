package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if _, err := loadConfig(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ожидалась ErrNotExist, получено %v", err)
	}
	in := &fileConfig{MAC: "B4:60:xx:xx:xx:xx", Token: "000102030405060708090a0b", BindKey: "00112233445566778899aabbccddeeff"}
	if ok := saveConfig(p, in); !ok {
		t.Fatal()
	}
	out, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if out.MAC != "B4:60:xx:xx:xx:xx" || out.Token != in.Token || out.BindKey != in.BindKey {
		t.Fatalf("%+v", out)
	}
	tok, err := out.tokenBytes()
	if err != nil || len(tok) != 12 {
		t.Fatal(err)
	}
}

func TestConfigInvalid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	for _, c := range []*fileConfig{
		{MAC: "zz", Token: "000102030405060708090a0b"},
		{MAC: "B4:60:xx:xx:xx:xx", Token: "0102"},
		{MAC: "B4:60:xx:xx:xx:xx", Token: "не hex"},
	} {
		saveConfig(p, c)
		if _, err := loadConfig(p); err == nil {
			t.Fatalf("принят неверный конфиг %+v", c)
		}
	}
}

func TestConfigShift(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	for _, offset := range []int{0, 25, -40} {
		in := &fileConfig{MAC: "B4:60:xx:xx:xx:xx", Token: "000102030405060708090a0b", Offset: offset}
		if ok := saveConfig(p, in); !ok {
			t.Fatal()
		}
		out, err := loadConfig(p)
		if err != nil || out.Offset != offset {
			t.Fatalf("offset %d -> %+v, %v", offset, out, err)
		}
	}
	// старый конфиг без поля offset: смещение 0
	old := []byte(`{"mac":"B4:60:xx:xx:xx:xx","token":"000102030405060708090a0b"}`)
	if err := os.WriteFile(p, old, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := loadConfig(p)
	if err != nil || out.Offset != 0 {
		t.Fatalf("%+v %v", out, err)
	}
}
