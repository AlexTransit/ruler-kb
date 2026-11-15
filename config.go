package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// fileConfig хранится в config.json рядом с программой.
type fileConfig struct {
	MAC     string `json:"mac"`
	Token   string `json:"token"`              // 24 hex-символа
	BindKey string `json:"bind_key,omitempty"` // для MiBeacon-рекламы, программе не нужен
	Offset  int    `json:"offset"`             // смещение в мм (может быть отрицательным): вывод = замер + offset
}

func defaultConfigPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "config.json")
	}
	return "config.json"
}

func normalizeMAC(s string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("неверный MAC %q", s)
	}
	return strings.ToUpper(hw.String()), nil
}

// loadConfig возвращает ошибку, для которой errors.Is(err, fs.ErrNotExist) == true, если файла нет.
func loadConfig(path string) (*fileConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c fileConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.MAC, err = normalizeMAC(c.MAC); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := c.tokenBytes(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *fileConfig) tokenBytes() ([]byte, error) {
	t, err := hex.DecodeString(strings.TrimSpace(c.Token))
	if err != nil || len(t) != 12 {
		return nil, errors.New("токен должен быть 24 hex-символа (12 байт)")
	}
	return t, nil
}

func saveConfig(path string, c *fileConfig) bool {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "не удалось сопоставить значения конфигурации (%v): %v\n", c, err)
		return false
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "не удалось записать %s (значения выше, сохраните вручную): %v\n", path, err)
		return false
	}
	return true
}
