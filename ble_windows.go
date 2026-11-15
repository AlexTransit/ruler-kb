//go:build windows && (amd64 || arm64)

package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"tinygo.org/x/bluetooth"
)

var (
	uuidVersion = bluetooth.New16BitUUID(0x0004) // чтение версии, используется как проверка связи
	uuidUPNP    = bluetooth.New16BitUUID(0x0010)
	uuidAVDTP   = bluetooth.New16BitUUID(0x0019)
	uuidDataTx  = bluetooth.New16BitUUID(0xFEA7) // запись команд
	uuidDataRx  = bluetooth.New16BitUUID(0xFEA8) // уведомления с замерами
)

var enableOnce sync.Once

// enableBLE инициализирует WinRT один раз. Повторный RoInitialize возвращает S_FALSE,
// который библиотека превращает в ошибку "Incorrect function": она не фатальна.
func enableBLE() {
	enableOnce.Do(func() { _ = bluetooth.DefaultAdapter.Enable() })
}

// errGattNotReady: сервисы есть, а характеристик нет. Так бывает ~10 с после спаривания,
// пока рулетка перезапускает BLE-стек.
var errGattNotReady = errors.New("рулетка ещё не готова")

type bleLink struct {
	dev                              bluetooth.Device
	ver, upnp, avdtp, dataTx, dataRx bluetooth.DeviceCharacteristic
}

func connectBLE(mac string, logf func(string, ...any)) (*bleLink, error) {
	enableBLE()
	adapter := bluetooth.DefaultAdapter
	var addr bluetooth.Address
	addr.Set(mac)

	dev, err := adapter.Connect(addr, bluetooth.ConnectionParams{})
	if err != nil {
		logf("прямое подключение не удалось (%v), ищу рулетку в эфире...", err)
		found := make(chan bluetooth.Address, 1)
		go adapter.Scan(func(a *bluetooth.Adapter, r bluetooth.ScanResult) {
			if strings.EqualFold(r.Address.String(), mac) {
				a.StopScan()
				select {
				case found <- r.Address:
				default:
				}
			}
		})
		select {
		case a := <-found:
			if dev, err = adapter.Connect(a, bluetooth.ConnectionParams{}); err != nil {
				return nil, err
			}
		case <-time.After(20 * time.Second):
			adapter.StopScan()
			return nil, fmt.Errorf("рулетка %s не найдена (включена? не занята телефоном?)", mac)
		}
	}

	l := &bleLink{dev: dev}
	want := map[bluetooth.UUID]*bluetooth.DeviceCharacteristic{
		uuidVersion: &l.ver, uuidUPNP: &l.upnp, uuidAVDTP: &l.avdtp,
		uuidDataTx: &l.dataTx, uuidDataRx: &l.dataRx,
	}
	var (
		found, nServices int
		lastErr          error
	)
	found, nServices, lastErr = discover(dev, want)
	if found == len(want) {
		return l, nil
	}
	dev.Disconnect()
	if found == 0 && nServices > 0 && lastErr == nil {
		return nil, errGattNotReady
	}
	return nil, fmt.Errorf("найдено %d из %d нужных характеристик (сервисов %d, последняя ошибка: %v)",
		found, len(want), nServices, lastErr)
}

func discover(dev bluetooth.Device, want map[bluetooth.UUID]*bluetooth.DeviceCharacteristic) (found, nServices int, lastErr error) {
	services, err := dev.DiscoverServices(nil)
	if err != nil {
		return 0, 0, fmt.Errorf("поиск сервисов: %w", err)
	}
	nServices = len(services)
	for _, s := range services {
		chars, err := s.DiscoverCharacteristics(nil)
		if err != nil {
			lastErr = err
			continue
		}
		for _, c := range chars {
			if p, ok := want[c.UUID()]; ok {
				*p = c
				found++
			}
		}
	}
	return found, nServices, lastErr
}

func (l *bleLink) SubscribeAVDTP(cb func([]byte)) error { return l.avdtp.EnableNotifications(cb) }
func (l *bleLink) SubscribeUPNP(cb func([]byte)) error  { return l.upnp.EnableNotifications(cb) }
func (l *bleLink) SubscribeData(cb func([]byte)) error  { return l.dataRx.EnableNotifications(cb) }

func (l *bleLink) WriteUPNP(b []byte) error {
	_, err := l.upnp.WriteWithoutResponse(b)
	return err
}
func (l *bleLink) WriteAVDTP(b []byte) error {
	_, err := l.avdtp.WriteWithoutResponse(b)
	return err
}
func (l *bleLink) WriteData(b []byte) error {
	_, err := l.dataTx.WriteWithoutResponse(b)
	return err
}

// Alive проверяет связь чтением версии (Mi Home делает то же самое).
func (l *bleLink) Alive() bool {
	done := make(chan bool, 1)
	go func() {
		defer func() {
			if recover() != nil {
				done <- false
			}
		}()
		buf := make([]byte, 32)
		n, err := l.ver.Read(buf)
		done <- err == nil && n > 0
	}()
	select {
	case ok := <-done:
		return ok
	case <-time.After(3 * time.Second):
		return false
	}
}

func (l *bleLink) Close() { l.dev.Disconnect() }

// foundDevice — устройство, замеченное при сканировании.
type foundDevice struct {
	MAC  string
	Name string
	RSSI int16
}

// scanDevices слушает эфир d и возвращает устройства по убыванию уровня сигнала.
func scanDevices(d time.Duration) ([]foundDevice, error) {
	enableBLE()
	adapter := bluetooth.DefaultAdapter
	var mu sync.Mutex
	seen := map[string]*foundDevice{}
	timer := time.AfterFunc(d, func() { adapter.StopScan() })
	defer timer.Stop()
	err := adapter.Scan(func(a *bluetooth.Adapter, r bluetooth.ScanResult) {
		mac := strings.ToUpper(r.Address.String())
		mu.Lock()
		defer mu.Unlock()
		f := seen[mac]
		if f == nil {
			f = &foundDevice{MAC: mac, RSSI: r.RSSI}
			seen[mac] = f
		}
		if r.RSSI > f.RSSI {
			f.RSSI = r.RSSI
		}
		if n := r.LocalName(); n != "" {
			f.Name = n // имя может прийти в scan response отдельно
		}
	})
	if err != nil {
		return nil, err
	}
	out := make([]foundDevice, 0, len(seen))
	for _, f := range seen {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RSSI > out[j].RSSI })
	return out, nil
}
