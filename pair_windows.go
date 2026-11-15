//go:build windows && (amd64 || arm64)

package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"rulerkb/ruler"
)

const scanTime = 10 * time.Second

func prompt(in *bufio.Reader, msg string) string {
	fmt.Print(msg)
	s, _ := in.ReadString('\n')
	return strings.ToLower(strings.TrimSpace(s))
}

// chooseDevice сканирует эфир и даёт выбрать устройство для спаривания.
func chooseDevice(ctx context.Context, in *bufio.Reader) (string, error) {
	showAll := false
	for ctx.Err() == nil {
		log.Printf("сканирую BLE-устройства %d с (включите рулетку: значок BLE мигает) ...", int(scanTime.Seconds()))
		devs, err := scanDevices(scanTime)
		if err != nil {
			return "", err
		}
		var list []foundDevice
		unnamed := 0
		for _, d := range devs {
			if d.Name == "" && !showAll {
				unnamed++
				continue
			}
			list = append(list, d)
		}

		// Одно устройство с "xiao" в имени — берём без вопросов.
		var xiao []foundDevice
		for _, d := range list {
			if strings.Contains(strings.ToLower(d.Name), "xiao") {
				xiao = append(xiao, d)
			}
		}
		if len(xiao) == 1 {
			log.Printf("найдена рулетка: %s (%s, %d dBm)", xiao[0].Name, xiao[0].MAC, xiao[0].RSSI)
			return xiao[0].MAC, nil
		}

		if len(list) == 0 {
			fmt.Println("Ничего не найдено.")
		}
		fmt.Printf("\n  №  %-17s  %5s  Имя\n", "MAC", "RSSI")
		for i, d := range list {
			name := d.Name
			if name == "" {
				name = "(без имени)"
			}
			fmt.Printf("%3d  %-17s  %5d  %s\n", i+1, d.MAC, d.RSSI, name)
		}
		if unnamed > 0 {
			fmt.Printf("      ... и ещё %d устройств без имени (a — показать)\n", unnamed)
		}
		fmt.Println("Подсказка: рулетка рядом с компьютером даёт самый сильный сигнал (RSSI ближе к 0).")

		for {
			ans := prompt(in, "Номер устройства / r — искать снова / a — показать безымянные / q — выход: ")
			switch ans {
			case "q":
				return "", errors.New("отменено")
			case "r":
			case "a":
				showAll = true
			default:
				n, err := strconv.Atoi(ans)
				if err != nil || n < 1 || n > len(list) {
					continue
				}
				return list[n-1].MAC, nil
			}
			break
		}
	}
	return "", ctx.Err()
}

// registerDevice подключается к устройству в режиме сопряжения и регистрирует токен.
func registerDevice(mac string, debug bool) (*ruler.RegResult, error) {
	log.Printf("спариваюсь с %s ...", mac)
	link, err := connectBLE(mac, log.Printf)
	if err != nil {
		return nil, err
	}
	defer link.Close()
	cl := ruler.NewClient(link, nil)
	cl.Logf = func(f string, a ...any) {
		if debug {
			log.Printf(f, a...)
		}
	}
	return cl.Register()
}

// pairWorker выполняет спаривание с заданным устройством и пишет config.json.
// Запускается в ОТДЕЛЬНОМ процессе (флаг -pair-only): библиотека BLE под Windows не освобождает
// GATT-объекты при Disconnect, и процесс, который спаривался, нельзя использовать для подключения.
func pairWorker(cfgPath, mac string, debug bool) error {
	res, err := registerDevice(mac, debug)
	if err != nil {
		return err
	}
	conf := &fileConfig{
		MAC:     mac,
		Token:   hex.EncodeToString(res.Token),
		BindKey: hex.EncodeToString(res.BindKey),
	}
	if old, err := loadConfig(cfgPath); err == nil {
		conf.Offset = old.Offset // повторное спаривание не должно сбрасывать смещение
	}
	// Токен уже записан в устройство: сначала на экран, потом в файл.
	log.Printf("спаривание выполнено. токен: %s", conf.Token)
	log.Printf("bind key (обычно не нужен): %s", conf.BindKey)
	saveConfig(cfgPath, conf)
	log.Printf("конфигурация записана в %s", cfgPath)
	return nil
}

func runPairWorker(cfgPath, mac string, debug bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"-pair-only", "-mac", mac, "-config", cfgPath}
	if debug {
		args = append(args, "-debug")
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// pairFlow: выбор устройства -> спаривание (в отдельном процессе) -> чтение config.json.
func pairFlow(ctx context.Context, cfgPath, forcedMAC string, debug bool) (*fileConfig, error) {
	in := bufio.NewReader(os.Stdin)
	for ctx.Err() == nil {
		mac := forcedMAC
		if mac == "" {
			var err error
			if mac, err = chooseDevice(ctx, in); err != nil {
				return nil, err
			}
		}
		err := runPairWorker(cfgPath, mac, debug)
		if err == nil {
			conf, lerr := loadConfig(cfgPath)
			if lerr != nil {
				return nil, lerr
			}
			return conf, nil
		}
		log.Printf("спаривание не удалось: %v", err)
		log.Println("Проверьте: значок BLE на рулетке мигает (режим сопряжения), Mi Home закрыт, рулетка удалена из Mi Home.")
		if prompt(in, "Enter — повторить, q — выход: ") == "q" {
			return nil, err
		}
	}
	return nil, ctx.Err()
}
