//go:build windows && (amd64 || arm64)

// The program reads measurements from the laser ruler (BLE) directly, without Mi Home,
// and "types" them on the keyboard: the distance in millimeters and Enter.
//
// Without flags: if config.json exists — reads the MAC and token and starts;
// if not — searches for BLE devices, pairs, writes config.json and starts.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"strconv"
	"time"

	"rulerkb/ruler"
)

type options struct {
	printOnly bool
	useVK     bool
	debug     bool
	offset    int // mm, added to each measurement
}

func main() {
	cfgPath := flag.String("config", defaultConfigPath(), "configuration file")
	macFlag := flag.String("mac", "", "ruler MAC address (overrides config; skips search during pairing)")
	tokenFlag := flag.String("token", "", "token, 24 hex characters (overrides config)")
	offsetFlag := flag.Int("offset", 0, "offset for measured data in mm. Can be negative. (overrides config)")
	pairOnly := flag.Bool("pair-only", false, "service mode: only pair with -mac and write config")
	repair := flag.Bool("register", false, "re-pair the ruler (pairing mode) and rewrite config")
	var opt options
	flag.BoolVar(&opt.printOnly, "print", false, "only print to console, without keyboard emulation")
	flag.BoolVar(&opt.useVK, "vk", false, "type numbers as virtual keys, not Unicode")
	flag.BoolVar(&opt.debug, "debug", false, "verbose protocol log")
	flag.Parse()

	forcedMAC := ""
	if *macFlag != "" {
		var err error
		if forcedMAC, err = normalizeMAC(*macFlag); err != nil {
			log.Fatal(err)
		}
	}

	if *pairOnly {
		if forcedMAC == "" {
			log.Fatal("-pair-only requires -mac")
		}
		if err := pairWorker(*cfgPath, forcedMAC, opt.debug); err != nil {
			log.Fatal(err)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	conf, err := loadConfig(*cfgPath)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Fatalf("configuration: %v", err)
	}

	if *repair || (!exists && *tokenFlag == "") {
		if !exists {
			log.Printf("configuration file %s not found, starting pairing", *cfgPath)
		}
		if conf, err = pairFlow(ctx, *cfgPath, forcedMAC, opt.debug); err != nil {
			log.Fatal(err)
		}
		// The pairing process has already completed and released BLE; allow the ruler to restart its stack.
		log.Println("pairing completed, waiting for BLE restart on the ruler (9 seconds) ...")
		select {
		case <-ctx.Done():
			return
		case <-time.After(9 * time.Second):
		}
	} else if exists {
		log.Printf("configuration: %s (ruler %s)", *cfgPath, conf.MAC)
	}

	if conf == nil {
		conf = &fileConfig{}
	}
	if forcedMAC != "" {
		conf.MAC = forcedMAC
	}
	if *tokenFlag != "" {
		conf.Token = *tokenFlag
	}
	if *offsetFlag != 0 {
		conf.Offset = *offsetFlag
		saveConfig(*cfgPath, conf)
	}
	if conf.MAC == "" {
		log.Fatal("ruler MAC address not set (-mac or config.json)")
	}
	token, err := conf.tokenBytes()
	if err != nil {
		log.Fatal(err)
	}

	opt.offset = conf.Offset
	if opt.offset != 0 {
		log.Printf("offset: %+d mm", opt.offset)
	}

	for ctx.Err() == nil {
		err := runOnce(ctx, conf.MAC, token, &opt)
		if ctx.Err() != nil {
			break
		}
		if errors.Is(err, ruler.ErrBadToken) {
			log.Fatalf("%v\nDelete %s and run the program again to re-pair the ruler.", err, *cfgPath)
		}
		if errors.Is(err, errGattNotReady) {
			log.Println("ruler is still ready after pairing, retrying in 3 seconds ...")
		} else {
			log.Printf("connection closed: %v; retrying in 3 seconds", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
		}
	}
}

func runOnce(ctx context.Context, mac string, token []byte, opt *options) error {
	dbg := func(f string, a ...any) {
		if opt.debug {
			log.Printf(f, a...)
		}
	}
	log.Printf("connecting to %s ...", mac)
	link, err := connectBLE(mac, log.Printf)
	if err != nil {
		return err
	}
	defer link.Close()

	cl := ruler.NewClient(link, token)
	cl.Logf = dbg
	if err := cl.Login(); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	log.Println("connected. Waiting for measurements, cursor should be in the right input field.")

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- cl.Run(rctx, func(mm int) {
			val := mm + opt.offset
			s := strconv.Itoa(val)
			if opt.offset != 0 {
				log.Printf("measurement: %d mm, offset %+d -> output: %s mm", mm, opt.offset, s)
			} else {
				log.Printf("measurement: %s mm", s)
			}
			if opt.printOnly {
				return
			}
			if err := typeNumber(s, opt.useVK); err != nil {
				log.Printf("keyboard input: %v", err)
			}
		})
	}()

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	fails := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errc:
			return err
		case <-tick.C:
			if link.Alive() {
				fails = 0
			} else if fails++; fails >= 2 {
				return errors.New("connection lost (ruler turned off?)")
			}
		}
	}
}
