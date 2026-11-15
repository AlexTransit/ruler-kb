//go:build windows && (amd64 || arm64)

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	inputKeyboard    = 1
	keyeventfKeyUp   = 0x0002
	keyeventfUnicode = 0x0004
	vkReturn         = 0x0D
	vkOemMinus       = 0xBD
)

type keybdInput struct {
	vk    uint16
	scan  uint16
	flags uint32
	time  uint32
	extra uintptr
}

// INPUT на 64-битной Windows занимает 40 байт.
type input struct {
	typ uint32
	_   uint32
	ki  keybdInput
	_   [8]byte
}

const (
	_ = uint(40 - unsafe.Sizeof(input{}))
	_ = uint(unsafe.Sizeof(input{}) - 40)
)

var procSendInput = syscall.NewLazyDLL("user32.dll").NewProc("SendInput")

func sendInputs(in []input) error {
	n, _, err := procSendInput.Call(uintptr(len(in)), uintptr(unsafe.Pointer(&in[0])), unsafe.Sizeof(in[0]))
	if int(n) != len(in) {
		return fmt.Errorf("SendInput: отправлено %d из %d: %v", n, len(in), err)
	}
	return nil
}

func key(vk, scan uint16, flags uint32) input {
	return input{typ: inputKeyboard, ki: keybdInput{vk: vk, scan: scan, flags: flags}}
}

// typeNumber печатает цифры и нажимает Enter в окне с фокусом.
func typeNumber(s string, useVK bool) error {
	var in []input
	for _, r := range s {
		if useVK {
			vk := uint16(r)
			if r == '-' {
				vk = vkOemMinus
			}
			in = append(in, key(vk, 0, 0), key(vk, 0, keyeventfKeyUp))
		} else {
			in = append(in,
				key(0, uint16(r), keyeventfUnicode),
				key(0, uint16(r), keyeventfUnicode|keyeventfKeyUp))
		}
	}
	in = append(in, key(vkReturn, 0, 0), key(vkReturn, 0, keyeventfKeyUp))
	return sendInputs(in)
}
