//go:build !(windows && (amd64 || arm64))

package main

import "fmt"

func main() { fmt.Println("rulerkb работает только в Windows (amd64/arm64)") }
