# RulerKB

English | [Русский](README.ru.md)

## Bluetooth Ruler (Keyboard) ⇒ Keyboard Input (mm + Enter), Windows 10/11, without Mi Home and Xiaomi servers.
The roulette connects to the computer via Bluetooth. Measured data is entered into the active window.
Worked on QWCJY001 

**Build (requires Go 1.22+):**

```
go mod tidy
go build -o ruler-kb.exe .
```

For using the ruler with Mi Home, you need to get the ruler's token.
You can get the token using:

https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor

**Bind the device using the received token**

> ruler-kb.exe -mac 00:11:22:33:44:55 -token 1234567890abcdef1234567890abcdef12345678

You can then use the local program and Mi Home

## Attach the ruler to this computer
Run ruler-kb.exe.
The program scans Bluetooth devices. Select the desired device. The list sorts by signal strength. If "xiao" is in the name, the program will automatically connect, create config.json, and run.

## Run **ruler-kb.exe**
Select the window to enter measurement data.
Perform the measurement.

## Bind the ruler to an additional computer
Copy config.json and ruler-kb.exe to another computer. Run and use it.

### Pairing Mode 
(Bluetooth icon blinks; if not blinking, reset the ruler by following the instructions).
Pairing disconnects the ruler from Mi Home or ruler-kb; the previous token becomes invalid.
The pairing itself is done in a separate process (flag -pair-only, service): The Windows Bluetooth library does not release resources while the process is alive, so it must be connected from another process.

### config.json

You can create it manually, for example, for an existing token:

```
{
  "mac": "B4:60:xx:xx:xx:xx",
  "token": "24 hex symbols",
  "bind_key": "optional",
  "offset": 0
}
```

- mac - device MAC address
- token - device token
- offset - offset in millimeters, positive or negative (e.g., 25 or -40). The output is measurement + offset. If the field is not present, the offset is 0. When pairing again, the offset is saved.

**Options:**

| Option | Parameter | Description |
| --- | --- | --- |
|-config | path | different configuration file |
|-debug || log protocol
|-mac | AA:BB:… | Ruler MAC address (overrides config; when pairing, skips search) |
|-pair-only|| only pair with -mac and rewrite config.json (must specify mac) |
|-print || only print to console, without keyboard input |
|-register|| re-pair the ruler and rewrite config.json |
|-offset| number | offset in millimeters, positive or negative (overrides config) |
|-token| HEX | token (overrides config) |
|-vk || input numbers using virtual keys (if Unicode input is not accepted) |

Tests (on any OS): ```go test ./...```