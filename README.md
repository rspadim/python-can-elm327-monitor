# ELM327 CAN Monitor

CAN bus monitor for ELM327 and python-can transports, showing the **latest frame per CAN ID**, sorted by ID.

## Original Reference
This project is inspired by the original Python CAN monitor:
https://github.com/alexandreblin/python-can-monitor

## Requirements
- Python 3.10+
- `rich` (TUI)
- Optional:
  - `pyserial` for `--transport serial`
  - `python-can` for `--transport pycan`

Install dependencies:

```powershell
py -m pip install rich
py -m pip install pyserial
py -m pip install python-can
```

## Quick Start
Default transport is Wi-Fi/TCP (`192.168.0.10:35000`):

```powershell
py elm327_can_monitor.py
```

## Transport Modes
- Default: `--transport wifi` (TCP/IP)
- `--transport tcp` is an alias of `wifi`
- `--transport serial` uses Bluetooth SPP / COM port
- `--transport pycan` uses native python-can bus APIs

Wi-Fi / TCP:

```powershell
py elm327_can_monitor.py --transport wifi --host 192.168.0.10 --port 35000
py elm327_can_monitor.py --transport tcp --host 192.168.0.10 --port 35000
```

Serial (Bluetooth ELM327 on COM):

```powershell
py elm327_can_monitor.py --transport serial --serial-port COM5 --serial-baud 38400
```

python-can:

```powershell
py elm327_can_monitor.py --transport pycan --pycan-interface socketcan --pycan-channel can0
```

## CAN Speed / ID Format
125 kbps, 11-bit (same default behavior as the original Arduino example):

```powershell
py elm327_can_monitor.py --can-speed 125 --can-id-format 11
```

500 kbps, 11-bit:

```powershell
py elm327_can_monitor.py --can-speed 500 --can-id-format 11
```

## Logging
By default, candump-format logging is enabled and auto-generates a file name:

```text
can.<datetime>.log
```

Example:

```text
can.20260305-103215.log
```

Custom log file:

```powershell
py elm327_can_monitor.py --log-file can_log.log
```

Disable log file:

```powershell
py elm327_can_monitor.py --no-log
```

## Useful Options
- `--refresh 0.25` screen refresh interval in seconds
- `-b 0x7E8 123` ignore specific IDs (hex or decimal)
- `--transport wifi|tcp|serial|pycan`
- `--host 192.168.0.10 --port 35000` Wi-Fi/TCP endpoint
- `--serial-port COM5 --serial-baud 38400` serial endpoint
- `--pycan-interface socketcan --pycan-channel can0` python-can endpoint
- `--pycan-bitrate 125000` optional python-can bitrate override
- `--can-speed 125|250|500|auto`
- `--can-id-format 11|29`
- `--reconnect-delay 1.0` seconds between reconnect attempts
- `--iface can0` interface name written to candump log lines

## Controls
- `q`: quit
- `Ctrl+C`: quit

## Windows Capture (tshark/Wireshark)
List network interface IDs on Windows:

```powershell
& "C:\Program Files\Wireshark\dumpcap.exe" -D
```

Example output: `6. ... (Wi-Fi)`, `9. ... (Ethernet)`.
Use these numbers in `-i`.

Capture only traffic for `192.168.0.10:35000`, save to file, and print packets to console:

```powershell
New-Item -ItemType Directory -Force -Path .\captures | Out-Null
& "C:\Program Files\Wireshark\tshark.exe" -i 6 -f "tcp and (host 192.168.0.10 or host 127.0.0.1) and port 35000" -i 9 -f "tcp and (host 192.168.0.10 or host 127.0.0.1) and port 35000" -i 10 -f "tcp and (host 192.168.0.10 or host 127.0.0.1) and port 35000" -w ".\captures\emu_35000_multi.pcapng" -P
```

## Notes
- ELM327 init commands: `ATZ`, `ATE0`, `ATL0`, `ATS0`, `ATH1`, `ATSPx`, `ATMA`.
- If connection drops, monitor auto-reconnects.
- Starts in clean output mode: no echo (`ATE0`), no LF (`ATL0`), no spaces (`ATS0`).
- CAN speed to `ATSP` mapping:
  - `500` + `11 bits` -> `ATSP6`
  - `500` + `29 bits` -> `ATSP7`
  - `250` + `11 bits` -> `ATSP8`
  - `250` + `29 bits` -> `ATSP9`
  - `125` + `11 bits` -> `ATSPA`
  - `125` + `29 bits` -> `ATSPB`
  - `auto` -> `ATSP0`
- Parser accepts common ELM327 monitor output variants (with or without DLC).
