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
  - `pyserial` for `--transport arduino` / `--transport alexandreblin/arduino-peugeot-can`
  - `python-can` for `--transport pycan`
  - `scapy` for `--transport pcap`

Install dependencies:

```powershell
py -m pip install rich
py -m pip install pyserial
py -m pip install python-can
py -m pip install scapy
```

## Quick Start
Default transport is Wi-Fi/TCP (`192.168.0.10:35000`):

```powershell
py elm327_can_monitor.py
```

## Transport Modes
- Default: `--transport wifi` (TCP/IP)
- `--transport tcp` is an alias of `wifi`
- `--transport serial` uses **ELM327 over serial** (typically Bluetooth SPP exposed as a COM port)
- `--transport arduino` reads `FRAME:ID=...` serial stream ([Arduino sketch - Alexandre Blin](https://github.com/alexandreblin/arduino-peugeot-can))
- `--transport alexandreblin/arduino-peugeot-can` is an alias of `arduino`
- `--transport pycan` uses native python-can bus APIs
- `--transport candump` replays candump log files
- `--transport pcap` replays ELM327 TCP payloads from pcap/pcapng

## Transport Overview
- `wifi` / `tcp`:
  - Source: ELM327 over TCP/IP (`--host`, `--port`)
  - Best for: Wi-Fi ELM327 adapters
  - Notes: sends ELM init commands (`ATZ`, `ATE0`, `ATL0`, `ATS0`, `ATH1`, `ATSPx`, `ATMA`)

- `serial`:
  - Source: ELM327 over serial COM/Bluetooth SPP (`--serial-port`, optional `--serial-baud`)
  - Best for: Bluetooth ELM327 adapters exposed as COM ports
  - Notes: same ELM init behavior as Wi-Fi mode

- `arduino` / `alexandreblin/arduino-peugeot-can`:
  - Source: serial text lines in this format:
    - `FRAME:ID=<decimal>:LEN=<n>:<hex bytes...>`
  - Best for: Arduino CAN reader sketch streams
  - Notes: defaults to `115200 8N1` internally

- `pycan`:
  - Source: native CAN interface via `python-can` (`--pycan-interface`, `--pycan-channel`)
  - Best for: direct CAN adapters supported by python-can (socketcan, pcan, etc.)
  - Notes: no ELM parsing/AT commands; reads raw CAN frames from the bus

- `candump`:
  - Source: candump log file (`--candump-file`)
  - Best for: offline replay/debug from saved logs
  - Notes: supports replay speed scaling (`--candump-speed`) and time window (`--start-dt`, `--end-dt`)

- `pcap`:
  - Source: TCP payloads extracted from pcap/pcapng (`--pcap-file`)
  - Best for: replay from captured ELM327 network traffic
  - Notes: filters TCP stream by `--pcap-host`/`--pcap-port` (defaults `192.168.0.10:35000`), supports `--pcap-speed`, `--start-dt`, `--end-dt`

Wi-Fi / TCP:

```powershell
py elm327_can_monitor.py --transport wifi --host 192.168.0.10 --port 35000
py elm327_can_monitor.py --transport tcp --host 192.168.0.10 --port 35000
```

Serial (Bluetooth ELM327 on COM):

```powershell
py elm327_can_monitor.py --transport serial --serial-port COM5 --serial-baud 38400
```

Arduino sketch stream (Alexandre Blin):

```powershell
py elm327_can_monitor.py --transport arduino --serial-port COM5
py elm327_can_monitor.py --transport "alexandreblin/arduino-peugeot-can" --serial-port COM5
```

Default serial settings for this mode: `115200`, `8N1`.
Reference: https://github.com/alexandreblin/arduino-peugeot-can

python-can:

```powershell
py elm327_can_monitor.py --transport pycan --pycan-interface socketcan --pycan-channel can0
```

candump file replay:

```powershell
py elm327_can_monitor.py --transport candump --candump-file .\can.20260305-101436.log
```

Follow a growing candump file (tail mode):

```powershell
py elm327_can_monitor.py --transport candump --candump-file .\can_live.log --follow
```

pcap/pcapng replay (TCP filter defaults to `192.168.0.10:35000`):

```powershell
py elm327_can_monitor.py --transport pcap --pcap-file .\captures\emu_35000_multi.pcapng
```

pcap replay in real-time (respect packet timestamps):

```powershell
py elm327_can_monitor.py --transport pcap --pcap-file .\captures\emu_35000_multi.pcapng --pcap-speed 1.0
```

Follow a growing pcap/pcapng file:

```powershell
py elm327_can_monitor.py --transport pcap --pcap-file .\captures\emu_live.pcapng --follow
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
- `--transport wifi|tcp|serial|arduino|alexandreblin/arduino-peugeot-can|pycan|candump|pcap`
- `--host 192.168.0.10 --port 35000` Wi-Fi/TCP endpoint
- `--serial-port COM5 --serial-baud 38400` serial endpoint
- `--pycan-interface socketcan --pycan-channel can0` python-can endpoint
- `--pycan-bitrate 125000` optional python-can bitrate override
- `--candump-file path.log` candump source file for replay
- `--candump-speed 1.0` replay time scale (`0` = as fast as possible)
- `--pcap-file path.pcapng` pcap source file for replay
- `--pcap-host 192.168.0.10 --pcap-port 35000` TCP filter for pcap parsing
- `--pcap-speed 1.0` pcap replay speed scale (`0` = as fast as possible)
- `--follow` keep reading as file grows
- `--follow-interval 0.2` polling interval in seconds for `--follow`
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
