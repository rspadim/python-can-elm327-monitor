# ELM327 Wi-Fi CAN Monitor

Monitor de barramento CAN via ELM327 (Wi-Fi), mostrando na tela a **ultima mensagem de cada ID**, ordenada por ID.

## Original Reference
This project is inspired by the original Python CAN monitor:
https://github.com/alexandreblin/python-can-monitor

## Requisitos
- Python 3.10+
- ELM327 Wi-Fi acessivel em `192.168.0.10:35000` (padrao deste script)
- Biblioteca Python `rich` para a interface TUI

Instalacao:

```powershell
py -m pip install rich
```

## Uso
No terminal, dentro desta pasta:

```powershell
py elm327_can_monitor.py
```

## Transport Modes
- Default: `--transport wifi` (TCP/IP)
- `--transport tcp` is an alias for `wifi` (same behavior, TCP/IP)
- Wi-Fi/TCP (TCP/IP): uses `--host` and `--port` (default `192.168.0.10:35000`)
- Serial (Bluetooth SPP / COM): uses `--serial-port` and `--serial-baud`

Wi-Fi (default):

```powershell
py elm327_can_monitor.py --transport wifi --host 192.168.0.10 --port 35000
```

TCP alias:

```powershell
py elm327_can_monitor.py --transport tcp --host 192.168.0.10 --port 35000
```

Serial (Bluetooth ELM327 on COM):

```powershell
py elm327_can_monitor.py --transport serial --serial-port COM5 --serial-baud 38400
```

Ou com parametros explicitos:

```powershell
py elm327_can_monitor.py --host 192.168.0.10 --port 35000
```

Para mostrar na tela e gravar ao mesmo tempo em formato `candump`:

```powershell
py elm327_can_monitor.py --log-file can_log.log
```

Por padrao, se voce nao passar `--log-file`, ele grava automaticamente em:

```text
can.<datahora>.log
```

Exemplo de nome real:

```text
can.20260305-103215.log
```

## Velocidade CAN (125 ou 500 kbps)
Sim, voce pode escolher facilmente.

125 kbps (equivalente ao `CAN_125KBPS` do Arduino):

```powershell
py elm327_can_monitor.py --can-speed 125 --can-id-format 11
```

500 kbps:

```powershell
py elm327_can_monitor.py --can-speed 500 --can-id-format 11
```

500 kbps com log candump:

```powershell
py elm327_can_monitor.py --can-speed 500 --can-id-format 11 --log-file can_log.log
```

## Opcoes uteis
- `--refresh 0.25` intervalo de atualizacao da tela em segundos
- `-b 0x7E8 123` ignora IDs especificos (hex ou decimal)
- `--transport wifi|tcp|serial` transport type (`wifi` default; `tcp` alias of `wifi`)
- `--host 192.168.0.10 --port 35000` TCP/IP endpoint for Wi-Fi/TCP transport
- `--serial-port COM5 --serial-baud 38400` serial endpoint for Bluetooth ELM327
- `--can-speed 125|250|500|auto` velocidade CAN em kbps (padrao: `125`)
- `--can-id-format 11|29` formato do ID CAN (padrao: `11`)
- `--reconnect-delay 1.0` segundos entre tentativas de reconexao ao ELM327
- `--log-file caminho.log` define o arquivo de log candump (se nao passar, usa `can.<datahora>.log`)
- `--no-log` desativa gravacao em arquivo
- `--iface can0` nome da interface usada no log candump (padrao: `can0`)

Exemplo:

```powershell
py elm327_can_monitor.py -b 0x7E8 0x7E9 --refresh 0.2
```

Com velocidade explicita (equivalente ao seu `CAN_125KBPS` antigo):

```powershell
py elm327_can_monitor.py --can-speed 125 --can-id-format 11
```

Com log candump + velocidade fixa:

```powershell
py elm327_can_monitor.py --can-speed 125 --can-id-format 11 --log-file can_log.log --iface can0
```

## Controles
- `q`: sair
- `Ctrl+C`: sair

## Windows Capture (tshark/Wireshark)
To list network interface IDs on Windows:

```powershell
& "C:\Program Files\Wireshark\dumpcap.exe" -D
```

Example output: `6. ... (Wi-Fi)`, `9. ... (Ethernet)`.
Use those numbers in `-i`.

Capture (default `-i 6 -i 9`) only traffic for `192.168.0.10:35000`, save to file, and print packets to console:

```powershell
& "C:\Program Files\Wireshark\tshark.exe" -i 6 -i 9 -f "tcp and host 192.168.0.10 and port 35000" -Y "ip.addr==192.168.0.10 && tcp.port==35000" -w ".\captures\emu_35000_multi.pcapng" -P
```

## Observacoes
- O script envia comandos AT de inicializacao: `ATZ`, `ATE0`, `ATL0`, `ATS0`, `ATH1`, `ATSPx`, `ATMA`.
- Se a conexao cair, o monitor tenta reconectar automaticamente (sem fechar a tela).
- Ja inicia em modo "limpo" no ELM327: sem eco (`ATE0`), sem LF (`ATL0`) e sem espacos (`ATS0`).
- Mapeamento de velocidade para `ATSP`:
  - `500` + `11 bits` -> `ATSP6`
  - `500` + `29 bits` -> `ATSP7`
  - `250` + `11 bits` -> `ATSP8`
  - `250` + `29 bits` -> `ATSP9`
  - `125` + `11 bits` -> `ATSPA`
  - `125` + `29 bits` -> `ATSPB`
  - `auto` -> `ATSP0`
- O parser tenta aceitar variacoes comuns de resposta do ELM327 (com ou sem campo DLC).
