#!/usr/bin/env python3
"""Simple CAN monitor for ELM327 or python-can transports.

Shows the last frame per CAN ID, sorted by ID.
"""

from __future__ import annotations

import argparse
import math
import os
from pathlib import Path
import re
import signal
import socket
import sys
import threading
import time
from dataclasses import dataclass
from typing import Optional

try:
    import serial  # type: ignore
except ImportError:
    serial = None  # type: ignore[assignment]

try:
    import can  # type: ignore
except ImportError:
    can = None  # type: ignore[assignment]

try:
    from rich.columns import Columns
    from rich.console import Group
    from rich.live import Live
    from rich.text import Text
except ImportError:
    Columns = None  # type: ignore[assignment]
    Group = None  # type: ignore[assignment]
    Live = None  # type: ignore[assignment]
    Text = None  # type: ignore[assignment]


IGNORE_PREFIXES = (
    "AT",
    "OK",
    "SEARCHING",
    "STOPPED",
    "NO DATA",
    "UNABLE TO CONNECT",
)
HEX_TOKEN_RE = re.compile(r"^[0-9A-Fa-f]{1,8}$")


class InvalidFrame(Exception):
    pass


@dataclass
class FrameInfo:
    data: bytes
    last_seen: float
    count: int


class ELM327HandlerBase:
    def __init__(
        self,
        host: str,
        protocol_code: str,
        can_id_bits: str,
        timeout: float = 1.0,
    ):
        self.host = host
        self.protocol_code = protocol_code.upper()
        self.can_id_bits = can_id_bits
        self.timeout = timeout
        self._buffer = ""

    def open(self) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    def _send_raw(self, text: str) -> None:
        raise NotImplementedError

    def _recv_text(self) -> str:
        raise NotImplementedError

    @staticmethod
    def _connection_label() -> str:
        return "ELM327 connection"

    def _safe_protocol_close(self) -> None:
        try:
            self._send_raw("\r")
            time.sleep(0.05)
            self._send_command("ATPC")
        except OSError:
            pass

    def _read_until_prompt(self) -> str:
        deadline = time.time() + 3.0
        chunks: list[str] = []
        while time.time() < deadline:
            chunk = self._recv_text()
            if not chunk:
                continue
            chunks.append(chunk)
            if ">" in chunk:
                break
        return "".join(chunks)

    def _drain_prompt(self) -> None:
        # Some adapters emit banner/prompt on connect.
        try:
            self._read_until_prompt()
        except OSError:
            pass

    def _send_command(self, command: str) -> str:
        self._send_raw(f"{command}\r")
        return self._read_until_prompt()

    def _init_adapter(self) -> None:
        # Keep the setup conservative to maximize compatibility.
        for cmd in ("ATZ", "ATE0", "ATL0", "ATS0", "ATH1"):
            self._send_command(cmd)
        protocol_resp = self._send_command(f"ATSP{self.protocol_code}")
        if self._is_error_response(protocol_resp):
            raise RuntimeError(
                f"ELM327 did not accept protocol ATSP{self.protocol_code}. "
                "Check speed/ID format or adapter support."
            )
        self._send_command("ATMA")

    def open(self) -> None:
        self._drain_prompt()
        self._init_adapter()

    def get_message(self) -> tuple[int, bytes]:
        while True:
            line = self._read_line()
            if line is None:
                continue
            return self._parse_monitor_line(line, self.can_id_bits)

    @staticmethod
    def _is_error_response(response: str) -> bool:
        upper = response.upper()
        return "?" in upper or "ERROR" in upper

    def _read_line(self) -> str | None:
        while True:
            if "\r" in self._buffer:
                line, self._buffer = self._buffer.split("\r", 1)
                line = line.strip().replace(">", "")
                if not line:
                    return None
                return line

            self._buffer += self._recv_text()

    @staticmethod
    def _parse_monitor_line(line: str, can_id_bits: str) -> tuple[int, bytes]:
        text = line.strip()
        if not text:
            raise InvalidFrame("empty line")

        upper = text.upper()
        for prefix in IGNORE_PREFIXES:
            if upper.startswith(prefix):
                raise InvalidFrame(text)

        if " " in upper:
            tokens = [tok for tok in upper.split() if tok]
            if len(tokens) < 2:
                raise InvalidFrame(text)
            if not HEX_TOKEN_RE.match(tokens[0]):
                raise InvalidFrame(text)

            frame_id = int(tokens[0], 16)
            payload_tokens = tokens[1:]
            if payload_tokens and re.fullmatch(r"[0-8]", payload_tokens[0]):
                dlc = int(payload_tokens[0], 16)
                if len(payload_tokens[1:]) >= dlc:
                    payload_tokens = payload_tokens[1: 1 + dlc]
            try:
                data = bytes(
                    int(tok, 16) for tok in payload_tokens if re.fullmatch(r"[0-9A-F]{1,2}", tok)
                )
            except ValueError as exc:
                raise InvalidFrame(text) from exc
            if not data:
                raise InvalidFrame(text)
            return frame_id, data

        # Compact format (e.g. with ATS0 + ATL0): ID followed by data bytes.
        compact = re.sub(r"[^0-9A-F]", "", upper)
        id_chars = 3 if can_id_bits == "11" else 8
        if len(compact) <= id_chars:
            raise InvalidFrame(text)

        frame_id_hex = compact[:id_chars]
        payload_hex = compact[id_chars:]

        # If the first nibble after ID looks like DLC and remaining data can satisfy it, consume DLC.
        if payload_hex and payload_hex[0] in "012345678":
            maybe_dlc = int(payload_hex[0], 16)
            remaining = payload_hex[1:]
            if len(remaining) >= maybe_dlc * 2:
                payload_hex = remaining[: maybe_dlc * 2]

        if len(payload_hex) % 2 != 0:
            payload_hex = payload_hex[:-1]

        if not payload_hex:
            raise InvalidFrame(text)

        try:
            frame_id = int(frame_id_hex, 16)
            data = bytes.fromhex(payload_hex)
        except ValueError as exc:
            raise InvalidFrame(text) from exc

        if not data:
            raise InvalidFrame(text)

        return frame_id, data


class ELM327WiFiHandler(ELM327HandlerBase):
    def __init__(
        self,
        host: str,
        port: int,
        protocol_code: str,
        can_id_bits: str,
        timeout: float = 1.0,
    ):
        super().__init__(host, protocol_code, can_id_bits, timeout=timeout)
        self.port = port
        self.sock: Optional[socket.socket] = None

    def open(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        super().open()

    def close(self) -> None:
        if self.sock:
            self._safe_protocol_close()
            try:
                self.sock.close()
            finally:
                self.sock = None

    def _send_raw(self, text: str) -> None:
        if not self.sock:
            raise OSError("Socket is not connected")
        self.sock.sendall(text.encode("ascii", errors="ignore"))

    def _recv_text(self) -> str:
        if not self.sock:
            raise OSError("Socket is not connected")
        try:
            data = self.sock.recv(4096)
        except socket.timeout:
            return ""
        if not data:
            raise EOFError("ELM327 socket closed")
        return data.decode("ascii", errors="ignore")


class ELM327SerialHandler(ELM327HandlerBase):
    def __init__(
        self,
        port_name: str,
        baudrate: int,
        protocol_code: str,
        can_id_bits: str,
        timeout: float = 1.0,
    ):
        super().__init__(port_name, protocol_code, can_id_bits, timeout=timeout)
        self.port_name = port_name
        self.baudrate = baudrate
        self.serial_dev = None

    def open(self) -> None:
        if serial is None:
            raise RuntimeError("pyserial is required for --transport serial (install: py -m pip install pyserial)")
        self.serial_dev = serial.Serial(self.port_name, self.baudrate, timeout=self.timeout)
        super().open()

    def close(self) -> None:
        if self.serial_dev:
            self._safe_protocol_close()
            try:
                self.serial_dev.close()
            finally:
                self.serial_dev = None

    def _send_raw(self, text: str) -> None:
        if not self.serial_dev:
            raise OSError("Serial port is not connected")
        self.serial_dev.write(text.encode("ascii", errors="ignore"))

    def _recv_text(self) -> str:
        if not self.serial_dev:
            raise OSError("Serial port is not connected")
        data = self.serial_dev.read(4096)
        if not data:
            return ""
        return data.decode("ascii", errors="ignore")


class PyCanHandler:
    def __init__(self, interface: str, channel: str, bitrate: int | None, timeout: float = 1.0):
        self.interface = interface
        self.channel = channel
        self.bitrate = bitrate
        self.timeout = timeout
        self.bus = None

    def open(self) -> None:
        if can is None:
            raise RuntimeError("python-can is required for --transport pycan (install: py -m pip install python-can)")
        kwargs = {"interface": self.interface, "channel": self.channel}
        if self.bitrate and self.bitrate > 0:
            kwargs["bitrate"] = self.bitrate
        self.bus = can.Bus(**kwargs)

    def close(self) -> None:
        if self.bus is not None:
            try:
                self.bus.shutdown()
            finally:
                self.bus = None

    def get_message(self) -> tuple[int, bytes]:
        if self.bus is None:
            raise OSError("python-can bus is not connected")
        msg = self.bus.recv(timeout=self.timeout)
        if msg is None:
            raise InvalidFrame("timeout")
        return int(msg.arbitration_id), bytes(msg.data)


class KeyReader:
    def __init__(self):
        self._is_windows = os.name == "nt"

    def read_key(self) -> str | None:
        if self._is_windows:
            return self._read_key_windows()
        return self._read_key_posix()

    def _read_key_windows(self) -> str | None:
        try:
            import msvcrt  # type: ignore
        except ImportError:
            return None

        if msvcrt.kbhit():
            try:
                return msvcrt.getwch()
            except Exception:
                return None
        return None

    def _read_key_posix(self) -> str | None:
        import select

        readable, _, _ = select.select([sys.stdin], [], [], 0)
        if readable:
            return sys.stdin.read(1)
        return None


def format_hex(data: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in data)


def format_ascii(data: bytes) -> str:
    out = []
    for byte in data:
        if byte == 0:
            out.append(".")
        elif 32 <= byte <= 126:
            out.append(chr(byte))
        else:
            out.append("?")
    return "".join(out)


def format_candump_line(ts: float, iface: str, frame_id: int, data: bytes) -> str:
    return f"({ts:.6f}) {iface} {frame_id:X}#{data.hex().upper()}"


def default_log_filename() -> str:
    return time.strftime("can.%Y%m%d-%H%M%S.log")


def build_view(
    messages: dict[int, FrameInfo],
    started_at: float,
    connected: bool,
    reconnects: int,
    last_error: str,
    term_width: int,
    term_height: int,
    log_path: str | None,
) -> Group:
    uptime = time.time() - started_at
    status = "CONNECTED" if connected else "DISCONNECTED"
    status_color = "green" if connected else "red"

    ids_sorted = sorted(messages.keys())
    # Compact row format to fit more columns on wide terminals.
    col_width = 40
    cols_fit = max(1, term_width // col_width)
    rows_capacity = max(6, term_height - 8)
    cols_needed_by_height = max(1, math.ceil(max(1, len(ids_sorted)) / rows_capacity))

    if term_width >= 240:
        cols_pref = 4
    elif term_width >= 160:
        cols_pref = 3
    elif term_width >= 80:
        cols_pref = 2
    else:
        cols_pref = 1

    cols_pref = min(cols_pref, max(1, len(ids_sorted)))
    cols_used = min(cols_fit, max(cols_pref, cols_needed_by_height))
    cols_used = min(cols_used, cols_needed_by_height)
    cols_used = max(1, cols_used)
    per_col_width = max(1, term_width // max(1, cols_used))
    show_age = per_col_width >= 40
    show_count = per_col_width >= 36
    rows_per_col = rows_capacity

    now = time.time()
    lines = []
    for frame_id in ids_sorted:
        info = messages[frame_id]
        msg_hex = format_hex(info.data)
        msg_ascii = format_ascii(info.data)
        age = now - info.last_seen
        base = f"{frame_id:>4d} {frame_id:>3X} {msg_hex:<17.17} {msg_ascii:<6.6}"
        if show_count:
            base += f" {info.count:>4d}"
        if show_age:
            base += f" {age:>4.1f}"
        lines.append(base)
    header = "IDd IDh Bytes             Txt"
    if show_count:
        header += "  Cnt"
    if show_age:
        header += "  Age"

    blocks = []
    for i in range(cols_used):
        start = i * rows_per_col
        end = start + rows_per_col
        section = lines[start:end]
        if not section:
            continue
        block_text = [header]
        block_text.extend(section)
        blocks.append(Text("\n".join(block_text), no_wrap=True))

    grid = Columns(blocks, equal=True, expand=True)

    header = Text.assemble(("ELM327 Wi-Fi CAN Monitor", "bold cyan"))
    parts = [
        "q to quit",
        f"Uptime: {uptime:6.1f}s",
        f"Status: {status}",
        f"Re: {reconnects}",
        f"Col: {cols_used}",
        f"Screen: {term_width}x{term_height}",
    ]
    if log_path:
        parts.append(f"Log: {Path(log_path).name}")

    # Keep header in a single line to avoid resize artifacts.
    for item in parts:
        candidate = f" | {item}"
        if len(header.plain) + len(candidate) > max(20, term_width - 2):
            break
        if item.startswith("Status: "):
            header.append(" | Status: ")
            header.append(status, style=status_color)
        else:
            header.append(candidate)
    if last_error:
        line4 = Text(f"Last error: {last_error}", style="yellow")
        return Group(header, line4, grid)
    return Group(header, grid)


def parse_blacklist(values: list[str]) -> set[int]:
    out: set[int] = set()
    for item in values:
        try:
            out.add(int(item, 0))
        except ValueError:
            continue
    return out


def resolve_protocol_code(can_speed: str, can_id_format: str) -> str:
    speed = can_speed.lower()
    bits = can_id_format
    if speed == "auto":
        return "0"

    table = {
        "500": {"11": "6", "29": "7"},
        "250": {"11": "8", "29": "9"},
        "125": {"11": "A", "29": "B"},
    }
    return table[speed][bits]


def run() -> int:
    if Live is None or Group is None or Columns is None or Text is None:
        print("Missing dependency: rich")
        print("Install with: py -m pip install rich")
        return 1

    parser = argparse.ArgumentParser(description="CAN monitor using ELM327 (wifi/serial) or python-can")
    parser.add_argument(
        "--transport",
        choices=("wifi", "tcp", "serial", "pycan"),
        default="wifi",
        help="Transport (default: wifi; wifi/tcp = TCP/IP, serial = COM/Bluetooth SPP, pycan = python-can bus)",
    )
    parser.add_argument("--host", default="192.168.0.10", help="ELM327 Wi-Fi host")
    parser.add_argument("--port", type=int, default=35000, help="ELM327 Wi-Fi port")
    parser.add_argument("--serial-port", default="", help="Serial COM port for ELM327 Bluetooth (e.g. COM5)")
    parser.add_argument("--serial-baud", type=int, default=38400, help="Serial baud rate (default: 38400)")
    parser.add_argument("--pycan-interface", default="socketcan", help="python-can interface (e.g. socketcan, pcan)")
    parser.add_argument("--pycan-channel", default="can0", help="python-can channel (e.g. can0, PCAN_USBBUS1)")
    parser.add_argument("--pycan-bitrate", type=int, default=0, help="python-can bitrate (0 = do not force)")
    parser.add_argument("--io-timeout", type=float, default=1.0, help="Transport I/O timeout in seconds")
    parser.add_argument("--refresh", type=float, default=0.25, help="Screen refresh interval (seconds)")
    parser.add_argument("--blacklist", "-b", nargs="*", default=[], help="IDs to ignore (e.g. 0x7E8 123)")
    parser.add_argument(
        "--can-speed",
        choices=("125", "250", "500", "auto"),
        default="125",
        help="CAN speed in kbps (default: 125)",
    )
    parser.add_argument(
        "--can-id-format",
        choices=("11", "29"),
        default="11",
        help="CAN ID format bits (default: 11)",
    )
    parser.add_argument("--reconnect-delay", type=float, default=1.0, help="Seconds between reconnect attempts")
    parser.add_argument(
        "--log-file",
        default="",
        help="Candump log file path (default: can.<datahora>.log)",
    )
    parser.add_argument("--no-log", action="store_true", help="Disable candump file logging")
    parser.add_argument("--iface", default="can0", help="Interface name used in candump log (default: can0)")
    args = parser.parse_args()
    transport = "wifi" if args.transport == "tcp" else args.transport

    if serial is None:
        print("Warning: pyserial is not installed. Serial transport will be unavailable.")
    if can is None:
        print("Warning: python-can is not installed. pycan transport will be unavailable.")

    if transport == "serial" and serial is None:
        print("Error: --transport serial requires pyserial. Install with: py -m pip install pyserial")
        return 1
    if transport == "pycan" and can is None:
        print("Error: --transport pycan requires python-can. Install with: py -m pip install python-can")
        return 1

    stop_event = threading.Event()
    messages: dict[int, FrameInfo] = {}
    lock = threading.Lock()
    blacklist = parse_blacklist(args.blacklist)
    error_holder: list[BaseException] = []
    state_lock = threading.Lock()
    connection_state = {"connected": False, "reconnects": 0, "last_error": ""}

    protocol_code = resolve_protocol_code(args.can_speed, args.can_id_format)
    if transport == "serial" and not args.serial_port:
        parser.error("--serial-port is required when --transport serial")

    if transport == "serial":
        handler = ELM327SerialHandler(
            args.serial_port,
            args.serial_baud,
            protocol_code=protocol_code,
            can_id_bits=args.can_id_format,
            timeout=args.io_timeout,
        )
    elif transport == "pycan":
        handler = PyCanHandler(
            interface=args.pycan_interface,
            channel=args.pycan_channel,
            bitrate=args.pycan_bitrate if args.pycan_bitrate > 0 else None,
            timeout=args.io_timeout,
        )
    else:
        handler = ELM327WiFiHandler(
            args.host,
            args.port,
            protocol_code=protocol_code,
            can_id_bits=args.can_id_format,
            timeout=args.io_timeout,
        )
    key_reader = KeyReader()
    log_file = None

    def sigint_handler(_sig, _frame):
        stop_event.set()

    signal.signal(signal.SIGINT, sigint_handler)

    def read_loop() -> None:
        try:
            while not stop_event.is_set():
                with state_lock:
                    connected = bool(connection_state["connected"])

                if not connected:
                    try:
                        handler.close()
                    except OSError:
                        pass
                    try:
                        handler.open()
                        with state_lock:
                            connection_state["connected"] = True
                            connection_state["last_error"] = ""
                    except BaseException as exc:
                        with state_lock:
                            connection_state["connected"] = False
                            connection_state["reconnects"] = int(connection_state["reconnects"]) + 1
                            connection_state["last_error"] = str(exc)
                        time.sleep(max(0.2, args.reconnect_delay))
                        continue

                try:
                    frame_id, data = handler.get_message()
                except InvalidFrame:
                    continue
                except (EOFError, OSError, RuntimeError) as exc:
                    with state_lock:
                        connection_state["connected"] = False
                        connection_state["reconnects"] = int(connection_state["reconnects"]) + 1
                        connection_state["last_error"] = str(exc)
                    time.sleep(max(0.2, args.reconnect_delay))
                    continue

                if frame_id in blacklist:
                    continue

                now = time.time()
                with lock:
                    previous = messages.get(frame_id)
                    count = (previous.count + 1) if previous else 1
                    messages[frame_id] = FrameInfo(data=data, last_seen=now, count=count)
                    if log_file:
                        log_file.write(format_candump_line(now, args.iface, frame_id, data) + "\n")
        except BaseException as exc:
            error_holder.append(exc)
            stop_event.set()

    log_path = None if args.no_log else (args.log_file or default_log_filename())

    if log_path:
        try:
            log_file = open(log_path, "a", encoding="ascii", buffering=1)
        except OSError as exc:
            print(f"Failed to open candump log '{log_path}': {exc}")
            return 1

    thread = threading.Thread(target=read_loop, daemon=True)
    thread.start()

    started_at = time.time()
    try:
        os.system("cls" if os.name == "nt" else "clear")
        last_size = None
        with Live(auto_refresh=False, screen=False) as live:
            while not stop_event.is_set():
                with lock:
                    snapshot = dict(messages)
                with state_lock:
                    connected = bool(connection_state["connected"])
                    reconnects = int(connection_state["reconnects"])
                    last_error = str(connection_state["last_error"])
                term_size = live.console.size
                size_now = (term_size.width, term_size.height)
                if size_now != last_size:
                    live.console.clear()
                    last_size = size_now

                live.update(
                    build_view(
                        snapshot,
                        started_at,
                        connected,
                        reconnects,
                        last_error,
                        term_size.width,
                        term_size.height,
                        log_path,
                    ),
                    refresh=True,
                )

                key = key_reader.read_key()
                if key and key.lower() == "q":
                    stop_event.set()
                    break

                if error_holder:
                    stop_event.set()
                    break

                time.sleep(max(0.05, args.refresh))
    finally:
        stop_event.set()
        handler.close()
        thread.join(timeout=1.5)
        if log_file:
            log_file.close()

    if error_holder:
        print(f"Error: {error_holder[0]}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(run())
