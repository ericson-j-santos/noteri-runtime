#!/usr/bin/env python3
"""Inventario local da porta Ollama via API somente leitura do Windows."""
from __future__ import annotations

import ctypes
import os
import socket
import struct

PORT = 11434
STATE_LISTEN = 2
AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
MAX_BYTES = 1024 * 1024


def parse_tcp_table(payload: bytes) -> str:
    """Confere linhas Win32 antes de afirmar ausencia de listener."""
    if len(payload) < 4 or len(payload) > MAX_BYTES:
        return "UNKNOWN"
    try:
        count = struct.unpack_from("<I", payload, 0)[0]
        if count > (MAX_BYTES - 4) // 24 or 4 + count * 24 > len(payload):
            return "UNKNOWN"
        for index in range(count):
            state, _addr, port, _raddr, _rport, _pid = struct.unpack_from(
                "<6I", payload, 4 + index * 24
            )
            if state == STATE_LISTEN and socket.ntohs(port & 0xffff) == PORT:
                return "LISTENING"
    except (ValueError, struct.error):
        return "UNKNOWN"
    return "ABSENT"


def inspect_windows_listener() -> str:
    """Consulta GetExtendedTcpTable; erro vira UNKNOWN, nunca ausencia."""
    if os.name != "nt":
        return "UNKNOWN"
    try:
        library = ctypes.WinDLL("iphlpapi")
        method = library.GetExtendedTcpTable
        method.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_bool,
            ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
        ]
        method.restype = ctypes.c_ulong
        size = ctypes.c_ulong(0)
        if method(None, ctypes.byref(size), False, AF_INET,
                  TCP_TABLE_OWNER_PID_ALL, 0) != 122:
            return "UNKNOWN"
        if not 4 <= size.value <= MAX_BYTES:
            return "UNKNOWN"
        buf = ctypes.create_string_buffer(size.value)
        if method(buf, ctypes.byref(size), False, AF_INET,
                  TCP_TABLE_OWNER_PID_ALL, 0) != 0:
            return "UNKNOWN"
        return parse_tcp_table(buf.raw[:size.value])
    except (OSError, AttributeError, ValueError, struct.error):
        return "UNKNOWN"
