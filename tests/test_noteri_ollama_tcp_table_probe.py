"""Contrato da inspeção Win32 da porta 11434 — nenhuma chamada mutante."""
from __future__ import annotations
import importlib.util
import socket
import struct
import sys
from pathlib import Path
from unittest.mock import patch
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("noteri_ollama_tcp_table_probe",
    ROOT/"scripts/noteri_ollama_tcp_table_probe.py")
assert spec and spec.loader
p=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=p
spec.loader.exec_module(p)

def row(port, state=2):
    return struct.pack("<6I", state, 0, socket.htons(port), 0, 0, 1)

class WindowsListenerTests(unittest.TestCase):
    def test_detect_ollama_listener(self):
        packet=struct.pack("<I",2)+row(8000)+row(11434)
        self.assertEqual(p.parse_tcp_table(packet),"LISTENING")

    def test_empty_and_other_port_are_absent(self):
        self.assertEqual(p.parse_tcp_table(struct.pack("<I",0)),"ABSENT")
        self.assertEqual(p.parse_tcp_table(struct.pack("<I",1)+row(8080)),"ABSENT")

    def test_non_listening_ollama_port_is_absent(self):
        self.assertEqual(p.parse_tcp_table(struct.pack("<I",1)+row(11434,5)),"ABSENT")

    def test_truncated_or_oversized_table_fails_closed(self):
        self.assertEqual(p.parse_tcp_table(b"\x01\x00\x00\x00"),"UNKNOWN")
        self.assertEqual(p.parse_tcp_table(struct.pack("<I",100000)),"UNKNOWN")
        self.assertEqual(p.parse_tcp_table(b"0"*(p.MAX_BYTES+1)),"UNKNOWN")

    def test_non_windows_cannot_be_reported_absent(self):
        with patch.object(p.os,"name","posix"):
            self.assertEqual(p.inspect_windows_listener(),"UNKNOWN")

    def test_no_process_execution_or_mutation_calls(self):
        source=(ROOT/"scripts/noteri_ollama_tcp_table_probe.py").read_text("utf-8")
        self.assertIn("GetExtendedTcpTable",source)
        for blocked in ("Popen(", "subprocess.run(", "os.system(", "Start-Service", "netsh"):
            self.assertNotIn(blocked,source)

if __name__=="__main__":
    unittest.main()
