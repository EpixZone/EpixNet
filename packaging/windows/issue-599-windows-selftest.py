#!/usr/bin/env python3
"""Local transport checks only. Does not launch EpixNet or prove Windows behavior."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location('fixture', Path(__file__).with_name('issue-599-windows-fixture.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
ADDRESS = 'epix1syntheticfixture'


def read_exact(connection, count):
    value = bytearray()
    while len(value) < count:
        chunk = connection.recv(count - len(value))
        if not chunk:
            raise ConnectionError('mock peer closed')
        value.extend(chunk)
    return bytes(value)


def read_frame(connection):
    first, second = read_exact(connection, 2)
    assert second & 128, 'client frame must be masked'
    size = second & 127
    if size == 126:
        size = struct.unpack('!H', read_exact(connection, 2))[0]
    elif size == 127:
        size = struct.unpack('!Q', read_exact(connection, 8))[0]
    mask = read_exact(connection, 4)
    payload = read_exact(connection, size)
    return first & 15, bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))


def frame(payload, opcode=1, final=True):
    prefix = bytes([(128 if final else 0) | opcode])
    if len(payload) < 126:
        prefix += bytes([len(payload)])
    elif len(payload) < 65536:
        prefix += bytes([126]) + struct.pack('!H', len(payload))
    else:
        prefix += bytes([127]) + struct.pack('!Q', len(payload))
    return prefix + payload


def handshake(connection, corrupt=False):
    header = bytearray()
    while not header.endswith(b'\r\n\r\n'):
        header.extend(read_exact(connection, 1))
    lines = header.decode().split('\r\n')
    assert lines[0] == f'GET /EpixNet-Internal/Websocket?wrapper_key={ADDRESS} HTTP/1.1'
    headers = {name.lower(): value.strip() for name, value in
               (line.split(':', 1) for line in lines[1:] if ':' in line)}
    assert headers['origin'] == 'http://' + headers['host']
    digest = base64.b64encode(hashlib.sha1((headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
    if corrupt:
        digest = digest.swapcase()
    connection.sendall(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                        'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + digest + '\r\n\r\n').encode())


class MockServer:
    def __init__(self, handler):
        self.errors = []
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.port = self.listener.getsockname()[1]
        def serve():
            try:
                self.listener.settimeout(2)
                connection, _ = self.listener.accept()
                with connection:
                    connection.settimeout(2)
                    handler(connection)
            except BaseException as error:
                self.errors.append(error)
            finally:
                self.listener.close()
        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

    def finish(self):
        self.thread.join(timeout=3)
        assert not self.thread.is_alive(), 'mock server did not stop'
        if self.errors:
            raise self.errors[0]


class TransportTests(unittest.TestCase):
    def test_masked_requests_events_fragmentation_and_ping(self):
        expected = {'address': ADDRESS, 'padding': 'a' * 70000}
        def handler(connection):
            handshake(connection)
            opcode, payload = read_frame(connection)
            self.assertEqual(opcode, 1)
            request = json.loads(payload)
            self.assertEqual(request['id'], 1000001)
            self.assertEqual(request['params']['content_base64'], 'b' * 70000)
            connection.sendall(frame(json.dumps({'cmd': 'siteInfo', 'params': {}}).encode()))
            reply = json.dumps({'cmd': 'response', 'to': 1000001, 'result': expected}).encode()
            connection.sendall(frame(reply[:150], final=False) + frame(b'ping', opcode=9))
            self.assertEqual(read_frame(connection), (10, b'ping'))
            connection.sendall(frame(reply[150:], opcode=0))
        server = MockServer(handler)
        self.assertEqual(fixture.command(server.port, ADDRESS, 'fileWrite', {'content_base64': 'b' * 70000}), expected)
        server.finish()

    def test_accept_is_case_sensitive(self):
        server = MockServer(lambda connection: handshake(connection, corrupt=True))
        with self.assertRaisesRegex(RuntimeError, 'invalid WebSocket accept'):
            fixture.command(server.port, ADDRESS, 'siteInfo')
        server.finish()

    def test_nested_command_error(self):
        def handler(connection):
            handshake(connection)
            read_frame(connection)
            connection.sendall(frame(b'{"cmd":"response","to":1000001,"result":{"error":"controlled failure"}}'))
        server = MockServer(handler)
        with self.assertRaisesRegex(RuntimeError, 'controlled failure'):
            fixture.command(server.port, ADDRESS, 'siteInfo')
        server.finish()

    def test_absolute_deadline_survives_repeated_events(self):
        def handler(connection):
            handshake(connection)
            read_frame(connection)
            try:
                for _ in range(20):
                    connection.sendall(frame(b'{"cmd":"pushed"}'))
                    time.sleep(0.04)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
        server = MockServer(handler)
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            fixture.command(server.port, ADDRESS, 'siteInfo', timeout=0.2)
        self.assertLess(time.monotonic() - started, 0.6)
        server.finish()

    def test_frame_limit_rejected_before_payload_read(self):
        def handler(connection):
            handshake(connection)
            read_frame(connection)
            connection.sendall(bytes([129, 127]) + struct.pack('!Q', fixture.MAX_FRAME + 1))
        server = MockServer(handler)
        with self.assertRaisesRegex(RuntimeError, 'exceeds 4 MiB'):
            fixture.command(server.port, ADDRESS, 'siteInfo')
        server.finish()

    def test_status_matches_real_endpoint_without_offline_field(self):
        value = {'serving': True, 'tor_enabled': False, 'i2p_enabled': False,
                 'mesh_enabled': False, 'connections': {'total': 0}}
        self.assertEqual(self.status_response(value), value)

    def test_status_rejects_network_or_missing_fields(self):
        for value in [{'serving': True, 'connections': {'total': 0}},
                      {'serving': True, 'tor_enabled': True, 'i2p_enabled': False,
                       'mesh_enabled': False, 'connections': {'total': 0}}]:
            with self.assertRaisesRegex(RuntimeError, 'network subsystem'):
                self.status_response(value)

    def status_response(self, value):
        def handler(connection):
            request = bytearray()
            while not request.endswith(b'\r\n\r\n'):
                request.extend(read_exact(connection, 1))
            payload = json.dumps(value).encode()
            connection.sendall(f'HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\n\r\n'.encode() + payload)
        server = MockServer(handler)
        try:
            return fixture.status(server.port)
        finally:
            server.finish()

    def test_manifest_incomplete_then_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'content.json'
            path.write_text('{"files":{}}')
            self.assertFalse(fixture.manifest_coverage(path, {'asset'})['ok'])
            path.write_text(json.dumps({'files': {'asset': {'size': fixture.FILE_BYTES, 'b3': 'a' * 64}}}))
            self.assertTrue(fixture.manifest_coverage(path, {'asset'})['ok'])
            path.write_text(json.dumps({'files': {'asset': {'size': 1, 'b3': 'a' * 64}}}))
            self.assertFalse(fixture.manifest_coverage(path, {'asset'})['ok'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
