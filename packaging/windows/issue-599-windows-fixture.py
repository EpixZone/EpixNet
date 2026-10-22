#!/usr/bin/env python3
"""Proposed native Windows #599 fixture. No builds or external network calls.

Uses the running node's actual WebSocket API, never the Windows CLI signing
fallback. Synthetic keys/data stay in RUNNER_TEMP and are deleted. The evidence
is a controlled Windows Server API test, not the reporter's Windows 10 UI.
"""
import argparse
import base64
import concurrent.futures
import ctypes
from ctypes import wintypes
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

FILES = 4096
FILE_BYTES = 100 * 1024
SIGN_TIMEOUT = 360
PROBE_INTERVAL = 0.5
PROBE_TIMEOUT = 2.0
PROBE_WORKERS = 8
TOTAL_TIMEOUT = 900
MAX_FRAME = 4 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def safe_error(error):
    # Never copy siteCreate output or command payloads into evidence.
    text = f'{type(error).__name__}: {error}'
    if re.search(r'private.?key|secret|mnemonic|master.?seed|authorization|password|token', text, re.I):
        return f'{type(error).__name__}: sensitive diagnostic redacted'
    return text[:1000]


class LocalWebSocket:
    """Small bounded RFC6455 client for localhost text/continuation/control frames."""
    def __init__(self, port, address, deadline):
        require(re.fullmatch(r'epix1[a-z0-9]+', address), 'invalid fixture address')
        self.deadline = deadline
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.settimeout(self.left())
            self.sock.connect(('127.0.0.1', port))
            key = base64.b64encode(os.urandom(16)).decode()
            host = f'127.0.0.1:{port}'
            request = (f'GET /EpixNet-Internal/Websocket?wrapper_key={address} HTTP/1.1\r\n'
                       f'Host: {host}\r\nOrigin: http://{host}\r\nUpgrade: websocket\r\n'
                       f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n'
                       'Sec-WebSocket-Version: 13\r\n\r\n').encode()
            self.send_bytes(request)
            header = bytearray()
            while not header.endswith(b'\r\n\r\n'):
                require(len(header) < 16384, 'WebSocket HTTP header too large')
                header.extend(self.read_exact(1))
            lines = header.decode('latin1').split('\r\n')
            require(lines[0].split()[1] == '101', 'WebSocket upgrade rejected')
            headers = {name.lower(): value.strip() for name, value in
                       (line.split(':', 1) for line in lines[1:] if ':' in line)}
            expected = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            require(headers.get('sec-websocket-accept', '').strip() == expected, 'invalid WebSocket accept')
        except BaseException:
            self.close()
            raise

    def left(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError('absolute WebSocket request deadline exceeded')
        return left

    def send_bytes(self, data):
        view = memoryview(data)
        while view:
            self.sock.settimeout(self.left())
            count = self.sock.send(view)
            require(count > 0, 'WebSocket send closed')
            view = view[count:]

    def read_exact(self, count):
        data = bytearray()
        while len(data) < count:
            self.sock.settimeout(self.left())
            chunk = self.sock.recv(count - len(data))
            require(bool(chunk), 'WebSocket closed before response')
            data.extend(chunk)
        return bytes(data)

    def send_frame(self, opcode, payload):
        require(len(payload) <= MAX_FRAME, 'outgoing frame exceeds 4 MiB')
        size = len(payload)
        prefix = bytes([0x80 | opcode])
        if size < 126:
            prefix += bytes([0x80 | size])
        elif size < 65536:
            prefix += bytes([0x80 | 126]) + struct.pack('!H', size)
        else:
            prefix += bytes([0x80 | 127]) + struct.pack('!Q', size)
        mask = os.urandom(4)
        self.send_bytes(prefix + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(payload)))

    def recv_text(self):
        chunks = bytearray()
        fragmented = False
        while True:
            first, second = self.read_exact(2)
            require(first & 0x70 == 0 and second & 0x80 == 0, 'unexpected WebSocket extension/masking')
            final, opcode, size = bool(first & 0x80), first & 15, second & 127
            if size == 126:
                size = struct.unpack('!H', self.read_exact(2))[0]
            elif size == 127:
                size = struct.unpack('!Q', self.read_exact(8))[0]
            require(size <= MAX_FRAME and len(chunks) + size <= MAX_FRAME, 'incoming message exceeds 4 MiB')
            if opcode >= 8:
                require(final and size <= 125, 'invalid control frame')
            payload = self.read_exact(size)
            if opcode == 8:
                raise ConnectionError('WebSocket closed before matching response')
            if opcode == 9:
                self.send_frame(10, payload)
                continue
            if opcode == 10:
                continue
            require((opcode == 1 and not fragmented) or (opcode == 0 and fragmented), 'unexpected frame sequence')
            chunks.extend(payload)
            if final:
                return chunks.decode('utf-8')
            fragmented = True

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def command(port, address, name, params=None, timeout=2):
    # Includes connect, HTTP upgrade, send, pushed events and matching reply.
    ws = LocalWebSocket(port, address, time.monotonic() + timeout)
    try:
        request_id = 1000001  # Same namespace used by the trusted local wrapper.
        ws.send_frame(1, json.dumps({'cmd': name, 'id': request_id, 'params': params or {}}).encode())
        events = 0
        while True:
            reply = json.loads(ws.recv_text())
            if reply.get('cmd') == 'response' and reply.get('to') == request_id:
                ws.left()
                value = reply.get('result')
                error = reply.get('error') or (value.get('error') if isinstance(value, dict) else None)
                if error:
                    raise RuntimeError(str(error))
                return value
            events += 1
            require(events <= 10000, 'too many pushed events before response')
    finally:
        ws.close()


class WindowsJob:
    """Kill-on-close job contains only fixture-owned executable processes."""
    def __init__(self):
        require(sys.platform == 'win32', 'native Windows runner required')
        SIZE_T = ctypes.c_size_t
        class Basic(ctypes.Structure):
            _fields_ = [('ProcessTime', ctypes.c_longlong), ('JobTime', ctypes.c_longlong),
                        ('Flags', wintypes.DWORD), ('MinWorkingSet', SIZE_T), ('MaxWorkingSet', SIZE_T),
                        ('ActiveProcesses', wintypes.DWORD), ('Affinity', SIZE_T),
                        ('Priority', wintypes.DWORD), ('Scheduling', wintypes.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in ('ReadOps', 'WriteOps', 'OtherOps', 'ReadBytes', 'WriteBytes', 'OtherBytes')]
        class Extended(ctypes.Structure):
            _fields_ = [('Basic', Basic), ('IO', IO), ('ProcessMemory', SIZE_T), ('JobMemory', SIZE_T),
                        ('PeakProcessMemory', SIZE_T), ('PeakJobMemory', SIZE_T)]
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        require(bool(self.handle), 'CreateJobObject failed')
        limits = Extended()
        limits.Basic.Flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.kernel.CloseHandle(self.handle)
            self.handle = None
            raise OSError(ctypes.get_last_error(), 'SetInformationJobObject failed')
        self.lock = threading.Lock()

    def launch(self, args, **kwargs):
        process = subprocess.Popen(args, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP, **kwargs)
        with self.lock:
            assigned = self.handle and self.kernel.AssignProcessToJobObject(self.handle, wintypes.HANDLE(int(process._handle)))
        if not assigned:
            process.kill()
            process.wait(timeout=10)
            raise RuntimeError('Cannot assign owned process to cleanup job')
        return process

    def close(self):
        with self.lock:
            if self.handle:
                self.kernel.CloseHandle(self.handle)
                self.handle = None


def status(port):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
    try:
        connection.request('GET', '/EpixNet-Internal/Status')
        response = connection.getresponse()
        require(response.status == 200, 'status HTTP failed')
        value = json.loads(response.read(1024 * 1024))
        require(value.get('serving') is True, 'node is not serving')
        # Offline is a persisted config value, not a field in this endpoint.
        require(all(value.get(key) is False for key in ('tor_enabled', 'i2p_enabled', 'mesh_enabled')), 'network subsystem enabled or missing')
        require(value.get('connections', {}).get('total') == 0, 'fixture has peer connections')
        return value
    finally:
        connection.close()


def create_xite(binary, job, env, root):
    child = job.launch([str(binary), 'siteCreate'], env=env, cwd=root,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, _ = child.communicate(timeout=40)
        require(child.returncode == 0, f'siteCreate failed with exit code {child.returncode}')
        match = re.search(r'Xite address:\s+(epix1[a-z0-9]+)', stdout)
        require(match is not None, 'siteCreate omitted its address')
        return match[1]
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)


def sanitize_log(source, target):
    if not source.exists():
        return
    with source.open('rb') as stream:
        stream.seek(max(0, source.stat().st_size - 2 * 1024 * 1024))
        lines = stream.read().decode('utf-8', errors='replace').splitlines()
    sensitive = re.compile(r'private.?key|secret|mnemonic|master.?seed|authorization|password|token|cookie', re.I)
    lines = ['[sensitive diagnostic line redacted]' if sensitive.search(line) else line for line in lines]
    target.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def manifest_coverage(path, expected):
    try:
        files = json.loads(path.read_text(encoding='utf-8')).get('files', {})
        valid = expected.issubset(files) and all(
            isinstance(files[name], dict) and files[name].get('size') == FILE_BYTES
            and re.fullmatch(r'[0-9a-f]{64}', files[name].get('b3', ''))
            for name in expected)
        return {'ok': bool(valid), 'asset_count': sum(name in files for name in expected)}
    except (OSError, ValueError, TypeError) as error:
        return {'ok': False, 'error': safe_error(error)}


def process_memory(process):
    class Counters(ctypes.Structure):
        _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize',
                'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage',
                'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage', 'PrivateUsage')]
    api = ctypes.WinDLL('psapi', use_last_error=True)
    api.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    api.GetProcessMemoryInfo.restype = wintypes.BOOL
    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    if not api.GetProcessMemoryInfo(wintypes.HANDLE(int(process._handle)), ctypes.byref(counters), counters.cb):
        return {'available': False, 'winerror': ctypes.get_last_error()}
    return {'available': True, 'working_set_bytes': counters.WorkingSetSize,
            'peak_working_set_bytes': counters.PeakWorkingSetSize, 'private_bytes': counters.PrivateUsage}


def run(args):
    require(sys.platform == 'win32', 'Run on native Windows; Linux syntax/self-tests are not Windows evidence')
    require(re.fullmatch(r'[0-9a-f]{40}', args.source_revision), 'source revision must be an exact 40-digit SHA')
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    result_file = output / 'result.json'
    require(not result_file.exists(), 'refusing to overwrite previous evidence')
    temp_parent = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    require(shutil.disk_usage(temp_parent).free >= 6 * 1024**3, 'need 6 GiB free before fixture')
    root = Path(tempfile.mkdtemp(prefix=f'epix-issue599-{args.case}-', dir=temp_parent))
    raw_log = root / 'node.raw.log'
    result = {'started_utc': utc(), 'case': args.case, 'source_revision': args.source_revision,
              'binary_sha256': sha256(binary), 'binary_bytes': binary.stat().st_size,
              'platform': platform.platform(), 'python': sys.version,
              'windows_version': list(sys.getwindowsversion()),
              'runner_image_os': os.getenv('ImageOS'), 'runner_image_version': os.getenv('ImageVersion'),
              'run_id': os.getenv('GITHUB_RUN_ID'), 'run_attempt': os.getenv('GITHUB_RUN_ATTEMPT'),
              'files': FILES, 'file_bytes': FILE_BYTES, 'payload_bytes': FILES * FILE_BYTES,
              'tokio_workers': 2, 'sign_deadline_seconds': SIGN_TIMEOUT,
              'probe_deadline_seconds': PROBE_TIMEOUT, 'probe_interval_seconds': PROBE_INTERVAL,
              'overall_deadline_seconds': TOTAL_TIMEOUT, 'passed': False,
              'scope': 'Synthetic native Windows server WebSocket API test; no visual spinner/checkmark test; not reporter Windows 10 or exact dataset.',
              'probes': [], 'memory_samples': [], 'host_free_bytes_before': shutil.disk_usage(temp_parent).free}
    job = None
    process = None
    log_handle = None
    sign_pool = None
    probe_pool = None
    timer = None
    started = time.monotonic()
    expired = threading.Event()

    def save():
        temporary = result_file.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        temporary.replace(result_file)

    def bound():
        require(not expired.is_set(), 'overall fixture deadline reached')
        require(shutil.disk_usage(temp_parent).free >= 3 * 1024**3, 'free disk fell below 3 GiB')
        if raw_log.exists():
            require(raw_log.stat().st_size <= 16 * 1024**2, 'raw server log exceeded 16 MiB')

    def timed(name, address, command_name, params, timeout):
        before = time.monotonic()
        try:
            reply = command(port, address, command_name, params, timeout)
            value = {'ok': reply == 'ok' if command_name != 'siteInfo' else isinstance(reply, dict) and reply.get('address') == address}
        except Exception as error:
            value = {'ok': False, 'error': safe_error(error), 'timed_out': isinstance(error, TimeoutError)}
        value['seconds'] = time.monotonic() - before
        result[name] = value
        # Only the main thread persists evidence after joining the sign worker.
        return value

    try:
        job = WindowsJob()
        def expire():
            expired.set()
            job.close()
        timer = threading.Timer(TOTAL_TIMEOUT, expire)
        timer.daemon = True
        timer.start()
        data = root / 'node'
        (data / 'private').mkdir(parents=True)
        config_path = data / 'private/config.json'
        config_path.write_text(json.dumps({'offline': True, 'xid_lc_enabled': False}), encoding='utf-8')
        env = {key: value for key, value in os.environ.items() if key.upper() in {
            'SYSTEMROOT', 'WINDIR', 'SYSTEMDRIVE', 'COMSPEC', 'PATHEXT', 'PATH',
            'PROCESSOR_ARCHITECTURE', 'NUMBER_OF_PROCESSORS', 'OS'}}
        for folder in ('home', 'appdata', 'localappdata', 'tmp'):
            (root / folder).mkdir()
        env.update(EPIX_DATA_DIR=str(data), EPIX_UI_ADDR='127.0.0.1:0', EPIX_TOR='disable',
                   EPIX_HEADLESS='1', TOKIO_WORKER_THREADS='2', HOME=str(root / 'home'),
                   USERPROFILE=str(root / 'home'), APPDATA=str(root / 'appdata'),
                   LOCALAPPDATA=str(root / 'localappdata'), TEMP=str(root / 'tmp'), TMP=str(root / 'tmp'))
        address = create_xite(binary, job, env, root)
        neighbor = create_xite(binary, job, env, root)
        result.update(address=address, neighbor=neighbor)
        xite = data / 'data' / address
        chunk = bytes(range(256)) * 400
        expected = set()
        for number in range(FILES):
            if number % 128 == 0:
                bound()
            relative = f'assets/{number // 128:02d}/{number:05d}.bin'
            path = xite / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(number.to_bytes(8, 'little') + chunk[8:])
            expected.add(relative)
        log_handle = raw_log.open('wb')
        process = job.launch([str(binary), address], env=env, cwd=root, stdout=log_handle, stderr=subprocess.STDOUT)
        result['owned_server_pid'] = process.pid
        ready_deadline = time.monotonic() + 90
        while time.monotonic() < ready_deadline:
            bound()
            require(process.poll() is None, f'server exited during startup: {process.returncode}')
            try:
                port = int((data / 'ui_port').read_text().strip())
                result['status_before'] = status(port)
                require(command(port, address, 'siteInfo').get('address') == address, 'large xite not ready')
                require(command(port, neighbor, 'siteInfo').get('address') == neighbor, 'neighbor not ready')
                break
            except (OSError, ValueError, RuntimeError, http.client.HTTPException):
                time.sleep(0.1)
        else:
            raise RuntimeError('server did not become ready within 90 seconds')
        result['startup_seconds'] = time.monotonic() - started
        result['offline_config_before'] = json.loads(config_path.read_text(encoding='utf-8')).get('offline') is True
        require(result['offline_config_before'], 'disposable offline config was not preserved')
        save()
        done = threading.Event()
        sign_started = threading.Event()
        sign_start = None
        def sign():
            nonlocal sign_start
            sign_start = time.monotonic()
            sign_started.set()
            try:
                return timed('large_sign', address, 'siteSign', {'privatekey': 'stored'}, SIGN_TIMEOUT)
            finally:
                done.set()
        def probe(sequence, scheduled):
            now = time.monotonic()
            sample = {'sequence': sequence, 'scheduled_seconds': scheduled - sign_start,
                      'at_seconds': now - sign_start, 'dispatch_lag_seconds': now - scheduled,
                      'started_while_signing': not done.is_set()}
            try:
                reply = command(port, neighbor, 'siteInfo', timeout=PROBE_TIMEOUT)
                sample['ok'] = isinstance(reply, dict) and reply.get('address') == neighbor
            except Exception as error:
                sample.update(ok=False, error=safe_error(error), timed_out=isinstance(error, TimeoutError))
            sample['seconds'] = time.monotonic() - now
            return sample
        sign_pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        probe_pool = concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_WORKERS)
        sign_future = sign_pool.submit(sign)
        require(sign_started.wait(timeout=2), 'sign worker did not start')
        futures = []
        sequence = 0
        next_probe = sign_start
        next_progress = sign_start + 5
        next_memory = sign_start
        while not done.is_set():
            bound()
            require(process.poll() is None, f'server exited while signing: {process.returncode}')
            now = time.monotonic()
            if now >= next_probe:
                if sum(not future.done() for future in futures) >= PROBE_WORKERS:
                    result['probes'].append({'sequence': sequence, 'ok': False, 'scheduler_saturated': True, 'started_while_signing': True})
                else:
                    futures.append(probe_pool.submit(probe, sequence, next_probe))
                sequence += 1
                next_probe = sign_start + sequence * PROBE_INTERVAL
            if now >= next_progress:
                print(json.dumps({'stage': 'signing', 'seconds': round(now - sign_start, 2), 'probes': sequence}), flush=True)
                next_progress = now + 5
            if now >= next_memory:
                result['memory_samples'].append({'at_seconds': now - sign_start, **process_memory(process)})
                next_memory = now + 1
            done.wait(min(0.02, max(0.0, next_probe - time.monotonic())))
        sign_future.result(timeout=2)
        result['probes'].extend(future.result(timeout=PROBE_TIMEOUT + 1) for future in futures)
        result['probes'].sort(key=lambda sample: sample['sequence'])
        active = [sample for sample in result['probes'] if sample['started_while_signing']]
        result['active_probe_count'] = len(active)
        result['neighbor_failure_count'] = sum(not sample.get('ok') for sample in active)
        result['neighbor_timeout_count'] = sum(bool(sample.get('timed_out')) for sample in active)
        result['max_probe_seconds'] = max((sample.get('seconds', 0) for sample in active), default=None)
        result['max_dispatch_lag_seconds'] = max((sample.get('dispatch_lag_seconds', 0) for sample in active), default=None)
        result['sign_exceeded_reported_five_minutes'] = result['large_sign']['seconds'] > 300
        result['initial_manifest_coverage'] = manifest_coverage(xite / 'content.json', expected)
        result['sign_request_timed_out'] = bool(result['large_sign'].get('timed_out'))
        result['timeout_interpretation'] = 'A client timeout does not cancel the server operation; recovery failures can overlap unfinished signing and do not alone prove a permanent crash.'
        save()
        # Always try recovery before assertions, even after sign/probe failure.
        for label, target, limit in [('neighbor', neighbor, 30), ('large', address, 150)]:
            bound()
            content_path = data / 'data' / target / 'content.json'
            content = json.loads(content_path.read_text(encoding='utf-8'))
            title = f'{label} title after large signing'
            description = f'{label} description after large signing'
            content.update(title=title, description=description)
            encoded = base64.b64encode(json.dumps(content).encode()).decode()
            timed(label + '_edit', target, 'fileWrite', {'inner_path': 'content.json', 'content_base64': encoded}, 10)
            timed(label + '_resign', target, 'siteSign', {'privatekey': 'stored'}, limit)
            timed(label + '_info_after', target, 'siteInfo', {}, 2)
            persisted = json.loads(content_path.read_text(encoding='utf-8'))
            result[label + '_title_description_persisted'] = persisted.get('title') == title and persisted.get('description') == description
            save()
        result['final_manifest_coverage'] = manifest_coverage(xite / 'content.json', expected)
        result['status_after'] = status(port)
        result['offline_config_after'] = json.loads(config_path.read_text(encoding='utf-8')).get('offline') is True
        result['server_alive_after'] = process.poll() is None
        failures = []
        if not result['large_sign']['ok'] or result['sign_exceeded_reported_five_minutes']:
            failures.append('large sign failed or exceeded reported five-minute window')
        if len(active) < 2 or result['max_dispatch_lag_seconds'] is None or result['max_dispatch_lag_seconds'] >= PROBE_TIMEOUT:
            failures.append('insufficient independent probe coverage; timing comparison inconclusive')
        if result['neighbor_failure_count']:
            failures.append('neighbor request responsiveness failed during signing')
        for label in ('neighbor', 'large'):
            if not all(result[label + suffix]['ok'] for suffix in ('_edit', '_resign', '_info_after')) or not result[label + '_title_description_persisted']:
                failures.append(label + ' edit/sign recovery failed')
        if not result['initial_manifest_coverage']['ok'] or not result['final_manifest_coverage']['ok'] or not result['server_alive_after']:
            failures.append('manifest coverage or final process health failed')
        if not result['offline_config_after']:
            failures.append('offline configuration was changed')
        result['failures'] = failures
        result['passed'] = not failures
    except BaseException as error:
        result['error'] = safe_error(error)
    finally:
        if timer:
            timer.cancel()
        if job:
            job.close()
        if process:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                    process.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired) as error:
                    result['process_cleanup_error'] = safe_error(error)
        for pool in (sign_pool, probe_pool):
            if pool:
                pool.shutdown(wait=True, cancel_futures=True)
        if log_handle:
            log_handle.close()
        try:
            sanitize_log(raw_log, output / 'server-tail.log')
        except OSError as error:
            result['log_capture_error'] = safe_error(error)
        result['owned_server_stopped'] = process is None or process.poll() is not None
        result['overall_deadline_reached'] = expired.is_set()
        cleanup_error = None
        for attempt in range(5):
            try:
                shutil.rmtree(root)
                cleanup_error = None
                break
            except OSError as error:
                cleanup_error = safe_error(error)
                time.sleep(2)
        result['temporary_data_removed'] = not root.exists()
        if cleanup_error:
            result['cleanup_error'] = cleanup_error
        result['passed'] = bool(result['passed'] and result['owned_server_stopped'] and result['temporary_data_removed'] and not expired.is_set())
        result['host_free_bytes_after'] = shutil.disk_usage(temp_parent).free
        result['total_seconds'] = time.monotonic() - started
        result['finished_utc'] = utc()
        save()
        print(json.dumps({key: value for key, value in result.items() if key != 'probes'}, indent=2), flush=True)
    return 0 if result['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--case', choices=['baseline', 'fixed'], required=True)
    return run(parser.parse_args())


if __name__ == '__main__':
    sys.exit(main())
