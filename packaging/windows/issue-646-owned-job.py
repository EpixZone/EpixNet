import ctypes
from ctypes import wintypes
import subprocess
import sys
import threading

def require(condition,message):
    if not condition: raise RuntimeError(message)

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
        self.kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        require(bool(self.handle), 'CreateJobObject failed')
        limits = Extended()
        self.kernel.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel.GetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.POINTER(SIZE_T), ctypes.POINTER(SIZE_T)]
        process_mask, system_mask = SIZE_T(), SIZE_T()
        require(self.kernel.GetProcessAffinityMask(self.kernel.GetCurrentProcess(), ctypes.byref(process_mask), ctypes.byref(system_mask)), 'Cannot obtain owned process affinity')
        cpus = [1 << bit for bit in range(ctypes.sizeof(SIZE_T) * 8) if process_mask.value & (1 << bit)][:2]
        require(bool(cpus), 'No available processors')
        limits.Basic.Flags = 0x2000 | 0x10 | 0x200  # Kill on close, affinity, total job memory.
        limits.Basic.Affinity = sum(cpus)
        limits.JobMemory = 3 * 1024 ** 3
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

    def process_ids(self):
        """Read actual membership, including detached relaunch descendants."""
        with self.lock:
            require(bool(self.handle), 'Job already closed')
            slots = 256
            while slots <= 8192:
                buffer = ctypes.create_string_buffer(8 + ctypes.sizeof(ctypes.c_size_t) * slots)
                if self.kernel.QueryInformationJobObject(self.handle, 3, buffer, len(buffer), None):
                    count = ctypes.c_uint32.from_buffer(buffer, 4).value
                    require(count <= slots, 'Invalid Job process list')
                    return list((ctypes.c_size_t * count).from_buffer(buffer, 8))
                if ctypes.get_last_error() != 234:
                    raise OSError(ctypes.get_last_error(), 'QueryInformationJobObject failed')
                slots *= 2
            raise RuntimeError('Owned Job process count exceeds bound')

    def adopt_verified_pid(self, pid):
        """Caller must first verify this PID is its exact fixture executable."""
        process = self.kernel.OpenProcess(0x0100 | 0x0001, False, pid)
        require(bool(process), 'Cannot open verified process for Job ownership')
        try:
            with self.lock:
                if not self.handle or not self.kernel.AssignProcessToJobObject(self.handle, process):
                    raise OSError(ctypes.get_last_error(), 'Cannot adopt verified process')
        finally:
            self.kernel.CloseHandle(process)
