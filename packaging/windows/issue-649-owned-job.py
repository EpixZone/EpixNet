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
