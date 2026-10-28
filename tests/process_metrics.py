"""Run a validation child and retain elapsed time and Windows kernel peak memory.

The counters describe that child only, not descendants or total system memory.
Unsupported hosts retain elapsed time and an explicit unavailable memory result.
"""
import ctypes
import os
import subprocess
import time


def run_measured(command, log, **kwargs):
    started = time.monotonic()
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, **kwargs)
    query = counters = None
    if os.name == 'nt':
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize',
                'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage',
                'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage')]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        query = ctypes.WinDLL('psapi', use_last_error=True).GetProcessMemoryInfo
        query.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        query.restype = wintypes.BOOL
    peaks = None
    while True:
        # Query before wait closes or destroys the process handle. Kernel peak
        # counters retain short-lived spikes between these samples.
        if query and query(int(process._handle), ctypes.byref(counters), counters.cb):
            peaks = {'peak_working_set_bytes': int(counters.PeakWorkingSetSize),
                     'peak_pagefile_usage_bytes': int(counters.PeakPagefileUsage)}
        try:
            code = process.wait(timeout=0.2)
            if query and query(int(process._handle), ctypes.byref(counters), counters.cb):
                peaks = {'peak_working_set_bytes': int(counters.PeakWorkingSetSize),
                         'peak_pagefile_usage_bytes': int(counters.PeakPagefileUsage)}
            break
        except subprocess.TimeoutExpired:
            pass
    return {'exit_code': code, 'elapsed_seconds': time.monotonic() - started,
            'memory_scope': 'direct_child_windows_kernel_peak' if peaks else 'unavailable',
            **(peaks or {})}
