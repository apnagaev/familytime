"""Канал между службой (SYSTEM) и помощником в сеансе пользователя.

Помощник каждые 2 с присылает отчёт (активное окно, простой, окна), служба отвечает указаниями.
Принимаются отчёты только от familytime-helper.exe из папки установки: проверяется путь процесса
на другом конце канала и его сеанс.
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import threading
import time
from ctypes import wintypes

import psutil
import pywintypes
import win32file
import win32pipe
import win32security
import winerror

from .. import PIPE_NAME

log = logging.getLogger("familytime.pipe")

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
_k32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
_k32.GetNamedPipeClientSessionId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]

# SYSTEM — всё, вошедшие пользователи — чтение и запись
SDDL = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"
BUF = 256 * 1024


def pid_session(pid: int) -> int | None:
    s = wintypes.DWORD()
    if _k32.ProcessIdToSessionId(pid, ctypes.byref(s)):
        return int(s.value)
    return None


class PipeServer:
    def __init__(self, helper_path: str):
        self.helper_path = os.path.normcase(os.path.abspath(helper_path))
        self.reports: dict[int, tuple[float, dict]] = {}
        self.directives: dict[int, dict] = {}
        self.lock = threading.Lock()
        self.stopping = False

    def start(self) -> None:
        threading.Thread(target=self._accept_loop, name="pipe-accept", daemon=True).start()

    def report(self, session_id: int, max_age: float = 15) -> dict | None:
        with self.lock:
            v = self.reports.get(session_id)
        if v and time.monotonic() - v[0] <= max_age:
            return v[1]
        return None

    def set_directive(self, session_id: int, d: dict) -> None:
        with self.lock:
            self.directives[session_id] = d

    def _accept_loop(self) -> None:
        sa = win32security.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            SDDL, win32security.SDDL_REVISION_1)
        while not self.stopping:
            try:
                h = win32pipe.CreateNamedPipe(
                    PIPE_NAME, win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT
                    | 0x00000008,                   # PIPE_REJECT_REMOTE_CLIENTS
                    win32pipe.PIPE_UNLIMITED_INSTANCES, BUF, BUF, 0, sa)
            except pywintypes.error as e:
                log.error("CreateNamedPipe: %s", e)
                time.sleep(5)
                continue
            try:
                win32pipe.ConnectNamedPipe(h, None)
            except pywintypes.error as e:
                if e.winerror != winerror.ERROR_PIPE_CONNECTED:
                    h.Close()
                    continue
            threading.Thread(target=self._serve, args=(h,), name="pipe-client", daemon=True).start()

    def _client_ok(self, h) -> int | None:
        pid = wintypes.ULONG()
        if not _k32.GetNamedPipeClientProcessId(int(h), ctypes.byref(pid)):
            return None
        try:
            exe = os.path.normcase(os.path.abspath(psutil.Process(pid.value).exe()))
        except (psutil.Error, OSError):
            return None
        if exe != self.helper_path:
            log.warning("канал: чужой процесс %s (%s) — отклонён", exe, pid.value)
            return None
        sid = wintypes.ULONG()
        if not _k32.GetNamedPipeClientSessionId(int(h), ctypes.byref(sid)):
            return pid_session(pid.value)
        return int(sid.value)

    def _serve(self, h) -> None:
        sid = self._client_ok(h)
        try:
            if sid is None:
                return
            while not self.stopping:
                data = b""
                while True:
                    hr, chunk = win32file.ReadFile(h, BUF)
                    data += chunk
                    if hr != winerror.ERROR_MORE_DATA:
                        break
                try:
                    rep = json.loads(data.decode("utf-8"))
                except ValueError:
                    continue
                with self.lock:
                    self.reports[sid] = (time.monotonic(), rep)
                    d = self.directives.get(sid, {})
                win32file.WriteFile(h, json.dumps(d, ensure_ascii=False).encode("utf-8"))
        except pywintypes.error:
            pass
        finally:
            try:
                win32pipe.DisconnectNamedPipe(h)
            except pywintypes.error:
                pass
            h.Close()
