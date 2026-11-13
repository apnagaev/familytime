"""Понятное название программы: «Ножницы» вместо snippingtool.exe.

1. Приложение из пакета (Microsoft Store, в том числе «Ножницы», «Калькулятор») — название из
   меню «Пуск»: AUMID процесса → shell:AppsFolder\\<AUMID>.
2. Обычная программа — «Описание файла» из свойств exe (на русской Windows часто по-русски).
3. Иначе — пусто, на портале останется имя exe.
Результат кешируется по пути к exe.
"""
from __future__ import annotations

import ctypes
import logging
from ctypes import wintypes

import psutil

log = logging.getLogger("familytime.appname")

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.OpenProcess.restype = wintypes.HANDLE
_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
APPMODEL_ERROR_NO_APPLICATION = 15703

_cache: dict[str, str] = {}


def _aumid(pid: int) -> str:
    try:
        fn = _k32.GetApplicationUserModelId
    except AttributeError:
        return ""
    fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_uint32), wintypes.LPWSTR]
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        size = ctypes.c_uint32(512)
        buf = ctypes.create_unicode_buffer(size.value)
        if fn(h, ctypes.byref(size), buf) != 0:          # 15703 — процесс не из пакета
            return ""
        return buf.value
    finally:
        _k32.CloseHandle(h)


def _apps_folder_name(aumid: str) -> str:
    try:
        from win32com.shell import shell, shellcon
        item = shell.SHCreateItemFromParsingName("shell:AppsFolder\\" + aumid, None,
                                                 shell.IID_IShellItem)
        return item.GetDisplayName(shellcon.SIGDN_NORMALDISPLAY) or ""
    except Exception:  # noqa: BLE001
        return ""


def _file_description(path: str) -> str:
    try:
        import win32api
        langs = win32api.GetFileVersionInfo(path, "\\VarFileInfo\\Translation") or []
        langs = sorted(langs, key=lambda lc: (lc[0] != 0x0419, lc[0] != 0x0409))  # ru, en, прочие
        for lang, cp in langs:
            v = win32api.GetFileVersionInfo(path, f"\\StringFileInfo\\{lang:04x}{cp:04x}\\FileDescription")
            if v and v.strip():
                return v.strip()
    except Exception:  # noqa: BLE001
        pass
    return ""


def app_name(pid: int) -> str:
    try:
        path = psutil.Process(pid).exe()
    except (psutil.Error, OSError):
        return ""
    key = path.lower()
    if key in _cache:
        return _cache[key]
    name = ""
    aumid = _aumid(pid)
    if aumid:
        name = _apps_folder_name(aumid)
    if not name:
        name = _file_description(path)
    name = " ".join(name.split())[:80]
    if name.lower() == path.rsplit("\\", 1)[-1].lower():
        name = ""
    _cache[key] = name
    if name:
        log.info("название программы: %s → %s", path.rsplit("\\", 1)[-1], name)
    return name
