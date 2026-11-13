"""Список точек Wi-Fi вокруг (Native Wifi API), запасной путь — netsh.

С Windows 11 24H2 эти вызовы требуют разрешения на определение местоположения: без него
WlanGetNetworkBssList отвечает ERROR_ACCESS_DENIED. Тогда функция возвращает None, и агент
просит сканировать помощника в сеансе пользователя.
"""
from __future__ import annotations

import ctypes
import subprocess
import time
from ctypes import POINTER, Structure, byref, c_ubyte, c_uint, c_ulonglong, c_void_p, wintypes

from ..core.wifi import parse_netsh

ERROR_ACCESS_DENIED = 5


class GUID(Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", c_ubyte * 8)]


class WLAN_INTERFACE_INFO(Structure):
    _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", wintypes.WCHAR * 256),
                ("isState", c_uint)]


class WLAN_INTERFACE_INFO_LIST(Structure):
    _fields_ = [("dwNumberOfItems", wintypes.DWORD), ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


class DOT11_SSID(Structure):
    _fields_ = [("uSSIDLength", wintypes.ULONG), ("ucSSID", c_ubyte * 32)]


class WLAN_RATE_SET(Structure):
    _fields_ = [("uRateSetLength", wintypes.ULONG), ("usRateSet", wintypes.USHORT * 126)]


class WLAN_BSS_ENTRY(Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID), ("uPhyId", wintypes.ULONG), ("dot11Bssid", c_ubyte * 6),
        ("dot11BssType", c_uint), ("dot11BssPhyType", c_uint), ("lRssi", wintypes.LONG),
        ("uLinkQuality", wintypes.ULONG), ("bInRegDomain", wintypes.BOOLEAN),
        ("usBeaconPeriod", wintypes.USHORT), ("ullTimestamp", c_ulonglong),
        ("ullHostTimestamp", c_ulonglong), ("usCapabilityInformation", wintypes.USHORT),
        ("ulChCenterFrequency", wintypes.ULONG), ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", wintypes.ULONG), ("ulIeSize", wintypes.ULONG),
    ]


class WLAN_BSS_LIST(Structure):
    _fields_ = [("dwTotalSize", wintypes.DWORD), ("dwNumberOfItems", wintypes.DWORD),
                ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]


def _api():
    w = ctypes.WinDLL("wlanapi.dll")
    w.WlanOpenHandle.argtypes = [wintypes.DWORD, c_void_p, POINTER(wintypes.DWORD),
                                 POINTER(wintypes.HANDLE)]
    w.WlanEnumInterfaces.argtypes = [wintypes.HANDLE, c_void_p,
                                     POINTER(POINTER(WLAN_INTERFACE_INFO_LIST))]
    w.WlanScan.argtypes = [wintypes.HANDLE, POINTER(GUID), c_void_p, c_void_p, c_void_p]
    w.WlanGetNetworkBssList.argtypes = [wintypes.HANDLE, POINTER(GUID), c_void_p, c_uint,
                                        wintypes.BOOL, c_void_p, POINTER(POINTER(WLAN_BSS_LIST))]
    w.WlanFreeMemory.argtypes = [c_void_p]
    w.WlanCloseHandle.argtypes = [wintypes.HANDLE, c_void_p]
    return w


def scan_native(wait: float = 4.0) -> list[dict] | None:
    w = _api()
    h = wintypes.HANDLE()
    neg = wintypes.DWORD()
    if w.WlanOpenHandle(2, None, byref(neg), byref(h)) != 0:
        return []                                  # нет службы WLAN / адаптера
    try:
        ifs = POINTER(WLAN_INTERFACE_INFO_LIST)()
        if w.WlanEnumInterfaces(h, None, byref(ifs)) != 0:
            return []
        try:
            n = ifs.contents.dwNumberOfItems
            base = ctypes.addressof(ifs.contents) + WLAN_INTERFACE_INFO_LIST.InterfaceInfo.offset
            guids = [GUID.from_buffer_copy(WLAN_INTERFACE_INFO.from_address(
                base + i * ctypes.sizeof(WLAN_INTERFACE_INFO)).InterfaceGuid) for i in range(n)]
        finally:
            w.WlanFreeMemory(ifs)
        if not guids:
            return []
        denied = False
        for g in guids:
            rc = w.WlanScan(h, byref(g), None, None, None)
            denied = denied or rc == ERROR_ACCESS_DENIED
        if wait:
            time.sleep(wait)
        aps: dict[str, int] = {}
        for g in guids:
            lst = POINTER(WLAN_BSS_LIST)()
            rc = w.WlanGetNetworkBssList(h, byref(g), None, 3, False, None, byref(lst))
            if rc == ERROR_ACCESS_DENIED:
                denied = True
                continue
            if rc != 0:
                continue
            try:
                cnt = lst.contents.dwNumberOfItems
                base = ctypes.addressof(lst.contents) + WLAN_BSS_LIST.wlanBssEntries.offset
                for i in range(cnt):
                    e = WLAN_BSS_ENTRY.from_address(base + i * ctypes.sizeof(WLAN_BSS_ENTRY))
                    mac = ":".join(f"{b:02x}" for b in bytes(e.dot11Bssid))
                    rssi = int(e.lRssi)
                    if mac not in aps or rssi > aps[mac]:
                        aps[mac] = rssi
            finally:
                w.WlanFreeMemory(lst)
        if not aps and denied:
            return None
        return [{"bssid": k, "rssi": v} for k, v in aps.items()]
    finally:
        w.WlanCloseHandle(h, None)


def scan_netsh() -> list[dict] | None:
    try:
        out = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                             capture_output=True, timeout=20,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        return []
    for enc in ("cp866", "utf-8", "cp1251"):
        try:
            text = out.stdout.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = out.stdout.decode(errors="replace")
    aps = parse_netsh(text)
    if not aps and out.returncode != 0:
        return None                                # «нужно разрешение на местоположение»
    return aps


def scan() -> list[dict] | None:
    try:
        r = scan_native()
    except OSError:
        r = []
    if r:
        return r
    n = scan_netsh()
    if n:
        return n
    return None if (r is None or n is None) else []
