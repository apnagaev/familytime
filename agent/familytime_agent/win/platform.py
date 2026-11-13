"""Всё, что агент делает с Windows: сеансы, помощник, процессы, политики браузеров, питание."""
from __future__ import annotations

import ctypes
import logging
import os
import socket
import winreg
from ctypes import wintypes

import psutil
import pywintypes
import win32con
import win32process
import win32profile
import win32security
import win32ts

from ..core.engine import Session
from . import wlan
from .pipe import PipeServer, pid_session

log = logging.getLogger("familytime.win")

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_wts = ctypes.WinDLL("wtsapi32", use_last_error=True)

WTSSessionInfoEx = 25
WTS_SESSIONSTATE_UNLOCK = 1
WTSActive = 0

# процессы, которые агент не трогает ни при каких списках
PROTECTED = {"csrss.exe", "winlogon.exe", "lsass.exe", "services.exe", "svchost.exe", "dwm.exe",
             "smss.exe", "wininit.exe", "fontdrvhost.exe", "familytime-agent.exe",
             "familytime-helper.exe", "system", "registry"}

BROWSER_KEYS = {
    # ключ политик: (имена значений блок-/разрешённых списков, режим инкогнито)
    r"Software\Policies\Google\Chrome": (("URLBlocklist", "URLAllowlist"),
                                         ("IncognitoModeAvailability", 1)),
    r"Software\Policies\Microsoft\Edge": (("URLBlocklist", "URLAllowlist"),
                                          ("InPrivateModeAvailability", 1)),
    r"Software\Policies\YandexBrowser": (("URLBlocklist", "URLAllowlist", "URLBlacklist", "URLWhitelist"),
                                         ("IncognitoModeAvailability", 1)),
}


class WTSINFOEX_LEVEL1_W(ctypes.Structure):
    _fields_ = [
        ("SessionId", wintypes.ULONG), ("SessionState", ctypes.c_int), ("SessionFlags", wintypes.LONG),
        ("WinStationName", wintypes.WCHAR * 33), ("UserName", wintypes.WCHAR * 21),
        ("DomainName", wintypes.WCHAR * 18), ("LogonTime", ctypes.c_longlong),
        ("ConnectTime", ctypes.c_longlong), ("DisconnectTime", ctypes.c_longlong),
        ("LastInputTime", ctypes.c_longlong), ("CurrentTime", ctypes.c_longlong),
        ("IncomingBytes", wintypes.DWORD), ("OutgoingBytes", wintypes.DWORD),
        ("IncomingFrames", wintypes.DWORD), ("OutgoingFrames", wintypes.DWORD),
        ("IncomingCompressedBytes", wintypes.DWORD), ("OutgoingCompressedBytes", wintypes.DWORD),
    ]


class WTSINFOEX_W(ctypes.Structure):
    _fields_ = [("Level", wintypes.DWORD), ("Data", WTSINFOEX_LEVEL1_W)]


_wts.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
                                             ctypes.POINTER(ctypes.c_void_p),
                                             ctypes.POINTER(wintypes.DWORD)]
_wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
_k32.GetComputerNameExW.argtypes = [ctypes.c_int, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]


class SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [("ACLineStatus", ctypes.c_ubyte), ("BatteryFlag", ctypes.c_ubyte),
                ("BatteryLifePercent", ctypes.c_ubyte), ("SystemStatusFlag", ctypes.c_ubyte),
                ("BatteryLifeTime", wintypes.DWORD), ("BatteryFullLifeTime", wintypes.DWORD)]


def session_info_ex(sid: int) -> WTSINFOEX_LEVEL1_W | None:
    buf = ctypes.c_void_p()
    size = wintypes.DWORD()
    if not _wts.WTSQuerySessionInformationW(None, sid, WTSSessionInfoEx, ctypes.byref(buf),
                                            ctypes.byref(size)):
        return None
    try:
        info = WTSINFOEX_W.from_address(buf.value)
        return WTSINFOEX_LEVEL1_W.from_buffer_copy(info.Data)
    finally:
        _wts.WTSFreeMemory(buf)


class WinPlatform:
    def __init__(self, install_dir: str):
        self.install_dir = install_dir
        self.helper = os.path.join(install_dir, "familytime-helper.exe")
        self.pipe = PipeServer(self.helper)
        self.pipe.start()
        self._sid_cache: dict[str, str] = {}

    # ---------- сведения ----------

    def hostname(self) -> str:
        buf = ctypes.create_unicode_buffer(256)
        size = wintypes.DWORD(256)
        if _k32.GetComputerNameExW(3, buf, ctypes.byref(size)):   # ComputerNameDnsFullyQualified
            return buf.value.lower()
        return socket.getfqdn().lower()

    def os_version(self) -> str:
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            name = winreg.QueryValueEx(k, "ProductName")[0]
            build = int(winreg.QueryValueEx(k, "CurrentBuild")[0])
            try:
                disp = winreg.QueryValueEx(k, "DisplayVersion")[0]
            except OSError:
                disp = ""
            if build >= 22000:
                name = name.replace("Windows 10", "Windows 11")
            return f"{name} {disp} ({build})".replace("  ", " ")
        except OSError:
            return "Windows"

    def local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.1", 9))          # пакет не отправляется, только выбор маршрута
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return ""

    def battery(self):
        st = SYSTEM_POWER_STATUS()
        if not _k32.GetSystemPowerStatus(ctypes.byref(st)):
            return None, None
        pct = None if st.BatteryLifePercent == 255 or st.BatteryFlag & 128 else int(st.BatteryLifePercent)
        ac = None if st.ACLineStatus == 255 else bool(st.ACLineStatus)
        return pct, ac

    def wifi_scan(self):
        return wlan.scan()

    # ---------- сеансы ----------

    def console_session(self) -> Session | None:
        sid = win32ts.WTSGetActiveConsoleSessionId()
        if sid == 0xFFFFFFFF:
            return None
        try:
            user = win32ts.WTSQuerySessionInformation(win32ts.WTS_CURRENT_SERVER_HANDLE, sid,
                                                      win32ts.WTSUserName)
            domain = win32ts.WTSQuerySessionInformation(win32ts.WTS_CURRENT_SERVER_HANDLE, sid,
                                                        win32ts.WTSDomainName)
        except pywintypes.error:
            return None
        if not user:
            return None
        info = session_info_ex(sid)
        locked = True
        if info is not None:
            locked = not (info.SessionState == WTSActive and info.SessionFlags == WTS_SESSIONSTATE_UNLOCK)
        return Session(int(sid), user.lower(), domain or "", locked)

    def helper_report(self, sid: int):
        return self.pipe.report(sid)

    def set_directive(self, sid: int, d: dict) -> None:
        self.pipe.set_directive(sid, d)

    def launch_helper(self, sid: int) -> None:
        # помощник есть, но молчит (завис или приостановлен) — перезапускаем
        for p in psutil.process_iter(["name"]):
            try:
                if (p.info["name"] or "").lower() == "familytime-helper.exe" and pid_session(p.pid) == sid:
                    log.warning("помощник в сеансе %s не отвечает — перезапуск", sid)
                    p.kill()
            except psutil.Error:
                continue
        token = win32ts.WTSQueryUserToken(sid)
        try:
            env = win32profile.CreateEnvironmentBlock(token, False)
            si = win32process.STARTUPINFO()
            si.lpDesktop = "winsta0\\default"
            hp, ht, pid, _ = win32process.CreateProcessAsUser(
                token, self.helper, f'"{self.helper}"', None, None, False,
                win32con.CREATE_UNICODE_ENVIRONMENT | win32con.NORMAL_PRIORITY_CLASS,
                env, self.install_dir, si)
            hp.Close()
            ht.Close()
            log.info("помощник запущен в сеансе %s (pid %s)", sid, pid)
        finally:
            token.Close()

    def logoff(self, sid: int) -> None:
        try:
            win32ts.WTSLogoffSession(win32ts.WTS_CURRENT_SERVER_HANDLE, sid, False)
        except pywintypes.error as e:
            log.warning("не удалось завершить сеанс %s: %s", sid, e)

    # ---------- процессы ----------

    def session_processes(self, sid: int):
        out = []
        for p in psutil.process_iter(["name"]):
            name = (p.info["name"] or "").lower()
            if name and name not in PROTECTED and pid_session(p.pid) == sid:
                out.append((p.pid, name))
        return out

    def kill(self, pid: int) -> None:
        try:
            p = psutil.Process(pid)
            if p.name().lower() in PROTECTED:
                return
            p.kill()
        except psutil.Error:
            pass

    # ---------- политики браузеров в разделе реестра пользователя ----------

    def _user_sid(self, user: str, domain: str) -> str | None:
        key = f"{domain}\\{user}".lower()
        if key in self._sid_cache:
            return self._sid_cache[key]
        try:
            sid, _, _ = win32security.LookupAccountName(None, f"{domain}\\{user}" if domain else user)
            s = win32security.ConvertSidToStringSid(sid)
        except pywintypes.error:
            return None
        self._sid_cache[key] = s
        return s

    def clear_browser_policy(self, sid: int, user: str, domain: str) -> None:
        """Убирает всё, что агент пишет в политики браузеров пользователя."""
        usid = self._user_sid(user, domain) if domain else next(
            (v for k, v in self._sid_cache.items() if k.endswith("\\" + user)), None)
        if not usid:
            return
        try:
            hive = winreg.OpenKey(winreg.HKEY_USERS, usid)
        except OSError:
            return
        with hive:
            if _clear(hive):
                log.info("%s: политики браузеров сняты", user)

    def set_browser_policy(self, sid: int, user: str, domain: str, allowed: list[str] | None,
                           blocked: list[str] | None = None) -> None:
        """Политики Chrome/Edge/Яндекса в разделе реестра пользователя.

        allowed = None — обычный режим: URLBlocklist = запрещённые сайты (если есть).
        allowed = [...] — «только учёба»: URLBlocklist = "*", URLAllowlist = allowed.
        """
        blocked = blocked or []
        usid = self._user_sid(user, domain) if domain else next(
            (v for k, v in self._sid_cache.items() if k.endswith("\\" + user)), None)
        if not usid:
            return
        try:
            hive = winreg.OpenKey(winreg.HKEY_USERS, usid)     # раздел загружен, пока пользователь вошёл
        except OSError:
            return
        if allowed is not None:
            block_list, allow_list = ["*"], allowed
        else:
            block_list, allow_list = blocked, []
        with hive:
            for path, (lists, (incog_name, incog_val)) in BROWSER_KEYS.items():
                with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_ALL_ACCESS) as k:
                    winreg.SetValueEx(k, incog_name, 0, winreg.REG_DWORD, incog_val)
                    winreg.SetValueEx(k, "BrowserGuestModeEnabled", 0, winreg.REG_DWORD, 0)
                    for name in lists:
                        _delete_tree(k, name)
                    # Яндекс: и новые имена, и старые (URLBlacklist/URLWhitelist)
                    pairs = [(lists[0], lists[1])] + ([(lists[2], lists[3])] if len(lists) == 4 else [])
                    for block_name, allow_name in pairs:
                        for name, values in ((block_name, block_list), (allow_name, allow_list)):
                            if not values:
                                continue
                            with winreg.CreateKeyEx(k, name, 0, winreg.KEY_ALL_ACCESS) as sub:
                                for i, d in enumerate(values, 1):
                                    winreg.SetValueEx(sub, str(i), 0, winreg.REG_SZ, d)
        log.info("%s: политики браузеров — %s, запрещённых %s", user,
                 "только учёба" if allowed is not None else "обычные", len(blocked))


def _clear(hive) -> bool:
    changed = False
    for path, (lists, (incog_name, _)) in BROWSER_KEYS.items():
        try:
            k = winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS)
        except OSError:
            continue
        with k:
            for name in lists:
                try:
                    winreg.OpenKey(k, name).Close()
                    _delete_tree(k, name)
                    changed = True
                except OSError:
                    pass
            for v in (incog_name, "BrowserGuestModeEnabled"):
                try:
                    winreg.DeleteValue(k, v)
                    changed = True
                except OSError:
                    pass
    return changed


def _delete_tree(parent, name: str) -> None:
    try:
        with winreg.OpenKey(parent, name, 0, winreg.KEY_ALL_ACCESS) as k:
            while True:
                try:
                    sub = winreg.EnumKey(k, 0)
                except OSError:
                    break
                _delete_tree(k, sub)
        winreg.DeleteKey(parent, name)
    except FileNotFoundError:
        pass
