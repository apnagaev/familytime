"""Помощник FamilyTime в сеансе пользователя (familytime-helper.exe).

Запускается службой. Каждые 2 с отправляет службе отчёт (активная программа, адрес вкладки,
простой, видимые окна) и выполняет указания: показать сообщение, закрыть окна, экран «потерян».
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import sys
import threading
import time
import tkinter as tk

import pywintypes
import win32api
import win32event
import win32file
import win32pipe
import winerror

from .. import PIPE_NAME, VERSION
from . import winutil
from .appname import app_name
from .browser_url import UrlReader
from .ui import UI

log = logging.getLogger("familytime.helper")

TITLES = {"warn": "Скоро конец времени", "limit": "Время закончилось",
          "window": "Сейчас время для учёбы", "info": "Только учёба"}


class Helper:
    def __init__(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.ui = UI(self.root)
        self.urls = UrlReader()
        self.pipe = None
        self.last_error = ""
        self.directive: dict = {}
        self.shown: set[str] = set()
        self.closed_browsers: set[str] = set()
        self.close_sent: dict[int, float] = {}
        self.wifi: dict | None = None
        self.fg: dict = {}
        self.tabs_closed: set[str] = set()
        self.wifi_at = 0.0
        self.browsers = {"chrome.exe", "msedge.exe", "browser.exe"}

    # ---------- отчёт ----------

    def collect(self) -> dict:
        hwnd, pid = winutil.foreground()
        if pid and hwnd:
            pid = winutil.real_pid(hwnd, pid)
        exe = winutil.exe_of(pid) if pid else ""
        domain = ""
        if exe in self.browsers and hwnd:
            domain = self.urls.get(hwnd, winutil.title_of(hwnd))
        app = app_name(pid) if pid else ""
        self.fg = {"exe": exe, "domain": domain, "app": app, "hwnd": int(hwnd or 0)}
        windows = []
        for w, p in winutil.app_windows():
            p = winutil.real_pid(w, p)
            windows.append({"pid": p, "exe": winutil.exe_of(p)})
        seen, uniq = set(), []
        for w in windows:
            if w["pid"] not in seen:
                seen.add(w["pid"])
                uniq.append(w)
        rep = {
            "v": 1,
            "idle": round(winutil.idle_seconds(), 1),
            "locked": winutil.desktop_locked(),
            "fullscreen": winutil.is_fullscreen(hwnd),
            "fg": self.fg,
            "windows": uniq[:200],
        }
        if self.wifi:
            rep["wifi"] = self.wifi
        return rep

    # ---------- канал ----------

    def _connect(self) -> None:
        h = win32file.CreateFile(PIPE_NAME, win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                 0, None, win32file.OPEN_EXISTING, 0, None)
        win32pipe.SetNamedPipeHandleState(h, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        # на другом конце должна быть служба (сеанс 0), а не подделка из сеанса пользователя.
        # GetNamedPipeServerSessionId не требует прав на процесс службы (в отличие от
        # ProcessIdToSessionId по pid, который обычному пользователю отказывает).
        sid = ctypes.c_ulong(0xFFFFFFFF)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetNamedPipeServerSessionId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        if not k32.GetNamedPipeServerSessionId(int(h), ctypes.byref(sid)) or sid.value != 0:
            err = ctypes.get_last_error()
            h.Close()
            raise pywintypes.error(5, "pipe", f"сервер канала не служба (сеанс {sid.value}, код {err})")
        self.pipe = h
        log.info("подключён к службе")

    def exchange(self, report: dict) -> dict:
        try:
            if self.pipe is None:
                self._connect()
            win32file.WriteFile(self.pipe, json.dumps(report, ensure_ascii=False).encode("utf-8"))
            data = b""
            while True:
                hr, chunk = win32file.ReadFile(self.pipe, 256 * 1024)
                data += chunk
                if hr != winerror.ERROR_MORE_DATA:
                    break
            self.directive = json.loads(data.decode("utf-8") or "{}")
            self.last_error = ""
        except (pywintypes.error, ValueError) as e:
            if self.pipe is not None:
                log.info("канал со службой закрыт: %s", e)
                try:
                    self.pipe.Close()
                except pywintypes.error:
                    pass
            elif str(e) != self.last_error:
                log.warning("нет связи со службой: %s", e)
            self.last_error = str(e)
            self.pipe = None
        return self.directive

    # ---------- указания ----------

    def apply(self, d: dict) -> None:
        now = time.time()
        n = d.get("notify")
        if n and n["id"] not in self.shown and n.get("expires", 0) > now:
            self.shown.add(n["id"])
            if n.get("modal"):
                self.ui.show_modal(TITLES.get(n["kind"], "Время за компьютером"), n["text"],
                                   n.get("portal", ""))
            else:
                self.ui.show_toast(n["text"])
        for pid in d.get("close", []):
            if now - self.close_sent.get(pid, 0) > 5:
                self.close_sent[pid] = now
                winutil.close_pid_windows(pid)
        cb = d.get("close_browsers")
        if cb and cb not in self.closed_browsers:
            self.closed_browsers.add(cb)
            for hwnd, pid in winutil.app_windows():
                if winutil.exe_of(pid) in self.browsers:
                    winutil.user32.PostMessageW(hwnd, winutil.WM_CLOSE, 0, 0)
        ct = d.get("close_tab")
        if ct and ct["id"] not in self.tabs_closed:
            self.tabs_closed.add(ct["id"])
            hwnd, _ = winutil.foreground()
            # только если на экране всё ещё та же вкладка: не закрыть чужое по ошибке
            if self.fg.get("domain") and (not ct.get("hwnd") or int(hwnd or 0) == ct["hwnd"]):
                cur = self.urls.get(hwnd, winutil.title_of(hwnd)) if hwnd else ""
                if cur and ct["domain"] in cur.lower():
                    log.info("закрываю вкладку с запрещённым сайтом %s", ct["domain"])
                    winutil.send_ctrl("w")
        lost = d.get("lost")
        self.ui.set_lost(lost["message"] if lost else None)
        if d.get("want_wifi") and now - self.wifi_at > 240:
            self.wifi_at = now
            threading.Thread(target=self._scan_wifi, daemon=True).start()

    def _scan_wifi(self) -> None:
        from ..win import wlan
        aps = wlan.scan()
        self.wifi = {"at": time.time(), "aps": aps or []}

    # ---------- цикл ----------

    def tick(self) -> None:
        try:
            self.apply(self.exchange(self.collect()))
        except Exception:  # noqa: BLE001
            log.exception("ошибка шага помощника")
        finally:
            self.root.after(2000, self.tick)

    def run(self) -> None:
        self.root.after(200, self.tick)
        self.root.mainloop()


def main() -> None:
    mutex = win32event.CreateMutex(None, False, "Local\\FamilyTimeHelper")
    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        return
    logdir = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "FamilyTime")
    os.makedirs(logdir, exist_ok=True)
    logging.basicConfig(filename=os.path.join(logdir, "helper.log"), level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", encoding="utf-8")
    logging.getLogger("comtypes").setLevel(logging.WARNING)    # генерация обёрток — шум
    log.info("помощник %s запущен, pid %s", VERSION, os.getpid())
    try:
        Helper().run()
    finally:
        del mutex


if __name__ == "__main__":
    sys.exit(main())
